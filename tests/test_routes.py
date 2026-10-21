import re
from io import BytesIO

import app as app_module
from app import app
from src import database


def _csrf_token(client):
    response = client.get("/scan")
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match
    return match.group(1).decode()


def test_dashboard_route_has_security_headers():
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_model_performance_route_without_model(monkeypatch):
    monkeypatch.setattr(app_module, "load_model", lambda: None)
    response = app.test_client().get("/model-performance")
    assert response.status_code == 200
    assert b"No trained model evaluation is available" in response.data


def test_scan_route_uses_csrf_and_persists(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "routes.sqlite3")
    database.init_db()
    client = app.test_client()
    token = _csrf_token(client)
    response = client.post("/scan", data={"url": "https://example.com", "csrf_token": token})
    assert response.status_code == 200
    assert b"Overall heuristic score" in response.data
    assert database.get_scan_history(limit=10)


def test_scan_rejects_missing_csrf_token():
    response = app.test_client().post("/scan", data={"url": "https://example.com"})
    assert response.status_code == 400


def test_interactive_scan_enforces_url_length_limit():
    client = app.test_client()
    token = _csrf_token(client)
    response = client.post(
        "/scan",
        data={"url": "https://example.com/" + ("x" * 2050), "csrf_token": token},
    )
    assert response.status_code == 200
    assert b"maximum 2048 characters" in response.data


def test_report_downloads_escape_untrusted_url(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "report.sqlite3")
    database.init_db()
    scan_id = database.add_scan({
        "submitted_url": 'https://example.test/"<script>alert(1)</script>',
        "normalised_url": "https://example.test/",
        "scan_time": "2026-01-01T00:00:00+00:00",
        "overall_risk": "Inconclusive",
        "findings": [],
        "model_version": "degraded-mode",
        "analysis_status": "degraded",
    })
    response = app.test_client().get(f"/history/{scan_id}/report.html")
    assert response.status_code == 200
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;" in response.data


def test_indicator_import_validates_and_deduplicates(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "indicators.sqlite3")
    database.init_db()
    client = app.test_client()
    token = _csrf_token(client)
    csv_data = b"url,source\nhttps://example.test/path,unit test\nhttps://example.test/path,duplicate\n"
    response = client.post(
        "/threat-intelligence/upload",
        data={"csrf_token": token, "csv_file": (BytesIO(csv_data), "indicators.csv")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 302
    assert database.get_indicator_count() == 1
    assert len(database.search_indicators("example.test/path")) == 1


def test_history_search_delete_and_clear_confirmation(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "history.sqlite3")
    database.init_db()
    first_id = database.add_scan({
        "submitted_url": "https://example.test/one",
        "normalised_url": "https://example.test/one",
        "scan_time": "2026-01-01T00:00:00+00:00",
        "overall_risk": "Suspicious",
        "findings": [],
        "analysis_status": "complete",
    })
    database.add_scan({
        "submitted_url": "https://other.test/two",
        "normalised_url": "https://other.test/two",
        "scan_time": "2026-01-02T00:00:00+00:00",
        "overall_risk": "Low apparent risk",
        "findings": [],
        "analysis_status": "complete",
    })
    client = app.test_client()
    assert b"example.test/one" in client.get("/history?q=example.test&risk=Suspicious").data
    assert b"other.test/two" not in client.get("/history?q=example.test&risk=Suspicious").data
    token = _csrf_token(client)
    response = client.post(f"/history/delete/{first_id}", data={"csrf_token": token})
    assert response.status_code == 302
    assert database.get_scan_by_id(first_id) is None

    refused = client.post("/history/clear", data={"csrf_token": token})
    assert refused.status_code == 302
    assert database.get_scan_history(limit=10)
    cleared = client.post("/history/clear", data={"csrf_token": token, "confirm": "yes"})
    assert cleared.status_code == 302
    assert database.get_scan_history(limit=10) == []
