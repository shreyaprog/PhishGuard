from io import StringIO

import pytest

from src import database


def test_database_initialisation_and_write(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.sqlite3")
    database.init_db()
    rec = {
        "submitted_url": "https://example.com",
        "normalised_url": "https://example.com",
        "scan_time": "2026-01-01T00:00:00Z",
        "model_verdict": "legitimate",
        "model_probability": 0.1,
        "rule_score": 5,
        "risk_score": 10,
        "overall_risk": "Low apparent risk",
        "findings": [],
        "model_version": "test",
        "analysis_status": "complete",
        "explanation": "Test"
    }
    inserted = database.add_scan(rec)
    assert inserted > 0
    history = database.get_scan_history(limit=10)
    assert any(item["submitted_url"] == "https://example.com" for item in history)
    assert database.get_scan_by_id(inserted)["risk_score"] == 10
    assert database.get_scan_history(category="Low apparent risk")
    assert database.get_scan_history(search="example.com")


def test_indicator_import_rejects_invalid_rows_without_partial_writes(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "indicators.sqlite3")
    database.init_db()
    content = StringIO("url,source\nhttps://valid.example.test,unit test\nnot-a-url,unit test\n")
    with pytest.raises(ValueError):
        database.import_indicators_from_csv(content)
    assert database.get_indicator_count() == 0
