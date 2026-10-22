import csv
import json
import sqlite3
from datetime import datetime, timezone

from config import DATABASE_PATH
from .url_parser import parse_url, validate_url


def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submitted_url TEXT NOT NULL,
            normalised_url TEXT,
            scan_time TEXT NOT NULL,
            model_verdict TEXT,
            model_probability REAL,
            rule_score INTEGER,
            risk_score INTEGER,
            overall_risk TEXT,
            findings TEXT,
            model_explanation TEXT,
            model_metadata TEXT,
            model_version TEXT,
            analysis_status TEXT,
            explanation TEXT
        )
        """
    )
    scan_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(scans)").fetchall()
    }
    if "risk_score" not in scan_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN risk_score INTEGER")
    if "model_explanation" not in scan_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN model_explanation TEXT")
    if "model_metadata" not in scan_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN model_metadata TEXT")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT,
            indicator_type TEXT,
            status TEXT,
            source TEXT,
            last_updated TEXT,
            notes TEXT,
            indicator_value TEXT,
            canonical_value TEXT,
            external_id TEXT,
            first_seen TEXT,
            last_seen TEXT,
            verification_status TEXT,
            feed_retrieved_at TEXT,
            created_at TEXT,
            updated_at TEXT,
            expires_at TEXT,
            raw_metadata TEXT
        )
        """
    )
    indicator_columns = {row["name"] for row in conn.execute("PRAGMA table_info(indicators)").fetchall()}
    for column_name, column_type in {
        "indicator_value": "TEXT",
        "canonical_value": "TEXT",
        "external_id": "TEXT",
        "first_seen": "TEXT",
        "last_seen": "TEXT",
        "verification_status": "TEXT",
        "feed_retrieved_at": "TEXT",
        "created_at": "TEXT",
        "updated_at": "TEXT",
        "expires_at": "TEXT",
        "raw_metadata": "TEXT",
    }.items():
        if column_name not in indicator_columns:
            conn.execute(f"ALTER TABLE indicators ADD COLUMN {column_name} {column_type}")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS feed_refreshes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            status TEXT,
            started_at TEXT,
            finished_at TEXT,
            records_fetched INTEGER,
            records_inserted INTEGER,
            records_updated INTEGER,
            invalid_records INTEGER,
            errors TEXT,
            last_successful_refresh TEXT
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_indicator_identity ON indicators (source, indicator_type, lower(url))"
    )
    conn.commit()
    conn.close()


def add_scan(record):
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO scans (submitted_url, normalised_url, scan_time, model_verdict, model_probability, rule_score, risk_score, overall_risk, findings, model_explanation, model_metadata, model_version, analysis_status, explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.get("submitted_url"),
            record.get("normalised_url"),
            record.get("scan_time"),
            record.get("model_verdict"),
            record.get("model_probability"),
            record.get("rule_score"),
            record.get("risk_score"),
            record.get("overall_risk"),
            json.dumps(record.get("findings", [])),
            json.dumps(record.get("model_explanation", [])),
            json.dumps(record.get("model_metadata", {})),
            record.get("model_version"),
            record.get("analysis_status"),
            record.get("explanation"),
        )
    )
    conn.commit()
    row_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.close()
    return row_id


def get_scan_history(limit=20, category=None, search=None):
    conn = get_connection()
    limit = max(1, min(int(limit), 5000))
    query = "SELECT * FROM scans"
    params = []
    filters = []
    if category:
        filters.append("overall_risk = ?")
        params.append(category)
    if search:
        escaped_search = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        filters.append("submitted_url LIKE ? ESCAPE '\\'")
        params.append(f"%{escaped_search}%")
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    data = dict(row)
    data["findings"] = json.loads(data["findings"] or "[]")
    data["model_explanation"] = json.loads(data["model_explanation"] or "[]")
    data["model_metadata"] = json.loads(data["model_metadata"] or "{}")
    return data


def delete_scan(scan_id):
    conn = get_connection()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()


def clear_history():
    conn = get_connection()
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()


def get_dashboard_stats():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) AS count FROM scans").fetchone()["count"]
    phishing = conn.execute("SELECT COUNT(*) AS count FROM scans WHERE overall_risk IN ('High risk', 'Suspicious')").fetchone()["count"]
    legitimate = conn.execute("SELECT COUNT(*) AS count FROM scans WHERE overall_risk = 'Low apparent risk'").fetchone()["count"]
    inconclusive = conn.execute("SELECT COUNT(*) AS count FROM scans WHERE overall_risk = 'Inconclusive'").fetchone()["count"]
    failed = conn.execute("SELECT COUNT(*) AS count FROM scans WHERE analysis_status = 'failed'").fetchone()["count"]
    recent = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 5").fetchall()
    risk_counts = conn.execute("SELECT overall_risk, COUNT(*) AS count FROM scans GROUP BY overall_risk").fetchall()
    conn.close()
    return {
        "total": total,
        "phishing_like": phishing,
        "phishing_percentage": round((phishing / total * 100), 2) if total else 0,
        "legitimate": legitimate,
        "inconclusive": inconclusive,
        "failed": failed,
        "recent": [dict(row) for row in recent],
        "risk_counts": [dict(row) for row in risk_counts],
    }


def get_indicator_count():
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) AS count FROM indicators").fetchone()["count"]
    conn.close()
    return count


def get_indicators():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM indicators ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def search_indicators(value):
    value = (value or "").strip()
    if not value:
        return []
    parsed_value = value
    hostname = value.lower()
    try:
        parsed = parse_url(value if "://" in value else f"https://{value}")
        parsed_value = parsed["normalised"].lower()
        hostname = parsed["hostname"].lower()
    except ValueError:
        pass
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT * FROM indicators
        WHERE lower(url) = ? OR lower(domain) = ? OR lower(indicator_value) = ? OR lower(url) = ? OR lower(domain) = ?
        ORDER BY id DESC LIMIT 50
        """,
        (parsed_value, hostname, parsed_value, value.lower(), hostname),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_feed_refresh_history(limit=20):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM feed_refreshes ORDER BY id DESC LIMIT ?",
        (max(1, min(int(limit), 500)),),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_feed_summary():
    conn = get_connection()
    latest = conn.execute("SELECT * FROM feed_refreshes ORDER BY id DESC LIMIT 1").fetchone()
    total = conn.execute("SELECT COUNT(*) AS count FROM indicators").fetchone()["count"]
    by_provider = conn.execute("SELECT source, COUNT(*) AS count FROM indicators GROUP BY source ORDER BY count DESC").fetchall()
    conn.close()
    return {
        "latest_refresh": dict(latest) if latest else None,
        "total_indicators": total,
        "by_provider": [dict(row) for row in by_provider],
    }


def import_indicators_from_csv(handle):
    reader = csv.DictReader(handle)
    if not reader.fieldnames or "url" not in {name.strip().lower() for name in reader.fieldnames}:
        raise ValueError("CSV must have a 'url' column.")

    url_column = next(name for name in reader.fieldnames if name.strip().lower() == "url")
    rows = []
    seen = set()
    for line_number, row in enumerate(reader, start=2):
        submitted_url = (row.get(url_column) or "").strip()
        if not submitted_url:
            raise ValueError(f"CSV row {line_number} has no URL.")
        valid, message = validate_url(submitted_url)
        if not valid:
            raise ValueError(f"CSV row {line_number}: {message}")
        parsed = parse_url(submitted_url)
        key = parsed["normalised"].lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append((
            parsed["normalised"],
            parsed["hostname"],
            (row.get("indicator_type") or ("url" if "://" in submitted_url else "domain")).strip()[:80],
            (row.get("status") or "known").strip()[:80],
            (row.get("source") or "CSV import").strip()[:160],
            (row.get("last_updated") or datetime.now(timezone.utc).isoformat(timespec="seconds")).strip()[:80],
            (row.get("notes") or "Imported from local CSV").strip()[:500],
            parsed["normalised"],
            parsed["normalised"],
            (row.get("external_id") or "").strip()[:255],
            (row.get("first_seen") or "").strip()[:80],
            (row.get("last_seen") or "").strip()[:80],
            (row.get("verification_status") or (row.get("status") or "known")).strip()[:200],
            (row.get("feed_retrieved_at") or datetime.now(timezone.utc).isoformat(timespec="seconds")).strip()[:80],
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            (row.get("expires_at") or "").strip()[:80],
            json.dumps({k: v for k, v in row.items() if v is not None}, ensure_ascii=True, sort_keys=True)[:10000],
        ))

    conn = get_connection()
    try:
        before = conn.total_changes
        conn.executemany(
            """
            INSERT INTO indicators (
                url, domain, indicator_type, status, source, last_updated, notes,
                indicator_value, canonical_value, external_id, first_seen, last_seen,
                verification_status, feed_retrieved_at, created_at, updated_at, expires_at, raw_metadata
            )
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM indicators WHERE lower(url) = lower(?) OR lower(indicator_value) = lower(?)
            )
            """,
            [row + (row[0], row[0]) for row in rows],
        )
        imported = conn.total_changes - before
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()
    return imported


def export_history_csv(path):
    rows = get_scan_history(limit=5000)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "submitted_url", "normalised_url", "scan_time", "model_verdict", "model_probability", "rule_score", "risk_score", "overall_risk", "analysis_status"])
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "id": row["id"],
                "submitted_url": row["submitted_url"],
                "normalised_url": row["normalised_url"],
                "scan_time": row["scan_time"],
                "model_verdict": row["model_verdict"],
                "model_probability": row["model_probability"],
                "rule_score": row["rule_score"],
                "risk_score": row.get("risk_score"),
                "overall_risk": row["overall_risk"],
                "analysis_status": row["analysis_status"],
            })


def history_csv_content():
    from io import StringIO

    output = StringIO(newline="")
    rows = get_scan_history(limit=5000)
    writer = csv.DictWriter(output, fieldnames=[
        "id", "submitted_url", "normalised_url", "scan_time", "model_verdict",
        "model_probability", "rule_score", "risk_score", "overall_risk", "analysis_status",
    ])
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key) for key in writer.fieldnames})
    return output.getvalue()
