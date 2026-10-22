import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from urllib import error, request

from config import THREAT_INTELLIGENCE_PROVIDER, THREAT_INTELLIGENCE_URLHAUS_API_URL
from src.database import get_connection
from src.url_parser import parse_url, validate_url

try:
    import requests  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - optional dependency fallback
    requests = None


class ThreatIntelligenceError(RuntimeError):
    """Base error for threat-intelligence operations."""


class ProviderConfigurationError(ThreatIntelligenceError):
    """Raised when the configured provider is unavailable or disabled."""


class ProviderResponseError(ThreatIntelligenceError):
    """Raised when the provider response cannot be processed or is unexpectedly empty."""


class ProviderRateLimitError(ProviderResponseError):
    """Raised when the provider enforces a rate limit."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalise_provider_name(provider_name: str | None) -> str:
    provider = (provider_name or THREAT_INTELLIGENCE_PROVIDER or "urlhaus").strip().lower()
    if not provider:
        return "urlhaus"
    return provider


def _to_utc_iso(value):
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="seconds")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text).astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            return text
    return None


def _is_enabled(provider_name: str | None = None) -> bool:
    name = _normalise_provider_name(provider_name)
    value = os.getenv(f"THREAT_INTELLIGENCE_{name.upper()}_ENABLED", "true").strip().lower()
    return value not in {"0", "false", "no", "disabled"}


def _safe_json_loads(raw: str, *, field_name: str):
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProviderResponseError(f"Malformed JSON from {field_name} provider") from exc
    if payload is None:
        raise ProviderResponseError(f"Empty JSON payload from {field_name} provider")
    return payload


def _provider_base_url(provider_name: str | None = None) -> str:
    name = _normalise_provider_name(provider_name)
    if name == "urlhaus":
        return os.getenv("THREAT_INTELLIGENCE_URLHAUS_API_URL", THREAT_INTELLIGENCE_URLHAUS_API_URL)
    raise ProviderConfigurationError(f"Unsupported provider: {name}")


def _extract_candidate_domain(value: str):
    candidate = (value or "").strip()
    if not candidate:
        return None, None
    try:
        parsed = parse_url(candidate if "://" in candidate else f"https://{candidate}")
    except ValueError:
        return None, None
    return parsed["hostname"], parsed.get("registrable_domain") or parsed["hostname"]


def normalise_indicator_record(raw_record: dict, provider_name: str | None = None):
    provider = _normalise_provider_name(provider_name)
    if not isinstance(raw_record, dict):
        return None
    value = (raw_record.get("url") or raw_record.get("indicator_value") or raw_record.get("value") or "").strip()
    if not value:
        domain_value = (raw_record.get("domain") or raw_record.get("hostname") or "").strip()
        if not domain_value:
            return None
        value = domain_value
        indicator_type = "domain"
    else:
        indicator_type = raw_record.get("indicator_type") or ("url" if "://" in value else "domain")
    if indicator_type not in {"url", "domain"}:
        indicator_type = "url" if "://" in value else "domain"
    try:
        if indicator_type == "url":
            valid, _ = validate_url(value)
            if not valid:
                return None
            parsed = parse_url(value)
            canonical_value = parsed["normalised"]
            domain_value = parsed["hostname"]
        else:
            candidate = value if value.startswith("http://") or value.startswith("https://") else f"https://{value}"
            parsed = parse_url(candidate)
            canonical_value = parsed["hostname"]
            domain_value = parsed["hostname"]
    except ValueError:
        return None
    status = (raw_record.get("status") or raw_record.get("threat") or raw_record.get("verification_status") or "unknown").strip()[:200]
    first_seen = _to_utc_iso(raw_record.get("first_seen") or raw_record.get("firstseen") or raw_record.get("date_added") or raw_record.get("date_first_seen"))
    last_seen = _to_utc_iso(raw_record.get("last_seen") or raw_record.get("lastseen") or raw_record.get("date_last_seen") or raw_record.get("date_seen"))
    expires_at = _to_utc_iso(raw_record.get("expires_at") or raw_record.get("expiry") or raw_record.get("expiration"))
    retrieved_at = _to_utc_iso(raw_record.get("retrieved_at")) or utc_now_iso()
    created_at = _to_utc_iso(raw_record.get("created_at")) or retrieved_at
    updated_at = _to_utc_iso(raw_record.get("updated_at")) or created_at
    provider_id = str(raw_record.get("external_id") or raw_record.get("id") or raw_record.get("reference") or raw_record.get("url") or canonical_value)
    record = {
        "indicator_type": indicator_type,
        "url": canonical_value if indicator_type == "url" else f"https://{domain_value}",
        "domain": domain_value,
        "indicator_value": canonical_value,
        "canonical_value": canonical_value,
        "provider": provider,
        "source": provider,
        "external_id": provider_id[:255],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "verification_status": status,
        "status": status,
        "feed_retrieved_at": retrieved_at,
        "created_at": created_at,
        "updated_at": updated_at,
        "expires_at": expires_at,
        "raw_metadata": json.dumps(raw_record, ensure_ascii=True, sort_keys=True)[:10000],
    }
    return record


class URLHausProvider:
    def __init__(self, *, provider_name: str = "urlhaus", base_url: str | None = None, timeout: int = 10, max_response_bytes: int = 1_048_576, enabled: bool | None = None):
        self.provider_name = _normalise_provider_name(provider_name)
        self.base_url = base_url or _provider_base_url(self.provider_name)
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.enabled = enabled if enabled is not None else _is_enabled(self.provider_name)

    def _request(self):
        if not self.enabled:
            raise ProviderConfigurationError(f"{self.provider_name} is disabled or unconfigured.")
        headers = {"User-Agent": "PhishGuard/0.1 (+local threat-intelligence client)", "Accept": "application/json, text/plain;q=0.9"}
        if requests is not None:
            response = requests.get(self.base_url, timeout=self.timeout, headers=headers)
            if response.status_code == 401:
                raise ProviderConfigurationError("The provider rejected the request; verify the configuration or access policy.")
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                raise ProviderRateLimitError(f"Rate limited by {self.provider_name}. Retry after {retry_after or 'briefly'}.")
            if response.status_code >= 400:
                raise ProviderResponseError(f"HTTP {response.status_code} from {self.provider_name}")
            payload = response.content[: self.max_response_bytes + 1]
            if len(payload) > self.max_response_bytes:
                raise ProviderResponseError(f"Response from {self.provider_name} exceeded the maximum allowed size.")
            return payload, response.headers
        req = request.Request(self.base_url, headers=headers)
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                payload = response.read(self.max_response_bytes + 1)
                if len(payload) > self.max_response_bytes:
                    raise ProviderResponseError(f"Response from {self.provider_name} exceeded the maximum allowed size.")
                return payload, dict(response.headers)
        except error.HTTPError as exc:
            if exc.code == 401:
                raise ProviderConfigurationError("The provider rejected the request; verify the configuration or access policy.") from exc
            if exc.code == 429:
                retry_after = exc.headers.get("Retry-After") if hasattr(exc, "headers") else None
                raise ProviderRateLimitError(f"Rate limited by {self.provider_name}. Retry after {retry_after or 'briefly'}.") from exc
            raise ProviderResponseError(f"HTTP {exc.code} from {self.provider_name}") from exc
        except (TimeoutError, OSError) as exc:
            raise ProviderResponseError(f"Connection to {self.provider_name} failed") from exc

    def fetch_indicators(self):
        payload, _ = self._request()
        content = payload.decode("utf-8", errors="strict")
        parsed = _safe_json_loads(content, field_name=self.provider_name)
        if not isinstance(parsed, dict):
            raise ProviderResponseError(f"Unexpected format from {self.provider_name}: expected a JSON object.")
        candidates = parsed.get("urls") or parsed.get("data") or parsed.get("results") or []
        if not isinstance(candidates, list):
            raise ProviderResponseError(f"Unexpected provider response shape from {self.provider_name}.")
        records = []
        for item in candidates:
            if not isinstance(item, dict):
                continue
            record = normalise_indicator_record(item, provider_name=self.provider_name)
            if record is not None:
                records.append(record)
        return records


def build_provider(provider_name: str | None = None, **kwargs):
    provider = _normalise_provider_name(provider_name)
    if provider in {"urlhaus", "abuse_ch", "abusech"}:
        return URLHausProvider(provider_name=provider, **kwargs)
    raise ProviderConfigurationError(f"The feed provider '{provider}' is not supported.")


def _match_reason_for(value: str, row):
    if value and row.get("url") and value.lower() == str(row.get("url")).lower():
        return "exact_url_match"
    if value and row.get("domain") and value.lower() == str(row.get("domain")).lower():
        return "exact_hostname_match"
    if value and row.get("domain"):
        candidate = value.lower()
        normalized_row = str(row.get("domain")).lower()
        if candidate == normalized_row:
            return "exact_hostname_match"
        if candidate.endswith("." + normalized_row) and candidate != normalized_row:
            return "subdomain_match"
    return "matching_policy"


def lookup_indicator(value: str, *, provider_name: str | None = None):
    candidate = (value or "").strip()
    if not candidate:
        return {
            "status": "NO_MATCH",
            "match_found": False,
            "provider": "local",
            "indicator_value": "",
            "indicator_type": "unknown",
            "match_method": "no_input",
            "explanation": "No URL or domain was supplied for a local indicator lookup.",
            "limitations": ["Threat intelligence data is contextual evidence, not proof of current maliciousness."],
        }
    try:
        if "//" in candidate:
            parsed = parse_url(candidate)
            lookup_values = [parsed["normalised"].lower(), parsed["hostname"].lower()]
        else:
            parsed = parse_url(f"https://{candidate}")
            lookup_values = [parsed["normalised"].lower(), parsed["hostname"].lower()]
    except ValueError:
        lookup_values = [candidate.lower()]

    conn = get_connection()
    try:
        query = """
            SELECT * FROM indicators
            WHERE lower(url) = ?
               OR lower(domain) = ?
               OR lower(indicator_value) = ?
               OR lower(url) = ?
               OR lower(domain) = ?
            ORDER BY id DESC
            LIMIT 25
        """
        params = [lookup_values[0], lookup_values[1], lookup_values[0], lookup_values[0], lookup_values[1]]
        rows = conn.execute(query, tuple(params)).fetchall()
    except sqlite3.Error as exc:
        return {
            "status": "LOOKUP_ERROR",
            "match_found": False,
            "provider": _normalise_provider_name(provider_name) if provider_name else "local",
            "indicator_value": candidate,
            "indicator_type": "unknown",
            "match_method": "database_error",
            "explanation": "The local indicator database could not be queried.",
            "limitations": [str(exc)],
        }
    finally:
        conn.close()

    if not rows:
        return {
            "status": "NO_MATCH",
            "match_found": False,
            "provider": "local",
            "indicator_value": candidate,
            "indicator_type": "unknown",
            "match_method": "no_exact_match",
            "explanation": "No exact local indicator match was found for the submitted URL or hostname.",
            "limitations": ["A no-match result does not prove the URL is legitimate.", "Indicators are source-specific evidence, not proof of current maliciousness."],
        }

    exact = None
    for row in rows:
        row_map = dict(row)
        if row_map.get("url") and candidate.lower() == str(row_map.get("url")).lower():
            exact = row_map
            break
        if row_map.get("domain") and candidate.lower() == str(row_map.get("domain")).lower():
            exact = row_map
            break
        if row_map.get("indicator_value") and candidate.lower() == str(row_map.get("indicator_value")).lower():
            exact = row_map
            break
    if exact is None:
        exact = dict(rows[0])
    match_method = _match_reason_for(candidate, exact)
    return {
        "status": "MATCH_FOUND",
        "match_found": True,
        "provider": exact.get("source") or exact.get("provider") or "local",
        "indicator_value": exact.get("indicator_value") or exact.get("url") or exact.get("domain"),
        "indicator_type": exact.get("indicator_type") or "url",
        "match_method": match_method,
        "source_status": exact.get("status") or exact.get("verification_status") or "known",
        "source_timestamps": {
            "first_seen": exact.get("first_seen"),
            "last_seen": exact.get("last_seen"),
            "retrieved_at": exact.get("feed_retrieved_at"),
            "updated_at": exact.get("updated_at"),
            "expires_at": exact.get("expires_at"),
        },
        "explanation": f"The submitted value matched a stored indicator from {exact.get('source') or 'the local feed'} using {match_method}.",
        "limitations": ["A threat-intelligence match is source-specific evidence, not proof of current maliciousness."],
    }


def refresh_provider_feed(provider_name: str | None = None, *, timeout: int = 10):
    provider_label = _normalise_provider_name(provider_name)
    started_at = utc_now_iso()
    result = {
        "provider": provider_label,
        "status": "failed",
        "started_at": started_at,
        "finished_at": None,
        "records_fetched": 0,
        "records_inserted": 0,
        "records_updated": 0,
        "records_rejected": 0,
        "errors": [],
        "last_successful_refresh": None,
    }
    conn = get_connection()
    try:
        try:
            provider = build_provider(provider_label, timeout=timeout)
            records = provider.fetch_indicators()
        except Exception as exc:  # pragma: no cover - network/adapter behaviour covered by tests
            result["errors"].append(str(exc))
            result["finished_at"] = utc_now_iso()
            conn.execute(
                "INSERT INTO feed_refreshes (provider, status, started_at, finished_at, records_fetched, records_inserted, records_updated, invalid_records, errors) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (provider_label, "failed", started_at, result["finished_at"], 0, 0, 0, 0, json.dumps(result["errors"], ensure_ascii=True)),
            )
            conn.commit()
            return result

        result["records_fetched"] = len(records)
        valid_records = []
        for raw_record in records:
            normalized = normalise_indicator_record(raw_record, provider_name=provider_label)
            if normalized is not None:
                valid_records.append(normalized)
            else:
                result["records_rejected"] += 1

        before = conn.execute("SELECT COUNT(*) AS count FROM indicators").fetchone()["count"]
        inserted = 0
        updated = 0
        for record in valid_records:
            existing = conn.execute(
                "SELECT * FROM indicators WHERE source = ? AND indicator_type = ? AND lower(url) = lower(?) LIMIT 1",
                (record["source"], record["indicator_type"], record["indicator_value"]),
            ).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO indicators (url, domain, indicator_type, status, source, last_updated, notes, indicator_value, canonical_value, external_id, first_seen, last_seen, verification_status, feed_retrieved_at, created_at, updated_at, expires_at, raw_metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        record["url"],
                        record["domain"],
                        record["indicator_type"],
                        record["status"],
                        record["source"],
                        record["updated_at"],
                        "Imported from URLHaus refresh",
                        record["indicator_value"],
                        record["canonical_value"],
                        record["external_id"],
                        record["first_seen"],
                        record["last_seen"],
                        record["verification_status"],
                        record["feed_retrieved_at"],
                        record["created_at"],
                        record["updated_at"],
                        record["expires_at"],
                        record["raw_metadata"],
                    ),
                )
                inserted += 1
            else:
                conn.execute(
                    "UPDATE indicators SET url = ?, domain = ?, indicator_type = ?, status = ?, last_updated = ?, indicator_value = ?, canonical_value = ?, external_id = ?, first_seen = ?, last_seen = ?, verification_status = ?, feed_retrieved_at = ?, updated_at = ?, expires_at = ?, raw_metadata = ? WHERE id = ?",
                    (
                        record["url"],
                        record["domain"],
                        record["indicator_type"],
                        record["status"],
                        record["updated_at"],
                        record["indicator_value"],
                        record["canonical_value"],
                        record["external_id"],
                        record["first_seen"],
                        record["last_seen"],
                        record["verification_status"],
                        record["feed_retrieved_at"],
                        record["updated_at"],
                        record["expires_at"],
                        record["raw_metadata"],
                        existing["id"],
                    ),
                )
                updated += 1
        conn.commit()
        result["records_inserted"] = inserted
        result["records_updated"] = updated
        result["status"] = "success"
        result["finished_at"] = utc_now_iso()
        result["last_successful_refresh"] = result["finished_at"]
        conn.execute(
            "INSERT INTO feed_refreshes (provider, status, started_at, finished_at, records_fetched, records_inserted, records_updated, invalid_records, errors, last_successful_refresh) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (provider_label, "success", started_at, result["finished_at"], result["records_fetched"], inserted, updated, result["records_rejected"], json.dumps(result["errors"], ensure_ascii=True), result["finished_at"]),
        )
        conn.commit()
        return result
    finally:
        conn.close()


def get_feed_status(provider_name: str | None = None):
    provider_label = _normalise_provider_name(provider_name)
    conn = get_connection()
    try:
        latest = conn.execute(
            "SELECT * FROM feed_refreshes WHERE provider = ? ORDER BY id DESC LIMIT 1",
            (provider_label,),
        ).fetchone()
        if latest is None:
            return {
                "provider": provider_label,
                "enabled": _is_enabled(provider_label),
                "last_attempted_refresh": None,
                "last_successful_refresh": None,
                "latest_status": "never_run",
                "stored_indicator_count": conn.execute("SELECT COUNT(*) AS count FROM indicators WHERE source = ?", (provider_label,)).fetchone()["count"],
            }
        refresh = dict(latest)
        return {
            "provider": provider_label,
            "enabled": _is_enabled(provider_label),
            "last_attempted_refresh": refresh.get("started_at"),
            "last_successful_refresh": refresh.get("last_successful_refresh") or refresh.get("finished_at"),
            "latest_status": refresh.get("status"),
            "stored_indicator_count": conn.execute("SELECT COUNT(*) AS count FROM indicators WHERE source = ?", (provider_label,)).fetchone()["count"],
            "records_fetched": refresh.get("records_fetched"),
            "records_inserted": refresh.get("records_inserted"),
            "records_updated": refresh.get("records_updated"),
            "invalid_records": refresh.get("invalid_records"),
        }
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Refresh local threat intelligence indicators from a configured provider.")
    parser.add_argument("command", nargs="?", default="refresh", choices=["refresh", "status"])
    parser.add_argument("--provider", default=None)
    args = parser.parse_args()
    if args.command == "status":
        print(json.dumps(get_feed_status(args.provider), sort_keys=True, indent=2))
    else:
        print(json.dumps(refresh_provider_feed(args.provider), sort_keys=True, indent=2))
