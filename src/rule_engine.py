from .url_parser import parse_url

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _make_finding(rule_id, title, severity, evidence, reason, recommendation, limitation):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "reason": reason,
        "recommendation": recommendation,
        "limitation": limitation,
    }


def run_rule_engine(raw_url: str):
    try:
        parsed = parse_url(raw_url)
    except ValueError:
        return []
    host = parsed["hostname"]
    findings = []
    path = parsed["path"]
    full = f"{host} {path} {parsed['query']}".lower()

    if parsed["is_ip"]:
        findings.append(_make_finding(
            "R001",
            "IP address hostname",
            "high",
            host,
            "Direct use of an IP address instead of a normal registrable domain can suggest a non-standard or malicious server configuration.",
            "Verify whether the destination is expected. Prefer a domain name managed by a legitimate service provider.",
            "An IP address may be used for internal testing or self-hosted systems and is not conclusive evidence of phishing."
        ))
    if parsed["has_userinfo"]:
        findings.append(_make_finding(
            "R002",
            "Credentials syntax present",
            "medium",
            parsed["netloc"],
            "The URL contains user credentials before the hostname, which is uncommon for trusted browsing and can be abused in deceptive links.",
            "Avoid clicking the link and check whether the URL was copied from a trusted message or email.",
            "Some internal systems legitimately use credentials in special URLs, but it is unusual in public web browsing."
        ))
    if "xn--" in host:
        findings.append(_make_finding(
            "R003",
            "Punycode or encoded hostname",
            "medium",
            host,
            "Punycode can disguise a domain by representing international characters using ASCII labels.",
            "Inspect the destination carefully and confirm the intended website through a trusted channel.",
            "Punycode is not automatically malicious, but it can be used in deceptive ways."
        ))
    if parsed["has_misleading_subdomain"]:
        findings.append(_make_finding(
            "R008",
            "Brand-like domain embedded in a subdomain",
            "high",
            parsed["subdomain"],
            "A domain-like name appears within the subdomain while the actual registrable domain is different.",
            "Check the registrable domain at the end of the hostname and open the intended service through a trusted route.",
            "Multi-level subdomains can be legitimate; this structural signal is not proof that the URL is malicious."
        ))
    if "%" in raw_url:
        findings.append(_make_finding(
            "R004",
            "URL encoding detected",
            "medium",
            raw_url[:120],
            "Encoded characters can hide suspicious text or mask the true destination beyond the visible URL.",
            "Examine the decoded destination before entering credentials or personal details.",
            "Some legitimate systems use percent-encoding for specific characters, so this should be treated as a supporting indicator only."
        ))
    suspicious_keywords = [word for word in ["login", "verify", "secure", "reset", "password", "confirm", "invoice", "payment", "bank"] if word in full]
    if suspicious_keywords:
        findings.append(_make_finding(
            "R005",
            "Sensitive keyword combination",
            "medium" if len(suspicious_keywords) <= 2 else "high",
            ", ".join(suspicious_keywords),
            "Keywords linked to account access, identity confirmation or account recovery are common in phishing pages.",
            "Open the site through a direct trusted link rather than a click-through URL from an email or chat message.",
            "A security-related phrase alone is not proof of phishing, because some legitimate applications use similar wording."
        ))
    if host.count("-") > 2 or (host.count(".") > 3 and host.split(".")[0] not in {"www", "login", "secure"}):
        findings.append(_make_finding(
            "R006",
            "Complex or suspicious hostname structure",
            "medium",
            host,
            "A very structured or heavily hyphenated hostname can be used to mimic a trusted brand or hide a malicious destination.",
            "Check the actual registrable domain and compare it against the expected brand or service.",
            "Some legitimate sites also use subdomains or additional naming conventions, so the pattern should be reviewed together with other signals."
        ))
    if parsed["has_query"] and ("login" in full or "verify" in full or "account" in full):
        findings.append(_make_finding(
            "R007",
            "Credential recovery wording in query string",
            "medium",
            parsed["query"][:160],
            "Sensitive account workflows often appear in query parameters to collect user actions or session data.",
            "Review the destination carefully and use the service's official app or website instead of a direct link.",
            "This is a weak indicator without other contextual evidence such as a suspicious hostname or email lure."
        ))
    if not findings:
        findings.append(_make_finding(
            "R010",
            "No major rule violations observed",
            "low",
            host,
            "The URL does not trigger obvious phishing heuristics according to the local rule set.",
            "Continue monitoring the URL and verify it against the trusted service if the user is unsure.",
            "A clean rule result is not a guarantee that the destination is safe."
        ))
    return findings
