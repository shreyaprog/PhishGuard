import ipaddress
import re
from urllib.parse import unquote, urlsplit

import tldextract

VALID_SCHEMES = {"http", "https"}
_extract_domain = tldextract.TLDExtract(suffix_list_urls=())


def validate_url(raw_url: str):
    if raw_url is None:
        return False, "URL is required."
    candidate = (raw_url or "").strip()
    if not candidate:
        return False, "URL is required."
    if len(candidate) > 8192:
        return False, "URL is too long for safe analysis."
    if any(ch.isspace() for ch in candidate):
        return False, "Whitespace is not allowed in a URL."
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", candidate):
        return False, "URL must include a scheme such as http:// or https://."
    try:
        split = urlsplit(candidate)
        hostname = split.hostname
        port = split.port
    except ValueError:
        return False, "URL could not be parsed safely."
    if split.scheme.lower() not in VALID_SCHEMES:
        return False, "Only http and https are supported for analysis."
    if not hostname:
        return False, "Hostname is missing from the URL."
    if hostname.startswith(".") or hostname.endswith("."):
        return False, "Hostname is malformed."
    if hostname.lower() == "localhost":
        return False, "Localhost URLs are restricted for this application."
    if port is not None:
        if not 1 <= port <= 65535:
            return False, "Port must be between 1 and 65535."
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return False, "Hostname contains invalid international characters."
        labels = ascii_hostname.split(".")
        if len(ascii_hostname) > 253 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[A-Za-z0-9-]+", label)
            for label in labels
        ):
            return False, "Hostname is malformed."
    return True, "Valid URL"


def parse_url(raw_url: str):
    if not raw_url:
        raise ValueError("URL is required.")
    candidate = raw_url.strip()
    ok, message = validate_url(candidate)
    if not ok:
        raise ValueError(message)
    split = urlsplit(candidate)
    hostname = (split.hostname or "").lower()
    port = split.port
    extracted = _extract_domain(candidate)
    registrable = extracted.top_domain_under_public_suffix or ""
    subdomain = extracted.subdomain or ""
    domain = extracted.domain or ""
    tld = extracted.suffix or ""
    subdomain_registered = _extract_domain(subdomain).top_domain_under_public_suffix if subdomain else ""
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        pass
    info = {
        "original": raw_url.strip(),
        "normalised": candidate,
        "scheme": split.scheme.lower(),
        "hostname": hostname,
        "port": port,
        "path": split.path or "/",
        "query": split.query,
        "fragment": split.fragment,
        "username": split.username,
        "password": split.password,
        "netloc": split.netloc,
        "is_ip": is_ip,
        "is_ipv6": ":" in hostname,
        "is_localhost": hostname in {"localhost", "127.0.0.1", "::1"},
        "full_domain": hostname,
        "registrable_domain": registrable,
        "subdomain": subdomain,
        "has_misleading_subdomain": bool(subdomain_registered and subdomain_registered != registrable),
        "domain": domain,
        "tld": tld,
        "has_userinfo": bool(split.username or split.password),
        "has_query": bool(split.query),
        "has_fragment": bool(split.fragment),
        "decoded_url": unquote(candidate),
    }
    return info


def normalise_url(raw_url: str):
    parsed = parse_url(raw_url)
    return parsed["normalised"]
