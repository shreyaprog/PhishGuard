import ipaddress
import re
from urllib.parse import parse_qsl

from .url_parser import parse_url

SUSPICIOUS_TOKENS = [
    "login", "signin", "verify", "secure", "account", "bank", "reset",
    "password", "update", "confirm", "alert", "urgent", "invoice", "payment",
    "pay", "mfa", "assistance", "credential"
]

FEATURE_COLUMNS = [
    "url_length", "hostname_length", "path_length", "dot_count", "subdomain_count",
    "hyphen_count", "digit_count", "special_char_count", "query_parameter_count",
    "has_ip_address", "has_explicit_port", "has_url_encoding", "has_at_symbol",
    "has_misleading_subdomain", "has_long_hostname", "uses_https", "uses_unusual_scheme",
    "is_valid_domain", "is_punycode", "has_login_keywords", "has_account_keywords",
    "has_urgency_keywords", "has_payment_keywords", "has_long_encoded_string"
]


def _count_chars(text, chars):
    return sum(1 for ch in text if ch in chars)


def _contains_keyword(value, keywords):
    lowered = (value or "").lower()
    return any(keyword in lowered for keyword in keywords)


def extract_features(raw_url: str):
    parsed = parse_url(raw_url)
    hostname = parsed["hostname"]
    path = parsed["path"]
    query = parsed["query"]
    host_tokens = hostname.split(".") if hostname else []
    query_params = parse_qsl(query, keep_blank_values=True)

    has_ip = False
    try:
        ipaddress.ip_address(hostname)
        has_ip = True
    except ValueError:
        pass

    has_long_hostname = len(hostname) > 25
    has_url_encoding = "%" in raw_url
    has_at_symbol = "@" in raw_url
    has_explicit_port = parsed["port"] is not None
    has_long_encoded_string = len(re.findall(r"%[0-9A-Fa-f]{2}", raw_url)) > 3
    is_punycode = "xn--" in hostname.lower()
    misleading = parsed["has_misleading_subdomain"]
    uses_unusual_scheme = parsed["scheme"] not in {"http", "https"}
    is_valid_domain = bool(hostname and ("." in hostname or hostname == "localhost"))

    features = {
        "url_length": len(raw_url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "dot_count": hostname.count("."),
        "subdomain_count": 0 if has_ip else max(len(host_tokens) - 2, 0),
        "hyphen_count": _count_chars(hostname, "-"),
        "digit_count": sum(ch.isdigit() for ch in hostname),
        "special_char_count": sum(1 for ch in hostname if not ch.isalnum() and ch not in {".", "-"}),
        "query_parameter_count": len(query_params),
        "has_ip_address": int(has_ip),
        "has_explicit_port": int(has_explicit_port),
        "has_url_encoding": int(has_url_encoding),
        "has_at_symbol": int(has_at_symbol),
        "has_misleading_subdomain": int(misleading),
        "has_long_hostname": int(has_long_hostname),
        "uses_https": int(parsed["scheme"] == "https"),
        "uses_unusual_scheme": int(uses_unusual_scheme),
        "is_valid_domain": int(is_valid_domain),
        "is_punycode": int(is_punycode),
        "has_login_keywords": int(_contains_keyword(hostname + " " + path + " " + query, ["login", "signin", "verify", "secure"])),
        "has_account_keywords": int(_contains_keyword(hostname + " " + path + " " + query, ["account", "profile", "security", "access"])),
        "has_urgency_keywords": int(_contains_keyword(hostname + " " + path + " " + query, ["urgent", "alert", "immediate", "action"])),
        "has_payment_keywords": int(_contains_keyword(hostname + " " + path + " " + query, ["payment", "invoice", "billing", "card", "bank"])),
        "has_long_encoded_string": int(has_long_encoded_string),
    }
    return features


def feature_vector(raw_url: str):
    features = extract_features(raw_url)
    return [features[col] for col in FEATURE_COLUMNS]
