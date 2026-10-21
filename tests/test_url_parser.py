from src.url_parser import parse_url, validate_url


def test_valid_url():
    ok, message = validate_url("https://www.example.com/login")
    assert ok is True


def test_invalid_url():
    ok, message = validate_url("not-a-url")
    assert ok is False


def test_ip_hostname():
    parsed = parse_url("https://93.184.216.34")
    assert parsed["is_ip"] is True


def test_punycode_url():
    parsed = parse_url("https://xn--test-123.example.com")
    assert parsed["hostname"].startswith("xn--")


def test_malformed_url_rejected():
    ok, _ = validate_url("http:///missing-host")
    assert ok is False


def test_ipv6_and_url_components_are_parsed():
    parsed = parse_url("https://[2001:db8::1]:8443/a?x=1#section")
    assert parsed["is_ip"] is True
    assert parsed["is_ipv6"] is True
    assert parsed["port"] == 8443
    assert parsed["query"] == "x=1"
    assert parsed["fragment"] == "section"


def test_invalid_port_is_rejected():
    ok, _ = validate_url("https://example.com:99999/")
    assert ok is False


def test_unsupported_scheme_is_rejected():
    ok, _ = validate_url("javascript:alert(1)")
    assert ok is False


def test_invalid_ipv6_and_hostname_characters_are_rejected():
    assert validate_url("https://[not-ip]/")[0] is False
    assert validate_url("https://example.com%zz/")[0] is False


def test_long_urls_can_be_parsed_for_offline_dataset_features():
    long_url = "https://example.com/" + ("x" * 2500)
    assert validate_url(long_url)[0] is True
