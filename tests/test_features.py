from src.feature_extractor import extract_features, feature_vector


def test_feature_vector_length():
    features = extract_features("https://www.example.com/login?next=verify")
    assert len(feature_vector("https://www.example.com/login?next=verify")) > 0
    assert features["has_login_keywords"] == 1


def test_encoded_chars_are_detected():
    features = extract_features("https://secure-bank-login.example.com/%65mail")
    assert features["has_url_encoding"] == 1


def test_misleading_subdomain_flagged():
    features = extract_features("https://login.paypal.com.example.net")
    assert features["has_misleading_subdomain"] == 1


def test_normal_subdomain_is_not_misleading():
    features = extract_features("https://secure.example.com")
    assert features["has_misleading_subdomain"] == 0
