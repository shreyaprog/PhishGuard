from src.rule_engine import run_rule_engine


def test_rule_engine_rejects_ip_url():
    findings = run_rule_engine("http://127.0.0.1/login")
    assert any(f["rule_id"] == "R001" for f in findings)


def test_rule_engine_handles_suspicious_keywords():
    findings = run_rule_engine("https://verify-account-login.securebank.example.com/reset")
    assert any(f["title"] == "Sensitive keyword combination" for f in findings)
