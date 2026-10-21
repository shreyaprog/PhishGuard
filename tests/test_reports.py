from src.report_generator import generate_report, render_html_report


def test_generate_report_contains_url():
    record = {
        "submitted_url": "https://example.com",
        "normalised_url": "https://example.com",
        "scan_time": "2026-01-01T00:00:00Z",
        "model_verdict": "legitimate",
        "model_probability": 0.12,
        "rule_score": 5,
        "overall_risk": "Low apparent risk",
        "analysis_status": "complete",
        "explanation": "This is a low-risk example.",
        "findings": [{"title": "No issue", "severity": "low"}]
    }
    report = generate_report(record)
    assert report["submitted_url"] == "https://example.com"
    html = render_html_report(record)
    assert "PhishGuard Report" in html


def test_html_report_escapes_untrusted_html():
    html = render_html_report({
        "submitted_url": 'https://example.test/"><script>alert(1)</script>',
        "findings": [],
    })
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
