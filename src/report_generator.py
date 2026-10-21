from html import escape


def generate_report(scan_record):
    findings = scan_record.get("findings", [])
    report = {
        "submitted_url": scan_record.get("submitted_url"),
        "normalised_url": scan_record.get("normalised_url"),
        "scan_time": scan_record.get("scan_time"),
        "model_verdict": scan_record.get("model_verdict"),
        "model_probability": scan_record.get("model_probability"),
        "rule_score": scan_record.get("rule_score"),
        "overall_risk": scan_record.get("overall_risk"),
        "analysis_status": scan_record.get("analysis_status"),
        "model_version": scan_record.get("model_version"),
        "risk_score": scan_record.get("risk_score"),
        "findings": findings,
        "model_explanation": scan_record.get("model_explanation", []),
        "model_metadata": scan_record.get("model_metadata", {}),
        "explanation": scan_record.get("explanation"),
    }
    return report


def render_html_report(scan_record):
    report = generate_report(scan_record)
    findings_html = ""
    for finding in report["findings"]:
        findings_html += (
            f"<li><strong>{escape(finding.get('title', 'Finding'))}</strong> "
            f"({escape(finding.get('severity', 'low'))})<br>"
            f"Evidence: {escape(str(finding.get('evidence', '')))}<br>"
            f"{escape(finding.get('reason', ''))}<br>"
            f"Recommended action: {escape(finding.get('recommendation', ''))}<br>"
            f"Limitation: {escape(finding.get('limitation', ''))}</li>"
        )
    model_explanation_html = "".join(
        f"<li>{escape(str(item.get('feature', 'Feature')))}: "
        f"{escape(str(item.get('direction', '')))} "
        f"({escape(str(item.get('contribution', '')) )})</li>"
        for item in report["model_explanation"]
    )
    return f"""
    <html>
<head><title>PhishGuard Report</title></head>
<body>
<h1>PhishGuard Report</h1>
<p><strong>Submitted URL:</strong> {escape(str(report['submitted_url']))}</p>
<p><strong>Scan time:</strong> {escape(str(report['scan_time']))}</p>
<p><strong>Verdict:</strong> {escape(str(report['overall_risk']))}</p>
<p><strong>Model verdict:</strong> {escape(str(report['model_verdict']))}</p>
<p><strong>Model probability:</strong> {escape(str(report['model_probability']))}</p>
<p><strong>Rule score:</strong> {escape(str(report['rule_score']))}</p>
<p><strong>Overall heuristic score:</strong> {escape(str(report['risk_score']))} / 100</p>
<p><strong>Model version:</strong> {escape(str(report['model_version']))}</p>
<p><strong>Model and dataset metadata:</strong> {escape(str(report['model_metadata']))}</p>
<h2>Findings</h2>
<ul>{findings_html}</ul>
<h2>Model feature contributions</h2>
<ul>{model_explanation_html}</ul>
<p><strong>Explanation:</strong> {escape(str(report['explanation']))}</p>
<p><strong>Limitations:</strong> This is a URL-based estimate, not proof of malicious intent or a guarantee of safety. Offline model results are not real-world performance guarantees. Review the URL and each finding before acting.</p>
</body>
</html>
"""
