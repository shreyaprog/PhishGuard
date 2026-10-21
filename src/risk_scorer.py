import math


RULE_GROUP_WEIGHTS = {
    "R001": ("host", 35),
    "R002": ("host", 35),
    "R003": ("obfuscation", 20),
    "R004": ("obfuscation", 20),
    "R005": ("sensitive_words", 15),
    "R006": ("host", 35),
    "R007": ("sensitive_words", 15),
    "R008": ("host", 35),
}


def calculate_rule_score(findings):
    groups = {}
    for finding in findings or []:
        rule_id = finding.get("rule_id")
        if rule_id in RULE_GROUP_WEIGHTS:
            group, weight = RULE_GROUP_WEIGHTS[rule_id]
            groups[group] = max(groups.get(group, 0), weight)
    return min(sum(groups.values()), 100)


def classify_risk(score, model_probability=None, findings=None):
    if score >= 70 or (model_probability is not None and model_probability >= 0.8):
        return "High risk"
    if score >= 35 or (model_probability is not None and model_probability >= 0.65):
        return "Suspicious"
    if score < 20 and (model_probability is None or model_probability < 0.4):
        return "Low apparent risk"
    return "Inconclusive"


def combine_signals(model_probability=None, findings=None):
    if model_probability is not None:
        if not isinstance(model_probability, (int, float)) or not math.isfinite(model_probability):
            raise ValueError("Model probability must be a finite number between 0 and 1.")
        if not 0 <= model_probability <= 1:
            raise ValueError("Model probability must be between 0 and 1.")
    rule_score = calculate_rule_score(findings or [])
    if model_probability is None:
        risk_score = rule_score
    else:
        risk_score = min(100, round((model_probability * 100 * 0.55) + (rule_score * 0.45)))
    verdict = classify_risk(risk_score, model_probability, findings or [])
    model_verdict = None
    disagreement = False
    if model_probability is not None:
        model_verdict = "phishing-like" if model_probability >= 0.5 else "likely legitimate"
        rule_verdict = "phishing-like" if rule_score >= 35 else "no strong rule signal"
        disagreement = (
            (model_verdict == "phishing-like" and rule_verdict == "no strong rule signal")
            or (model_verdict == "likely legitimate" and rule_verdict == "phishing-like")
        )
    return {
        "rule_score": rule_score,
        "risk_score": risk_score,
        "overall_risk": verdict,
        "model_verdict": model_verdict,
        "signals_disagree": disagreement,
    }
