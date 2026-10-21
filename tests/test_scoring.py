from src.risk_scorer import calculate_rule_score, combine_signals


def test_rule_score_calculation():
    findings = [
        {"rule_id": "R001", "severity": "high"},
        {"rule_id": "R006", "severity": "medium"},
        {"rule_id": "R004", "severity": "medium"},
    ]
    assert calculate_rule_score(findings) == 55


def test_combine_signals_returns_risk():
    result = combine_signals(model_probability=0.8, findings=[{"rule_id": "R001", "severity": "high"}])
    assert result["overall_risk"] in {"High risk", "Suspicious"}


def test_no_finding_baseline_is_low_apparent_risk_without_model():
    findings = [{"rule_id": "R010", "severity": "low"}]
    result = combine_signals(findings=findings)
    assert result["rule_score"] == 0
    assert result["overall_risk"] == "Low apparent risk"


def test_disagreement_is_reported():
    result = combine_signals(model_probability=0.8, findings=[])
    assert result["signals_disagree"] is True


def test_invalid_model_probability_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        combine_signals(model_probability=1.1, findings=[])
