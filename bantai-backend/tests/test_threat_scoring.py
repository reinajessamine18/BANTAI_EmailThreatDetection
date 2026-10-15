import pytest

from app.services.threat_scoring import (
    RiskPolicy,
    probability_to_score,
    risk_tier,
    ui_risk_level,
)

POLICY = RiskPolicy(low_max=39, medium_max=79)


@pytest.mark.parametrize("p,expected", [(0.0, 0), (0.88, 88), (0.885, 89), (0.994, 99), (0.996, 100), (1.0, 100), (0.5, 50)])
def test_probability_to_score_rounds_half_up(p, expected):
    assert probability_to_score(p) == expected


@pytest.mark.parametrize("bad", [-0.01, 1.01, float("nan"), float("inf"), True])
def test_probability_to_score_rejects_invalid(bad):
    with pytest.raises(ValueError):
        probability_to_score(bad)


@pytest.mark.parametrize("score,tier", [(0, "Low"), (39, "Low"), (40, "Medium"), (79, "Medium"), (80, "Critical"), (100, "Critical")])
def test_tier_boundaries(score, tier):
    assert risk_tier(score, POLICY) == tier


@pytest.mark.parametrize("bad", [-1, 101, 5.5, True, "50"])
def test_risk_tier_rejects_invalid_score(bad):
    with pytest.raises(ValueError):
        risk_tier(bad, POLICY)


@pytest.mark.parametrize("low,mid", [(50, 40), (40, 40), (-1, 50), (10, 100), ("a", 50), (True, 50)])
def test_policy_rejects_inconsistent_thresholds(low, mid):
    with pytest.raises(ValueError):
        RiskPolicy(low, mid)


def test_ui_levels_match_frontend_names():
    assert [ui_risk_level(t) for t in ("Low", "Medium", "Critical")] == ["safe", "suspicious", "phishing"]
    with pytest.raises(ValueError):
        ui_risk_level("High")
