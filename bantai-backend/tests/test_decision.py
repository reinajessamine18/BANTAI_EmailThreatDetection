from app.services.decision import assess
from app.services.email_parser import parse_eml
from tests.helpers import FakePrediction, contribution, real_catalog
from tests.test_indicators import PHISH

BENIGN = (
    b"From: Ana <ana@school.example>\r\nReturn-Path: <ana@school.example>\r\nSubject: Lunch\r\n"
    b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n\r\n"
    b"Are we still meeting for lunch tomorrow?\r\n"
)


def test_critical_phishing_assessment_end_to_end(tmp_path):
    cat = real_catalog(tmp_path)
    prediction = FakePrediction(
        phishing_probability=0.92, classification="Phishing",
        top_contributions=(
            contribution("meeting", -0.4), contribution("verify", 1.2),
            contribution("zzword", 0.3), contribution("urgent", 0.9),
        ),
    )
    a = assess(parse_eml(PHISH), prediction, cat)
    assert (a.threat_score, a.risk_tier, a.risk_level) == (92, "Critical", "phishing")
    assert a.model_classification == "Phishing" and a.phishing_probability == 0.92
    assert [e.token for e in a.token_explanations] == ["verify", "urgent", "meeting", "zzword"]
    assert a.token_explanations[0].title == "Request for Sensitive Information"
    assert a.token_explanations[2].direction == "toward_safe"
    assert {"has_ip_url", "spf_fail", "sender_domain_mismatch"} <= {i.feature_key for i in a.indicators}
    assert len(a.indicator_values) == 20


def test_low_risk_benign_assessment(tmp_path):
    cat = real_catalog(tmp_path)
    prediction = FakePrediction(0.03, "Safe", (contribution("lunch", -0.8),))
    a = assess(parse_eml(BENIGN), prediction, cat)
    assert (a.threat_score, a.risk_tier, a.risk_level) == (3, "Low", "safe")
    assert a.indicators == ()


def test_score_depends_only_on_model_probability_not_on_indicators(tmp_path):
    cat = real_catalog(tmp_path)
    same = FakePrediction(0.30, "Safe", ())
    assert assess(parse_eml(PHISH), same, cat).threat_score == assess(parse_eml(BENIGN), same, cat).threat_score == 30


def test_tier_can_differ_from_model_label_and_both_are_reported(tmp_path):
    cat = real_catalog(tmp_path)
    a = assess(parse_eml(BENIGN), FakePrediction(0.60, "Phishing", ()), cat)
    assert (a.model_classification, a.risk_tier, a.risk_level) == ("Phishing", "Medium", "suspicious")


def test_catalog_threshold_change_changes_tier_without_code_change(tmp_path):
    from dataclasses import replace
    from app.services.threat_scoring import RiskPolicy
    cat = replace(real_catalog(tmp_path), policy=RiskPolicy(low_max=20, medium_max=60))
    assert assess(parse_eml(BENIGN), FakePrediction(0.70, "Phishing", ()), cat).risk_tier == "Critical"
