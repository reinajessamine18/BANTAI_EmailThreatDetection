import pytest

from app.services.catalog import CatalogError, FeatureInsight, build_catalog
from tests.helpers import real_catalog

GOOD = {
    "risk_low_max": "39", "risk_medium_max": "79", "top_n_explanations": "5",
    "insight_generic_phishing": 'Word "{token}" up.', "insight_generic_safe": 'Word "{token}" down.',
}
FEATURE = FeatureInsight(1, "urgency_keyword_count", "text", "Educational Insight", "T", "tmpl")


def test_real_seed_builds_a_valid_catalog(tmp_path):
    cat = real_catalog(tmp_path)
    assert (cat.policy.low_max, cat.policy.medium_max, cat.top_n) == (39, 79, 5)
    assert cat.token_features["urgent"].feature_key == "urgency_keyword_count"
    assert cat.token_features["verify"].title == "Request for Sensitive Information"
    assert set(cat.lexicons) == {"urgency_keyword_count", "credential_request_count"}
    assert "urgent" in cat.lexicons["urgency_keyword_count"]
    assert "sentiment_score" not in cat.features          # inactive features are excluded
    assert "spf_fail" in cat.features and len(cat.features) == 20


def test_tokens_mapped_to_inactive_or_unknown_features_are_ignored():
    cat = build_catalog(GOOD, [FEATURE], [("urgent", "urgency_keyword_count"), ("x", "sentiment_score")])
    assert set(cat.token_features) == {"urgent"}


@pytest.mark.parametrize("key", ["risk_low_max", "risk_medium_max", "top_n_explanations",
                                 "insight_generic_phishing", "insight_generic_safe"])
def test_missing_setting_is_a_clear_error(key):
    settings = {k: v for k, v in GOOD.items() if k != key}
    with pytest.raises(CatalogError):
        build_catalog(settings, [FEATURE], [])


@pytest.mark.parametrize("override", [
    {"risk_low_max": "abc"}, {"risk_low_max": "80"}, {"risk_medium_max": "100"},
    {"top_n_explanations": "0"}, {"insight_generic_safe": "no placeholder here"},
])
def test_invalid_setting_is_a_clear_error(override):
    with pytest.raises(CatalogError):
        build_catalog({**GOOD, **override}, [FEATURE], [])
