import pytest

from app.services.explanations import TITLE_LOWERED, TITLE_RAISED, explain_tokens
from tests.helpers import FakeContribution, contribution, real_catalog


def test_mapped_phishing_word_gets_educational_text(tmp_path):
    cat = real_catalog(tmp_path)
    [e] = explain_tokens([contribution("verify", 1.4)], cat)
    assert e.rank == 1 and e.direction == "toward_phishing"
    assert e.title == "Request for Sensitive Information"
    assert 'The word "verify"' in e.message and "Legitimate organizations" in e.message
    assert e.contribution == 1.4                       # raw log-odds, untouched


def test_unmapped_phishing_word_gets_generic_text(tmp_path):
    cat = real_catalog(tmp_path)
    [e] = explain_tokens([contribution("zzword", 0.6)], cat)
    assert e.title == TITLE_RAISED and e.insight_type == "Educational Insight"
    assert 'The word "zzword"' in e.message and "toward phishing" in e.message


def test_safe_direction_never_gets_phishing_lesson_even_if_mapped(tmp_path):
    cat = real_catalog(tmp_path)
    [e] = explain_tokens([contribution("verify", -0.7)], cat)    # 'verify' IS in the map
    assert e.title == TITLE_LOWERED and "toward safe" in e.message
    assert "Legitimate organizations" not in e.message


def test_top_n_limit_and_ordering_by_absolute_value(tmp_path):
    cat = real_catalog(tmp_path)                                  # top_n = 5
    items = [contribution(f"w{i}", v) for i, v in enumerate([0.1, -0.9, 0.5, 0.2, -0.3, 1.1, 0.05])]
    out = explain_tokens(items, cat)
    assert [e.token for e in out] == ["w5", "w1", "w2", "w4", "w3"]
    assert [e.rank for e in out] == [1, 2, 3, 4, 5]


def test_token_is_sanitized_and_braces_are_harmless(tmp_path):
    cat = real_catalog(tmp_path)
    [e] = explain_tokens([contribution("a\x00b{0}{token}\n", 0.5)], cat)
    assert "\x00" not in e.token and "\n" not in e.token
    assert "{0}" in e.message                                      # inserted literally, no formatting


def test_empty_input_and_bad_direction(tmp_path):
    cat = real_catalog(tmp_path)
    assert explain_tokens([], cat) == ()
    with pytest.raises(ValueError):
        explain_tokens([FakeContribution("x", 0.3, "sideways")], cat)
