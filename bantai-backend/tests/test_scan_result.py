import json

from app.services.decision import assess
from app.services.email_parser import parse_eml
from app.services.scan_result import build_scan_payload
from tests.helpers import FakePrediction, contribution, real_catalog
from tests.test_indicators import PHISH


def _payload(tmp_path, scan_id=7):
    cat = real_catalog(tmp_path)
    parsed = parse_eml(PHISH)
    prediction = FakePrediction(0.92, "Phishing", (contribution("verify", 1.2), contribution("meeting", -0.4)))
    a = assess(parsed, prediction, cat)
    return build_scan_payload(parsed=parsed, assessment=a, scan_id=scan_id, file_name="m.eml",
                              scanned_at="2026-10-13T10:00:00Z", inference_ms=41, model_version="v1")


def test_payload_has_every_field_the_react_screen_reads(tmp_path):
    p = _payload(tmp_path)
    for key in ("riskLevel", "threatScore", "explanations", "fileName", "scannedAt",
                "inferenceTimeMs", "sender", "subject", "emailBody"):
        assert key in p
    assert (p["riskLevel"], p["threatScore"], p["riskTier"]) == ("phishing", 92, "Critical")
    assert p["scanCode"] == "BNT-0007" and p["saved"] is True
    assert p["sender"] == "support@paypal-update.example" and "verify" in p["emailBody"].lower()


def test_word_and_indicator_explanations_have_the_shape_the_frontend_renders(tmp_path):
    ex = _payload(tmp_path)["explanations"]
    words = [e for e in ex if e["kind"] == "word"]
    inds = [e for e in ex if e["kind"] == "indicator"]
    assert [w["feature"] for w in words] == ["verify", "meeting"]
    assert words[0]["value"] == 1.2 and words[1]["value"] == -0.4 and words[1]["direction"] == "toward_safe"
    assert all(isinstance(e["title"], str) and e["insight"] for e in ex)
    assert inds and all(e["value"] is None and "observed" in e for e in inds)
    assert ex.index(words[-1]) < ex.index(inds[0])            # words first, then indicators


def test_unsaved_scan_has_no_id_and_payload_is_json_serializable(tmp_path):
    p = _payload(tmp_path, scan_id=None)
    assert p["scanId"] is None and p["scanCode"] is None and p["saved"] is False
    json.dumps(p)                                              # must not raise


def test_shap_block_states_the_unit_and_links_are_defanged(tmp_path):
    p = _payload(tmp_path)
    assert p["shap"]["unit"] == "log-odds" and "not whether" in p["shap"]["note"]
    assert p["links"] and all(l["url"].startswith("hxxp") for l in p["links"])
    assert "?" not in "".join(l["url"] for l in p["links"])
