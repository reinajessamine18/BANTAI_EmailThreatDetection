#!/usr/bin/env python
"""
test_packaged_content_nlp.py

Automated unit and regression test suite for Phase 7:
  Model Packaging and Inference Contract Implementation.

Verifies:
  1. Package manifest and cryptographic SHA-256 verification.
  2. Exact model/vectorizer pairing, dimensional consistency (25k), and classes contract.
  3. Valid content-only inference (probabilities, margins, decision threshold).
  4. Explicit rejection of missing, empty, whitespace-only, and post-cleaning degenerate inputs.
  5. URL and email excision with visible anchor text preservation.
  6. Training/inference preprocessing parity and idempotency.
  7. On-demand SHAP TreeExplainer token attributions and 1e-5 additivity enforcement.
  8. Robust error handling on corrupt or missing package artifacts.
  9. Latency and resource performance validation.
  10. Disclosure of provisional release status, data-quality caveats, and academic disclaimers.
"""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import numpy as np
import pytest
import scipy.special

ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.models.content_nlp_inference import (
    ADDITIVITY_TOLERANCE,
    CLASS_LEGITIMATE,
    CLASS_PHISHING,
    DEFAULT_PACKAGE_DIR,
    LABEL_LEGITIMATE,
    LABEL_PHISHING,
    MAX_BODY_CHARS,
    ContentNLPPrediction,
    ContentNLPPredictor,
    InferenceError,
    get_predictor,
    predict_email,
    validate_body_text,
    warm_up,
)
from src.preprocessing.content_cleaner import (
    CleanerConfig,
    ContentOnlyCleaner,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ML_DIR = REPO_ROOT / "machine-learning"
PACKAGE_DIR = ML_DIR / "artifacts" / "packaged_content_nlp"
MANIFEST_FILE = PACKAGE_DIR / "model_manifest.json"
ENV_LOCK_FILE = PACKAGE_DIR / "environment_lock.json"


def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class TestPackagedContentNLP:
    """Automated test suite for Phase 7 packaged content-only NLP model."""

    def test_01_package_manifest_and_checksum_verification(self):
        assert PACKAGE_DIR.is_dir(), f"Missing package directory: {PACKAGE_DIR}"
        assert MANIFEST_FILE.is_file(), f"Missing manifest: {MANIFEST_FILE}"
        assert ENV_LOCK_FILE.is_file(), f"Missing env lock: {ENV_LOCK_FILE}"

        with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        assert manifest["package_name"] == "BANTAI_Content_Only_NLP_Primary"
        assert manifest["candidate_experiment_id"] == "EXP-4"
        assert manifest["release_status"] == "provisional_research_candidate"
        assert manifest["model_type"] == "exploratory_full_corpus_refit"

        artifacts = manifest["artifacts"]
        for key in ["model_joblib", "model_json", "vectorizer_joblib", "environment_lock"]:
            entry = artifacts[key]
            fpath = PACKAGE_DIR / entry["filename"]
            assert fpath.is_file(), f"Artifact file missing from disk: {fpath}"
            actual_sha = compute_sha256(fpath)
            assert actual_sha == entry["sha256"], f"Checksum mismatch for {fpath.name}: {actual_sha} != {entry['sha256']}"

    def test_02_model_vectorizer_pairing_and_feature_dimensions(self):
        predictor = ContentNLPPredictor(PACKAGE_DIR, lazy_explainer=True)
        assert predictor.model.n_features_in_ == 25000
        assert len(predictor.vectorizer.vocabulary_) == 25000
        assert len(predictor.feature_names) == 25000
        assert list(predictor.model.classes_) == [0, 1]
        assert getattr(predictor.model, "objective", None) == "binary:logistic"

    def test_03_valid_content_only_inference(self):
        predictor = ContentNLPPredictor(PACKAGE_DIR, lazy_explainer=True)

        # Phishing sample
        phish_text = (
            "Dear Customer, We detected unauthorized access to your account. "
            "Please verify your security credentials immediately before your access is suspended."
        )
        res_phish = predictor.predict(phish_text, explain=False)
        assert isinstance(res_phish, ContentNLPPrediction)
        assert res_phish.label == LABEL_PHISHING
        assert res_phish.classification == CLASS_PHISHING
        assert res_phish.phishing_probability >= 0.50
        assert res_phish.safe_probability == pytest.approx(1.0 - res_phish.phishing_probability, abs=1e-6)
        assert res_phish.raw_margin > 0
        assert res_phish.shap_base_value is None

        # Logistic link verification
        sig_p = float(scipy.special.expit(res_phish.raw_margin))
        assert abs(sig_p - res_phish.phishing_probability) <= 1e-5

        # Legitimate corporate sample
        ham_text = (
            "Hi team, Here is the updated agenda for our engineering sync tomorrow at 10 AM. "
            "Please review the attached notes and let me know if you have questions."
        )
        res_ham = predictor.predict(ham_text, explain=False)
        assert res_ham.label == LABEL_LEGITIMATE
        assert res_ham.classification == CLASS_LEGITIMATE
        assert res_ham.safe_probability > 0.50
        assert res_ham.phishing_probability < 0.50
        assert res_ham.raw_margin < 0

        sig_p_ham = float(scipy.special.expit(res_ham.raw_margin))
        assert abs(sig_p_ham - res_ham.phishing_probability) <= 1e-5

    def test_04_invalid_and_degenerate_input_rejection(self):
        predictor = ContentNLPPredictor(PACKAGE_DIR, lazy_explainer=True)

        # 1. Non-string / None
        with pytest.raises(TypeError, match="must be a non-null string"):
            predictor.predict(None)

        with pytest.raises(TypeError, match="must be a non-null string"):
            predictor.predict(12345)

        # 2. Empty string
        with pytest.raises(ValueError, match="cannot be empty"):
            predictor.predict("")

        # 3. Whitespace-only string
        with pytest.raises(ValueError, match="contains only whitespace characters"):
            predictor.predict("   \t\r\n  ")

        # 4. Content that becomes empty after canonical cleaning (URL only)
        with pytest.raises(ValueError, match="no readable natural-language text after canonical cleaning"):
            predictor.predict("https://phish.example.com/login?token=abc12345")

        # 5. Content that becomes empty after canonical cleaning (Email only)
        with pytest.raises(ValueError, match="no readable natural-language text after canonical cleaning"):
            predictor.predict("user@domain.com admin@corp.org")

        # 6. Content that becomes empty after canonical cleaning (Empty HTML markup only)
        with pytest.raises(ValueError, match="no readable natural-language text after canonical cleaning"):
            predictor.predict("<div><p><span></span></p></div>")

        # 7. Oversized input (> 200,000 characters)
        oversized = "a " * 100_001  # 200,002 chars
        with pytest.raises(ValueError, match="exceeds maximum allowable limit"):
            predictor.predict(oversized)

    def test_05_url_and_email_removal_with_anchor_preservation(self):
        predictor = ContentNLPPredictor(PACKAGE_DIR, lazy_explainer=True)

        # Anchor text preservation: visible link text is retained, href is stripped
        html_input = (
            "<p>Dear user, please <a href='https://malicious-phish.net/login'>click here to reset password</a> "
            "or contact support@example.com for help.</p>"
        )
        cleaned = predictor.cleaner.clean(html_input)

        assert "https://malicious-phish.net" not in cleaned
        assert "support@example.com" not in cleaned
        assert "click here to reset password" in cleaned
        assert "Dear user, please click here to reset password or contact for help." in cleaned

    def test_06_training_inference_preprocessing_parity(self):
        # Verify runtime cleaner matches training cleaner
        runtime_cleaner = ContentOnlyCleaner(
            CleanerConfig(
                url_strategy="remove",
                email_strategy="remove",
                normalize_whitespace=True,
                normalize_punctuation_spacing=True,
                preserve_case=True,
                extract_from_mime=False,
                preserve_anchor_text=True,
            )
        )
        train_cleaner = ContentOnlyCleaner()

        sample = "Please verify your account at https://bank.com immediately. Contact us at info@bank.com."
        c_train = train_cleaner.clean(sample)
        c_runtime = runtime_cleaner.clean(sample)
        assert c_train == c_runtime

        # Idempotency check: clean(clean(x)) == clean(x) on natural prose
        prose_sample = "Please verify your account immediately. Contact our support team for help."
        c_prose = runtime_cleaner.clean(prose_sample)
        assert runtime_cleaner.clean(c_prose) == c_prose

    def test_07_on_demand_shap_output_mapping_and_additivity(self):
        predictor = ContentNLPPredictor(PACKAGE_DIR, lazy_explainer=False)

        text = "Urgent: Please update your online banking account security credentials immediately."
        res = predictor.predict(text, explain=True, top_k=5)

        assert res.shap_base_value is not None
        assert res.additivity_residual is not None
        assert res.additivity_residual <= ADDITIVITY_TOLERANCE

        # Check positive contributions (toward phishing)
        assert len(res.top_positive_tokens) > 0
        for tok in res.top_positive_tokens:
            assert tok.contribution > 0
            assert tok.direction == "toward_phishing"
            assert isinstance(tok.token, str) and len(tok.token) > 0
            assert tok.token in predictor.vectorizer.vocabulary_

        # Verify margin decomposition
        calc_margin = res.shap_base_value + sum(t.contribution for t in res.top_positive_tokens + res.top_negative_tokens)
        # Note: res.additivity_residual verifies base_val + all_25k_shap == raw_margin
        assert abs(res.raw_margin - (res.shap_base_value + np.sum(predictor.get_explainer().shap_values(predictor.vectorizer.transform([predictor.cleaner.clean(text)]))[0]))) <= ADDITIVITY_TOLERANCE

    def test_08_error_handling_missing_or_corrupt_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # 1. Missing manifest
            with pytest.raises(InferenceError, match="Missing model manifest"):
                ContentNLPPredictor(tmp_path)

            # 2. Corrupt manifest SHA-256
            fake_manifest = {
                "artifacts": {
                    "model_joblib": {"filename": "model.joblib", "sha256": "fake_sha"},
                    "vectorizer_joblib": {"filename": "vectorizer.joblib", "sha256": "fake_sha"},
                }
            }
            with open(tmp_path / "model_manifest.json", "w", encoding="utf-8") as f:
                json.dump(fake_manifest, f)

            with pytest.raises(InferenceError, match="Packaged artifact file missing"):
                ContentNLPPredictor(tmp_path)

            # 3. Checksum mismatch
            (tmp_path / "model.joblib").write_text("corrupted content", encoding="utf-8")
            (tmp_path / "vectorizer.joblib").write_text("corrupted content", encoding="utf-8")

            with pytest.raises(InferenceError, match="Cryptographic checksum mismatch"):
                ContentNLPPredictor(tmp_path)

    def test_09_resource_performance_benchmarks(self):
        predictor = warm_up(PACKAGE_DIR)
        sample_medium = (
            "Dear Customer, We observed unusual activity on your account. "
            "Please click the link to update your security preferences and verify your billing address."
        )

        # Classification latency without SHAP (target: < 20 ms)
        t0 = time.time()
        for _ in range(20):
            _ = predictor.predict(sample_medium, explain=False)
        avg_classify_ms = ((time.time() - t0) / 20) * 1000
        assert avg_classify_ms < 20.0, f"Classification latency too high: {avg_classify_ms:.2f} ms"

        # Classification + SHAP latency (target: < 50 ms)
        t0 = time.time()
        for _ in range(10):
            _ = predictor.predict(sample_medium, explain=True)
        avg_explain_ms = ((time.time() - t0) / 10) * 1000
        assert avg_explain_ms < 50.0, f"Explanation latency too high: {avg_explain_ms:.2f} ms"

    def test_10_disclosed_limitations_and_provisional_status_in_manifest(self):
        with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        assert manifest["release_status"] == "provisional_research_candidate"
        assert "sa_row_4038" in " ".join(manifest["data_quality_limitations"])
        assert "23 candidate" in " ".join(manifest["data_quality_limitations"])
        assert "33.00%" in " ".join(manifest["data_quality_limitations"])
        assert "exploratory full-corpus refit" in manifest["disclaimer"]
        assert "In-sample training error is not a valid measure" in manifest["disclaimer"]
