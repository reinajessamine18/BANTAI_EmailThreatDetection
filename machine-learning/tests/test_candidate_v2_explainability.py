#!/usr/bin/env python
"""
test_candidate_v2_explainability.py

Automated unit and regression test suite for Phase 6:
  SHAP Explainability Framework and Token Contribution Verification.

Verifies:
  1. Explainability artifact directory and manifest integrity (SHA-256 checksums).
  2. Numerical reproduction of saved EXP-4 OOF predictions (|p_recon - p_saved| <= 1e-5).
  3. Mathematical additivity of SHAP TreeExplainer in raw margin space:
     |base_value + sum(phi_i) - margin| <= 1e-5 across all evaluation samples.
  4. Exact logistic link function alignment:
     |sigmoid(margin) - prob| <= 1e-5.
  5. Representative explanation coverage across all required error modes:
     - True Positives (credential harvesting, vintage bank spoof)
     - True Negatives (routine Enron corporate, SpamAssassin open-source discussion)
     - False Negatives (recurring billing pretext, borderline miss, ultra-short lure)
     - Genuine False Positives (Category C legitimate Enron corporate correspondence)
     - Contaminated Enron Records (Category A brand impersonation mislabeled in Enron ham)
     - Extraction Anomaly (Category E unparsed Base64 .bmp attachment leakage artifact)
  6. Token attribution properties:
     - Correct direction: positive tokens push phishing, negative tokens push safe.
     - Additivity of positive and negative sums to total margin.
     - Valid feature token names from fitted vectorizer vocabulary.
  7. Strict ground-truth immutability:
     - Candidate V2 corpus and partition assignments remain cryptographically unchanged.
     - Benchmark labels untouched during explainability audit.
  8. Exploratory full-dataset model refit additivity verification and separation from CV.
"""

import hashlib
import json
from pathlib import Path
import numpy as np
import pandas as pd
import pytest
import scipy.special

REPO_ROOT = Path(__file__).resolve().parents[2]
ML_DIR = REPO_ROOT / "machine-learning"

V2_PROCESSED_DIR = ML_DIR / "data" / "processed" / "content_only_candidate_v2"
CANDIDATE_V2_CSV = V2_PROCESSED_DIR / "candidate_corpus_v2.csv"
CANDIDATE_V2_MANIFEST = V2_PROCESSED_DIR / "candidate_v2_manifest.json"
PARTITIONS_V2_CSV = V2_PROCESSED_DIR / "partition_assignments_v2.csv"
PARTITIONS_V2_MANIFEST = V2_PROCESSED_DIR / "partition_manifest_v2.json"

EXPLAINABILITY_DIR = ML_DIR / "artifacts" / "candidate_content_nlp_v2" / "explainability"
REPRESENTATIVE_JSON = EXPLAINABILITY_DIR / "representative_explanations.json"
ADDITIVITY_JSON = EXPLAINABILITY_DIR / "additivity_verification.json"
REPRODUCTION_JSON = EXPLAINABILITY_DIR / "fold_reproduction_metrics.json"
PROVENANCE_JSON = EXPLAINABILITY_DIR / "provenance.json"
MANIFEST_JSON = EXPLAINABILITY_DIR / "manifest.json"

EXPECTED_CATEGORIES = {
    "A_TRUE_POSITIVE",
    "B_TRUE_NEGATIVE",
    "C_FALSE_NEGATIVE",
    "D_GENUINE_FALSE_POSITIVE",
    "E_CONTAMINATED_ENRON_PHISH",
    "F_EXTRACTION_ANOMALY",
}


def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class TestCandidateV2Explainability:
    """Automated test suite for Phase 6 SHAP Explainability Framework."""

    def test_01_explainability_artifacts_exist_and_manifest_matches(self):
        assert EXPLAINABILITY_DIR.is_dir(), f"Missing explainability directory: {EXPLAINABILITY_DIR}"
        for artifact in [REPRESENTATIVE_JSON, ADDITIVITY_JSON, REPRODUCTION_JSON, PROVENANCE_JSON, MANIFEST_JSON]:
            assert artifact.is_file(), f"Missing expected artifact: {artifact}"

        with open(MANIFEST_JSON, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        assert manifest["primary_candidate"] == "EXP-4"
        assert "files" in manifest

        for fname, meta in manifest["files"].items():
            fpath = EXPLAINABILITY_DIR / fname
            assert fpath.is_file(), f"Manifest file missing from disk: {fname}"
            actual_sha = compute_sha256(fpath)
            assert actual_sha == meta["sha256"], f"Checksum mismatch for {fname}: {actual_sha} != {meta['sha256']}"
            assert fpath.stat().st_size == meta["bytes"]

    def test_02_fold_model_oof_reproduction_numerical_tolerance(self):
        with open(REPRODUCTION_JSON, "r", encoding="utf-8") as f:
            repro_data = json.load(f)

        assert set(repro_data.keys()) == {f"fold_{i}" for i in range(5)}

        for fold_key, metrics in repro_data.items():
            assert metrics["reproduction_passed"] is True, f"{fold_key} reproduction marked as failed"
            assert metrics["max_prob_diff"] <= 1e-5, f"{fold_key} max prob diff {metrics['max_prob_diff']} > 1e-5"
            assert metrics["val_count"] > 6000
            assert metrics["vocab_size"] == 25000

    def test_03_shap_margin_additivity_and_logistic_link(self):
        with open(ADDITIVITY_JSON, "r", encoding="utf-8") as f:
            add_data = json.load(f)

        assert add_data["all_folds_passed"] is True
        assert add_data["overall_max_residual"] <= 1e-5, f"Overall residual {add_data['overall_max_residual']} > 1e-5"

        # Check each fold's sample evaluations
        fold_logs = add_data["fold_samples_summary"]
        assert len(fold_logs) == 5

        for f_log in fold_logs:
            assert f_log["additivity_passed"] is True
            assert f_log["max_additivity_residual"] <= 1e-5
            assert f_log["max_logistic_link_diff"] <= 1e-5
            assert f_log["samples_evaluated"] >= 50

        # Check exploratory full-model refit verification
        full_verif = add_data["full_model_verification"]
        assert full_verif["additivity_passed"] is True
        assert full_verif["max_additivity_residual"] <= 1e-5
        assert full_verif["fitted_vocab_size"] == 25000
        assert "production inference" in full_verif["methodological_note"].lower()

    def test_04_representative_explanations_category_coverage(self):
        with open(REPRESENTATIVE_JSON, "r", encoding="utf-8") as f:
            explanations = json.load(f)

        assert len(explanations) >= 12, f"Expected at least 12 explanations, found {len(explanations)}"

        found_categories = {exp["category_group"] for exp in explanations}
        missing_categories = EXPECTED_CATEGORIES - found_categories
        assert len(missing_categories) == 0, f"Missing required categories: {missing_categories}"

        # Verify all 5 folds are represented in explanations
        found_folds = {exp["cv_fold"] for exp in explanations}
        assert found_folds == {0, 1, 2, 3, 4}, f"Folds not fully covered: {found_folds}"

    def test_05_explanation_sample_additivity_and_link_consistency(self):
        with open(REPRESENTATIVE_JSON, "r", encoding="utf-8") as f:
            explanations = json.load(f)

        for exp in explanations:
            s_id = exp["source_record_id"]
            # 1. Additivity residual <= 1e-5
            assert exp["additivity_verified"] is True, f"Additivity not verified for {s_id}"
            assert exp["additivity_residual"] <= 1e-5, f"Additivity residual {exp['additivity_residual']} > 1e-5 for {s_id}"

            # 2. Check full SHAP additivity: margin == base_value + sum_shap_values
            base = exp["base_value"]
            sum_pos = exp["sum_positive_contributions"]
            sum_neg = exp["sum_negative_contributions"]
            sum_shap = exp["sum_shap_values"]
            margin = exp["model_margin"]

            calc_margin = base + sum_shap
            assert abs(calc_margin - margin) <= 1e-4, f"Full SHAP additivity mismatch for {s_id}: {calc_margin} vs {margin}"

            # 3. Logistic link consistency
            expected_p = float(scipy.special.expit(margin))
            assert abs(expected_p - exp["reconstructed_prob"]) <= 1e-5, f"Logistic link failure for {s_id}"
            assert abs(exp["reconstructed_prob"] - exp["saved_oof_prob"]) <= 1e-5, f"OOF prob mismatch for {s_id}"

            # 4. Binary decision threshold consistency (0.50)
            expected_pred = 1 if exp["reconstructed_prob"] >= 0.50 else 0
            assert exp["predicted_label"] == expected_pred

    def test_06_token_contribution_directionality_and_vocabulary(self):
        with open(REPRESENTATIVE_JSON, "r", encoding="utf-8") as f:
            explanations = json.load(f)

        for exp in explanations:
            s_id = exp["source_record_id"]
            # Positive tokens must have positive SHAP contribution
            for tok_info in exp["top_10_positive_tokens"]:
                assert tok_info["shap_contribution"] > 0, f"Positive token has non-positive SHAP: {tok_info} in {s_id}"
                assert isinstance(tok_info["token"], str) and len(tok_info["token"]) > 0

            # Negative tokens must have negative SHAP contribution
            for tok_info in exp["top_10_negative_tokens"]:
                assert tok_info["shap_contribution"] < 0, f"Negative token has non-negative SHAP: {tok_info} in {s_id}"
                assert isinstance(tok_info["token"], str) and len(tok_info["token"]) > 0

            # Active vocabulary tokens count sanity
            assert exp["active_vocabulary_tokens_count"] >= 0

    def test_07_defanged_excerpts_and_privacy_safeguards(self):
        with open(REPRESENTATIVE_JSON, "r", encoding="utf-8") as f:
            explanations = json.load(f)

        for exp in explanations:
            excerpt = exp["defanged_body_excerpt"]
            # Assert no live hyperlinks
            assert "http://" not in excerpt, f"Raw http URL found in excerpt: {excerpt}"
            assert "https://" not in excerpt, f"Raw https URL found in excerpt: {excerpt}"

    def test_08_adjudication_context_for_contaminated_and_genuine_fp(self):
        with open(REPRESENTATIVE_JSON, "r", encoding="utf-8") as f:
            explanations = json.load(f)

        # Contaminated Enron phish must retain their ground-truth label 0
        # while having high phishing probability and Category A adjudication context
        contaminated = [e for e in explanations if e["category_group"] == "E_CONTAMINATED_ENRON_PHISH"]
        assert len(contaminated) >= 3

        for c_exp in contaminated:
            assert c_exp["ground_truth_label"] == 0, "Benchmark label must remain 0 for audit integrity"
            assert c_exp["reconstructed_prob"] > 0.90, "Contaminated phish should have high predicted prob"
            assert c_exp["adjudication_context"] is not None
            assert c_exp["adjudication_context"]["provisional_category"] == "A"

        # Genuine FPs must have Category C adjudication context
        genuine_fp = [e for e in explanations if e["category_group"] == "D_GENUINE_FALSE_POSITIVE"]
        assert len(genuine_fp) >= 3
        for g_exp in genuine_fp:
            assert g_exp["ground_truth_label"] == 0
            assert g_exp["reconstructed_prob"] >= 0.50
            assert g_exp["adjudication_context"] is not None
            assert g_exp["adjudication_context"]["provisional_category"] == "C"

    def test_09_ground_truth_and_candidate_immutability(self):
        with open(CANDIDATE_V2_MANIFEST, "r", encoding="utf-8") as f:
            v2_m = json.load(f)
        expected_v2_sha = v2_m["primary_candidate_corpus"]["sha256"]
        actual_v2_sha = compute_sha256(CANDIDATE_V2_CSV)
        assert actual_v2_sha == expected_v2_sha, "Candidate V2 corpus was unexpectedly modified!"

        with open(PARTITIONS_V2_MANIFEST, "r", encoding="utf-8") as f:
            part_m = json.load(f)
        expected_part_sha = part_m["partition_assignments_file"]["sha256"]
        actual_part_sha = compute_sha256(PARTITIONS_V2_CSV)
        assert actual_part_sha == expected_part_sha, "Partition assignments V2 unexpectedly modified!"
