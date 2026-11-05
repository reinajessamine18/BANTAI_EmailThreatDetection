#!/usr/bin/env python
"""
test_candidate_v2_experiments.py

Automated unit and regression tests for Phase 4.6 Candidate V2 Controlled Experiments:
  - Verifies presence and structure of all 6 experiment artifact suites (EXP-0 through EXP-5).
  - Validates exact hyperparameter compliance across all TF-IDF configurations.
  - Verifies out-of-fold prediction counts (35,522 rows) and probability distributions.
  - Verifies source-transfer diagnostic predictions (Split A: 5,647 rows; Split B: 4,214 rows).
  - Verifies master experiment summary and cryptographic manifests.
  - Asserts strict preservation of Candidate V1 and Candidate V2 ground-truth files.
"""

import json
from pathlib import Path
import pandas as pd
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ML_DIR = REPO_ROOT / "machine-learning"
ARTIFACTS_DIR = ML_DIR / "artifacts" / "candidate_content_nlp_v2"

V2_PROCESSED_DIR = ML_DIR / "data" / "processed" / "content_only_candidate_v2"
CANDIDATE_V2_CSV = V2_PROCESSED_DIR / "candidate_corpus_v2.csv"
PARTITIONS_V2_CSV = V2_PROCESSED_DIR / "partition_assignments_v2.csv"

V1_PROCESSED_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
CANDIDATE_V1_CSV = V1_PROCESSED_DIR / "candidate_corpus.csv"
PARTITIONS_V1_CSV = V1_PROCESSED_DIR / "partition_assignments.csv"

EXP_IDS = ["exp-0", "exp-1", "exp-2", "exp-3", "exp-4", "exp-5"]

EXPECTED_CONFIGS = {
    "exp-0": {"ngram_range": [1, 1], "max_features": 50000, "min_df": 1},
    "exp-1": {"ngram_range": [1, 1], "max_features": 25000, "min_df": 1},
    "exp-2": {"ngram_range": [1, 2], "max_features": 25000, "min_df": 1},
    "exp-3": {"ngram_range": [1, 1], "max_features": 25000, "min_df": 3},
    "exp-4": {"ngram_range": [1, 1], "max_features": 25000, "min_df": 5},
    "exp-5": {"ngram_range": [1, 2], "max_features": 25000, "min_df": 3},
}


class TestCandidateV2Experiments:
    def test_01_all_six_experiment_directories_exist(self):
        assert ARTIFACTS_DIR.is_dir(), f"Missing artifacts root: {ARTIFACTS_DIR}"
        for exp_id in EXP_IDS:
            exp_dir = ARTIFACTS_DIR / exp_id
            assert exp_dir.is_dir(), f"Missing experiment directory: {exp_dir}"

    def test_02_experiment_configs_and_hyperparameters(self):
        for exp_id in EXP_IDS:
            config_path = ARTIFACTS_DIR / exp_id / "experiment_config.json"
            assert config_path.is_file(), f"Missing config: {config_path}"
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)

            expected = EXPECTED_CONFIGS[exp_id]
            assert cfg["tfidf_params"]["ngram_range"] == expected["ngram_range"]
            assert cfg["tfidf_params"]["max_features"] == expected["max_features"]
            assert cfg["tfidf_params"]["min_df"] == expected["min_df"]

            # Authoritative XGBoost parameters
            assert cfg["xgb_params"]["n_estimators"] == 100
            assert cfg["xgb_params"]["max_depth"] == 6
            assert cfg["xgb_params"]["learning_rate"] == 0.3
            assert cfg["xgb_params"]["random_state"] == 42
            assert cfg["xgb_params"]["n_jobs"] == 1
            assert cfg["xgb_params"]["eval_metric"] == "logloss"
            assert cfg["xgb_params"]["tree_method"] == "hist"
            assert cfg["decision_threshold"] == 0.50

    def test_03_oof_predictions_schema_and_integrity(self):
        expected_cols = [
            "candidate_row_id",
            "source_id",
            "source_record_id",
            "label",
            "cv_fold",
            "y_prob",
            "y_pred",
        ]
        for exp_id in EXP_IDS:
            oof_path = ARTIFACTS_DIR / exp_id / "oof_predictions.csv"
            assert oof_path.is_file(), f"Missing OOF predictions: {oof_path}"
            df_oof = pd.read_csv(oof_path)

            assert len(df_oof) == 35522, f"Expected 35,522 OOF rows in {exp_id}, got {len(df_oof)}"
            assert list(df_oof.columns) == expected_cols
            assert df_oof["candidate_row_id"].is_monotonic_increasing
            assert df_oof.isna().sum().sum() == 0
            assert set(df_oof["cv_fold"].unique()) == {0, 1, 2, 3, 4}
            assert ((df_oof["y_prob"] >= 0.0) & (df_oof["y_prob"] <= 1.0)).all()
            assert set(df_oof["y_pred"].unique()).issubset({0, 1})

    def test_04_source_transfer_predictions_integrity(self):
        for exp_id in EXP_IDS:
            # Split A
            split_a_path = ARTIFACTS_DIR / exp_id / "split_a_predictions.csv"
            assert split_a_path.is_file(), f"Missing Split A file in {exp_id}"
            df_a = pd.read_csv(split_a_path)
            assert len(df_a) == 5647, f"Expected 5,647 Split A rows in {exp_id}, got {len(df_a)}"
            assert set(df_a["source_id"].unique()) == {"nazario", "spamassassin_ham"}
            assert ((df_a["y_prob"] >= 0.0) & (df_a["y_prob"] <= 1.0)).all()

            # Split B
            split_b_path = ARTIFACTS_DIR / exp_id / "split_b_predictions.csv"
            assert split_b_path.is_file(), f"Missing Split B file in {exp_id}"
            df_b = pd.read_csv(split_b_path)
            assert len(df_b) == 4214, f"Expected 4,214 Split B rows in {exp_id}, got {len(df_b)}"
            assert set(df_b["source_id"].unique()) == {"phishing_pot", "spamassassin_ham"}
            assert ((df_b["y_prob"] >= 0.0) & (df_b["y_prob"] <= 1.0)).all()

    def test_05_metrics_json_integrity(self):
        metric_keys = [
            "accuracy",
            "phishing_precision",
            "phishing_recall",
            "phishing_f1",
            "macro_f1",
            "specificity",
            "false_positive_rate",
            "pr_auc",
            "roc_auc",
        ]
        for exp_id in EXP_IDS:
            cv_path = ARTIFACTS_DIR / exp_id / "cv_fold_metrics.json"
            assert cv_path.is_file(), f"Missing CV metrics: {cv_path}"
            with open(cv_path, "r", encoding="utf-8") as f:
                cv_data = json.load(f)

            for fold in range(5):
                fold_key = f"fold_{fold}"
                assert fold_key in cv_data
                for k in metric_keys:
                    assert k in cv_data[fold_key]

            assert "oof_aggregate" in cv_data
            for k in metric_keys:
                assert k in cv_data["oof_aggregate"]

            assert "fold_summary_stats" in cv_data
            for k in metric_keys:
                assert k in cv_data["fold_summary_stats"]

            transfer_path = ARTIFACTS_DIR / exp_id / "source_transfer_metrics.json"
            assert transfer_path.is_file(), f"Missing transfer metrics: {transfer_path}"
            with open(transfer_path, "r", encoding="utf-8") as f:
                trans_data = json.load(f)
            assert "split_a" in trans_data
            assert "split_b" in trans_data

    def test_06_master_summary_and_manifest(self):
        summary_csv = ARTIFACTS_DIR / "experiments_summary.csv"
        summary_json = ARTIFACTS_DIR / "experiments_summary.json"
        master_manifest = ARTIFACTS_DIR / "manifest.json"

        assert summary_csv.is_file(), f"Missing summary CSV: {summary_csv}"
        assert summary_json.is_file(), f"Missing summary JSON: {summary_json}"
        assert master_manifest.is_file(), f"Missing master manifest: {master_manifest}"

        df_sum = pd.read_csv(summary_csv)
        assert len(df_sum) == 6
        assert list(df_sum["id"]) == ["EXP-0", "EXP-1", "EXP-2", "EXP-3", "EXP-4", "EXP-5"]

        with open(master_manifest, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)
        assert manifest_data["total_experiments"] == 6
        assert len(manifest_data["file_checksums_sha256"]) > 0

    def test_07_candidate_v1_and_v2_corpus_preservation(self):
        import hashlib

        def sha256_of(path):
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()

        # V1 integrity
        assert (
            sha256_of(CANDIDATE_V1_CSV)
            == "26e151b7c48dcad03752bf6da9aa3c2b41a965b1fb3ed3b1e5e99fac64496cd3"
        )
        assert (
            sha256_of(PARTITIONS_V1_CSV)
            == "4378d24d364d907ce06bf533b5b178fa44bbed71f23ceb8dfba5d18c22fd363a"
        )

        # V2 integrity
        assert (
            sha256_of(CANDIDATE_V2_CSV)
            == "7b5761a25cb8fe440c96207697eb010561504d53bbdbdd0c1ddf15064c0fe7c0"
        )
        assert (
            sha256_of(PARTITIONS_V2_CSV)
            == "8b6fb8d3e9446bae7f7cf3871c867dc681b773a19883daf3977bfc03998324ea"
        )

