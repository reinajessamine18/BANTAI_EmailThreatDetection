"""
Unit Tests for Phase 4.5: Baseline Candidate Model Training
Built with Python's standard unittest framework (zero external test dependencies).

Verifies:
  1. Artifact directory existence and required files.
  2. Out-of-fold (OOF) predictions completeness (37,350 rows, no NaNs, valid probabilities).
  3. Tier 1 CV fold metrics completeness (5 folds + OOF aggregate with required metrics).
  4. Tier 2 source-transfer metrics completeness (Split A, Split B, aggregate and per-source).
  5. Candidate model and vectorizer loadability and smoke inference.
  6. Experiment configuration adherence (unigram TF-IDF, fixed XGBoost baseline).
  7. Manifest cryptographic integrity (SHA-256 validation).
"""

import hashlib
import json
from pathlib import Path
import unittest
import joblib
import pandas as pd

ML_DIR = Path(__file__).resolve().parent.parent
PROCESSED_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
CANDIDATE_CSV = PROCESSED_DIR / "candidate_corpus.csv"
PARTITIONS_CSV = PROCESSED_DIR / "partition_assignments.csv"
ARTIFACT_DIR = ML_DIR / "artifacts" / "candidate_content_nlp"

REQUIRED_METRICS = [
    "confusion_matrix",
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


class TestCandidateBaselineTraining(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert ARTIFACT_DIR.exists(), f"Artifact directory missing: {ARTIFACT_DIR}"
        cls.config_path = ARTIFACT_DIR / "experiment_config.json"
        cls.cv_metrics_path = ARTIFACT_DIR / "cv_fold_metrics.json"
        cls.transfer_metrics_path = ARTIFACT_DIR / "source_transfer_metrics.json"
        cls.oof_csv_path = ARTIFACT_DIR / "oof_predictions.csv"
        cls.split_a_csv_path = ARTIFACT_DIR / "split_a_predictions.csv"
        cls.split_b_csv_path = ARTIFACT_DIR / "split_b_predictions.csv"
        cls.vec_path = ARTIFACT_DIR / "candidate_baseline_vectorizer.joblib"
        cls.model_path = ARTIFACT_DIR / "candidate_baseline_model.joblib"
        cls.manifest_path = ARTIFACT_DIR / "candidate_baseline_manifest.json"

    def test_01_artifact_directory_and_files_exist(self):
        """Verifies that all required Phase 4.5 candidate artifacts exist on disk."""
        self.assertTrue(self.config_path.exists(), f"Missing {self.config_path}")
        self.assertTrue(self.cv_metrics_path.exists(), f"Missing {self.cv_metrics_path}")
        self.assertTrue(self.transfer_metrics_path.exists(), f"Missing {self.transfer_metrics_path}")
        self.assertTrue(self.oof_csv_path.exists(), f"Missing {self.oof_csv_path}")
        self.assertTrue(self.split_a_csv_path.exists(), f"Missing {self.split_a_csv_path}")
        self.assertTrue(self.split_b_csv_path.exists(), f"Missing {self.split_b_csv_path}")
        self.assertTrue(self.vec_path.exists(), f"Missing {self.vec_path}")
        self.assertTrue(self.model_path.exists(), f"Missing {self.model_path}")
        self.assertTrue(self.manifest_path.exists(), f"Missing {self.manifest_path}")

    def test_02_oof_predictions_integrity(self):
        """Verifies out-of-fold predictions completeness, probabilities, and alignment."""
        df_oof = pd.read_csv(self.oof_csv_path)
        self.assertEqual(len(df_oof), 37350, f"Expected 37,350 OOF rows, got {len(df_oof)}")

        required_cols = {"candidate_row_id", "source_id", "source_record_id", "label", "cv_fold", "y_prob", "y_pred"}
        self.assertTrue(required_cols.issubset(set(df_oof.columns)), f"Columns missing: {required_cols - set(df_oof.columns)}")

        # No null values
        self.assertEqual(df_oof.isna().sum().sum(), 0, "OOF predictions contain NaNs")

        # Row coverage: exactly 0 to 37349
        self.assertEqual(sorted(df_oof["candidate_row_id"].tolist()), list(range(37350)))

        # Probabilities between 0.0 and 1.0
        self.assertTrue(((df_oof["y_prob"] >= 0.0) & (df_oof["y_prob"] <= 1.0)).all())

        # Predictions match threshold 0.5
        expected_pred = (df_oof["y_prob"] >= 0.5).astype(int)
        self.assertTrue((df_oof["y_pred"] == expected_pred).all())

        # All 5 folds represented
        self.assertEqual(sorted(df_oof["cv_fold"].unique().tolist()), [0, 1, 2, 3, 4])

    def test_03_cv_fold_metrics_integrity(self):
        """Verifies 5-fold cross-validation metrics structure, completeness, and values."""
        with open(self.cv_metrics_path, "r", encoding="utf-8") as f:
            cv_metrics = json.load(f)

        for fold_key in ["fold_0", "fold_1", "fold_2", "fold_3", "fold_4", "oof_aggregate"]:
            self.assertIn(fold_key, cv_metrics, f"Missing key {fold_key} in CV metrics")
            metrics = cv_metrics[fold_key]
            for m in REQUIRED_METRICS:
                self.assertIn(m, metrics, f"Missing metric {m} in {fold_key}")

            cm = metrics["confusion_matrix"]
            total_cm = cm["tn"] + cm["fp"] + cm["fn"] + cm["tp"]
            if fold_key == "oof_aggregate":
                self.assertEqual(total_cm, 37350)
            else:
                self.assertTrue(7400 <= total_cm <= 7600)

            # Assert metric values are bounded
            for score_key in ["accuracy", "phishing_precision", "phishing_recall", "phishing_f1", "macro_f1", "specificity", "false_positive_rate", "pr_auc", "roc_auc"]:
                val = metrics[score_key]
                self.assertTrue(0.0 <= val <= 1.0, f"Metric {score_key} out of range in {fold_key}: {val}")

    def test_04_source_transfer_integrity(self):
        """Verifies Split A and Split B prediction outputs and metrics structure."""
        with open(self.transfer_metrics_path, "r", encoding="utf-8") as f:
            st_metrics = json.load(f)

        self.assertIn("split_a", st_metrics)
        self.assertIn("split_b", st_metrics)

        # Check Split A test size (5,647)
        df_a = pd.read_csv(self.split_a_csv_path)
        self.assertEqual(len(df_a), 5647)
        self.assertEqual(set(df_a["source_id"].unique()), {"nazario", "spamassassin_ham"})
        cm_a = st_metrics["split_a"]["aggregate"]["confusion_matrix"]
        self.assertEqual(cm_a["tn"] + cm_a["fp"] + cm_a["fn"] + cm_a["tp"], 5647)

        # Check Split B test size (6,042)
        df_b = pd.read_csv(self.split_b_csv_path)
        self.assertEqual(len(df_b), 6042)
        self.assertEqual(set(df_b["source_id"].unique()), {"phishing_pot", "spamassassin_ham"})
        cm_b = st_metrics["split_b"]["aggregate"]["confusion_matrix"]
        self.assertEqual(cm_b["tn"] + cm_b["fp"] + cm_b["fn"] + cm_b["tp"], 6042)

    def test_05_candidate_model_load_and_smoke_inference(self):
        """Verifies candidate vectorizer and model can be loaded and executed for inference."""
        vec = joblib.load(self.vec_path)
        model = joblib.load(self.model_path)

        sample_texts = [
            "Please find attached the weekly corporate schedule and financial review.",
            "URGENT: Your account credentials have been suspended. Click here to verify your identity.",
        ]
        X = vec.transform(sample_texts)
        self.assertEqual(X.shape[0], 2)
        self.assertEqual(X.shape[1], 50000)

        probs = model.predict_proba(X)
        self.assertEqual(probs.shape, (2, 2))
        preds = model.predict(X)
        self.assertEqual(len(preds), 2)
        self.assertTrue((probs[:, 1] >= 0.0).all() and (probs[:, 1] <= 1.0).all())

    def test_06_experiment_config_compliance(self):
        """Verifies experiment configuration adheres strictly to baseline settings."""
        with open(self.config_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        tfidf = config["tfidf_params"]
        self.assertEqual(tfidf["ngram_range"], [1, 1])
        self.assertEqual(tfidf["max_features"], 50000)
        self.assertEqual(tfidf["lowercase"], True)
        self.assertIsNone(tfidf["stop_words"])

        xgb_p = config["xgb_params"]
        self.assertEqual(xgb_p["random_state"], 42)
        self.assertEqual(xgb_p["n_jobs"], 1)
        self.assertEqual(xgb_p["eval_metric"], "logloss")
        self.assertEqual(xgb_p["n_estimators"], 100)

    def test_07_manifest_checksum_verification(self):
        """Verifies that all files recorded in candidate_baseline_manifest.json match disk checksums."""
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        for filename, expected_sha in manifest["file_checksums_sha256"].items():
            file_path = ARTIFACT_DIR / filename
            self.assertTrue(file_path.exists(), f"Manifest file missing: {file_path}")
            hasher = hashlib.sha256()
            with open(file_path, "rb") as f_in:
                while chunk := f_in.read(65536):
                    hasher.update(chunk)
            actual_sha = hasher.hexdigest()
            self.assertEqual(actual_sha, expected_sha, f"Checksum mismatch for {filename}: {actual_sha} vs {expected_sha}")


if __name__ == "__main__":
    unittest.main()

