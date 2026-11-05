"""
Unit Tests for BANTAI Dataset Partitioning (Phase 4.4)
Built with Python's standard unittest framework (zero external test dependencies).

Verifies:
  1. Record count and traceability (all 37,350 candidate records matched).
  2. Tier 1 5-fold StratifiedGroupKFold integrity:
     - Exact fold coverage (no duplicates, no unassigned rows).
     - Strictly zero group leakage between train and val partitions for all 5 folds.
     - Stratification balance (~9.4% phish per fold).
  3. Tier 2 source-transfer integrity:
     - Split A exact counts (31,703 train vs 5,647 test) and zero sequence overlap.
     - Split B exact counts (31,308 train vs 6,042 test) and zero sequence overlap.
     - Strict source collection isolation.
  4. Manifest checksums and reproducibility.
"""

import sys
import json
import hashlib
import unittest
from pathlib import Path
import pandas as pd

ML_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ML_DIR))

PROCESSED_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
CANDIDATE_CSV = PROCESSED_DIR / "candidate_corpus.csv"
PARTITIONS_CSV = PROCESSED_DIR / "partition_assignments.csv"
PARTITION_MANIFEST = PROCESSED_DIR / "partition_manifest.json"


class TestPartitionAssignments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert CANDIDATE_CSV.exists(), f"Missing candidate corpus: {CANDIDATE_CSV}"
        assert PARTITIONS_CSV.exists(), f"Missing partition assignments: {PARTITIONS_CSV}"
        assert PARTITION_MANIFEST.exists(), f"Missing partition manifest: {PARTITION_MANIFEST}"

        cls.candidate_df = pd.read_csv(CANDIDATE_CSV)
        cls.partitions_df = pd.read_csv(PARTITIONS_CSV)
        with open(PARTITION_MANIFEST, "r", encoding="utf-8") as f:
            cls.manifest_data = json.load(f)

    def test_01_record_count_and_traceability(self):
        """Verifies that all 37,350 records are accounted for and traceable to candidate corpus."""
        total = len(self.partitions_df)
        self.assertEqual(total, 37350, f"Expected 37,350 partition rows, got {total}")
        self.assertEqual(len(self.candidate_df), total)

        # Verify alignment with candidate corpus
        self.assertTrue((self.partitions_df["candidate_row_id"] == self.candidate_df.index).all())
        self.assertTrue((self.partitions_df["source_id"] == self.candidate_df["source_id"]).all())
        self.assertTrue((self.partitions_df["source_record_id"] == self.candidate_df["source_record_id"]).all())
        self.assertTrue((self.partitions_df["label"] == self.candidate_df["label"]).all())
        self.assertTrue((self.partitions_df["analyzer_sequence_hash"] == self.candidate_df["analyzer_sequence_hash"]).all())

    def test_02_tier_1_fold_coverage_and_completeness(self):
        """Verifies that the 5 validation folds collectively cover every candidate record exactly once."""
        fold_counts = dict(self.partitions_df["cv_fold"].value_counts())
        self.assertEqual(set(fold_counts.keys()), {0, 1, 2, 3, 4}, "Folds must be integers 0 through 4")
        self.assertEqual(sum(fold_counts.values()), 37350)

        # Check no negative or unassigned folds
        self.assertFalse((self.partitions_df["cv_fold"] < 0).any())

    def test_03_tier_1_zero_group_leakage(self):
        """Verifies strictly zero analyzer-sequence group leakage across train/val boundaries in all 5 folds."""
        groups = self.partitions_df["analyzer_sequence_hash"].values
        folds = self.partitions_df["cv_fold"].values

        for fold_idx in range(5):
            val_mask = (folds == fold_idx)
            train_mask = (folds != fold_idx)

            val_groups = set(groups[val_mask])
            train_groups = set(groups[train_mask])

            overlap = val_groups & train_groups
            self.assertEqual(len(overlap), 0, f"Fold {fold_idx} has {len(overlap)} leaking groups!")

    def test_04_tier_1_stratification_balance(self):
        """Verifies that each of the 5 validation folds maintains the target class balance (~9.40% phish)."""
        for fold_idx in range(5):
            fold_df = self.partitions_df[self.partitions_df["cv_fold"] == fold_idx]
            phish_pct = (fold_df["label"] == 1).mean() * 100
            # Acceptable range: 8.8% to 10.0% given group integer sizes
            self.assertGreater(phish_pct, 8.8, f"Fold {fold_idx} phishing percentage too low: {phish_pct:.2f}%")
            self.assertLess(phish_pct, 10.0, f"Fold {fold_idx} phishing percentage too high: {phish_pct:.2f}%")

    def test_05_tier_2_split_a_integrity(self):
        """Verifies Split A source isolation, exact counts, and zero sequence overlap."""
        train_mask = (self.partitions_df["split_a_role"] == "train")
        test_mask = (self.partitions_df["split_a_role"] == "test")

        train_df = self.partitions_df[train_mask]
        test_df = self.partitions_df[test_mask]

        self.assertEqual(len(train_df), 31703, f"Split A train count mismatch: {len(train_df)}")
        self.assertEqual(len(test_df), 5647, f"Split A test count mismatch: {len(test_df)}")

        # Source isolation
        self.assertTrue(set(train_df["source_id"].unique()).issubset({"phishing_pot", "enron_ham"}))
        self.assertTrue(set(test_df["source_id"].unique()).issubset({"nazario", "spamassassin_ham"}))

        # Zero sequence overlap
        train_hashes = set(train_df["analyzer_sequence_hash"])
        test_hashes = set(test_df["analyzer_sequence_hash"])
        self.assertEqual(len(train_hashes & test_hashes), 0, "Split A has sequence overlap!")

    def test_06_tier_2_split_b_integrity(self):
        """Verifies Split B source isolation, exact counts, and zero sequence overlap."""
        train_mask = (self.partitions_df["split_b_role"] == "train")
        test_mask = (self.partitions_df["split_b_role"] == "test")

        train_df = self.partitions_df[train_mask]
        test_df = self.partitions_df[test_mask]

        self.assertEqual(len(train_df), 31308, f"Split B train count mismatch: {len(train_df)}")
        self.assertEqual(len(test_df), 6042, f"Split B test count mismatch: {len(test_df)}")

        # Source isolation
        self.assertTrue(set(train_df["source_id"].unique()).issubset({"nazario", "enron_ham"}))
        self.assertTrue(set(test_df["source_id"].unique()).issubset({"phishing_pot", "spamassassin_ham"}))

        # Zero sequence overlap
        train_hashes = set(train_df["analyzer_sequence_hash"])
        test_hashes = set(test_df["analyzer_sequence_hash"])
        self.assertEqual(len(train_hashes & test_hashes), 0, "Split B has sequence overlap!")

    def test_07_manifest_checksum_and_schema(self):
        """Verifies partition manifest checksum and metadata consistency."""
        hasher = hashlib.sha256()
        with open(PARTITIONS_CSV, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        self.assertEqual(hasher.hexdigest(), self.manifest_data["partition_assignments_file"]["sha256"])

        # Check candidate corpus reference checksum
        self.assertEqual(self.manifest_data["candidate_corpus_reference"]["total_records"], 37350)
        self.assertEqual(self.manifest_data["tier_1_cv_stratified_group_kfold"]["n_splits"], 5)
        self.assertEqual(self.manifest_data["tier_1_cv_stratified_group_kfold"]["random_state"], 42)


if __name__ == "__main__":
    unittest.main()

