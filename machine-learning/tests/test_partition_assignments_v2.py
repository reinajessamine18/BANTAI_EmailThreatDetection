"""
Unit Tests for BANTAI Candidate V2 Dataset Partitioning (Phase 4.5.9)
Built with Python's standard unittest framework.

Verifies:
  1. Record count and traceability (all 35,522 Candidate V2 records matched).
  2. Tier 1 5-fold StratifiedGroupKFold integrity:
     - Exact fold coverage (no duplicates, no unassigned rows).
     - Strictly zero group leakage between train and val partitions for all 5 folds.
     - Stratification balance (~4.73% phish per fold).
  3. Tier 2 source-transfer integrity:
     - Split A exact counts (29,875 train vs 5,647 test) and zero sequence overlap.
     - Split B exact counts (31,308 train vs 4,214 test) and zero sequence overlap.
     - Strict source collection isolation.
  4. Manifest checksums and Candidate V1 preservation.
"""

import sys
import json
import hashlib
import unittest
from pathlib import Path
import pandas as pd

ML_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ML_DIR))

PROCESSED_V2_DIR = ML_DIR / "data" / "processed" / "content_only_candidate_v2"
CANDIDATE_V2_CSV = PROCESSED_V2_DIR / "candidate_corpus_v2.csv"
PARTITIONS_V2_CSV = PROCESSED_V2_DIR / "partition_assignments_v2.csv"
PARTITION_V2_MANIFEST = PROCESSED_V2_DIR / "partition_manifest_v2.json"

PROCESSED_V1_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
CANDIDATE_V1_CSV = PROCESSED_V1_DIR / "candidate_corpus.csv"
PARTITIONS_V1_CSV = PROCESSED_V1_DIR / "partition_assignments.csv"


class TestPartitionAssignmentsV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert CANDIDATE_V2_CSV.exists(), f"Missing Candidate V2 corpus: {CANDIDATE_V2_CSV}"
        assert PARTITIONS_V2_CSV.exists(), f"Missing Candidate V2 partition assignments: {PARTITIONS_V2_CSV}"
        assert PARTITION_V2_MANIFEST.exists(), f"Missing Candidate V2 partition manifest: {PARTITION_V2_MANIFEST}"

        cls.candidate_df = pd.read_csv(CANDIDATE_V2_CSV)
        cls.partitions_df = pd.read_csv(PARTITIONS_V2_CSV)
        with open(PARTITION_V2_MANIFEST, "r", encoding="utf-8") as f:
            cls.manifest_data = json.load(f)

    def test_01_record_count_and_traceability(self):
        """Verifies that all 35,522 records are accounted for and traceable to Candidate V2 corpus."""
        total = len(self.partitions_df)
        self.assertEqual(total, 35522, f"Expected 35,522 partition rows, got {total}")
        self.assertEqual(len(self.candidate_df), total)

        # Verify alignment with candidate corpus
        self.assertTrue((self.partitions_df["candidate_row_id"] == self.candidate_df.index).all())
        self.assertTrue((self.partitions_df["source_id"] == self.candidate_df["source_id"]).all())
        self.assertTrue((self.partitions_df["source_record_id"] == self.candidate_df["source_record_id"]).all())
        self.assertTrue((self.partitions_df["label"] == self.candidate_df["label"]).all())
        self.assertTrue((self.partitions_df["analyzer_sequence_hash"] == self.candidate_df["analyzer_sequence_hash"]).all())

        # Verify class counts
        self.assertEqual((self.partitions_df["label"] == 1).sum(), 1681)
        self.assertEqual((self.partitions_df["label"] == 0).sum(), 33841)

    def test_02_tier_1_fold_coverage_and_completeness(self):
        """Verifies that the 5 validation folds collectively cover every candidate record exactly once."""
        fold_counts = dict(self.partitions_df["cv_fold"].value_counts())
        self.assertEqual(set(fold_counts.keys()), {0, 1, 2, 3, 4}, "Folds must be integers 0 through 4")
        self.assertEqual(sum(fold_counts.values()), 35522)

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
        """Verifies that each of the 5 validation folds maintains the target class balance (~4.73% phish)."""
        for fold_idx in range(5):
            fold_df = self.partitions_df[self.partitions_df["cv_fold"] == fold_idx]
            phish_pct = (fold_df["label"] == 1).mean() * 100
            # Target mean is 4.732%; acceptable range given integer group sizes is 4.0% to 5.6%
            self.assertGreater(phish_pct, 4.0, f"Fold {fold_idx} phishing percentage too low: {phish_pct:.2f}%")
            self.assertLess(phish_pct, 5.6, f"Fold {fold_idx} phishing percentage too high: {phish_pct:.2f}%")

    def test_05_tier_2_split_a_integrity(self):
        """Verifies Split A source isolation, exact counts, and zero sequence overlap."""
        train_mask = (self.partitions_df["split_a_role"] == "train")
        test_mask = (self.partitions_df["split_a_role"] == "test")

        train_df = self.partitions_df[train_mask]
        test_df = self.partitions_df[test_mask]

        self.assertEqual(len(train_df), 29875, f"Split A train count mismatch: {len(train_df)}")
        self.assertEqual(len(test_df), 5647, f"Split A test count mismatch: {len(test_df)}")

        # Source isolation
        self.assertEqual(set(train_df["source_id"].unique()), {"phishing_pot", "enron_ham"})
        self.assertEqual(set(test_df["source_id"].unique()), {"nazario", "spamassassin_ham"})

        # Class counts
        self.assertEqual((train_df["label"] == 1).sum(), 124)
        self.assertEqual((train_df["label"] == 0).sum(), 29751)
        self.assertEqual((test_df["label"] == 1).sum(), 1557)
        self.assertEqual((test_df["label"] == 0).sum(), 4090)

        # Sequence overlap
        train_hashes = set(train_df["analyzer_sequence_hash"])
        test_hashes = set(test_df["analyzer_sequence_hash"])
        self.assertEqual(len(train_hashes & test_hashes), 0, "Sequence overlap in Split A!")

    def test_06_tier_2_split_b_integrity(self):
        """Verifies Split B source isolation, exact counts, and zero sequence overlap."""
        train_mask = (self.partitions_df["split_b_role"] == "train")
        test_mask = (self.partitions_df["split_b_role"] == "test")

        train_df = self.partitions_df[train_mask]
        test_df = self.partitions_df[test_mask]

        self.assertEqual(len(train_df), 31308, f"Split B train count mismatch: {len(train_df)}")
        self.assertEqual(len(test_df), 4214, f"Split B test count mismatch: {len(test_df)}")

        # Source isolation
        self.assertEqual(set(train_df["source_id"].unique()), {"nazario", "enron_ham"})
        self.assertEqual(set(test_df["source_id"].unique()), {"phishing_pot", "spamassassin_ham"})

        # Class counts
        self.assertEqual((train_df["label"] == 1).sum(), 1557)
        self.assertEqual((train_df["label"] == 0).sum(), 29751)
        self.assertEqual((test_df["label"] == 1).sum(), 124)
        self.assertEqual((test_df["label"] == 0).sum(), 4090)

        # Sequence overlap
        train_hashes = set(train_df["analyzer_sequence_hash"])
        test_hashes = set(test_df["analyzer_sequence_hash"])
        self.assertEqual(len(train_hashes & test_hashes), 0, "Sequence overlap in Split B!")

    def test_07_manifest_checksum_and_v1_preservation(self):
        """Verifies that manifest checksums match files and V1 partition files remain untouched."""
        # Verify V2 partition file SHA
        hasher = hashlib.sha256()
        with open(PARTITIONS_V2_CSV, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        actual_sha = hasher.hexdigest()
        expected_sha = self.manifest_data["partition_assignments_file"]["sha256"]
        self.assertEqual(actual_sha, expected_sha, "Manifest SHA-256 mismatch for partition_assignments_v2.csv!")

        # Verify V1 partition file untouched
        self.assertTrue(PARTITIONS_V1_CSV.exists())
        hasher_v1 = hashlib.sha256()
        with open(PARTITIONS_V1_CSV, "rb") as f:
            while chunk := f.read(65536):
                hasher_v1.update(chunk)
        self.assertEqual(hasher_v1.hexdigest(), "4378d24d364d907ce06bf533b5b178fa44bbed71f23ceb8dfba5d18c22fd363a")


if __name__ == "__main__":
    unittest.main()
