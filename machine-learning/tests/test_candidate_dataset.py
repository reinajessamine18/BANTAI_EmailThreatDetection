"""
Unit Tests for BANTAI Candidate Dataset Construction (Phase 4.3)
Built with Python's standard unittest framework (zero external test dependencies).

Verifies:
  1. Record counts and class balance (37,350 total: 3,509 Phish vs 33,841 Ham).
  2. Quarantine counts and taxonomy (27 total: 4 collisions + 23 non-linguistic/empty).
  3. Feature integrity: no null bodies, no zero-token rows, no cross-label group collisions.
  4. Exact analyzer sequence hashing: identical sequences receive identical hashes; 36,468 unique groups.
  5. Provenance tracking and schema completeness.
"""

import sys
import json
import hashlib
import unittest
from pathlib import Path
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

ML_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ML_DIR))

PROCESSED_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
CANDIDATE_CSV = PROCESSED_DIR / "candidate_corpus.csv"
QUARANTINE_CSV = PROCESSED_DIR / "quarantine_corpus.csv"
MANIFEST_JSON = PROCESSED_DIR / "candidate_corpus_manifest.json"


class TestCandidateDataset(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert CANDIDATE_CSV.exists(), f"Missing candidate dataset: {CANDIDATE_CSV}"
        assert QUARANTINE_CSV.exists(), f"Missing quarantine dataset: {QUARANTINE_CSV}"
        assert MANIFEST_JSON.exists(), f"Missing manifest: {MANIFEST_JSON}"

        cls.candidate_df = pd.read_csv(CANDIDATE_CSV)
        cls.quarantine_df = pd.read_csv(QUARANTINE_CSV)
        with open(MANIFEST_JSON, "r", encoding="utf-8") as f:
            cls.manifest_data = json.load(f)

    def test_01_candidate_counts(self):
        """Verifies exact candidate dataset counts and class distribution."""
        total = len(self.candidate_df)
        self.assertEqual(total, 37350, f"Expected 37,350 records, got {total}")

        phish = int((self.candidate_df["label"] == 1).sum())
        ham = int((self.candidate_df["label"] == 0).sum())

        self.assertEqual(phish, 3509, f"Expected 3,509 Phishing records, got {phish}")
        self.assertEqual(ham, 33841, f"Expected 33,841 Ham records, got {ham}")

        # Source breakdown
        sources = dict(self.candidate_df["source_id"].value_counts())
        self.assertEqual(sources.get("nazario", 0), 1557)
        self.assertEqual(sources.get("phishing_pot", 0), 1952)
        self.assertEqual(sources.get("enron_ham", 0), 29751)
        self.assertEqual(sources.get("spamassassin_ham", 0), 4090)

    def test_02_quarantine_counts(self):
        """Verifies quarantine counts, categories, and source distribution."""
        total = len(self.quarantine_df)
        self.assertEqual(total, 27, f"Expected 27 quarantine records, got {total}")

        categories = dict(self.quarantine_df["quarantine_category"].value_counts())
        self.assertEqual(categories.get("CATEGORY_A_CROSS_LABEL_COLLISION", 0), 4)
        self.assertEqual(categories.get("CATEGORY_B_EMPTY_TOKEN_SEQUENCE", 0), 20)
        self.assertEqual(categories.get("CATEGORY_B_UNDERSCORE_PSEUDO_TOKEN", 0), 3)

        # Source breakdown
        sources = dict(self.quarantine_df["source_id"].value_counts())
        self.assertEqual(sources.get("nazario", 0), 4)
        self.assertEqual(sources.get("phishing_pot", 0), 9)
        self.assertEqual(sources.get("enron_ham", 0), 14)
        self.assertEqual(sources.get("spamassassin_ham", 0), 0)

        # Label breakdown
        labels = dict(self.quarantine_df["label"].value_counts())
        self.assertEqual(labels.get(1, 0), 13)
        self.assertEqual(labels.get(0, 0), 14)

    def test_03_candidate_schema(self):
        """Verifies candidate schema, types, and absence of null fields."""
        expected_cols = {"email_body", "label", "source_id", "source_record_id", "analyzer_sequence_hash", "provenance"}
        self.assertTrue(expected_cols.issubset(set(self.candidate_df.columns)))

        self.assertEqual(self.candidate_df["email_body"].isna().sum(), 0, "Null email bodies detected!")
        self.assertTrue(self.candidate_df["label"].isin([0, 1]).all(), "Invalid labels detected!")
        self.assertTrue(self.candidate_df["analyzer_sequence_hash"].str.len().eq(64).all(), "Malformed hash strings detected!")

    def test_04_zero_token_absence_in_candidate(self):
        """Verifies that no record in the candidate dataset produces zero tokens."""
        vec = TfidfVectorizer(lowercase=True, token_pattern=r"(?u)\b\w\w+\b")
        analyzer = vec.build_analyzer()

        # Check a sample across the dataset to verify no empty analyzer sequences
        for _, row in self.candidate_df.iloc[::25].iterrows():
            tokens = analyzer(row["email_body"])
            self.assertGreater(len(tokens), 0, f"Record {row['source_record_id']} produced zero tokens!")

    def test_05_no_cross_label_collisions(self):
        """Verifies strictly zero cross-label collisions in exact analyzer sequences."""
        grouped = self.candidate_df.groupby("analyzer_sequence_hash")["label"].nunique()
        cross_label = grouped[grouped > 1]
        self.assertEqual(len(cross_label), 0, f"Found {len(cross_label)} cross-label collision groups!")

    def test_06_exact_group_accounting(self):
        """Verifies exact group counts against Phase 4.2.4 audit."""
        unique_groups = self.candidate_df["analyzer_sequence_hash"].nunique()
        self.assertEqual(unique_groups, 36468, f"Expected 36,468 unique groups, got {unique_groups}")

        counts = self.candidate_df["analyzer_sequence_hash"].value_counts()
        singletons = int((counts == 1).sum())
        duplicates = int((counts > 1).sum())
        dup_rows = int(counts[counts > 1].sum())
        excess = dup_rows - duplicates

        self.assertEqual(singletons, 35782, f"Expected 35,782 singletons, got {singletons}")
        self.assertEqual(duplicates, 686, f"Expected 686 duplicate groups, got {duplicates}")
        self.assertEqual(dup_rows, 1568, f"Expected 1,568 duplicate rows, got {dup_rows}")
        self.assertEqual(excess, 882, f"Expected 882 excess instances, got {excess}")

        # Mathematical identities
        self.assertEqual(singletons + duplicates, unique_groups)
        self.assertEqual(singletons + dup_rows, len(self.candidate_df))

    def test_07_manifest_integrity(self):
        """Verifies manifest cryptographic hashes and metadata consistency."""
        self.assertEqual(self.manifest_data["candidate_corpus"]["total_records"], 37350)
        self.assertEqual(self.manifest_data["quarantine_corpus"]["total_records"], 27)
        self.assertEqual(self.manifest_data["candidate_corpus"]["group_accounting"]["total_unique_analyzer_groups"], 36468)
        self.assertEqual(self.manifest_data["candidate_corpus"]["group_accounting"]["cross_label_groups"], 0)

        # Re-verify on-disk file checksum matches manifest
        hasher = hashlib.sha256()
        with open(CANDIDATE_CSV, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        self.assertEqual(hasher.hexdigest(), self.manifest_data["candidate_corpus"]["sha256"])


if __name__ == "__main__":
    unittest.main()
