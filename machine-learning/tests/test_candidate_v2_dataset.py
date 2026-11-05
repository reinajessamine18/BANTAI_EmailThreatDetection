"""
BANTAI — Candidate V2 Dataset Test Suite (Phase 4.5.8)
Formal Research Title: XGBoost-Based Email Threat Detection and Analysis Engine
Methodology: CRISP-DM Phase 4 / Quality Gate

Validates:
  1. Candidate V2 row counts (exactly 35,522 rows: 1,681 Phish vs 33,841 Ham).
  2. Source distribution (Nazario: 1,557, Phishing Pot: 124, Enron: 29,751, SpamAssassin: 4,090).
  3. Schema, data types, and column integrity.
  4. Complete accounting of all 1,952 Phishing Pot records across modeling and non-modeling sets.
  5. Zero empty analyzer sequence records and zero cross-label collisions.
  6. Strict preservation of Candidate V1 artifacts.
"""

import json
import hashlib
from pathlib import Path
import pytest
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

ML_DIR = Path(__file__).resolve().parent.parent
PROCESSED_V1_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
PROCESSED_V2_DIR = ML_DIR / "data" / "processed" / "content_only_candidate_v2"

CANDIDATE_V1_CSV = PROCESSED_V1_DIR / "candidate_corpus.csv"
CANDIDATE_V2_CSV = PROCESSED_V2_DIR / "candidate_corpus_v2.csv"
MANIFEST_V2_JSON = PROCESSED_V2_DIR / "candidate_v2_manifest.json"

CHALLENGE_ADVANCE_FEE_CSV = PROCESSED_V2_DIR / "advance_fee_fraud_challenge.csv"
CHALLENGE_PRIZE_LURES_CSV = PROCESSED_V2_DIR / "fraudulent_prize_lures.csv"
CHALLENGE_CASINO_CSV = PROCESSED_V2_DIR / "ordinary_casino_promotions.csv"
CHALLENGE_COMMERCIAL_CSV = PROCESSED_V2_DIR / "commercial_advertising.csv"
PENDING_CATEGORY_G_CSV = PROCESSED_V2_DIR / "pending_category_g_pool.csv"
NOISE_QUARANTINE_CSV = PROCESSED_V2_DIR / "noise_quarantine.csv"


@pytest.fixture(scope="module")
def v2_df():
    assert CANDIDATE_V2_CSV.exists(), f"Candidate V2 corpus missing at {CANDIDATE_V2_CSV}"
    return pd.read_csv(CANDIDATE_V2_CSV)


@pytest.fixture(scope="module")
def manifest_v2():
    assert MANIFEST_V2_JSON.exists(), f"Manifest V2 missing at {MANIFEST_V2_JSON}"
    with open(MANIFEST_V2_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def test_v2_corpus_exists_and_row_count(v2_df):
    """Verifies that Candidate V2 exists and contains exactly 35,522 records."""
    assert len(v2_df) == 35522


def test_v2_class_distribution(v2_df):
    """Verifies the exact class distribution: 1,681 Phishing vs 33,841 Legitimate."""
    class_counts = v2_df["label"].value_counts().to_dict()
    assert class_counts[1] == 1681, f"Expected 1,681 phishing, got {class_counts.get(1)}"
    assert class_counts[0] == 33841, f"Expected 33,841 legitimate, got {class_counts.get(0)}"


def test_v2_source_breakdown(v2_df):
    """Verifies the source distribution matches approved CRISP-DM admission criteria."""
    sources = v2_df["source_id"].value_counts().to_dict()
    assert sources["nazario"] == 1557
    assert sources["phishing_pot"] == 124
    assert sources["enron_ham"] == 29751
    assert sources["spamassassin_ham"] == 4090


def test_v2_schema_and_column_integrity(v2_df):
    """Verifies that Candidate V2 follows the approved schema with zero missing values."""
    expected_cols = [
        "email_body",
        "label",
        "source_id",
        "source_record_id",
        "analyzer_sequence_hash",
        "provenance",
    ]
    assert list(v2_df.columns) == expected_cols
    assert v2_df["email_body"].isna().sum() == 0
    assert v2_df["label"].isna().sum() == 0
    assert v2_df["source_id"].isna().sum() == 0
    assert v2_df["source_record_id"].isna().sum() == 0
    assert v2_df["analyzer_sequence_hash"].isna().sum() == 0


def test_v2_zero_token_absence(v2_df):
    """Verifies that zero records produce empty token sequences under the TF-IDF analyzer."""
    vec = TfidfVectorizer(lowercase=True, token_pattern=r"(?u)\b\w\w+\b")
    analyzer = vec.build_analyzer()
    for idx, text in enumerate(v2_df["email_body"]):
        tokens = analyzer(str(text))
        assert len(tokens) > 0, f"Empty analyzer token sequence found at index {idx}"


def test_v2_cross_label_collisions(v2_df):
    """Verifies zero cross-label collisions under analyzer sequence hashes."""
    collisions = v2_df.groupby("analyzer_sequence_hash")["label"].nunique()
    cross_label = collisions[collisions > 1]
    assert len(cross_label) == 0, f"Found {len(cross_label)} cross-label collisions!"


def test_phishing_pot_complete_accounting():
    """Verifies that all 1,952 Phishing Pot records are strictly partitioned with zero overlap."""
    df_v2 = pd.read_csv(CANDIDATE_V2_CSV)
    v2_pot_ids = set(df_v2[df_v2["source_id"] == "phishing_pot"]["source_record_id"])
    assert len(v2_pot_ids) == 124

    df_aff = pd.read_csv(CHALLENGE_ADVANCE_FEE_CSV)
    assert len(df_aff) == 15
    aff_ids = set(df_aff["source_record_id"])

    df_prize = pd.read_csv(CHALLENGE_PRIZE_LURES_CSV)
    assert len(df_prize) == 28
    prize_ids = set(df_prize["source_record_id"])

    df_casino = pd.read_csv(CHALLENGE_CASINO_CSV)
    assert len(df_casino) == 138
    casino_ids = set(df_casino["source_record_id"])

    df_comm = pd.read_csv(CHALLENGE_COMMERCIAL_CSV)
    assert len(df_comm) == 116
    comm_ids = set(df_comm["source_record_id"])

    df_cat_g = pd.read_csv(PENDING_CATEGORY_G_CSV)
    assert len(df_cat_g) == 1043
    cat_g_ids = set(df_cat_g["source_record_id"])

    df_noise = pd.read_csv(NOISE_QUARANTINE_CSV)
    assert len(df_noise) == 488
    noise_ids = set(df_noise["source_record_id"])

    # Disjointness checks
    id_sets = [v2_pot_ids, aff_ids, prize_ids, casino_ids, comm_ids, cat_g_ids, noise_ids]
    for i in range(len(id_sets)):
        for j in range(i + 1, len(id_sets)):
            assert id_sets[i].isdisjoint(id_sets[j]), f"Overlap detected between sets {i} and {j}"

    # Total accounting check
    all_accounted = set().union(*id_sets)
    assert len(all_accounted) == 1952


def test_v1_preservation_integrity(manifest_v2):
    """Verifies that Candidate V1 artifacts remain untouched and checksum-verified."""
    assert CANDIDATE_V1_CSV.exists()
    hasher = hashlib.sha256()
    with open(CANDIDATE_V1_CSV, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    actual_sha = hasher.hexdigest()
    expected_sha = manifest_v2["v1_preservation_verification"]["v1_candidate_corpus_sha256"]
    assert actual_sha == expected_sha, "Candidate V1 corpus was modified!"
    assert actual_sha == "26e151b7c48dcad03752bf6da9aa3c2b41a965b1fb3ed3b1e5e99fac64496cd3"

