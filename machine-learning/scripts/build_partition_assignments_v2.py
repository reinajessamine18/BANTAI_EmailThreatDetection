"""
BANTAI — Candidate V2 Leakage-Resistant Dataset Partitioning Script (Phase 4.5.9)
Formal Research Title: XGBoost-Based Email Threat Detection and Analysis Engine using Explainability Framework
Methodology: CRISP-DM Phase 3 (Data Preparation) / Phase 4.5.9 (Candidate V2 Partitioning)

Generates:
  1. partition_assignments_v2.csv (Traceable compact mapping table for 35,522 Candidate V2 records)
  2. partition_manifest_v2.json (Cryptographic checksums, splitter parameters, fold & split metrics)
"""

import sys
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Set
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.feature_extraction.text import TfidfVectorizer

# Project imports
ML_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ML_DIR))

# Paths
PROCESSED_V2_DIR = ML_DIR / "data" / "processed" / "content_only_candidate_v2"
CANDIDATE_V2_CSV = PROCESSED_V2_DIR / "candidate_corpus_v2.csv"
CANDIDATE_V2_MANIFEST = PROCESSED_V2_DIR / "candidate_v2_manifest.json"
PARTITIONS_V2_CSV = PROCESSED_V2_DIR / "partition_assignments_v2.csv"
PARTITION_V2_MANIFEST = PROCESSED_V2_DIR / "partition_manifest_v2.json"

SPLIT_SEED = 42
N_SPLITS = 5


def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 checksum of a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_partition_assignments_v2():
    """Generates deterministic CV folds and source-transfer partition assignments for Candidate V2."""
    print("--- PHASE 4.5.9: CANDIDATE V2 LEAKAGE-RESISTANT PARTITIONING ---")

    # Step 1: Validate input Candidate V2 corpus
    assert CANDIDATE_V2_CSV.exists(), f"Missing Candidate V2 corpus: {CANDIDATE_V2_CSV}"
    assert CANDIDATE_V2_MANIFEST.exists(), f"Missing Candidate V2 manifest: {CANDIDATE_V2_MANIFEST}"

    print(f"Validating Candidate V2 corpus checksum against {CANDIDATE_V2_MANIFEST.name}...")
    with open(CANDIDATE_V2_MANIFEST, "r", encoding="utf-8") as f:
        cand_manifest_data = json.load(f)

    expected_sha = cand_manifest_data["primary_candidate_corpus"]["sha256"]
    actual_sha = compute_sha256(CANDIDATE_V2_CSV)
    assert actual_sha == expected_sha, f"Candidate V2 SHA mismatch! Expected {expected_sha}, got {actual_sha}"
    print(f"Checksum verified: {actual_sha}")

    df = pd.read_csv(CANDIDATE_V2_CSV)
    total_records = len(df)
    print(f"Loaded Candidate V2 corpus: {total_records} records")
    assert total_records == 35522, f"Expected 35,522 records, got {total_records}"

    phish_count = int((df["label"] == 1).sum())
    ham_count = int((df["label"] == 0).sum())
    assert phish_count == 1681, f"Phishing count mismatch: expected 1,681, got {phish_count}"
    assert ham_count == 33841, f"Ham count mismatch: expected 33,841, got {ham_count}"

    unique_groups = df["analyzer_sequence_hash"].nunique()
    assert unique_groups == 34903, f"Unique group count mismatch: expected 34,903, got {unique_groups}"

    # Step 2: Tier 1 — Five-fold StratifiedGroupKFold
    print(f"\nGenerating Tier 1 5-fold StratifiedGroupKFold (seed={SPLIT_SEED}, n_splits={N_SPLITS})...")
    sgkf = StratifiedGroupKFold(n_splits=N_SPLITS, shuffle=True, random_state=SPLIT_SEED)

    X = df.index.values
    y = df["label"].values
    groups = df["analyzer_sequence_hash"].values

    cv_folds = [-1] * total_records
    fold_details = []

    for fold_idx, (train_idx, val_idx) in enumerate(sgkf.split(X, y, groups)):
        for idx in val_idx:
            cv_folds[idx] = fold_idx

        train_groups = set(groups[train_idx])
        val_groups = set(groups[val_idx])
        group_overlap = len(train_groups & val_groups)
        assert group_overlap == 0, f"Group leakage detected in fold {fold_idx}!"

        val_df = df.iloc[val_idx]
        train_df = df.iloc[train_idx]

        val_phish = int((val_df["label"] == 1).sum())
        val_ham = int((val_df["label"] == 0).sum())
        train_phish = int((train_df["label"] == 1).sum())
        train_ham = int((train_df["label"] == 0).sum())

        f_stat = {
            "fold": fold_idx,
            "val_total": len(val_idx),
            "val_phish": val_phish,
            "val_ham": val_ham,
            "val_phish_pct": round(val_phish / len(val_idx) * 100, 4),
            "val_sources": {str(k): int(v) for k, v in val_df["source_id"].value_counts().items()},
            "val_unique_groups": len(val_groups),
            "train_total": len(train_idx),
            "train_phish": train_phish,
            "train_ham": train_ham,
            "train_phish_pct": round(train_phish / len(train_idx) * 100, 4),
            "train_sources": {str(k): int(v) for k, v in train_df["source_id"].value_counts().items()},
            "train_unique_groups": len(train_groups),
            "group_leakage": group_overlap,
        }
        fold_details.append(f_stat)
        print(f"  Fold {fold_idx}: Val Total={len(val_idx)} (Phish={val_phish}, Ham={val_ham}, Pct={f_stat['val_phish_pct']}%) | Groups={len(val_groups)} | Group Leakage={group_overlap}")

    assert -1 not in cv_folds, "Some records were not assigned to any fold!"

    # Step 3: Tier 2 — Source-Transfer Assignments
    print("\nGenerating Tier 2 Source-Transfer Partition Assignments...")

    # Split A: Train (PhishPot 124 + Enron 29,751) -> Test (Nazario 1,557 + SA Ham 4,090)
    split_a_train_sources = {"phishing_pot", "enron_ham"}
    split_a_test_sources = {"nazario", "spamassassin_ham"}
    split_a_roles = [
        "train" if s in split_a_train_sources else "test"
        for s in df["source_id"]
    ]

    # Split B: Train (Nazario 1,557 + Enron 29,751) -> Test (PhishPot 124 + SA Ham 4,090)
    split_b_train_sources = {"nazario", "enron_ham"}
    split_b_test_sources = {"phishing_pot", "spamassassin_ham"}
    split_b_roles = [
        "train" if s in split_b_train_sources else "test"
        for s in df["source_id"]
    ]

    # Verify Split A counts
    split_a_train_cnt = sum(1 for r in split_a_roles if r == "train")
    split_a_test_cnt = sum(1 for r in split_a_roles if r == "test")
    print(f"  Split A: Train={split_a_train_cnt} (Expected: 29,875) | Test={split_a_test_cnt} (Expected: 5,647)")
    assert split_a_train_cnt == 29875, f"Split A train mismatch: {split_a_train_cnt}"
    assert split_a_test_cnt == 5647, f"Split A test mismatch: {split_a_test_cnt}"

    # Verify Split B counts
    split_b_train_cnt = sum(1 for r in split_b_roles if r == "train")
    split_b_test_cnt = sum(1 for r in split_b_roles if r == "test")
    print(f"  Split B: Train={split_b_train_cnt} (Expected: 31,308) | Test={split_b_test_cnt} (Expected: 4,214)")
    assert split_b_train_cnt == 31308, f"Split B train mismatch: {split_b_train_cnt}"
    assert split_b_test_cnt == 4214, f"Split B test mismatch: {split_b_test_cnt}"

    # Check sequence overlap for both splits
    split_a_train_hashes = set(df[df["source_id"].isin(split_a_train_sources)]["analyzer_sequence_hash"])
    split_a_test_hashes = set(df[df["source_id"].isin(split_a_test_sources)]["analyzer_sequence_hash"])
    split_a_seq_overlap = len(split_a_train_hashes & split_a_test_hashes)
    assert split_a_seq_overlap == 0, f"Split A sequence overlap detected: {split_a_seq_overlap}"

    split_b_train_hashes = set(df[df["source_id"].isin(split_b_train_sources)]["analyzer_sequence_hash"])
    split_b_test_hashes = set(df[df["source_id"].isin(split_b_test_sources)]["analyzer_sequence_hash"])
    split_b_seq_overlap = len(split_b_train_hashes & split_b_test_hashes)
    assert split_b_seq_overlap == 0, f"Split B sequence overlap detected: {split_b_seq_overlap}"

    # Calculate vocabulary metrics from exact analyzer tokens without vectorizer fitting
    vec = TfidfVectorizer(lowercase=True, token_pattern=r"(?u)\b\w\w+\b")
    analyzer = vec.build_analyzer()

    def calc_vocab_stats(train_sources, test_sources):
        train_vocab = set()
        for text in df[df["source_id"].isin(train_sources)]["email_body"]:
            train_vocab.update(analyzer(str(text)))
        test_vocab = set()
        for text in df[df["source_id"].isin(test_sources)]["email_body"]:
            test_vocab.update(analyzer(str(text)))
        shared = train_vocab & test_vocab
        return {
            "train_vocab_size": len(train_vocab),
            "test_vocab_size": len(test_vocab),
            "shared_vocab_size": len(shared),
            "test_coverage_pct": round(len(shared) / len(test_vocab) * 100, 4),
            "train_coverage_pct": round(len(shared) / len(train_vocab) * 100, 4),
        }

    print("\nMeasuring source-transfer vocabulary overlap from analyzer tokens...")
    split_a_vocab = calc_vocab_stats(split_a_train_sources, split_a_test_sources)
    print(f"  Split A Vocab: Train={split_a_vocab['train_vocab_size']}, Test={split_a_vocab['test_vocab_size']}, Shared={split_a_vocab['shared_vocab_size']}, Test Coverage={split_a_vocab['test_coverage_pct']}%")

    split_b_vocab = calc_vocab_stats(split_b_train_sources, split_b_test_sources)
    print(f"  Split B Vocab: Train={split_b_vocab['train_vocab_size']}, Test={split_b_vocab['test_vocab_size']}, Shared={split_b_vocab['shared_vocab_size']}, Test Coverage={split_b_vocab['test_coverage_pct']}%")

    # Step 4: Construct Compact Assignment Table
    df_partitions = pd.DataFrame({
        "candidate_row_id": df.index,
        "source_id": df["source_id"],
        "source_record_id": df["source_record_id"],
        "label": df["label"],
        "analyzer_sequence_hash": df["analyzer_sequence_hash"],
        "cv_fold": cv_folds,
        "split_a_role": split_a_roles,
        "split_b_role": split_b_roles,
    })

    print(f"\nWriting partition assignments to {PARTITIONS_V2_CSV}...")
    df_partitions.to_csv(PARTITIONS_V2_CSV, index=False, encoding="utf-8")
    partitions_sha = compute_sha256(PARTITIONS_V2_CSV)
    print(f"Saved {PARTITIONS_V2_CSV.name} ({len(df_partitions)} rows, SHA-256: {partitions_sha})")

    # Step 5: Construct Partition Manifest
    import sklearn
    manifest_data = {
        "metadata": {
            "title": "BANTAI Candidate V2 Content-Only Partition Manifest",
            "research_title": "XGBoost-Based Email Threat Detection and Analysis Engine using Explainability Framework",
            "crisp_dm_phase": "Phase 3 (Data Preparation) / Phase 4.5.9 (Candidate V2 Partitioning)",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "target_branch": "feature/content-only-NLP",
            "software_versions": {
                "python": sys.version.split()[0],
                "scikit_learn": sklearn.__version__,
                "pandas": pd.__version__,
            },
        },
        "candidate_corpus_reference": {
            "file_name": CANDIDATE_V2_CSV.name,
            "sha256": actual_sha,
            "total_records": total_records,
            "phish_records": phish_count,
            "ham_records": ham_count,
            "class_imbalance_ratio": f"{ham_count / phish_count:.2f} : 1",
            "total_unique_analyzer_groups": unique_groups,
        },
        "partition_assignments_file": {
            "file_name": PARTITIONS_V2_CSV.name,
            "sha256": partitions_sha,
            "total_rows": len(df_partitions),
        },
        "tier_1_cv_stratified_group_kfold": {
            "splitter_class": "sklearn.model_selection.StratifiedGroupKFold",
            "n_splits": N_SPLITS,
            "shuffle": True,
            "random_state": SPLIT_SEED,
            "grouping_column": "analyzer_sequence_hash",
            "stratification_column": "label",
            "total_records": total_records,
            "folds": fold_details,
        },
        "tier_2_source_transfer": {
            "split_a": {
                "description": "Train on Phishing Pot (124) + Enron Ham (29,751); Test on Nazario (1,557) + SpamAssassin Ham (4,090)",
                "train_sources": sorted(list(split_a_train_sources)),
                "test_sources": sorted(list(split_a_test_sources)),
                "train_records": split_a_train_cnt,
                "train_phish": int((df[df["source_id"].isin(split_a_train_sources)]["label"] == 1).sum()),
                "train_ham": int((df[df["source_id"].isin(split_a_train_sources)]["label"] == 0).sum()),
                "train_class_imbalance": f"{(df[df['source_id'].isin(split_a_train_sources)]['label'] == 0).sum() / (df[df['source_id'].isin(split_a_train_sources)]['label'] == 1).sum():.2f} : 1",
                "test_records": split_a_test_cnt,
                "test_phish": int((df[df["source_id"].isin(split_a_test_sources)]["label"] == 1).sum()),
                "test_ham": int((df[df["source_id"].isin(split_a_test_sources)]["label"] == 0).sum()),
                "test_class_imbalance": f"{(df[df['source_id'].isin(split_a_test_sources)]['label'] == 0).sum() / (df[df['source_id'].isin(split_a_test_sources)]['label'] == 1).sum():.2f} : 1",
                "exact_analyzer_sequence_overlap": split_a_seq_overlap,
                "vocabulary_metrics": split_a_vocab,
            },
            "split_b": {
                "description": "Train on Nazario (1,557) + Enron Ham (29,751); Test on Phishing Pot (124) + SpamAssassin Ham (4,090)",
                "train_sources": sorted(list(split_b_train_sources)),
                "test_sources": sorted(list(split_b_test_sources)),
                "train_records": split_b_train_cnt,
                "train_phish": int((df[df["source_id"].isin(split_b_train_sources)]["label"] == 1).sum()),
                "train_ham": int((df[df["source_id"].isin(split_b_train_sources)]["label"] == 0).sum()),
                "train_class_imbalance": f"{(df[df['source_id'].isin(split_b_train_sources)]['label'] == 0).sum() / (df[df['source_id'].isin(split_b_train_sources)]['label'] == 1).sum():.2f} : 1",
                "test_records": split_b_test_cnt,
                "test_phish": int((df[df["source_id"].isin(split_b_test_sources)]["label"] == 1).sum()),
                "test_ham": int((df[df["source_id"].isin(split_b_test_sources)]["label"] == 0).sum()),
                "test_class_imbalance": f"{(df[df['source_id'].isin(split_b_test_sources)]['label'] == 0).sum() / (df[df['source_id'].isin(split_b_test_sources)]['label'] == 1).sum():.2f} : 1",
                "exact_analyzer_sequence_overlap": split_b_seq_overlap,
                "vocabulary_metrics": split_b_vocab,
            },
        },
    }

    print(f"Writing manifest to {PARTITION_V2_MANIFEST}...")
    with open(PARTITION_V2_MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    print("\nCandidate V2 Partition assignments built and manifest sealed successfully!")
    return df_partitions, manifest_data


if __name__ == "__main__":
    build_partition_assignments_v2()

