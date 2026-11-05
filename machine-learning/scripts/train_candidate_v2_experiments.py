#!/usr/bin/env python
"""
BANTAI — Phase 4.6: Candidate V2 Controlled TF-IDF and XGBoost Experiments
Executes the six approved TF-IDF configurations on Candidate V2 partitions:
  EXP-0: (1, 1), max_features=50,000, min_df=1 (Reference baseline)
  EXP-1: (1, 1), max_features=25,000, min_df=1 (Vocabulary cap)
  EXP-2: (1, 2), max_features=25,000, min_df=1 (Bigrams addition)
  EXP-3: (1, 1), max_features=25,000, min_df=3 (Document frequency pruning min_df=3)
  EXP-4: (1, 1), max_features=25,000, min_df=5 (Document frequency pruning min_df=5)
  EXP-5: (1, 2), max_features=25,000, min_df=3 (Bigrams + pruning min_df=3)

For each configuration:
  1. Tier 1: 5-Fold StratifiedGroupKFold Cross-Validation sequentially.
  2. Tier 2: Bidirectional Source-Transfer Diagnostics (Split A and Split B).
  3. Exploratory full-dataset model refit and serialization.
  4. Cryptographic checksums and JSON/CSV experiment summaries.

Strictly adheres to:
  - 8 GB RAM laptop safeguards (sequential execution, gc.collect(), n_jobs=1, sparse matrices).
  - No SMOTE, oversampling, undersampling, or class re-weighting (scale_pos_weight=1.0).
  - No threshold tuning (fixed default decision threshold of 0.50).
  - Zero cross-fold or source-transfer data leakage.
"""

import ctypes
import gc
import hashlib
import json
import os
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
import xgboost as xgb

# ---------------------------------------------------------------------------
# Path Configuration
# ---------------------------------------------------------------------------
ML_DIR = Path(__file__).resolve().parent.parent
PROCESSED_V2_DIR = ML_DIR / "data" / "processed" / "content_only_candidate_v2"
CANDIDATE_V2_CSV = PROCESSED_V2_DIR / "candidate_corpus_v2.csv"
CANDIDATE_V2_MANIFEST = PROCESSED_V2_DIR / "candidate_v2_manifest.json"
PARTITIONS_V2_CSV = PROCESSED_V2_DIR / "partition_assignments_v2.csv"
PARTITIONS_V2_MANIFEST = PROCESSED_V2_DIR / "partition_manifest_v2.json"

PROCESSED_V1_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
CANDIDATE_V1_CSV = PROCESSED_V1_DIR / "candidate_corpus.csv"
PARTITIONS_V1_CSV = PROCESSED_V1_DIR / "partition_assignments.csv"

ARTIFACTS_ROOT = ML_DIR / "artifacts" / "candidate_content_nlp_v2"

# ---------------------------------------------------------------------------
# Experiment Configurations (Authoritative Specification)
# ---------------------------------------------------------------------------
EXPERIMENTS = [
    {
        "id": "EXP-0",
        "name": "Reference Baseline (Unigram, 50k, min_df=1)",
        "ngram_range": (1, 1),
        "max_features": 50000,
        "min_df": 1,
    },
    {
        "id": "EXP-1",
        "name": "Vocabulary Cap (Unigram, 25k, min_df=1)",
        "ngram_range": (1, 1),
        "max_features": 25000,
        "min_df": 1,
    },
    {
        "id": "EXP-2",
        "name": "Bigrams Addition (Unigram+Bigram, 25k, min_df=1)",
        "ngram_range": (1, 2),
        "max_features": 25000,
        "min_df": 1,
    },
    {
        "id": "EXP-3",
        "name": "Doc-Frequency Pruning min_df=3 (Unigram, 25k, min_df=3)",
        "ngram_range": (1, 1),
        "max_features": 25000,
        "min_df": 3,
    },
    {
        "id": "EXP-4",
        "name": "Doc-Frequency Pruning min_df=5 (Unigram, 25k, min_df=5)",
        "ngram_range": (1, 1),
        "max_features": 25000,
        "min_df": 5,
    },
    {
        "id": "EXP-5",
        "name": "Bigrams + Doc-Frequency Pruning min_df=3 (Unigram+Bigram, 25k, min_df=3)",
        "ngram_range": (1, 2),
        "max_features": 25000,
        "min_df": 3,
    },
]

TFIDF_COMMON = {
    "lowercase": True,
    "stop_words": None,
    "token_pattern": r"(?u)\b\w\w+\b",
}

XGB_PARAMS = {
    "n_estimators": 100,
    "max_depth": 6,
    "learning_rate": 0.3,
    "random_state": 42,
    "n_jobs": 1,
    "eval_metric": "logloss",
    "tree_method": "hist",
}

DECISION_THRESHOLD = 0.50

V1_CANDIDATE_SHA256 = "26e151b7c48dcad03752bf6da9aa3c2b41a965b1fb3ed3b1e5e99fac64496cd3"
V1_PARTITION_SHA256 = "4378d24d364d907ce06bf533b5b178fa44bbed71f23ceb8dfba5d18c22fd363a"


# ---------------------------------------------------------------------------
# System & Resource Monitoring Utilities
# ---------------------------------------------------------------------------
class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_uint32),
        ("dwMemoryLoad", ctypes.c_uint32),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("sullAvailExtendedVirtual", ctypes.c_uint64),
    ]


def get_system_ram() -> dict:
    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
    return {
        "total_gb": round(stat.ullTotalPhys / (1024**3), 2),
        "avail_gb": round(stat.ullAvailPhys / (1024**3), 2),
        "memory_load_pct": int(stat.dwMemoryLoad),
    }


def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# Metric Calculation Utility
# ---------------------------------------------------------------------------
def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray = None) -> dict:
    """Computes comprehensive binary classification metrics."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    total = tn + fp + fn + tp

    accuracy = float((tp + tn) / total) if total > 0 else 0.0
    phishing_precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    phishing_recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    phishing_f1 = (
        float(2 * phishing_precision * phishing_recall / (phishing_precision + phishing_recall))
        if (phishing_precision + phishing_recall) > 0
        else 0.0
    )
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    specificity = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    false_positive_rate = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    unique_classes = np.unique(y_true)
    if y_prob is not None and len(unique_classes) > 1:
        pr_auc = float(average_precision_score(y_true, y_prob))
        roc_auc = float(roc_auc_score(y_true, y_prob))
    else:
        pr_auc = None
        roc_auc = None

    return {
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "accuracy": accuracy,
        "phishing_precision": phishing_precision,
        "phishing_recall": phishing_recall,
        "phishing_f1": phishing_f1,
        "macro_f1": macro_f1,
        "specificity": specificity,
        "false_positive_rate": false_positive_rate,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
    }


# ---------------------------------------------------------------------------
# Pre-training Integrity Verification
# ---------------------------------------------------------------------------
def run_preflight_checks():
    print("================================================================================")
    print("PHASE 4.6: PRE-TRAINING INTEGRITY VERIFICATION")
    print("================================================================================")

    for p in [CANDIDATE_V2_CSV, CANDIDATE_V2_MANIFEST, PARTITIONS_V2_CSV, PARTITIONS_V2_MANIFEST]:
        if not p.exists():
            raise FileNotFoundError(f"Missing required artifact: {p}")

    # Check Candidate V2 checksum
    with open(CANDIDATE_V2_MANIFEST, "r", encoding="utf-8") as f:
        cand_manifest = json.load(f)
    expected_cand_sha = cand_manifest["primary_candidate_corpus"]["sha256"]
    actual_cand_sha = compute_sha256(CANDIDATE_V2_CSV)
    if actual_cand_sha != expected_cand_sha:
        raise ValueError(f"Candidate V2 checksum mismatch: {actual_cand_sha} != {expected_cand_sha}")
    print(f"[OK] Candidate V2 corpus checksum verified: {actual_cand_sha}")

    # Check Partition V2 checksum
    with open(PARTITIONS_V2_MANIFEST, "r", encoding="utf-8") as f:
        part_manifest = json.load(f)
    expected_part_sha = part_manifest["partition_assignments_file"]["sha256"]
    actual_part_sha = compute_sha256(PARTITIONS_V2_CSV)
    if actual_part_sha != expected_part_sha:
        raise ValueError(f"Partition V2 checksum mismatch: {actual_part_sha} != {expected_part_sha}")
    print(f"[OK] Partition V2 checksum verified: {actual_part_sha}")

    # Verify Candidate V1 preservation
    if CANDIDATE_V1_CSV.exists():
        actual_v1_cand_sha = compute_sha256(CANDIDATE_V1_CSV)
        if actual_v1_cand_sha != V1_CANDIDATE_SHA256:
            raise ValueError(f"Candidate V1 corpus was modified! {actual_v1_cand_sha} != {V1_CANDIDATE_SHA256}")
        print(f"[OK] Candidate V1 corpus preservation verified: {actual_v1_cand_sha}")

    if PARTITIONS_V1_CSV.exists():
        actual_v1_part_sha = compute_sha256(PARTITIONS_V1_CSV)
        if actual_v1_part_sha != V1_PARTITION_SHA256:
            raise ValueError(f"Candidate V1 partitions were modified! {actual_v1_part_sha} != {V1_PARTITION_SHA256}")
        print(f"[OK] Candidate V1 partitions preservation verified: {actual_v1_part_sha}")

    # Load tables
    df_cand = pd.read_csv(CANDIDATE_V2_CSV)
    df_part = pd.read_csv(PARTITIONS_V2_CSV)

    if len(df_cand) != 35522:
        raise ValueError(f"Expected 35,522 candidate records, got {len(df_cand)}")
    if len(df_part) != 35522:
        raise ValueError(f"Expected 35,522 partition records, got {len(df_part)}")
    print(f"[OK] Candidate V2 record count verified: {len(df_cand):,} records")

    phish_count = int((df_cand["label"] == 1).sum())
    ham_count = int((df_cand["label"] == 0).sum())
    if phish_count != 1681 or ham_count != 33841:
        raise ValueError(f"Label mismatch: Phish={phish_count} (expected 1,681), Ham={ham_count} (expected 33,841)")
    print(f"[OK] Label counts verified: {phish_count:,} Phishing, {ham_count:,} Legitimate")

    # Check zero-leakage across folds
    for fold in range(5):
        val_hashes = set(df_part[df_part["cv_fold"] == fold]["analyzer_sequence_hash"])
        train_hashes = set(df_part[df_part["cv_fold"] != fold]["analyzer_sequence_hash"])
        overlap = val_hashes.intersection(train_hashes)
        if len(overlap) > 0:
            raise ValueError(f"Fold {fold} has {len(overlap)} overlapping sequence groups!")
    print("[OK] Tier 1 zero group leakage verified across all 5 folds.")

    # Check Tier 2 source isolation
    split_a_train_sources = set(df_part[df_part["split_a_role"] == "train"]["source_id"])
    split_a_test_sources = set(df_part[df_part["split_a_role"] == "test"]["source_id"])
    if split_a_train_sources != {"phishing_pot", "enron_ham"}:
        raise ValueError(f"Split A train sources mismatch: {split_a_train_sources}")
    if split_a_test_sources != {"nazario", "spamassassin_ham"}:
        raise ValueError(f"Split A test sources mismatch: {split_a_test_sources}")

    split_b_train_sources = set(df_part[df_part["split_b_role"] == "train"]["source_id"])
    split_b_test_sources = set(df_part[df_part["split_b_role"] == "test"]["source_id"])
    if split_b_train_sources != {"nazario", "enron_ham"}:
        raise ValueError(f"Split B train sources mismatch: {split_b_train_sources}")
    if split_b_test_sources != {"phishing_pot", "spamassassin_ham"}:
        raise ValueError(f"Split B test sources mismatch: {split_b_test_sources}")
    print("[OK] Tier 2 source isolation verified for Split A and Split B.")

    ram = get_system_ram()
    print(f"[OK] System RAM: {ram['avail_gb']} GB available of {ram['total_gb']} GB ({ram['memory_load_pct']}% load)")
    print("================================================================================\n")
    return df_cand, df_part, actual_cand_sha, actual_part_sha


# ---------------------------------------------------------------------------
# Single Experiment Runner
# ---------------------------------------------------------------------------
def run_single_experiment(
    exp_def: dict,
    df_cand: pd.DataFrame,
    df_part: pd.DataFrame,
    actual_cand_sha: str,
    actual_part_sha: str,
) -> dict:
    exp_id = exp_def["id"]
    exp_name = exp_def["name"]
    ngram_range = exp_def["ngram_range"]
    max_features = exp_def["max_features"]
    min_df = exp_def["min_df"]

    print(f"\n################################################################################")
    print(f"STARTING {exp_id}: {exp_name}")
    print(f"Parameters: ngram_range={ngram_range}, max_features={max_features:,}, min_df={min_df}")
    print(f"################################################################################\n")

    exp_dir = ARTIFACTS_ROOT / exp_id.lower()
    exp_dir.mkdir(parents=True, exist_ok=True)

    tfidf_params = {
        **TFIDF_COMMON,
        "ngram_range": ngram_range,
        "max_features": max_features,
        "min_df": min_df,
    }

    t0_exp = time.time()
    resource_log = []

    # -----------------------------------------------------------------------
    # Tier 1 — Five-Fold Cross-Validation
    # -----------------------------------------------------------------------
    print(f"[{exp_id}] Tier 1: 5-Fold Stratified Group Cross-Validation...")
    cv_results = {}
    oof_predictions = np.zeros(len(df_cand), dtype=int)
    oof_probabilities = np.zeros(len(df_cand), dtype=float)

    for fold in range(5):
        t_fold_start = time.time()
        ram_before = get_system_ram()

        val_mask = (df_part["cv_fold"] == fold).values
        train_mask = ~val_mask

        val_indices = np.where(val_mask)[0]
        train_indices = np.where(train_mask)[0]

        X_train_text = df_cand.loc[train_indices, "email_body"].astype(str).tolist()
        y_train = df_cand.loc[train_indices, "label"].astype(int).values

        X_val_text = df_cand.loc[val_indices, "email_body"].astype(str).tolist()
        y_val = df_cand.loc[val_indices, "label"].astype(int).values

        # 1. Fit TF-IDF on train text only
        vec = TfidfVectorizer(**tfidf_params)
        X_train_tfidf = vec.fit_transform(X_train_text)
        X_val_tfidf = vec.transform(X_val_text)
        vocab_size = len(vec.vocabulary_)

        # 2. Train XGBoost
        model = xgb.XGBClassifier(**XGB_PARAMS)
        model.fit(X_train_tfidf, y_train)

        # 3. Predict on validation set
        val_probs = model.predict_proba(X_val_tfidf)[:, 1]
        val_preds = (val_probs >= DECISION_THRESHOLD).astype(int)

        oof_probabilities[val_indices] = val_probs
        oof_predictions[val_indices] = val_preds

        # 4. Compute fold metrics
        fold_metrics = compute_metrics(y_val, val_preds, val_probs)
        fold_metrics["train_count"] = len(y_train)
        fold_metrics["val_count"] = len(y_val)
        fold_metrics["fitted_vocab_size"] = vocab_size
        fold_metrics["duration_seconds"] = round(time.time() - t_fold_start, 2)
        cv_results[f"fold_{fold}"] = fold_metrics

        print(
            f"  [{exp_id}] Fold {fold}: Acc={fold_metrics['accuracy']:.4f}, "
            f"Prec={fold_metrics['phishing_precision']:.4f}, Rec={fold_metrics['phishing_recall']:.4f}, "
            f"F1={fold_metrics['phishing_f1']:.4f}, ROC-AUC={fold_metrics['roc_auc']:.4f}, "
            f"PR-AUC={fold_metrics['pr_auc']:.4f}, Vocab={vocab_size:,} ({fold_metrics['duration_seconds']}s)"
        )

        del X_train_text, X_val_text, X_train_tfidf, X_val_tfidf, vec, model
        gc.collect()

        ram_after = get_system_ram()
        resource_log.append({
            "stage": f"tier1_fold_{fold}",
            "ram_before_avail_gb": ram_before["avail_gb"],
            "ram_after_avail_gb": ram_after["avail_gb"],
            "duration_sec": fold_metrics["duration_seconds"],
        })

    # Aggregate OOF metrics
    y_all = df_cand["label"].astype(int).values
    oof_metrics = compute_metrics(y_all, oof_predictions, oof_probabilities)
    oof_metrics["total_records"] = len(y_all)
    cv_results["oof_aggregate"] = oof_metrics

    # Fold summary stats (mean, std, min, max)
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
    cv_summary_stats = {}
    for k in metric_keys:
        vals = [cv_results[f"fold_{f}"][k] for f in range(5)]
        cv_summary_stats[k] = {
            "mean": float(np.mean(vals)),
            "std": float(np.std(vals)),
            "min": float(np.min(vals)),
            "max": float(np.max(vals)),
        }
    cv_results["fold_summary_stats"] = cv_summary_stats

    # Save OOF predictions
    df_oof = pd.DataFrame({
        "candidate_row_id": df_part["candidate_row_id"],
        "source_id": df_part["source_id"],
        "source_record_id": df_part["source_record_id"],
        "label": df_part["label"],
        "cv_fold": df_part["cv_fold"],
        "y_prob": np.round(oof_probabilities, 6),
        "y_pred": oof_predictions,
    })
    oof_csv_path = exp_dir / "oof_predictions.csv"
    df_oof.to_csv(oof_csv_path, index=False)

    print(
        f"  [{exp_id}] Tier 1 OOF Aggregate: Acc={oof_metrics['accuracy']:.4f}, "
        f"Prec={oof_metrics['phishing_precision']:.4f}, Rec={oof_metrics['phishing_recall']:.4f}, "
        f"F1={oof_metrics['phishing_f1']:.4f}, ROC-AUC={oof_metrics['roc_auc']:.4f}, "
        f"PR-AUC={oof_metrics['pr_auc']:.4f}"
    )

    # -----------------------------------------------------------------------
    # Tier 2 — Source-Transfer Diagnostics
    # -----------------------------------------------------------------------
    print(f"[{exp_id}] Tier 2: Bidirectional Source-Transfer Diagnostics...")
    transfer_results = {}

    # Split A: Train (Phishing Pot 124 + Enron Ham 29,751 = 29,875) -> Test (Nazario 1,557 + SA Ham 4,090 = 5,647)
    t_start_a = time.time()
    ram_before_a = get_system_ram()

    split_a_train_mask = (df_part["split_a_role"] == "train").values
    split_a_test_mask = (df_part["split_a_role"] == "test").values

    train_idx_a = np.where(split_a_train_mask)[0]
    test_idx_a = np.where(split_a_test_mask)[0]

    X_train_text_a = df_cand.loc[train_idx_a, "email_body"].astype(str).tolist()
    y_train_a = df_cand.loc[train_idx_a, "label"].astype(int).values

    X_test_text_a = df_cand.loc[test_idx_a, "email_body"].astype(str).tolist()
    y_test_a = df_cand.loc[test_idx_a, "label"].astype(int).values

    vec_a = TfidfVectorizer(**tfidf_params)
    X_train_tfidf_a = vec_a.fit_transform(X_train_text_a)
    X_test_tfidf_a = vec_a.transform(X_test_text_a)
    vocab_a = len(vec_a.vocabulary_)

    model_a = xgb.XGBClassifier(**XGB_PARAMS)
    model_a.fit(X_train_tfidf_a, y_train_a)

    test_probs_a = model_a.predict_proba(X_test_tfidf_a)[:, 1]
    test_preds_a = (test_probs_a >= DECISION_THRESHOLD).astype(int)

    df_split_a = pd.DataFrame({
        "candidate_row_id": df_part.loc[test_idx_a, "candidate_row_id"].values,
        "source_id": df_part.loc[test_idx_a, "source_id"].values,
        "source_record_id": df_part.loc[test_idx_a, "source_record_id"].values,
        "label": y_test_a,
        "split_a_role": "test",
        "y_prob": np.round(test_probs_a, 6),
        "y_pred": test_preds_a,
    })
    split_a_csv_path = exp_dir / "split_a_predictions.csv"
    df_split_a.to_csv(split_a_csv_path, index=False)

    metrics_a_agg = compute_metrics(y_test_a, test_preds_a, test_probs_a)
    naz_mask = (df_split_a["source_id"] == "nazario").values
    metrics_a_naz = compute_metrics(y_test_a[naz_mask], test_preds_a[naz_mask], test_probs_a[naz_mask])
    sa_mask_a = (df_split_a["source_id"] == "spamassassin_ham").values
    metrics_a_sa = compute_metrics(y_test_a[sa_mask_a], test_preds_a[sa_mask_a], test_probs_a[sa_mask_a])

    duration_a = round(time.time() - t_start_a, 2)
    transfer_results["split_a"] = {
        "description": "Train on Phishing Pot + Enron Ham (29,875) -> Test on Nazario + SpamAssassin Ham (5,647)",
        "train_sources": ["phishing_pot", "enron_ham"],
        "test_sources": ["nazario", "spamassassin_ham"],
        "train_count": len(y_train_a),
        "test_count": len(y_test_a),
        "fitted_vocab_size": vocab_a,
        "duration_seconds": duration_a,
        "aggregate": metrics_a_agg,
        "per_source": {
            "nazario": {
                "count": int(naz_mask.sum()),
                "true_label": 1,
                "metrics": metrics_a_naz,
            },
            "spamassassin_ham": {
                "count": int(sa_mask_a.sum()),
                "true_label": 0,
                "metrics": metrics_a_sa,
            },
        },
    }

    print(
        f"  [{exp_id}] Split A Aggregate: Acc={metrics_a_agg['accuracy']:.4f}, "
        f"Prec={metrics_a_agg['phishing_precision']:.4f}, Rec={metrics_a_agg['phishing_recall']:.4f}, "
        f"F1={metrics_a_agg['phishing_f1']:.4f}, ROC-AUC={metrics_a_agg['roc_auc']:.4f}, "
        f"PR-AUC={metrics_a_agg['pr_auc']:.4f} ({duration_a}s)"
    )

    del X_train_text_a, X_test_text_a, X_train_tfidf_a, X_test_tfidf_a, vec_a, model_a
    gc.collect()

    ram_after_a = get_system_ram()
    resource_log.append({
        "stage": "tier2_split_a",
        "ram_before_avail_gb": ram_before_a["avail_gb"],
        "ram_after_avail_gb": ram_after_a["avail_gb"],
        "duration_sec": duration_a,
    })

    # Split B: Train (Nazario 1,557 + Enron Ham 29,751 = 31,308) -> Test (Phishing Pot 124 + SA Ham 4,090 = 4,214)
    t_start_b = time.time()
    ram_before_b = get_system_ram()

    split_b_train_mask = (df_part["split_b_role"] == "train").values
    split_b_test_mask = (df_part["split_b_role"] == "test").values

    train_idx_b = np.where(split_b_train_mask)[0]
    test_idx_b = np.where(split_b_test_mask)[0]

    X_train_text_b = df_cand.loc[train_idx_b, "email_body"].astype(str).tolist()
    y_train_b = df_cand.loc[train_idx_b, "label"].astype(int).values

    X_test_text_b = df_cand.loc[test_idx_b, "email_body"].astype(str).tolist()
    y_test_b = df_cand.loc[test_idx_b, "label"].astype(int).values

    vec_b = TfidfVectorizer(**tfidf_params)
    X_train_tfidf_b = vec_b.fit_transform(X_train_text_b)
    X_test_tfidf_b = vec_b.transform(X_test_text_b)
    vocab_b = len(vec_b.vocabulary_)

    model_b = xgb.XGBClassifier(**XGB_PARAMS)
    model_b.fit(X_train_tfidf_b, y_train_b)

    test_probs_b = model_b.predict_proba(X_test_tfidf_b)[:, 1]
    test_preds_b = (test_probs_b >= DECISION_THRESHOLD).astype(int)

    df_split_b = pd.DataFrame({
        "candidate_row_id": df_part.loc[test_idx_b, "candidate_row_id"].values,
        "source_id": df_part.loc[test_idx_b, "source_id"].values,
        "source_record_id": df_part.loc[test_idx_b, "source_record_id"].values,
        "label": y_test_b,
        "split_b_role": "test",
        "y_prob": np.round(test_probs_b, 6),
        "y_pred": test_preds_b,
    })
    split_b_csv_path = exp_dir / "split_b_predictions.csv"
    df_split_b.to_csv(split_b_csv_path, index=False)

    metrics_b_agg = compute_metrics(y_test_b, test_preds_b, test_probs_b)
    pp_mask = (df_split_b["source_id"] == "phishing_pot").values
    metrics_b_pp = compute_metrics(y_test_b[pp_mask], test_preds_b[pp_mask], test_probs_b[pp_mask])
    sa_mask_b = (df_split_b["source_id"] == "spamassassin_ham").values
    metrics_b_sa = compute_metrics(y_test_b[sa_mask_b], test_preds_b[sa_mask_b], test_probs_b[sa_mask_b])

    duration_b = round(time.time() - t_start_b, 2)
    transfer_results["split_b"] = {
        "description": "Train on Nazario + Enron Ham (31,308) -> Test on Phishing Pot + SpamAssassin Ham (4,214)",
        "train_sources": ["nazario", "enron_ham"],
        "test_sources": ["phishing_pot", "spamassassin_ham"],
        "train_count": len(y_train_b),
        "test_count": len(y_test_b),
        "fitted_vocab_size": vocab_b,
        "duration_seconds": duration_b,
        "aggregate": metrics_b_agg,
        "per_source": {
            "phishing_pot": {
                "count": int(pp_mask.sum()),
                "true_label": 1,
                "metrics": metrics_b_pp,
            },
            "spamassassin_ham": {
                "count": int(sa_mask_b.sum()),
                "true_label": 0,
                "metrics": metrics_b_sa,
            },
        },
    }

    print(
        f"  [{exp_id}] Split B Aggregate: Acc={metrics_b_agg['accuracy']:.4f}, "
        f"Prec={metrics_b_agg['phishing_precision']:.4f}, Rec={metrics_b_agg['phishing_recall']:.4f}, "
        f"F1={metrics_b_agg['phishing_f1']:.4f}, ROC-AUC={metrics_b_agg['roc_auc']:.4f}, "
        f"PR-AUC={metrics_b_agg['pr_auc']:.4f} ({duration_b}s)"
    )

    del X_train_text_b, X_test_text_b, X_train_tfidf_b, X_test_tfidf_b, vec_b, model_b
    gc.collect()

    ram_after_b = get_system_ram()
    resource_log.append({
        "stage": "tier2_split_b",
        "ram_before_avail_gb": ram_before_b["avail_gb"],
        "ram_after_avail_gb": ram_after_b["avail_gb"],
        "duration_sec": duration_b,
    })

    # -----------------------------------------------------------------------
    # Exploratory Full Candidate V2 Refit & Serialization
    # -----------------------------------------------------------------------
    print(f"[{exp_id}] Exploratory Full Candidate V2 Refit (N = 35,522)...")
    t_start_full = time.time()
    ram_before_full = get_system_ram()

    X_full_text = df_cand["email_body"].astype(str).tolist()
    y_full = df_cand["label"].astype(int).values

    full_vec = TfidfVectorizer(**tfidf_params)
    X_full_tfidf = full_vec.fit_transform(X_full_text)
    full_vocab_size = len(full_vec.vocabulary_)

    full_model = xgb.XGBClassifier(**XGB_PARAMS)
    full_model.fit(X_full_tfidf, y_full)

    full_vec_path = exp_dir / "exploratory_full_vectorizer.joblib"
    full_model_path = exp_dir / "exploratory_full_model.joblib"
    full_model_json_path = exp_dir / "exploratory_full_model.json"

    joblib.dump(full_vec, full_vec_path)
    joblib.dump(full_model, full_model_path)
    full_model.save_model(str(full_model_json_path))

    duration_full = round(time.time() - t_start_full, 2)
    print(f"  [{exp_id}] Exploratory model saved (Vocab={full_vocab_size:,}) in {duration_full}s.")

    del X_full_text, X_full_tfidf, full_vec, full_model
    gc.collect()

    ram_after_full = get_system_ram()
    resource_log.append({
        "stage": "exploratory_full_refit",
        "ram_before_avail_gb": ram_before_full["avail_gb"],
        "ram_after_avail_gb": ram_after_full["avail_gb"],
        "duration_sec": duration_full,
    })

    # Save metrics JSON files
    with open(exp_dir / "cv_fold_metrics.json", "w", encoding="utf-8") as f:
        json.dump(cv_results, f, indent=2)

    with open(exp_dir / "source_transfer_metrics.json", "w", encoding="utf-8") as f:
        json.dump(transfer_results, f, indent=2)

    total_exp_time = round(time.time() - t0_exp, 2)

    experiment_config = {
        "experiment_id": exp_id,
        "experiment_name": exp_name,
        "crisp_dm_stage": "CRISP-DM Phase 4 (Modeling) & Phase 5 (Evaluation)",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": "BANTAI Content-Only Candidate Corpus V2",
        "total_records": len(df_cand),
        "phishing_records": int((y_all == 1).sum()),
        "legitimate_records": int((y_all == 0).sum()),
        "decision_threshold": DECISION_THRESHOLD,
        "tfidf_params": {
            "ngram_range": list(ngram_range),
            "max_features": max_features,
            "min_df": min_df,
            "lowercase": TFIDF_COMMON["lowercase"],
            "stop_words": TFIDF_COMMON["stop_words"],
            "token_pattern": TFIDF_COMMON["token_pattern"],
        },
        "xgb_params": XGB_PARAMS,
        "full_fitted_vocab_size": full_vocab_size,
        "software_versions": {
            "python": sys.version,
            "scikit_learn": "1.6.1",
            "xgboost": "2.1.4",
            "pandas": "2.3.3",
            "numpy": "1.26.4",
            "joblib": "1.5.3",
        },
        "resource_monitoring": resource_log,
        "total_execution_seconds": total_exp_time,
    }

    with open(exp_dir / "experiment_config.json", "w", encoding="utf-8") as f:
        json.dump(experiment_config, f, indent=2)

    # Manifest for this experiment
    exp_files = [
        "experiment_config.json",
        "cv_fold_metrics.json",
        "source_transfer_metrics.json",
        "oof_predictions.csv",
        "split_a_predictions.csv",
        "split_b_predictions.csv",
        "exploratory_full_vectorizer.joblib",
        "exploratory_full_model.joblib",
        "exploratory_full_model.json",
    ]
    exp_manifest = {
        "manifest_version": "1.0.0",
        "experiment_id": exp_id,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "candidate_v2_corpus_sha256": actual_cand_sha,
        "partition_v2_assignments_sha256": actual_part_sha,
        "file_checksums_sha256": {fname: compute_sha256(exp_dir / fname) for fname in exp_files},
    }
    with open(exp_dir / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(exp_manifest, f, indent=2)

    print(f"[{exp_id}] COMPLETE in {total_exp_time}s. Artifacts saved -> {exp_dir}\n")

    return {
        "id": exp_id,
        "name": exp_name,
        "ngram_range": str(ngram_range),
        "max_features": max_features,
        "min_df": min_df,
        "full_vocab_size": full_vocab_size,
        "duration_sec": total_exp_time,
        "oof_accuracy": oof_metrics["accuracy"],
        "oof_precision": oof_metrics["phishing_precision"],
        "oof_recall": oof_metrics["phishing_recall"],
        "oof_f1": oof_metrics["phishing_f1"],
        "oof_macro_f1": oof_metrics["macro_f1"],
        "oof_specificity": oof_metrics["specificity"],
        "oof_fpr": oof_metrics["false_positive_rate"],
        "oof_pr_auc": oof_metrics["pr_auc"],
        "oof_roc_auc": oof_metrics["roc_auc"],
        "oof_cm": oof_metrics["confusion_matrix"],
        "cv_f1_mean": cv_summary_stats["phishing_f1"]["mean"],
        "cv_f1_std": cv_summary_stats["phishing_f1"]["std"],
        "split_a_recall_nazario": metrics_a_naz["phishing_recall"],
        "split_a_fpr_sa": metrics_a_sa["false_positive_rate"],
        "split_a_f1_agg": metrics_a_agg["phishing_f1"],
        "split_b_recall_pot": metrics_b_pp["phishing_recall"],
        "split_b_fpr_sa": metrics_b_sa["false_positive_rate"],
        "split_b_f1_agg": metrics_b_agg["phishing_f1"],
    }


# ---------------------------------------------------------------------------
# Master Orchestration
# ---------------------------------------------------------------------------
def execute_phase4_6_experiments():
    start_all = time.time()
    df_cand, df_part, actual_cand_sha, actual_part_sha = run_preflight_checks()

    ARTIFACTS_ROOT.mkdir(parents=True, exist_ok=True)

    summary_records = []

    for exp_def in EXPERIMENTS:
        summary = run_single_experiment(
            exp_def,
            df_cand,
            df_part,
            actual_cand_sha,
            actual_part_sha,
        )
        summary_records.append(summary)

    # Build Master Summary Table
    df_summary = pd.DataFrame(summary_records)
    summary_csv_path = ARTIFACTS_ROOT / "experiments_summary.csv"
    df_summary.to_csv(summary_csv_path, index=False)
    print(f"Saved master experiments summary CSV -> {summary_csv_path}")

    summary_json_path = ARTIFACTS_ROOT / "experiments_summary.json"
    with open(summary_json_path, "w", encoding="utf-8") as f:
        json.dump(summary_records, f, indent=2)
    print(f"Saved master experiments summary JSON -> {summary_json_path}")

    # Build Master Manifest
    all_artifact_files = {}
    for root, dirs, files in os.walk(ARTIFACTS_ROOT):
        for fname in sorted(files):
            fpath = Path(root) / fname
            rel_path = fpath.relative_to(ARTIFACTS_ROOT).as_posix()
            if rel_path != "manifest.json":
                all_artifact_files[rel_path] = compute_sha256(fpath)

    master_manifest = {
        "manifest_version": "2.0.0",
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "formal_research_title": "XGBoost-Based Email Threat Detection and Analysis Engine using Explainability Framework",
        "phase": "Phase 4.6 (Candidate V2 Controlled TF-IDF and XGBoost Experiments)",
        "candidate_v2_corpus_sha256": actual_cand_sha,
        "partition_v2_assignments_sha256": actual_part_sha,
        "total_experiments": len(EXPERIMENTS),
        "total_files": len(all_artifact_files),
        "file_checksums_sha256": all_artifact_files,
    }
    master_manifest_path = ARTIFACTS_ROOT / "manifest.json"
    with open(master_manifest_path, "w", encoding="utf-8") as f:
        json.dump(master_manifest, f, indent=2)
    print(f"Saved master manifest -> {master_manifest_path}")

    total_all_time = round(time.time() - start_all, 2)
    print(f"\n================================================================================")
    print(f"ALL SIX PHASE 4.6 EXPERIMENTS COMPLETED IN {total_all_time}s ({total_all_time / 60:.2f} min)")
    print(f"================================================================================")


if __name__ == "__main__":
    execute_phase4_6_experiments()

