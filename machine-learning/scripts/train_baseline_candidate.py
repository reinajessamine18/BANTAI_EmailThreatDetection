#!/usr/bin/env python
"""
BANTAI — Phase 4.5: Baseline Candidate Model Training
Sequential training of unigram TF-IDF + XGBoost candidate models on Phase 4.4 partitions.

Executes:
  1. Pre-training integrity checks (checksums, record counts, zero-leakage verification).
  2. Tier 1: 5-Fold StratifiedGroupKFold Cross-Validation sequentially.
  3. Tier 2: Bidirectional Source-Transfer Experiments (Split A and Split B).
  4. Full candidate baseline model fitting and serialization.
  5. Cryptographic artifact manifest creation.

Strictly adheres to:
  - 8 GB RAM laptop limits (sequential execution, garbage collection, sparse representation).
  - No hyperparameter tuning.
  - No SMOTE or class re-balancing (scale_pos_weight default).
  - No test-set data leakage.
"""

import ctypes
import gc
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
import xgboost as xgb

# ---------------------------------------------------------------------------
# Path Configuration
# ---------------------------------------------------------------------------
ML_DIR = Path(__file__).resolve().parent.parent
PROCESSED_DIR = ML_DIR / "data" / "processed" / "content_only_candidate"
CANDIDATE_CSV = PROCESSED_DIR / "candidate_corpus.csv"
CANDIDATE_MANIFEST = PROCESSED_DIR / "candidate_corpus_manifest.json"
PARTITIONS_CSV = PROCESSED_DIR / "partition_assignments.csv"
PARTITIONS_MANIFEST = PROCESSED_DIR / "partition_manifest.json"

ARTIFACT_DIR = ML_DIR / "artifacts" / "candidate_content_nlp"

# ---------------------------------------------------------------------------
# Model & Vectorizer Hyperparameters (Authoritative Baseline)
# ---------------------------------------------------------------------------
TFIDF_PARAMS = {
    "max_features": 50000,
    "lowercase": True,
    "stop_words": None,
    "ngram_range": (1, 1),
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

DECISION_THRESHOLD = 0.5


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


def get_system_ram():
    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
    return {
        "total_gb": round(stat.ullTotalPhys / (1024**3), 2),
        "avail_gb": round(stat.ullAvailPhys / (1024**3), 2),
        "memory_load_pct": stat.dwMemoryLoad,
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

    # Probabilistic curves (requires both classes present in y_true)
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
    print("PHASE 4.5: PRE-TRAINING INTEGRITY VERIFICATION")
    print("================================================================================")

    if not CANDIDATE_CSV.exists():
        raise FileNotFoundError(f"Missing candidate corpus: {CANDIDATE_CSV}")
    if not CANDIDATE_MANIFEST.exists():
        raise FileNotFoundError(f"Missing candidate manifest: {CANDIDATE_MANIFEST}")
    if not PARTITIONS_CSV.exists():
        raise FileNotFoundError(f"Missing partition assignments: {PARTITIONS_CSV}")
    if not PARTITIONS_MANIFEST.exists():
        raise FileNotFoundError(f"Missing partition manifest: {PARTITIONS_MANIFEST}")

    # Check candidate checksum
    with open(CANDIDATE_MANIFEST, "r", encoding="utf-8") as f:
        cand_manifest = json.load(f)
    expected_cand_sha = cand_manifest["candidate_corpus"]["sha256"]
    actual_cand_sha = compute_sha256(CANDIDATE_CSV)
    if actual_cand_sha != expected_cand_sha:
        raise ValueError(f"Candidate corpus checksum mismatch: {actual_cand_sha} != {expected_cand_sha}")
    print(f"[OK] Candidate corpus checksum verified: {actual_cand_sha}")

    # Check partition checksum
    with open(PARTITIONS_MANIFEST, "r", encoding="utf-8") as f:
        part_manifest = json.load(f)
    expected_part_sha = part_manifest["partition_assignments_file"]["sha256"]
    actual_part_sha = compute_sha256(PARTITIONS_CSV)
    if actual_part_sha != expected_part_sha:
        raise ValueError(f"Partition assignments checksum mismatch: {actual_part_sha} != {expected_part_sha}")
    print(f"[OK] Partition assignments checksum verified: {actual_part_sha}")

    # Load tables
    df_cand = pd.read_csv(CANDIDATE_CSV)
    df_part = pd.read_csv(PARTITIONS_CSV)

    if len(df_cand) != 37350:
        raise ValueError(f"Expected 37,350 candidate records, got {len(df_cand)}")
    if len(df_part) != 37350:
        raise ValueError(f"Expected 37,350 partition records, got {len(df_part)}")
    print(f"[OK] Record count verified: {len(df_cand):,} records")

    # Labels verification
    labels = sorted(df_cand["label"].unique().tolist())
    if labels != [0, 1]:
        raise ValueError(f"Labels must be [0, 1], got {labels}")
    print(f"[OK] Binary labels verified: {labels}")

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


def generate_manifest(actual_cand_sha: str, actual_part_sha: str):
    manifest_files = [
        "experiment_config.json",
        "cv_fold_metrics.json",
        "source_transfer_metrics.json",
        "oof_predictions.csv",
        "split_a_predictions.csv",
        "split_b_predictions.csv",
        "candidate_baseline_vectorizer.joblib",
        "candidate_baseline_model.joblib",
        "candidate_baseline_model.json",
    ]
    manifest_dict = {
        "manifest_version": "1.0.0",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "experiment_name": "candidate_baseline_content_nlp",
        "input_corpus_sha256": actual_cand_sha,
        "input_partitions_sha256": actual_part_sha,
        "file_checksums_sha256": {fname: compute_sha256(ARTIFACT_DIR / fname) for fname in manifest_files},
    }

    manifest_path = ARTIFACT_DIR / "candidate_baseline_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_dict, f, indent=2)
    print(f"Saved candidate baseline manifest -> {manifest_path}")
    return manifest_path


# ---------------------------------------------------------------------------
# Training Orchestration
# ---------------------------------------------------------------------------
def execute_phase4_5_training():
    start_total_time = time.time()
    df_cand, df_part, actual_cand_sha, actual_part_sha = run_preflight_checks()

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------------------
    # Tier 1 — Five-Fold Cross-Validation
    # ---------------------------------------------------------------------------
    print("================================================================================")
    print("TIER 1: FIVE-FOLD STRATIFIED GROUP CROSS-VALIDATION")
    print("================================================================================")

    cv_results = {}
    oof_predictions = np.zeros(len(df_cand), dtype=int)
    oof_probabilities = np.zeros(len(df_cand), dtype=float)

    resource_log = []

    for fold in range(5):
        t0 = time.time()
        ram_before = get_system_ram()

        val_mask = df_part["cv_fold"] == fold
        train_mask = ~val_mask

        val_indices = np.where(val_mask)[0]
        train_indices = np.where(train_mask)[0]

        X_train_text = df_cand.loc[train_indices, "email_body"].astype(str).tolist()
        y_train = df_cand.loc[train_indices, "label"].astype(int).values

        X_val_text = df_cand.loc[val_indices, "email_body"].astype(str).tolist()
        y_val = df_cand.loc[val_indices, "label"].astype(int).values

        print(f"--- Fold {fold} ---")
        print(f"  Train: {len(y_train):,} (Phish: {int((y_train == 1).sum()):,}, Ham: {int((y_train == 0).sum()):,})")
        print(f"  Val:   {len(y_val):,} (Phish: {int((y_val == 1).sum()):,}, Ham: {int((y_val == 0).sum()):,})")

        # 1. Fit TF-IDF on train text only
        vec = TfidfVectorizer(**TFIDF_PARAMS)
        X_train_tfidf = vec.fit_transform(X_train_text)
        X_val_tfidf = vec.transform(X_val_text)
        print(f"  Fitted TF-IDF vocabulary: {len(vec.vocabulary_):,} features")

        # 2. Train XGBoost
        model = xgb.XGBClassifier(**XGB_PARAMS)
        model.fit(X_train_tfidf, y_train)

        # 3. Predict on validation set
        val_probs = model.predict_proba(X_val_tfidf)[:, 1]
        val_preds = (val_probs >= DECISION_THRESHOLD).astype(int)

        oof_probabilities[val_indices] = val_probs
        oof_predictions[val_indices] = val_preds

        # 4. Evaluate fold
        fold_metrics = compute_metrics(y_val, val_preds, val_probs)
        fold_metrics["train_count"] = len(y_train)
        fold_metrics["val_count"] = len(y_val)
        fold_metrics["duration_seconds"] = round(time.time() - t0, 2)
        cv_results[f"fold_{fold}"] = fold_metrics

        print(f"  Results: Acc={fold_metrics['accuracy']:.4f}, Prec={fold_metrics['phishing_precision']:.4f}, "
              f"Rec={fold_metrics['phishing_recall']:.4f}, F1={fold_metrics['phishing_f1']:.4f}, "
              f"ROC-AUC={fold_metrics['roc_auc']:.4f}, PR-AUC={fold_metrics['pr_auc']:.4f}")
        print(f"  CM: TN={fold_metrics['confusion_matrix']['tn']}, FP={fold_metrics['confusion_matrix']['fp']}, "
              f"FN={fold_metrics['confusion_matrix']['fn']}, TP={fold_metrics['confusion_matrix']['tp']}")

        # Explicit cleanup
        del X_train_text, X_val_text, X_train_tfidf, X_val_tfidf, vec, model
        gc.collect()

        ram_after = get_system_ram()
        resource_log.append({
            "stage": f"fold_{fold}",
            "ram_before_avail_gb": ram_before["avail_gb"],
            "ram_after_avail_gb": ram_after["avail_gb"],
            "duration_sec": fold_metrics["duration_seconds"],
        })
        print(f"  Fold {fold} finished in {fold_metrics['duration_seconds']}s. RAM available: {ram_after['avail_gb']} GB\n")

    # Aggregate OOF metrics across all 37,350 candidate records
    y_all = df_cand["label"].astype(int).values
    oof_metrics = compute_metrics(y_all, oof_predictions, oof_probabilities)
    oof_metrics["total_records"] = len(y_all)
    cv_results["oof_aggregate"] = oof_metrics

    # Compute mean and std across 5 folds
    metric_keys = ["accuracy", "phishing_precision", "phishing_recall", "phishing_f1", "macro_f1", "specificity", "false_positive_rate", "pr_auc", "roc_auc"]
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

    print("================================================================================")
    print("TIER 1 OOF AGGREGATE RESULTS (N = 37,350)")
    print("================================================================================")
    print(f"Accuracy:            {oof_metrics['accuracy']:.4f}")
    print(f"Phishing Precision:  {oof_metrics['phishing_precision']:.4f}")
    print(f"Phishing Recall:     {oof_metrics['phishing_recall']:.4f}")
    print(f"Phishing F1-Score:   {oof_metrics['phishing_f1']:.4f}")
    print(f"Macro F1-Score:      {oof_metrics['macro_f1']:.4f}")
    print(f"Specificity:         {oof_metrics['specificity']:.4f}")
    print(f"False Positive Rate: {oof_metrics['false_positive_rate']:.4f}")
    print(f"PR-AUC:              {oof_metrics['pr_auc']:.4f}")
    print(f"ROC-AUC:             {oof_metrics['roc_auc']:.4f}")
    print(f"Confusion Matrix:    TN={oof_metrics['confusion_matrix']['tn']}, FP={oof_metrics['confusion_matrix']['fp']}, "
          f"FN={oof_metrics['confusion_matrix']['fn']}, TP={oof_metrics['confusion_matrix']['tp']}")
    print("================================================================================\n")

    # Save OOF predictions table
    df_oof = pd.DataFrame({
        "candidate_row_id": df_part["candidate_row_id"],
        "source_id": df_part["source_id"],
        "source_record_id": df_part["source_record_id"],
        "label": df_part["label"],
        "cv_fold": df_part["cv_fold"],
        "y_prob": np.round(oof_probabilities, 6),
        "y_pred": oof_predictions,
    })
    oof_csv_path = ARTIFACT_DIR / "oof_predictions.csv"
    df_oof.to_csv(oof_csv_path, index=False)
    print(f"Saved OOF predictions table -> {oof_csv_path}")

    # ---------------------------------------------------------------------------
    # Tier 2 — Source-Transfer Generalization Experiments
    # ---------------------------------------------------------------------------
    print("\n================================================================================")
    print("TIER 2: BIDIRECTIONAL SOURCE-TRANSFER EXPERIMENTS")
    print("================================================================================")

    transfer_results = {}

    # -----------------------
    # Split A: Train (PhishPot + Enron) -> Test (Nazario + SA Ham)
    # -----------------------
    print("--- SPLIT A: Train (PhishPot + Enron) -> Test (Nazario + SA Ham) ---")
    t_start_a = time.time()
    ram_before_a = get_system_ram()

    split_a_train_mask = df_part["split_a_role"] == "train"
    split_a_test_mask = df_part["split_a_role"] == "test"

    train_idx_a = np.where(split_a_train_mask)[0]
    test_idx_a = np.where(split_a_test_mask)[0]

    X_train_text_a = df_cand.loc[train_idx_a, "email_body"].astype(str).tolist()
    y_train_a = df_cand.loc[train_idx_a, "label"].astype(int).values

    X_test_text_a = df_cand.loc[test_idx_a, "email_body"].astype(str).tolist()
    y_test_a = df_cand.loc[test_idx_a, "label"].astype(int).values

    vec_a = TfidfVectorizer(**TFIDF_PARAMS)
    X_train_tfidf_a = vec_a.fit_transform(X_train_text_a)
    X_test_tfidf_a = vec_a.transform(X_test_text_a)
    print(f"  Fitted Split A vocabulary: {len(vec_a.vocabulary_):,} features")

    model_a = xgb.XGBClassifier(**XGB_PARAMS)
    model_a.fit(X_train_tfidf_a, y_train_a)

    test_probs_a = model_a.predict_proba(X_test_tfidf_a)[:, 1]
    test_preds_a = (test_probs_a >= DECISION_THRESHOLD).astype(int)

    # Save Split A predictions
    df_split_a = pd.DataFrame({
        "candidate_row_id": df_part.loc[test_idx_a, "candidate_row_id"],
        "source_id": df_part.loc[test_idx_a, "source_id"],
        "source_record_id": df_part.loc[test_idx_a, "source_record_id"],
        "label": y_test_a,
        "split_a_role": "test",
        "y_prob": np.round(test_probs_a, 6),
        "y_pred": test_preds_a,
    })
    split_a_csv_path = ARTIFACT_DIR / "split_a_predictions.csv"
    df_split_a.to_csv(split_a_csv_path, index=False)

    # Compute Split A aggregate and per-source metrics
    metrics_a_agg = compute_metrics(y_test_a, test_preds_a, test_probs_a)

    # Nazario subset (Phishing: label 1)
    naz_mask = (df_split_a["source_id"] == "nazario").values
    metrics_a_naz = compute_metrics(y_test_a[naz_mask], test_preds_a[naz_mask], test_probs_a[naz_mask])

    # SpamAssassin Ham subset (Legitimate: label 0)
    sa_mask_a = (df_split_a["source_id"] == "spamassassin_ham").values
    metrics_a_sa = compute_metrics(y_test_a[sa_mask_a], test_preds_a[sa_mask_a], test_probs_a[sa_mask_a])

    duration_a = round(time.time() - t_start_a, 2)
    transfer_results["split_a"] = {
        "description": "Train on Phishing Pot + Enron Ham (31,703) -> Test on Nazario + SpamAssassin Ham (5,647)",
        "train_sources": ["phishing_pot", "enron_ham"],
        "test_sources": ["nazario", "spamassassin_ham"],
        "train_count": len(y_train_a),
        "test_count": len(y_test_a),
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

    print(f"  Split A Aggregate: Acc={metrics_a_agg['accuracy']:.4f}, Prec={metrics_a_agg['phishing_precision']:.4f}, "
          f"Rec={metrics_a_agg['phishing_recall']:.4f}, F1={metrics_a_agg['phishing_f1']:.4f}, "
          f"ROC-AUC={metrics_a_agg['roc_auc']:.4f}, PR-AUC={metrics_a_agg['pr_auc']:.4f}")
    print(f"  Nazario Test (N={naz_mask.sum()}): Phishing Recall={metrics_a_naz['phishing_recall']:.4f} "
          f"(TP={metrics_a_naz['confusion_matrix']['tp']}, FN={metrics_a_naz['confusion_matrix']['fn']})")
    print(f"  SpamAssassin Ham Test (N={sa_mask_a.sum()}): Specificity={metrics_a_sa['specificity']:.4f}, "
          f"FPR={metrics_a_sa['false_positive_rate']:.4f} (TN={metrics_a_sa['confusion_matrix']['tn']}, FP={metrics_a_sa['confusion_matrix']['fp']})")

    del X_train_text_a, X_test_text_a, X_train_tfidf_a, X_test_tfidf_a, vec_a, model_a
    gc.collect()

    ram_after_a = get_system_ram()
    resource_log.append({
        "stage": "split_a",
        "ram_before_avail_gb": ram_before_a["avail_gb"],
        "ram_after_avail_gb": ram_after_a["avail_gb"],
        "duration_sec": duration_a,
    })
    print(f"  Split A completed in {duration_a}s. RAM available: {ram_after_a['avail_gb']} GB\n")

    # -----------------------
    # Split B: Train (Nazario + Enron) -> Test (PhishPot + SA Ham)
    # -----------------------
    print("--- SPLIT B: Train (Nazario + Enron) -> Test (PhishPot + SA Ham) ---")
    t_start_b = time.time()
    ram_before_b = get_system_ram()

    split_b_train_mask = df_part["split_b_role"] == "train"
    split_b_test_mask = df_part["split_b_role"] == "test"

    train_idx_b = np.where(split_b_train_mask)[0]
    test_idx_b = np.where(split_b_test_mask)[0]

    X_train_text_b = df_cand.loc[train_idx_b, "email_body"].astype(str).tolist()
    y_train_b = df_cand.loc[train_idx_b, "label"].astype(int).values

    X_test_text_b = df_cand.loc[test_idx_b, "email_body"].astype(str).tolist()
    y_test_b = df_cand.loc[test_idx_b, "label"].astype(int).values

    vec_b = TfidfVectorizer(**TFIDF_PARAMS)
    X_train_tfidf_b = vec_b.fit_transform(X_train_text_b)
    X_test_tfidf_b = vec_b.transform(X_test_text_b)
    print(f"  Fitted Split B vocabulary: {len(vec_b.vocabulary_):,} features")

    model_b = xgb.XGBClassifier(**XGB_PARAMS)
    model_b.fit(X_train_tfidf_b, y_train_b)

    test_probs_b = model_b.predict_proba(X_test_tfidf_b)[:, 1]
    test_preds_b = (test_probs_b >= DECISION_THRESHOLD).astype(int)

    # Save Split B predictions
    df_split_b = pd.DataFrame({
        "candidate_row_id": df_part.loc[test_idx_b, "candidate_row_id"],
        "source_id": df_part.loc[test_idx_b, "source_id"],
        "source_record_id": df_part.loc[test_idx_b, "source_record_id"],
        "label": y_test_b,
        "split_b_role": "test",
        "y_prob": np.round(test_probs_b, 6),
        "y_pred": test_preds_b,
    })
    split_b_csv_path = ARTIFACT_DIR / "split_b_predictions.csv"
    df_split_b.to_csv(split_b_csv_path, index=False)

    # Compute Split B aggregate and per-source metrics
    metrics_b_agg = compute_metrics(y_test_b, test_preds_b, test_probs_b)

    # Phishing Pot subset (Phishing: label 1)
    pp_mask = (df_split_b["source_id"] == "phishing_pot").values
    metrics_b_pp = compute_metrics(y_test_b[pp_mask], test_preds_b[pp_mask], test_probs_b[pp_mask])

    # SpamAssassin Ham subset (Legitimate: label 0)
    sa_mask_b = (df_split_b["source_id"] == "spamassassin_ham").values
    metrics_b_sa = compute_metrics(y_test_b[sa_mask_b], test_preds_b[sa_mask_b], test_probs_b[sa_mask_b])

    duration_b = round(time.time() - t_start_b, 2)
    transfer_results["split_b"] = {
        "description": "Train on Nazario + Enron Ham (31,308) -> Test on Phishing Pot + SpamAssassin Ham (6,042)",
        "train_sources": ["nazario", "enron_ham"],
        "test_sources": ["phishing_pot", "spamassassin_ham"],
        "train_count": len(y_train_b),
        "test_count": len(y_test_b),
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

    print(f"  Split B Aggregate: Acc={metrics_b_agg['accuracy']:.4f}, Prec={metrics_b_agg['phishing_precision']:.4f}, "
          f"Rec={metrics_b_agg['phishing_recall']:.4f}, F1={metrics_b_agg['phishing_f1']:.4f}, "
          f"ROC-AUC={metrics_b_agg['roc_auc']:.4f}, PR-AUC={metrics_b_agg['pr_auc']:.4f}")
    print(f"  Phishing Pot Test (N={pp_mask.sum()}): Phishing Recall={metrics_b_pp['phishing_recall']:.4f} "
          f"(TP={metrics_b_pp['confusion_matrix']['tp']}, FN={metrics_b_pp['confusion_matrix']['fn']})")
    print(f"  SpamAssassin Ham Test (N={sa_mask_b.sum()}): Specificity={metrics_b_sa['specificity']:.4f}, "
          f"FPR={metrics_b_sa['false_positive_rate']:.4f} (TN={metrics_b_sa['confusion_matrix']['tn']}, FP={metrics_b_sa['confusion_matrix']['fp']})")

    del X_train_text_b, X_test_text_b, X_train_tfidf_b, X_test_tfidf_b, vec_b, model_b
    gc.collect()

    ram_after_b = get_system_ram()
    resource_log.append({
        "stage": "split_b",
        "ram_before_avail_gb": ram_before_b["avail_gb"],
        "ram_after_avail_gb": ram_after_b["avail_gb"],
        "duration_sec": duration_b,
    })
    print(f"  Split B completed in {duration_b}s. RAM available: {ram_after_b['avail_gb']} GB\n")

    # ---------------------------------------------------------------------------
    # Full Candidate Baseline Model Training & Serialization
    # ---------------------------------------------------------------------------
    print("================================================================================")
    print("FULL CANDIDATE BASELINE MODEL TRAINING & SERIALIZATION (N = 37,350)")
    print("================================================================================")
    t_start_full = time.time()
    ram_before_full = get_system_ram()

    X_full_text = df_cand["email_body"].astype(str).tolist()
    y_full = df_cand["label"].astype(int).values

    full_vec = TfidfVectorizer(**TFIDF_PARAMS)
    X_full_tfidf = full_vec.fit_transform(X_full_text)
    print(f"Fitted Full Candidate vocabulary: {len(full_vec.vocabulary_):,} features")

    full_model = xgb.XGBClassifier(**XGB_PARAMS)
    full_model.fit(X_full_tfidf, y_full)

    full_vec_path = ARTIFACT_DIR / "candidate_baseline_vectorizer.joblib"
    full_model_path = ARTIFACT_DIR / "candidate_baseline_model.joblib"
    joblib.dump(full_vec, full_vec_path)
    joblib.dump(full_model, full_model_path)

    # Also save standard .json / .pkl representations for cross-platform compatibility
    model_json_path = ARTIFACT_DIR / "candidate_baseline_model.json"
    full_model.save_model(str(model_json_path))

    duration_full = round(time.time() - t_start_full, 2)
    print(f"Full model trained and serialized in {duration_full}s.")
    print(f"  Vectorizer saved -> {full_vec_path}")
    print(f"  Model saved      -> {full_model_path}")
    print(f"  JSON model saved -> {model_json_path}")

    del X_full_text, X_full_tfidf, full_vec, full_model
    gc.collect()

    ram_after_full = get_system_ram()
    resource_log.append({
        "stage": "full_candidate_model",
        "ram_before_avail_gb": ram_before_full["avail_gb"],
        "ram_after_avail_gb": ram_after_full["avail_gb"],
        "duration_sec": duration_full,
    })

    # ---------------------------------------------------------------------------
    # Persist JSON Artifacts & Metadata
    # ---------------------------------------------------------------------------
    cv_metrics_path = ARTIFACT_DIR / "cv_fold_metrics.json"
    with open(cv_metrics_path, "w", encoding="utf-8") as f:
        json.dump(cv_results, f, indent=2)
    print(f"Saved CV fold metrics -> {cv_metrics_path}")

    transfer_metrics_path = ARTIFACT_DIR / "source_transfer_metrics.json"
    with open(transfer_metrics_path, "w", encoding="utf-8") as f:
        json.dump(transfer_results, f, indent=2)
    print(f"Saved source-transfer metrics -> {transfer_metrics_path}")

    experiment_config = {
        "experiment_name": "candidate_baseline_content_nlp",
        "crisp_dm_stage": "CRISP-DM Phase 4 (Modeling) & Phase 5 (Evaluation)",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_candidate_records": len(df_cand),
        "phishing_records": int((y_all == 1).sum()),
        "legitimate_records": int((y_all == 0).sum()),
        "decision_threshold": DECISION_THRESHOLD,
        "tfidf_params": {
            "ngram_range": list(TFIDF_PARAMS["ngram_range"]),
            "max_features": TFIDF_PARAMS["max_features"],
            "lowercase": TFIDF_PARAMS["lowercase"],
            "stop_words": TFIDF_PARAMS["stop_words"],
            "token_pattern": TFIDF_PARAMS["token_pattern"],
        },
        "xgb_params": {
            "n_estimators": XGB_PARAMS["n_estimators"],
            "max_depth": XGB_PARAMS["max_depth"],
            "learning_rate": XGB_PARAMS["learning_rate"],
            "random_state": XGB_PARAMS["random_state"],
            "n_jobs": XGB_PARAMS["n_jobs"],
            "eval_metric": XGB_PARAMS["eval_metric"],
            "tree_method": XGB_PARAMS["tree_method"],
        },
        "software_versions": {
            "python": sys.version,
            "scikit_learn": "1.6.1",
            "xgboost": "2.1.4",
            "pandas": "2.3.3",
            "numpy": "1.26.4",
            "joblib": "1.5.3",
        },
        "resource_monitoring": resource_log,
        "total_execution_seconds": round(time.time() - start_total_time, 2),
    }

    config_path = ARTIFACT_DIR / "experiment_config.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(experiment_config, f, indent=2)
    print(f"Saved experiment config -> {config_path}")

    # Build Cryptographic Manifest
    generate_manifest(actual_cand_sha, actual_part_sha)

    total_time = round(time.time() - start_total_time, 2)
    print(f"\n================================================================================")
    print(f"PHASE 4.5 TRAINING COMPLETE IN {total_time}s")
    print(f"================================================================================")


if __name__ == "__main__":
    if "--manifest-only" in sys.argv:
        _, _, actual_cand_sha, actual_part_sha = run_preflight_checks()
        generate_manifest(actual_cand_sha, actual_part_sha)
    else:
        execute_phase4_5_training()
