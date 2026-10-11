#!/usr/bin/env python
"""Minimal TF-IDF + XGBoost baseline for BANTAI email threat detection.

Stage 1: Train on prepared data, evaluate on validation only.
No SHAP, no threat scores, no hyperparameter tuning, no test-set evaluation.
"""

import json
import sys
from pathlib import Path

import joblib
import pandas as pd
import xgboost as xgb
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# ---------------------------------------------------------------------------
# Project configuration (all paths relative to the machine-learning directory)
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent          # D:\SCHOOL FILES\JUNIOR YEAR\BANTAI_EmailThreatDetection\machine-learning
TRAIN_CSV = BASE_DIR / "data" / "processed" / "train.csv"
VAL_CSV   = BASE_DIR / "data" / "processed" / "validation.csv"
ARTIFACT_DIR = BASE_DIR / "artifacts" / "baseline"

# TF-IDF parameters — word‑level, capped for 8 GB RAM laptop
TFIDF_PARAMS = {
    "max_features": 50_000,
    "lowercase": True,
    "stop_words": None,
    "ngram_range": (1, 1),
}

# XGBoost parameters — reproducible, single-thread, no obsolete flags
XGB_PARAMS = {
    "random_state": 42,
    "n_jobs": 1,
    "eval_metric": "logloss",
    "n_estimators": 100,            # fixed baseline value; recorded in experiment log
}

# ---------------------------------------------------------------------------
# Step 0 – .gitignore inspection (report; do not auto‑edit)
# ---------------------------------------------------------------------------
gitignore_path = BASE_DIR.parent / ".gitignore"        # project root
needed_rule    = "machine-learning/artifacts/baseline/"

print("=== Gitignore inspection ===")
try:
    gi = gitignore_path.read_text()
except FileNotFoundError:
    gi = ""

if needed_rule in gi:
    print(f"OK: .gitignore already ignores '{needed_rule}'")
else:
    print(f"NOTE: .gitignore does NOT contain '{needed_rule}'")
    print("Add this line to .gitignore to local-track artifacts:")
    print(f"  {needed_rule}")
print("(Wait for your approval before saving artifacts to this directory.)\n")

# ---------------------------------------------------------------------------
# Step 1 – Verify prepared CSVs
# ---------------------------------------------------------------------------
print("=== Verify prepared CSVs ===")
if not TRAIN_CSV.exists():
    raise FileNotFoundError(f"Training CSV not found: {TRAIN_CSV}")
if not VAL_CSV.exists():
    raise FileNotFoundError(f"Validation CSV not found: {VAL_CSV}")

train_df = pd.read_csv(TRAIN_CSV)
val_df   = pd.read_csv(VAL_CSV)

expected_cols = {"body", "label"}
if set(train_df.columns) != expected_cols:
    raise ValueError(f"Train CSV columns {set(train_df.columns)} != expected {expected_cols}")
if set(val_df.columns) != expected_cols:
    raise ValueError(f"Val CSV columns {set(val_df.columns)} != expected {expected_cols}")

# Verify labels are 0/1
train_labels = sorted(train_df["label"].unique().tolist())
val_labels   = sorted(val_df["label"].unique().tolist())
if train_labels != [0, 1] or val_labels != [0, 1]:
    raise ValueError(f"Expected labels [0,1]; train={train_labels}, val={val_labels}")

print(f"Train: {len(train_df):,} rows  labels={train_labels}")
print(f"Val:   {len(val_df):,} rows    labels={val_labels}\n")

# ---------------------------------------------------------------------------
# Step 2 – Check for existing artifacts (stop if they exist)
# ---------------------------------------------------------------------------
print("=== Artifact directory check ===")
if ARTIFACT_DIR.is_dir():
    existing = list(ARTIFACT_DIR.iterdir())
    if existing:
        print(f"WARNING: {ARTIFACT_DIR} already contains {len(existing)} file(s):")
        for f in existing:
            print(f"  - {f.name}")
        print("Stopping before overwrite. Please manually clean or approve.")
        sys.exit(1)   # do not overwrite without explicit approval
print("Artifact directory clear (or empty).\n")

# ---------------------------------------------------------------------------
# Step 3 – Fit TF-IDF on training bodies only (no data leakage)
# ---------------------------------------------------------------------------
print("=== TF-IDF fit on training bodies only ===")
corpus = train_df["body"].astype(str).tolist()

vectorizer = TfidfVectorizer(**TFIDF_PARAMS)
X_train = vectorizer.fit_transform(corpus)

# Transform validation using the *fitted* vectorizer only
X_val = vectorizer.transform(val_df["body"].astype(str).tolist())

print(f"TF-IDF vocabulary size: {len(vectorizer.vocabulary_)}")
print(f"Train X shape:      {X_train.shape}")
print(f"Val   X shape:      {X_val.shape}\n")

# ---------------------------------------------------------------------------
# Step 4 – Train XGBoost Classifier (fixed params, no eval_set)
# ---------------------------------------------------------------------------
print("=== Train XGBClassifier with fixed parameters ===")
model = xgb.XGBClassifier(**XGB_PARAMS)

# NOTE: eval_set is intentionally omitted per user instructions:
# "Do not pass eval_set unless it is actually needed."
model.fit(X_train, train_df["label"].astype(int).values)

print(f"Model trained: n_estimators={model.n_estimators}, "
      f"random_state={model.random_state}\n")

# ---------------------------------------------------------------------------
# Step 5 – Evaluate on validation data only
# ---------------------------------------------------------------------------
print("=== Evaluate on validation split only ===")
val_predictions = model.predict(X_val)
val_probabilities = model.predict_proba(X_val)[:, 1]  # probability for class 1 (Phishing)

val_accuracy = accuracy_score(val_df["label"].astype(int), val_predictions)
val_precision = precision_score(val_df["label"].astype(int), val_predictions, average="binary")
val_recall = recall_score(val_df["label"].astype(int), val_predictions, average="binary")
val_f1 = f1_score(val_df["label"].astype(int), val_predictions, average="binary")
val_roc_auc = roc_auc_score(val_df["label"].astype(int), val_probabilities)
val_cm = confusion_matrix(val_df["label"].astype(int), val_predictions)

print(f"Validation Accuracy:  {val_accuracy:.4f}")
print(f"Validation Precision: {val_precision:.4f}")
print(f"Validation Recall:    {val_recall:.4f}")
print(f"Validation F1-score:  {val_f1:.4f}")
print(f"Validation ROC-AUC:   {val_roc_auc:.4f}")
print(f"Validation Confusion Matrix:\n{val_cm}\n")

# ---------------------------------------------------------------------------
# Step 6 – Save artifacts (only if directory was empty/absent)
# ---------------------------------------------------------------------------
print("=== Save artifacts ===")
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

# Save fitted TF-IDF vectorizer
vec_path = ARTIFACT_DIR / "tfidf_vectorizer.pkl"
joblib.dump(vectorizer, vec_path)
print(f"Saved vectorizer → {vec_path}")

# Save trained XGBoost model
model_path = ARTIFACT_DIR / "xgboost_model.pkl"
joblib.dump(model, model_path)
print(f"Saved model      → {model_path}")

# Save experiment configuration & results (actual values only)
config = {
    "tfidf_params": TFIDF_PARAMS,
    "xgb_params": {k: v for k, v in XGB_PARAMS.items()},
    "train_rows": len(train_df),
    "val_rows": len(val_df),
    "tfidf_vocab_size": len(vectorizer.vocabulary_),
    "n_estimators": XGB_PARAMS["n_estimators"],
    "random_state": 42,
    "validation_metrics": {
        "accuracy": float(val_accuracy),
        "precision": float(val_precision),
        "recall": float(val_recall),
        "f1_score": float(val_f1),
        "roc_auc": float(val_roc_auc),
        "confusion_matrix": val_cm.tolist(),
    },
}
config_path = ARTIFACT_DIR / "experiment_config.json"
with open(config_path, "w") as f:
    json.dump(config, f, indent=2)
print(f"Saved config     → {config_path}\n")

print("=== Stage 1 complete ===")
print("No raw email bodies were printed.")
print("No SHAP, threat scores, or risk thresholds were computed.")
print("No test‑set evaluation was performed.")
print(f"Artifacts and report located at: {ARTIFACT_DIR}")