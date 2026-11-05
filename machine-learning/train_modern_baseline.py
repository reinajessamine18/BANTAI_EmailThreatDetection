#!/usr/bin/env python
"""
train_modern_baseline.py

Trains a modern baseline model on the 2024 modern email dataset:
- Data: 24,500 training rows from modern_email_dataset.csv (35k total sample)
- Features: TF-IDF with bigrams (ngram_range=(1, 2), max_features=25,000, stop_words=None)
- Classifier: XGBoost (random_state=42, n_jobs=2, eval_metric='logloss')
- Evaluates on the new validation split (5,250 rows)
- Saves artifacts to artifacts/modern_baseline/
- Ultimate Test: Evaluates String A (Blynk mockup) to verify real-world false positive resolution
"""

from __future__ import annotations

import gc
import io
import json
import math
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import scipy.sparse
import shap
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

# Safe UTF-8 console output on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE_DIR = Path(__file__).resolve().parent
TRAIN_CSV = BASE_DIR / "data" / "processed" / "train.csv"
VAL_CSV = BASE_DIR / "data" / "processed" / "validation.csv"
ARTIFACT_DIR = BASE_DIR / "artifacts" / "modern_baseline"

# Model & Feature parameters
TFIDF_PARAMS = {
    "ngram_range": (1, 2),
    "max_features": 25_000,
    "stop_words": None,
    "lowercase": True,
}

XGB_PARAMS = {
    "random_state": 42,
    "n_jobs": 2,
    "eval_metric": "logloss",
    "n_estimators": 100,
}


def probability_to_score(probability: float) -> int:
    return min(100, int(math.floor(float(probability) * 100 + 0.5)))


def get_risk_tier(score: int) -> str:
    if score <= 39:
        return "Low (Safe)"
    if score <= 79:
        return "Medium (Suspicious)"
    return "Critical (Phishing)"


def main() -> None:
    print("=" * 70)
    print("TRAINING MODERN 2024 BASELINE MODEL (25k BIGRAMS + XGBOOST)")
    print("=" * 70)

    # 1. Load Data
    print(f"Loading data from:\n  Train: {TRAIN_CSV}\n  Val:   {VAL_CSV}")
    train_df = pd.read_csv(TRAIN_CSV)
    val_df = pd.read_csv(VAL_CSV)

    print(f"Train rows: {len(train_df):,} | Val rows: {len(val_df):,}")
    print(f"Train class distribution: {train_df['label'].value_counts().to_dict()}")
    print(f"Val class distribution:   {val_df['label'].value_counts().to_dict()}\n")

    train_bodies = train_df["body"].astype(str).tolist()
    y_train = train_df["label"].astype(int).values
    del train_df
    gc.collect()

    # 2. Vectorize with TF-IDF
    print("Fitting TF-IDF Vectorizer (ngram_range=(1,2), max_features=25,000, stop_words=None)...")
    vectorizer = TfidfVectorizer(**TFIDF_PARAMS)
    X_train = vectorizer.fit_transform(train_bodies)
    del train_bodies
    gc.collect()

    if not scipy.sparse.issparse(X_train):
        raise TypeError("X_train must be scipy.sparse!")

    val_bodies = val_df["body"].astype(str).tolist()
    y_val = val_df["label"].astype(int).values
    del val_df
    gc.collect()

    X_val = vectorizer.transform(val_bodies)
    del val_bodies
    gc.collect()

    if not scipy.sparse.issparse(X_val):
        raise TypeError("X_val must be scipy.sparse!")

    print(f"Fitted Vocabulary Size: {len(vectorizer.vocabulary_):,}")
    print(f"X_train shape (sparse): {X_train.shape} (format: {X_train.format})")
    print(f"X_val shape (sparse):   {X_val.shape} (format: {X_val.format})\n")

    # 3. Train XGBoost
    print("Training XGBoost Classifier (n_jobs=2)...")
    model = xgb.XGBClassifier(**XGB_PARAMS)
    model.fit(X_train, y_train)

    del X_train, y_train
    gc.collect()

    print("Model training complete.\n")

    # 4. Evaluate on Validation Split
    print("=" * 70)
    print("VALIDATION EVALUATION METRICS")
    print("=" * 70)

    val_preds = model.predict(X_val)
    val_probs = model.predict_proba(X_val)[:, 1]

    val_acc = accuracy_score(y_val, val_preds)
    val_prec_phish = precision_score(y_val, val_preds, average="binary")
    val_rec_phish = recall_score(y_val, val_preds, average="binary")
    val_f1_phish = f1_score(y_val, val_preds, average="binary")
    val_roc_auc = roc_auc_score(y_val, val_probs)
    val_cm = confusion_matrix(y_val, val_preds)

    tn, fp, fn, tp = val_cm.ravel()
    safe_rec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    safe_prec = tn / (tn + fn) if (tn + fn) > 0 else 0.0
    safe_f1 = 2 * (safe_prec * safe_rec) / (safe_prec + safe_rec) if (safe_prec + safe_rec) > 0 else 0.0

    print("Confusion Matrix (Rows = True Label [0=Safe, 1=Phishing], Cols = Predicted):")
    print(f"  [TN={tn:5d}, FP={fp:5d}]  (True Safe: {tn+fp:,})")
    print(f"  [FN={fn:5d}, TP={tp:5d}]  (True Phishing: {fn+tp:,})\n")

    print(f"Overall Accuracy:       {val_acc:.4f} ({val_acc*100:.2f}%)")
    print(f"ROC-AUC:                {val_roc_auc:.4f}\n")

    print("Safe Class (Label 0) Metrics:")
    print(f"  False Positive Count: {fp:,} (out of {tn+fp:,} safe emails, FP Rate: {fp/(tn+fp)*100:.2f}%)")
    print(f"  Safe Recall:          {safe_rec:.4f} ({safe_rec*100:.2f}%)")
    print(f"  Safe Precision:       {safe_prec:.4f} ({safe_prec*100:.2f}%)")
    print(f"  Safe F1-Score:        {safe_f1:.4f} ({safe_f1*100:.2f}%)\n")

    print("Phishing Class (Label 1) Metrics:")
    print(f"  False Negative Count: {fn:,} (out of {fn+tp:,} phishing emails, FN Rate: {fn/(fn+tp)*100:.2f}%)")
    print(f"  Phishing Recall:      {val_rec_phish:.4f} ({val_rec_phish*100:.2f}%)")
    print(f"  Phishing Precision:   {val_prec_phish:.4f} ({val_prec_phish*100:.2f}%)")
    print(f"  Phishing F1-Score:    {val_f1_phish:.4f} ({val_f1_phish*100:.2f}%)\n")

    # 5. Save Artifacts
    print("=" * 70)
    print("SAVING ARTIFACTS")
    print("=" * 70)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    vec_path = ARTIFACT_DIR / "tfidf_vectorizer.pkl"
    joblib.dump(vectorizer, vec_path)
    print(f"Saved Vectorizer -> {vec_path}")

    model_path = ARTIFACT_DIR / "xgboost_model.pkl"
    joblib.dump(model, model_path)
    print(f"Saved Model      -> {model_path}")

    config = {
        "dataset": "Modern 2024 Email Dataset (35,000 sampled rows)",
        "train_rows": 24500,
        "val_rows": 5250,
        "tfidf_params": TFIDF_PARAMS,
        "xgb_params": {k: v for k, v in XGB_PARAMS.items()},
        "tfidf_vocab_size": len(vectorizer.vocabulary_),
        "validation_metrics": {
            "accuracy": float(val_acc),
            "roc_auc": float(val_roc_auc),
            "safe_precision": float(safe_prec),
            "safe_recall": float(safe_rec),
            "safe_f1": float(safe_f1),
            "phishing_precision": float(val_prec_phish),
            "phishing_recall": float(val_rec_phish),
            "phishing_f1": float(val_f1_phish),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        },
    }
    config_path = ARTIFACT_DIR / "experiment_config.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    print(f"Saved Config     -> {config_path}\n")

    # 6. The Ultimate Test: String A (Blynk mockup)
    print("=" * 70)
    print("THE ULTIMATE TEST: REAL-WORLD BLYNK EMAIL MOCKUP")
    print("=" * 70)

    blynk_text = (
        "Welcome to Blynk! Here are your quickstart instructions. "
        "Use your auth token to connect your device to the cloud. Thank you for signing up."
    )
    print(f'Email Text: "{blynk_text}"\n')

    blynk_X = vectorizer.transform([blynk_text])
    blynk_probs = model.predict_proba(blynk_X)[0]
    blynk_phish_prob = float(blynk_probs[1])
    blynk_safe_prob = float(blynk_probs[0])
    blynk_score = probability_to_score(blynk_phish_prob)
    blynk_tier = get_risk_tier(blynk_score)
    blynk_decision = "Safe" if blynk_phish_prob < 0.50 else "Phishing"

    print(f"  Raw Phishing Probability: {blynk_phish_prob:.4f} (Safe: {blynk_safe_prob:.4f})")
    print(f"  Threat Score:            {blynk_score}/100")
    print(f"  Risk Tier:               {blynk_tier}")
    print(f"  Binary Decision (0.50):  {blynk_decision}")

    # Top SHAP features for Blynk email
    explainer = shap.TreeExplainer(model)
    blynk_shap = explainer.shap_values(blynk_X)[0]
    base_val = float(explainer.expected_value) if np.asarray(explainer.expected_value).ndim == 0 else float(explainer.expected_value[0])
    vocab_inv = {idx: word for word, idx in vectorizer.vocabulary_.items()}

    push_phish = []
    push_safe = []
    for idx in set(blynk_X.indices):
        val = float(blynk_shap[idx])
        tok = vocab_inv.get(idx, f"idx_{idx}")
        w = float(blynk_X[0, idx])
        if val > 0:
            push_phish.append((tok, val, w))
        else:
            push_safe.append((tok, val, w))

    push_phish.sort(key=lambda x: x[1], reverse=True)
    push_safe.sort(key=lambda x: x[1])

    print(f"\n  SHAP Base Value: {base_val:+.4f}")
    print("  SHAP Feature Breakdown for Blynk:")
    print("    Tokens Pushing Toward PHISHING (+ margin):")
    if push_phish:
        for r, (t, v, w) in enumerate(push_phish[:5], 1):
            print(f"      {r}. '{t}': SHAP +{v:.4f} (TF-IDF: {w:.4f})")
    else:
        print("      [None]")

    print("    Tokens Pushing Toward SAFE (- margin):")
    if push_safe:
        for r, (t, v, w) in enumerate(push_safe[:5], 1):
            print(f"      {r}. '{t}': SHAP {v:.4f} (TF-IDF: {w:.4f})")
    else:
        print("      [None]")

    print("\n" + "=" * 70)
    print("MODERN BASELINE TRAINING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()

