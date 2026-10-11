#!/usr/bin/env python
"""
verify_baseline.py

Beginner-friendly verification script for the BANTAI TF-IDF + XGBoost baseline.

This script loads the saved artifacts (TF-IDF vectorizer and XGBoost model)
and checks them against a small sample from the validation set — no training,
no retraining, no data leakage.

It is intentionally read-only: it does not modify artifacts, datasets, or any
other project files. It simply confirms that the saved model can make
predictions and that the probabilities are well-formed.

Usage (from the project root, or with the venv Python):
    machine-learning\\.venv\\Scripts\\python.exe machine-learning\verify_baseline.py
"""

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Project paths (all relative to the machine-learning directory)
# ---------------------------------------------------------------------------
ML_DIR = Path(__file__).parent  # D:\SCHOOL FILES\JUNIOR YEAR\BANTAI_EmailThreatDetection\machine-learning

ARTIFACTS_DIR = ML_DIR / "artifacts" / "baseline"
VECTORIZER_PATH = ARTIFACTS_DIR / "tfidf_vectorizer.pkl"
MODEL_PATH = ARTIFACTS_DIR / "xgboost_model.pkl"

VAL_CSV = ML_DIR / "data" / "processed" / "validation.csv"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def load_artifacts():
    """Load the fitted vectorizer and trained XGBoost model.

    Returns
    -------
    vectorizer : TfidfVectorizer
        The fitted scikit-learn TF-IDF vectorizer.
    model : XGBClassifier
        The trained XGBoost classifier.
    """
    if not VECTORIZER_PATH.is_file():
        raise FileNotFoundError(
            f"Vectorizer not found: {VECTORIZER_PATH}. "
            "Run train_baseline.py first to generate artifacts."
        )
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}. "
            "Run train_baseline.py first to generate artifacts."
        )

    print(f"Loading vectorizer from: {VECTORIZER_PATH}")
    vectorizer = joblib.load(VECTORIZER_PATH)

    print(f"Loading model from: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)

    return vectorizer, model


def load_validation_sample(n_rows=5):
    """Read only the first *n_rows* from the validation CSV.

    This is a lightweight read — only the requested number of rows are
    loaded into memory. The CSV is expected to have two columns:
        body (email text)
        label  (0 = Safe, 1 = Phishing)

    Parameters
    ----------
    n_rows : int, default 5
        How many rows to read from the top of the validation set.

    Returns
    -------
    df : pandas.DataFrame
        Two columns: ``body`` and ``label``. Only *n_rows* are returned.
    """
    if not VAL_CSV.is_file():
        raise FileNotFoundError(
            f"Validation CSV not found: {VAL_CSV}. "
            "Check that the prepared dataset exists."
        )

    # Read only the requested rows; keep dtype flexible (labels may be int or str)
    df = pd.read_csv(VAL_CSV, nrows=n_rows, dtype={"body": str, "label": int})

    expected_cols = {"body", "label"}
    actual_cols = set(df.columns)
    if not expected_cols.issubset(actual_cols):
        missing = expected_cols - actual_cols
        extra = actual_cols - expected_cols
        msg = f"Validation CSV columns: {actual_cols}\n"
        if missing:
            msg += f"Missing columns: {missing}\n"
        if extra:
            msg += f"Unexpected columns: {extra}\n"
        raise ValueError(msg)

    # Ensure we really only have n_rows (pd.read_csv nrows is best-effort)
    df = df.head(n_rows)
    return df


def transform_bodies(vectorizer, df):
    """Transform bodies using the already-fitted vectorizer.

    The vectorizer was fit on training bodies only; using it here is safe
    because it preserves the same feature space.

    Parameters
    ----------
    vectorizer : TfidfVectorizer
        Already-fitted TF-IDF vectorizer (from the saved artifacts).
    df : pandas.DataFrame
        Must contain a ``body`` column with email text.

    Returns
    -------
    X : scipy.sparse matrix
        TF-IDF feature matrix for the sample bodies, shape (n_samples, n_features).
    """
    bodies = df["body"].astype(str).tolist()
    X = vectorizer.transform(bodies)  # use the fitted vectorizer
    return X


def check_probabilities(probas):
    """Validate that predicted probability pairs are well-formed.

    Checks
    ------
    * Each row has exactly 2 entries (safe probability, phishing probability).
    * Every probability is finite (no NaN/Inf).
    * Every probability lies in [0, 1].
    * Each pair sums to approximately 1 (allowing for floating rounding).

    Parameters
    ----------
    probas : numpy.ndarray
        Shape (n_samples, 2) or (n_samples,) depending on model output.

    Returns
    -------
    None
        Prints validation results. Raises ValueError if any check fails.
    """
    probas = np.asarray(probas)

    if probas.ndim == 1:
        # If the model returned a single probability per sample (e.g. predict_proba with one column),
        # we treat it as the phishing-class probability and fabricate the safe complement.
        print("  Note: predict_proba returned 1 column per sample; assuming column is P(Phishing=1).")
        safe = 1 - probas
        probas = np.column_stack([safe, probas])

    if probas.shape[1] != 2:
        raise ValueError(f"Expected probability shape (n_samples, 2), got {probas.shape}")

    all_ok = True
    for i, row in enumerate(probas):
        p0, p1 = row[0], row[1]

        # Finite check
        if not np.isfinite(p0) or not np.isfinite(p1):
            raise ValueError(
                f"Sample {i}: non-finite probability detected (NaN or Inf). "
                f"p0={p0}, p1={p1}"
            )

        # Range check
        if not (0.0 <= p0 <= 1.0 and 0.0 <= p1 <= 1.0):
            raise ValueError(
                f"Sample {i}: probability out of [0,1] range. p0={p0}, p1={p1}"
            )

        # Sum-to-one check (within a small tolerance)
        s = p0 + p1
        if not abs(s - 1.0) < 1e-6:
            raise ValueError(
                f"Sample {i}: probability pair does not sum to 1. p0+p1={s:.6f}"
            )

        all_ok = all_ok and True

    if all_ok:
        print(f"  Probability validation passed for all {len(probas)} samples.")
        print("  * All probabilities are finite.")
        print("  * All probabilities are in [0, 1].")
        print("  * Each pair sums to ~1 (within 1e-6 tolerance).")


# ---------------------------------------------------------------------------
# Main verification routine
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("BANTAI Baseline Verification Script")
    print("=" * 60)
    print()

    # --- Load artifacts ---
    try:
        vectorizer, model = load_artifacts()
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    # --- Load a small sample from validation ---
    try:
        val_sample = load_validation_sample(n_rows=5)
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR loading validation sample: {e}")
        sys.exit(1)

    print(f"Loaded {len(val_sample)} row(s) from validation CSV.")
    print(f"Columns: {list(val_sample.columns)}")
    print(f"True labels: {list(val_sample['label'].astype(int).values)}")
    print()

    # --- Transform bodies with the fitted vectorizer ---
    try:
        X_sample = transform_bodies(vectorizer, val_sample)
    except Exception as e:  # noqa: BLE001
        print(f"ERROR transforming bodies: {e}")
        sys.exit(1)

    print(f"TF-IDF matrix shape: {X_sample.shape}")
    print()

    # --- Run predictions ---
    try:
        predicted_labels = model.predict(X_sample)
        predicted_probs = model.predict_proba(X_sample)
    except Exception as e:  # noqa: BLE001
        print(f"ERROR during prediction: {e}")
        sys.exit(1)

    print("Predictions on the 5-sample validation set:")
    print("-" * 50)

    # --- Print per-sample results ---
    for i in range(len(val_sample)):
        true_label = int(val_sample["label"].iloc[i])
        pred_label = int(predicted_labels[i])
        probs = predicted_probs[i]

        # probs is [P(class_0), P(class_1)] = [P(Safe), P(Phishing)]
        p_safe = float(probs[0])
        p_phishing = float(probs[1])

        print(f"Sample {i + 1}:")
        print(f"  True label :   {true_label}  (0=Safe, 1=Phishing)")
        print(f"  Predicted  :   {pred_label}  (0=Safe, 1=Phishing)")
        print(f"  Probabilities: P(Safe)={p_safe:.4f}, P(Phishing)={p_phishing:.4f}")
        print()

    # --- Probability validation ---
    print("Probability validation:")
    try:
        check_probabilities(predicted_probs)
    except ValueError as e:
        print(f"  WARNING: {e}")

    # --- Shape check ---
    print()
    print("Shape check:")
    print(f"  X_sample (TF-IDF features): {X_sample.shape}")
    print(f"  predicted_labels: {len(predicted_labels)} labels")
    print(f"  predicted_proba shape: {predicted_probs.shape}")

    print()
    print("=" * 60)
    print("Verification complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()