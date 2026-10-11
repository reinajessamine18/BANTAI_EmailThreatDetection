#!/usr/bin/env python
"""
explain_one_email.py

Lightweight SHAP prototype for BANTAI: explains the model's output
for a single email from the validation set.

It reuses the existing TF-IDF vectorizer and XGBoost model artifacts
without retraining, and explains one email's phishing-class prediction
in terms of which tokens push the prediction up or down.

This script is READ-ONLY: it does not save plots, modify artifacts,
retrain the model, or install new packages.

NOTE on SHAP value space:
  The SHAP value space (margin vs. probability) depends on the
  explainer configuration.  This script reports whatever space the
  explainer provides and does not mis-label raw contributions as
  probability percentages.
"""

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# -------- SHAP import with graceful fallback ----------
try:
    import shap
except ImportError:
    sys.stderr.write(
        "Error: the 'shap' package is not installed. "
        "Install it with: pip install shap\n"
    )
    sys.exit(1)
# ----------------------------------------------------

# -------- Project paths (relative to this script) --------
SCRIPT_DIR = Path(__file__).parent              # machine-learning/

ARTIFACTS_DIR = SCRIPT_DIR / "artifacts" / "baseline"
VECTORIZER_PATH = ARTIFACTS_DIR / "tfidf_vectorizer.pkl"
MODEL_PATH = ARTIFACTS_DIR / "xgboost_model.pkl"

VAL_CSV = SCRIPT_DIR / "data" / "processed" / "validation.csv"

# ---------------------------------------------------------------------------
# Helper: load the saved vectorizer and model
# ---------------------------------------------------------------------------
def load_artifacts():
    """Load the fitted TF-IDF vectorizer and the trained XGBoost model."""

    if not VECTORIZER_PATH.is_file():
        raise FileNotFoundError(
            f"Vectorizer not found: {VECTORIZER_PATH}. "
            "Run train_baseline.py first to generate the artifacts."
        )
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}. "
            "Run train_baseline.py first to generate the artifacts."
        )

    print(f"Loading vectorizer from: {VECTORIZER_PATH}")
    vectorizer = joblib.load(VECTORIZER_PATH)

    print(f"Loading model from: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)

    return vectorizer, model


# ---------------------------------------------------------------------------
# Helper: read exactly one validation email
# ---------------------------------------------------------------------------
def load_one_validation_email():
    """Read the first validation row with label 0 (Safe).

    Returns
    -------
    df : pandas.DataFrame
        Exactly one row with columns ``body`` and ``label``.
    """
    if not VAL_CSV.is_file():
        raise FileNotFoundError(
            f"Validation CSV not found: {VAL_CSV}. "
            "Run prepare_dataset.py first."
        )

    # Scan CSV in bounded chunks to find the first label-0 (Safe) row.
    # Using chunksize limits memory use on the 8 GB RAM laptop;
    # we stop as soon as we encounter the first matching row.
    chunk_size = 10_000
    df = None
    for chunk in pd.read_csv(VAL_CSV, chunksize=chunk_size, dtype={"body": str, "label": int}):
        label0_mask = chunk["label"] == 0
        if label0_mask.any():
            matching_positions = np.flatnonzero(label0_mask.to_numpy())

            if matching_positions.size:
                df = chunk.iloc[[matching_positions[0]]]
                break

    if df is None:
        raise ValueError(
            f"No email with label=0 (Safe) found in validation CSV: {VAL_CSV}. "
            "All rows have label=1 (Phishing)."
        )

    # Validate expected columns cleanly.
    expected_cols = {"body", "label"}
    actual_cols = set(df.columns)
    if not expected_cols.issubset(actual_cols):
        missing = expected_cols - actual_cols
        extra = actual_cols - expected_cols
        raise ValueError(
            f"Validation CSV columns: {actual_cols}\n"
            f"Missing expected columns: {missing}\n"
            f"Unexpected extra columns: {extra}"
        )

    # Guarantee exactly one row (head-1 safety), preserving DataFrame type.
    df = df.head(1).reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# SHAP explanation engine
# ---------------------------------------------------------------------------
def compute_shap_explanation(model, X):
    """Compute SHAP values for one email and return (base_value, shap_1, output_space).

    Contributions are for the phishing class only when the returned shape
    makes that interpretation clear.
    """
    try:
        explainer = shap.TreeExplainer(model)
    except Exception as e:  # noqa: BLE001
        print(f"WARNING: could not create TreeExplainer: {e}")
        return None, None, "not verified"

    try:
        shap_values = explainer.shap_values(X)
    except Exception as e:  # noqa: BLE001
        print(f"WARNING: could not compute SHAP values: {e}")
        return None, None, "not verified"

    # -----------------------------------------------------------------
    # Report the configured output space, not a guess based on output indices.
    # -----------------------------------------------------------------
    model_output = getattr(explainer, "model_output", None)
    if model_output == "raw":
        output_space = "raw model output (binary XGBoost margin/log-odds)"
    elif model_output == "probability":
        output_space = "probability output"
    elif model_output == "log_loss":
        output_space = "log-loss output"
    else:
        output_space = "not verified"

    expected_value = np.asarray(explainer.expected_value)

    # -----------------------------------------------------------------
    # Handle SHAP's list-style multi-output return before converting the values.
    # -----------------------------------------------------------------
    if isinstance(shap_values, list):
        if len(shap_values) != 2:
            raise ValueError(
                f"Expected two SHAP outputs for binary classification; got {len(shap_values)}."
            )
        shap_arr = np.asarray(shap_values[1])
        if expected_value.ndim == 1 and expected_value.size == 2:
            base_value = float(expected_value[1])
        elif expected_value.ndim == 0 or expected_value.size == 1:
            base_value = float(expected_value.reshape(-1)[0])
        else:
            raise ValueError(
                f"Cannot safely select class-1 expected value from shape {expected_value.shape}."
            )
    else:
        shap_arr = np.asarray(shap_values)
        if expected_value.ndim == 0:
            base_value = float(expected_value.item())
        elif expected_value.ndim == 1 and expected_value.size == 1:
            base_value = float(expected_value[0])
        elif expected_value.ndim == 1 and expected_value.size == 2:
            if shap_arr.ndim == 3 and shap_arr.shape[2] == 2:
                base_value = float(expected_value[1])
            else:
                raise ValueError(
                    "Expected value has two class entries, but SHAP output does not "
                    "unambiguously identify class 1."
                )
        else:
            raise ValueError(f"Unsupported expected_value shape: {expected_value.shape}")

    # -----------------------------------------------------------------
    # Supported output layouts for one sample.
    # -----------------------------------------------------------------
    if shap_arr.ndim == 2:
        if shap_arr.shape[0] != 1:
            raise ValueError(f"Expected one sample; got SHAP shape {shap_arr.shape}.")
        shap_1 = shap_arr[0, :].copy()
    elif shap_arr.ndim == 3:
        if shap_arr.shape[0] != 1 or shap_arr.shape[2] != 2:
            raise ValueError(
                f"Ambiguous 3D SHAP shape {shap_arr.shape}; expected (1, n_features, 2)."
            )
        shap_1 = shap_arr[0, :, 1].copy()
    elif shap_arr.ndim == 1:
        shap_1 = shap_arr.copy()
    else:
        raise ValueError(f"Unsupported SHAP shape: {shap_arr.shape}.")

    if shap_1.ndim != 1 or shap_1.shape[0] != X.shape[1]:
        raise ValueError(
            f"SHAP feature-count mismatch: vector shape {shap_1.shape}; "
            f"input has {X.shape[1]} features."
        )

    return base_value, shap_1, output_space


# ---------------------------------------------------------------------------
# Main explanation routine
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("BANTAI - Explain one email's phishing classification")
    print("=" * 60)
    print()

    # --- Load artifacts ---
    try:
        vectorizer, model = load_artifacts()
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    # --- Load one validation email ---
    try:
        val_one = load_one_validation_email()
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR loading validation email: {e}")
        sys.exit(1)

    email_body = val_one["body"].iloc[0]
    true_label = int(val_one["label"].iloc[0])          # 0 = Safe, 1 = Phishing

    # --- Transform email body with fitted TF-IDF vectorizer ---
    X = vectorizer.transform([email_body])  # sparse matrix (1, n_features)
    X_dense = X.toarray()[0]  # dense row for present-feature filter (display only)

    # --- Predict label and probabilities ---
    predicted_label = int(model.predict(X)[0])          # 0 = Safe, 1 = Phishing
    probabilities = model.predict_proba(X)[0]           # shape (2,): [P(Safe), P(Phishing)]
    p_safe = float(probabilities[0])
    p_phishing = float(probabilities[1])

    # --- SHAP explanation ---
    # We will compute SHAP values and safely extract the base value and
    # class-1 contributions.  The space (margin/log-odds vs. probability)
    # is determined by the explainer; we report whatever we obtain and
    # explicitly disclaim conversion to probability percentages.
    try:
        base_value, shap_1, output_space = compute_shap_explanation(model, X)
    except ValueError as e:
        print(f"WARNING: SHAP explanation rejected: {e}")
        base_value, shap_1, output_space = None, None, "not verified"

    # -----------------------------------------------------------------
    # Print results: SHAP token contributions (present-feature filter)
    # -----------------------------------------------------------------
    print(f"True label    : {true_label}   (0 = Safe, 1 = Phishing)")
    print(f"Predicted     : {predicted_label}   (0 = Safe, 1 = Phishing)")
    print(f"Probabilities : P(Safe)={p_safe:.4f},  P(Phishing)={p_phishing:.4f}")
    print(f"SHAP base value: {base_value:.4f}" if base_value is not None else "SHAP base value: unavailable")
    print()

    if base_value is not None and shap_1 is not None:
        # --- Map TF-IDF feature indices to vocabulary words ---
        vocab = vectorizer.vocabulary_  # dict: word -> index (0-based)
        # Build reverse map: index -> word (only for words in the vocabulary)
        index_to_word = {}
        for word, idx in vocab.items():
            if idx not in index_to_word:
                index_to_word[idx] = word

        # Collect (contribution, word) pairs where contribution != 0
        # and the feature has nonzero TF-IDF in this email (present-feature filter).
        # This is a presentation rule only; the complete shap_1 vector is used
        # for the numerical consistency check below.
        contributions = []
        for idx, contrib in enumerate(shap_1):
            if abs(contrib) > 0 and idx in index_to_word and X_dense[idx] != 0:
                contributions.append((float(contrib), index_to_word[idx]))

        # Sort: positive contributions push toward Phishing, negative toward Safe
        positive = sorted([(c, w) for c, w in contributions if c > 0], key=lambda x: x[0], reverse=True)[:10]
        negative = sorted([(c, w) for c, w in contributions if c < 0], key=lambda x: x[0])[:10]  # most negative first

        print("SHAP token contributions for class Phishing:")
        print("  (A positive value means the token pushes the prediction toward Phishing;")
        print("   a negative value means it pushes toward Safe.)")
        print()

        if positive:
            print("Top 10 positive contributions (toward Phishing):")
            for rank, (contrib, word) in enumerate(positive, start=1):
                print(f"  {rank:2d}.  {word:30s}  {contrib: .6f}")
        else:
            print("  No positive SHAP contributions found.")

        if negative:
            print("Top 10 negative contributions (toward Safe):")
            for rank, (contrib, word) in enumerate(negative, start=1):
                print(f"  {rank:2d}.  {word:30s}  {contrib: .6f}")
        else:
            print("  No negative SHAP contributions found.")

        print()
        # -----------------------------------------------------------------
        # Numerical consistency check: only when output_space is verified as raw model output.
        # -----------------------------------------------------------------
        if output_space == "raw model output (binary XGBoost margin/log-odds)":
            # Try the project's XGBoost model API to obtain the raw margin directly.
            try:
                raw_margin = float(model.predict(X, output_margin=True)[0])
            except Exception as e:  # noqa: BLE001
                print(f"Diagnostic: {type(e).__name__}: {e}")
                print()
                print("Numerical consistency check:")
                print("  Skipped: could not obtain raw margin from model.predict(X, output_margin=True).")
                print(f"  SHAP base value: {base_value:.4f}")
                print(f"  SHAP sum (base + sum(shap)): {base_value + np.sum(shap_1):.4f}")
                print()
            else:
                # Compare base_value + sum(shap_1) vs. direct raw margin
                shap_consistency = base_value + np.sum(shap_1)
                residual = abs(raw_margin - shap_consistency)

                if not np.isfinite(residual):
                    # Residual is not finite (NaN/Inf)
                    print()
                    print("Numerical consistency check:")
                    print(f"  raw margin:           {raw_margin:.8e}")
                    print(f"  base_value + sum(SHAP) = {shap_consistency:.8e}")
                    print("  residual: NOT FINITE")
                    print("  (Check could not be evaluated: residual is not finite.)")
                elif residual <= 1e-5:
                    # PASSED: values agree within tolerance
                    print()
                    print("Numerical consistency check:")
                    print(f"  raw margin:           {raw_margin:.8e}")
                    print(f"  base_value + sum(SHAP) = {shap_consistency:.8e}")
                    print(f"  residual (|difference|) = {residual:.8e}")
                    print("  PASSED: values agree within tolerance of 1e-5.")
                else:
                    # FAILED: values do not agree within tolerance
                    print()
                    print("Numerical consistency check:")
                    print(f"  raw margin:           {raw_margin:.8e}")
                    print(f"  base_value + sum(SHAP) = {shap_consistency:.8e}")
                    print(f"  residual (|difference|) = {residual:.8e}")
                    print("  FAILED: values do not agree within tolerance of 1e-5.")
        else:
            # output_space is not verified as raw model output; skip comparison
            print()
            print("Numerical consistency check skipped:")
            print(f"  SHAP output space is '{output_space}'; not verified as raw model output.")
            print("  Skipping comparison between SHAP sum and model margin.")
            print(f"  SHAP base value: {base_value:.4f}")
            print(f"  SHAP sum (base + sum(shap)): {base_value + np.sum(shap_1):.4f}")

        print()
        print(f"SHAP output space: {output_space}.")
        if output_space == "not verified":
            print("Important: SHAP output space could not be verified; do not interpret contributions as probability percentages.")
        elif output_space == "probability output":
            print("Important: SHAP contributions are in probability output space; individual contributions are not percentages by themselves.")
        else:
            print("Important: SHAP contributions are not probabilities and do not add up to 100%.")
            print("Use model.predict_proba() values above for probability interpretations.")
    else:
        print("SHAP explanation could not be fully computed (see warnings above).")
        print("The base value and SHAP contributions are printed as-is "
              "without conversion to probability percentages.")

    print()
    print("=" * 60)
    print("End of explanation for one email.")
    print("=" * 60)


if __name__ == "__main__":
    main()
