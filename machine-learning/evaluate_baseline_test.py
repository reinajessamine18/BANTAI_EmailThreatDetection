#!/usr/bin/env python
"""
evaluate_baseline_test.py

Held-out test evaluation of the existing BANTAI TF-IDF + XGBoost baseline on
the prepared test split, using the saved artifacts.

This script ONLY evaluates. It does not train, retrain, tune, or overwrite the
vectorizer, the model, the datasets, or the existing experiment configuration.
It reads the test CSV in batches to keep memory use low on an 8 GB RAM laptop,
and it never prints email bodies or other sensitive email content.

Usage (from the project root):
    machine-learning\\.venv\\Scripts\\python.exe machine-learning\\evaluate_baseline_test.py
"""

import sys
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ML_DIR = Path(__file__).parent  # ...\BANTAI_EmailThreatDetection\machine-learning

ARTIFACTS_DIR = ML_DIR / "artifacts" / "baseline"
VECTORIZER_PATH = ARTIFACTS_DIR / "tfidf_vectorizer.pkl"
MODEL_PATH = ARTIFACTS_DIR / "xgboost_model.pkl"

TEST_CSV = ML_DIR / "data" / "processed" / "test.csv"
REPORT_PATH = ML_DIR / "reports" / "baseline_test_evaluation.md"

# Rows processed per batch. Smaller = less RAM per batch; larger = fewer loop
# iterations. 2000 is a safe default for an 8 GB RAM laptop.
BATCH_SIZE = 2_000

# Project label convention: 0 = Safe, 1 = Phishing.
NEGATIVE_LABEL = 0
POSITIVE_LABEL = 1

EXPECTED_COLUMNS = ["body", "label"]
PROBABILITY_SUM_TOLERANCE = 1e-5  # each row's (p0 + p1) should be ~1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_artifacts():
    """Load the saved TF-IDF vectorizer and XGBoost model (read-only).

    Returns
    -------
    (vectorizer, model)
    """
    if not VECTORIZER_PATH.is_file():
        raise FileNotFoundError(
            f"Vectorizer not found: {VECTORIZER_PATH}. "
            "Run train_baseline.py to generate the baseline artifacts."
        )
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}. "
            "Run train_baseline.py to generate the baseline artifacts."
        )

    print(f"Loading vectorizer: {VECTORIZER_PATH}")
    vectorizer = joblib.load(VECTORIZER_PATH)

    print(f"Loading model:      {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)

    return vectorizer, model


def resolve_positive_column(model):
    """Return the predict_proba column index for the phishing class (label 1).

    We never assume the column order. scikit-learn/XGBoost store the class
    order in ``model.classes_``; we look up where label 1 actually is.
    """
    classes = np.asarray(model.classes_)

    if POSITIVE_LABEL not in classes:
        raise ValueError(
            f"The model does not contain the phishing class ({POSITIVE_LABEL}). "
            f"model.classes_ = {classes.tolist()}"
        )

    positive_col = int(np.where(classes == POSITIVE_LABEL)[0][0])
    return classes, positive_col


def validate_test_csv():
    """Check the test CSV header before the main loop (fail fast)."""
    if not TEST_CSV.is_file():
        raise FileNotFoundError(
            f"Test CSV not found: {TEST_CSV}. Run prepare_dataset.py first."
        )

    header = pd.read_csv(TEST_CSV, nrows=0)
    if list(header.columns) != EXPECTED_COLUMNS:
        raise ValueError(
            f"Test CSV columns are {list(header.columns)}; "
            f"expected {EXPECTED_COLUMNS}."
        )


def evaluate_in_batches(vectorizer, model, positive_col):
    """Score the test set batch by batch and return aggregated arrays + checks.

    Returns a dictionary with:
        y_true, y_pred, y_prob : numpy arrays over all scored rows
        n_rows                 : number of scored rows
        n_non_finite           : count of non-finite probability values
        n_out_of_range         : count of probability values outside [0, 1]
        n_bad_sum              : count of rows whose probabilities do not sum to ~1
        labels_seen            : set of true labels encountered
    """
    y_true_parts = []
    y_pred_parts = []
    y_prob_parts = []

    n_rows = 0
    n_non_finite = 0
    n_out_of_range = 0
    n_bad_sum = 0
    labels_seen = set()

    n_classes = len(np.asarray(model.classes_))

    reader = pd.read_csv(
        TEST_CSV,
        usecols=EXPECTED_COLUMNS,
        dtype={"body": str, "label": int},
        chunksize=BATCH_SIZE,
    )

    for batch_index, chunk in enumerate(reader, start=1):
        # Transform with the *fitted* vectorizer only (no refit, no leakage).
        texts = chunk["body"].astype(str).tolist()
        X_batch = vectorizer.transform(texts)
        y_pred = model.predict(X_batch)

        if np.asarray(y_pred).ndim != 1 or len(y_pred) != len(chunk):
            raise ValueError(
                f"predict returned an unexpected shape for a batch of {len(chunk)} rows."
            )

        proba = np.asarray(model.predict_proba(X_batch))

        # --- shape validation ---
        if proba.ndim != 2:
            raise ValueError(f"Unexpected predict_proba shape: {proba.shape}")
        if proba.shape[1] != n_classes:
            raise ValueError(
                f"predict_proba returned {proba.shape[1]} columns but the model "
                f"declares {n_classes} classes."
            )
        if proba.shape[0] != len(chunk):
            raise ValueError(
                f"predict_proba returned {proba.shape[0]} rows for a batch of "
                f"{len(chunk)} rows."
            )

        # --- probability integrity checks (aggregated for the whole set) ----
        n_non_finite += int((~np.isfinite(proba)).sum())
        n_out_of_range += int(((proba < 0.0) | (proba > 1.0)).sum())
        n_bad_sum += int(
            (np.abs(proba.sum(axis=1) - 1.0) > PROBABILITY_SUM_TOLERANCE).sum()
        )
        if not np.isin(y_pred, [NEGATIVE_LABEL, POSITIVE_LABEL]).all():
            raise ValueError("predict returned unexpected class labels.")

        y_true_parts.append(chunk["label"].to_numpy())
        y_pred_parts.append(np.asarray(y_pred).astype(int))
        y_prob_parts.append(proba[:, positive_col].astype(float))

        labels_seen.update(np.unique(chunk["label"].to_numpy()).tolist())
        n_rows += len(chunk)

        print(f"  batch {batch_index:>3}: scored {len(chunk):,} rows (total {n_rows:,})")

    if not y_true_parts:
        raise ValueError("The test CSV produced no batches to score.")

    return {
        "y_true": np.concatenate(y_true_parts),
        "y_pred": np.concatenate(y_pred_parts),
        "y_prob": np.concatenate(y_prob_parts),
        "n_rows": n_rows,
        "n_non_finite": n_non_finite,
        "n_out_of_range": n_out_of_range,
        "n_bad_sum": n_bad_sum,
        "labels_seen": labels_seen,
    }


def compute_metrics(y_true, y_pred, y_prob):
    """Compute test metrics and record any undefined cases.

    Returns
    -------
    (metrics, warnings)
        metrics : dict of metric name -> float or None
        warnings : list of human-readable notes about undefined metrics
    """
    warnings = []
    metrics = {}

    unique_true = np.unique(y_true)
    unique_pred = np.unique(y_pred)

    n_true_pos = int((y_true == POSITIVE_LABEL).sum())
    n_pred_pos = int((y_pred == POSITIVE_LABEL).sum())

    metrics["accuracy"] = float(accuracy_score(y_true, y_pred))

    # Precision/recall/F1 for the phishing class. zero_division=0 keeps the
    # computation defined; we report the undefined cases explicitly below.
    metrics["precision"] = float(
        precision_score(y_true, y_pred, pos_label=POSITIVE_LABEL, zero_division=0)
    )
    metrics["recall"] = float(
        recall_score(y_true, y_pred, pos_label=POSITIVE_LABEL, zero_division=0)
    )
    metrics["f1_score"] = float(
        f1_score(y_true, y_pred, pos_label=POSITIVE_LABEL, zero_division=0)
    )

    if n_pred_pos == 0:
        warnings.append(
            "Precision is undefined (no rows were predicted as phishing); "
            "reported as 0.0."
        )
    if n_true_pos == 0:
        warnings.append(
            "Recall is undefined (the test set contains no phishing rows); "
            "reported as 0.0."
        )

    # ROC-AUC requires both classes to be present in the true labels.
    if unique_true.size == 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_prob))
    else:
        metrics["roc_auc"] = None
        warnings.append(
            "ROC-AUC is undefined because only one true class is present: "
            f"{unique_true.tolist()}."
        )

    metrics["confusion_matrix"] = confusion_matrix(
        y_true, y_pred, labels=[NEGATIVE_LABEL, POSITIVE_LABEL]
    ).tolist()

    if not set(unique_true.tolist()).issubset({NEGATIVE_LABEL, POSITIVE_LABEL}):
        warnings.append(f"Unexpected true labels found: {unique_true.tolist()}.")
    if not set(unique_pred.tolist()).issubset({NEGATIVE_LABEL, POSITIVE_LABEL}):
        warnings.append(f"Unexpected predicted labels found: {unique_pred.tolist()}.")

    return metrics, warnings


def _fmt(value):
    """Format a metric value for display; None means 'undefined'."""
    return "undefined" if value is None else f"{value:.4f}"


def build_report(result, metrics, warnings, classes, positive_col):
    """Build the Markdown test-evaluation report as a string."""
    cm = metrics["confusion_matrix"]
    tn, fp = cm[0][0], cm[0][1]
    fn, tp = cm[1][0], cm[1][1]

    lines = []
    lines.append("# Baseline Test-Set Evaluation: TF-IDF + XGBoost")
    lines.append("")
    lines.append(
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')} "
        "by `machine-learning/evaluate_baseline_test.py`"
    )
    lines.append("")
    lines.append(
        "**Project:** BANTAI - XGBoost-Based Email Threat Detection and "
        "Analysis Engine using Explainability Framework"
    )
    lines.append("")
    lines.append(
        "**Scope:** evaluation of the existing `baseline` artifacts on the "
        "prepared held-out test split. No training, tuning, or artifact changes."
    )
    lines.append("")
    lines.append(
        "> Every metric below was produced by an actual run of this script. "
        "No values are estimated or copied from other splits, and no email "
        "body text is printed or stored."
    )
    lines.append("")
    lines.append("## 1. Artifacts and inputs")
    lines.append("")
    lines.append("| Item | Value |")
    lines.append("|---|---|")
    lines.append(f"| Vectorizer artifact | `{VECTORIZER_PATH}` |")
    lines.append(f"| Model artifact | `{MODEL_PATH}` |")
    lines.append(f"| Model class order (`model.classes_`) | `{classes.tolist()}` |")
    lines.append(f"| P(Phishing) probability column used | index {positive_col} |")
    lines.append(f"| Test CSV | `{TEST_CSV}` |")
    lines.append(f"| Test rows scored | {result['n_rows']:,} |")
    lines.append(f"| Batch size used | {BATCH_SIZE:,} |")
    lines.append("")
    lines.append("## 2. Test-set metrics (positive class = Phishing, label 1)")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Accuracy | {_fmt(metrics['accuracy'])} |")
    lines.append(f"| Precision (Phishing) | {_fmt(metrics['precision'])} |")
    lines.append(f"| Recall (Phishing) | {_fmt(metrics['recall'])} |")
    lines.append(f"| F1-score (Phishing) | {_fmt(metrics['f1_score'])} |")
    lines.append(f"| ROC-AUC | {_fmt(metrics['roc_auc'])} |")
    lines.append("")
    lines.append(
        "**These are test metrics** from the held-out split. They are separate "
        "from the validation metrics in `baseline_experiment_report.md` and do "
        "not replace them."
    )
    lines.append("")
    lines.append("## 3. Confusion matrix")
    lines.append("")
    lines.append("| | Predicted Safe | Predicted Phishing |")
    lines.append("|---|---|---|")
    lines.append(f"| **True Safe** | {tn:,} | {fp:,} |")
    lines.append(f"| **True Phishing** | {fn:,} | {tp:,} |")
    lines.append("")
    lines.append(
        f"Derived counts: false positives = {fp:,}; false negatives = {fn:,}. "
        "(Rows = true label; columns = predicted label.)"
    )
    lines.append("")
    lines.append("## 4. Probability and class-order checks")
    lines.append("")
    lines.append("| Check | Result |")
    lines.append("|---|---|")
    lines.append(f"| Non-finite probability values | {result['n_non_finite']} |")
    lines.append(f"| Probability values outside [0, 1] | {result['n_out_of_range']} |")
    lines.append(
        f"| Rows whose probabilities did not sum to ~1 "
        f"(tolerance {PROBABILITY_SUM_TOLERANCE}) | {result['n_bad_sum']} |"
    )
    lines.append(
        f"| Class-order handling | P(Phishing) read from `predict_proba` column "
        f"{positive_col}, based on `model.classes_` |"
    )
    lines.append("")
    lines.append("## 5. Undefined metrics and warnings")
    lines.append("")
    if warnings:
        for warning in warnings:
            lines.append(f"- {warning}")
    else:
        lines.append("- None. All metrics were defined for this run.")
    lines.append("")
    lines.append("## 6. Evaluation limitations")
    lines.append("")
    lines.append(
        "- This is a single fixed baseline; no hyperparameter tuning was "
        "performed, and the test set must not be used for tuning."
    )
    lines.append(
        "- This report evaluates the prepared held-out test split "
        "(`machine-learning/data/processed/test.csv`) using the saved baseline "
        "artifacts."
    )
    lines.append(
        "- Metrics are point estimates; no confidence intervals or "
        "significance tests are reported."
    )
    lines.append("- No inference-time or hardware measurements were recorded.")
    lines.append(
        f"- The test set was scored in batches of {BATCH_SIZE:,} rows to limit "
        "memory use; batching does not change the metrics."
    )
    lines.append(
        "- Dataset origin, version, and license are not documented in the "
        "repository (see the open items in `baseline_experiment_report.md`)."
    )
    lines.append("- This report is generated locally and is not committed automatically.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "*Generated by `machine-learning/evaluate_baseline_test.py`. "
        "Actual results only; no values were fabricated.*"
    )
    lines.append("")
    return "\n".join(lines)


def write_report(report_text):
    """Write the Markdown report (the only file this script creates)."""
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report_text, encoding="utf-8")
    print(f"\nSaved test-evaluation report -> {REPORT_PATH}")


# ---------------------------------------------------------------------------
# Main routine
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("BANTAI - Baseline held-out TEST evaluation")
    print("=" * 60)
    print()

    # Refuse to overwrite a previous test report so results are preserved.
    if REPORT_PATH.exists():
        print(f"ERROR: report already exists: {REPORT_PATH}")
        print("Move or rename it before re-running, so previous results are preserved.")
        sys.exit(1)

    try:
        validate_test_csv()
        vectorizer, model = load_artifacts()
        classes, positive_col = resolve_positive_column(model)
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print(
        f"Model classes: {classes.tolist()} | "
        f"P(Phishing) is predict_proba column {positive_col}"
    )
    print(f"Batch size: {BATCH_SIZE:,}")
    print()

    print("Scoring the test set in batches (no email bodies are printed)...")
    try:
        result = evaluate_in_batches(vectorizer, model, positive_col)
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR during evaluation: {e}")
        sys.exit(1)

    if result["n_rows"] == 0:
        print("ERROR: no rows were scored; check the test CSV.")
        sys.exit(1)

    if not result["labels_seen"].issubset({NEGATIVE_LABEL, POSITIVE_LABEL}):
        print(f"ERROR: unexpected labels in the test set: {sorted(result['labels_seen'])}")
        sys.exit(1)

    # Abort before writing a report if the probabilities are invalid.
    if result["n_non_finite"] or result["n_out_of_range"]:
        print("ERROR: invalid probabilities detected:")
        print(f"  non-finite: {result['n_non_finite']}")
        print(f"  outside [0, 1]: {result['n_out_of_range']}")
        sys.exit(1)

    if result["n_bad_sum"]:
        print(
            f"WARNING: {result['n_bad_sum']} row(s) had probabilities that "
            "did not sum to ~1."
        )

    metrics, warnings = compute_metrics(
        result["y_true"], result["y_pred"], result["y_prob"]
    )

    # --- console summary (counts and metrics only; no email content) ---
    print()
    print("=== Test-set metrics (positive class = Phishing) ===")
    print(f"Rows scored : {result['n_rows']:,}")
    print(f"Accuracy    : {_fmt(metrics['accuracy'])}")
    print(f"Precision   : {_fmt(metrics['precision'])}")
    print(f"Recall      : {_fmt(metrics['recall'])}")
    print(f"F1-score    : {_fmt(metrics['f1_score'])}")
    print(f"ROC-AUC     : {_fmt(metrics['roc_auc'])}")
    print(f"Confusion matrix [[TN, FP], [FN, TP]]: {metrics['confusion_matrix']}")

    if warnings:
        print()
        print("Warnings:")
        for warning in warnings:
            print(f"  - {warning}")

    report_text = build_report(result, metrics, warnings, classes, positive_col)
    write_report(report_text)

    print()
    print("No email bodies were printed or stored.")
    print("No artifacts, datasets, or existing configuration files were modified.")


if __name__ == "__main__":
    main()
