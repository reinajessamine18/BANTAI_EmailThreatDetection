#!/usr/bin/env python
"""
test_baseline_inference.py

Dependency-free assertion tests for
``machine-learning/src/models/baseline_inference.py``.

It uses a few validation examples (never the held-out test set), one at a
time, and does not modify artifacts or datasets. It never prints email body
text. If the local artifacts or the validation CSV are missing, it reports
that the tests were skipped rather than failing.

Usage (from the repository root):
    machine-learning\\.venv\\Scripts\\python.exe machine-learning\\tests\\test_baseline_inference.py
"""

import sys
from pathlib import Path

import numpy as np

# Make ``machine-learning/`` importable so ``src.models.baseline_inference``
# and the existing prototype script can be imported.
ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.models import baseline_inference as bi  # noqa: E402, RUF100

ARTIFACTS_DIR = ML_DIR / "artifacts" / "baseline"
VALIDATION_CSV = ML_DIR / "data" / "processed" / "validation.csv"

RESULTS = []


class SkipTest(Exception):
    """Raised when a test cannot run in the current environment."""


def run(name, fn):
    """Run one test function and record PASS / FAIL / ERROR / SKIP."""
    try:
        fn()
    except SkipTest as exc:
        RESULTS.append(("SKIP", name, str(exc)))
    except AssertionError as exc:
        RESULTS.append(("FAIL", name, str(exc) or "assertion failed"))
    except Exception as exc:  # noqa: BLE001
        RESULTS.append(("ERROR", name, f"{type(exc).__name__}: {exc}"))
    else:
        RESULTS.append(("PASS", name, ""))


def artifacts_present():
    return all(
        (ARTIFACTS_DIR / name).is_file()
        for name in (bi.VECTORIZER_FILENAME, bi.MODEL_FILENAME)
    )


def load_validation_rows():
    """Read the first two validation rows (body + label); never printed."""
    import pandas as pd

    if not VALIDATION_CSV.is_file():
        raise SkipTest(f"validation CSV not found: {VALIDATION_CSV}")
    df = pd.read_csv(
        VALIDATION_CSV,
        usecols=["body", "label"],
        dtype={"body": str, "label": int},
        nrows=2,
    )
    if len(df) < 2:
        raise SkipTest("validation CSV has fewer than two rows")
    return df


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_phishing_example():
    df = load_validation_rows()
    body = df["body"].iloc[0]
    assert int(df["label"].iloc[0]) == 1, "row 0 is expected to be Phishing (label 1)"

    result = bi.predict_email(body, top_k=10)

    assert result.label == 1, f"expected label 1, got {result.label}"
    assert result.classification == "Phishing"
    assert abs(result.phishing_probability - 0.9930) < 1e-3, (
        f"phishing_probability {result.phishing_probability} differs from 0.9930"
    )
    assert result.shap_output_space == bi.OUTPUT_SPACE_RAW
    assert result.additivity_residual <= bi.ADDITIVITY_TOLERANCE, (
        f"residual {result.additivity_residual} exceeds {bi.ADDITIVITY_TOLERANCE}"
    )


def test_safe_example():
    df = load_validation_rows()
    body = df["body"].iloc[1]
    assert int(df["label"].iloc[1]) == 0, "row 1 is expected to be Safe (label 0)"

    result = bi.predict_email(body, top_k=10)

    assert result.label == 0, f"expected label 0, got {result.label}"
    assert result.classification == "Safe"
    assert abs(result.phishing_probability - 0.0204) < 1e-3, (
        f"phishing_probability {result.phishing_probability} differs from 0.0204"
    )
    assert result.additivity_residual <= bi.ADDITIVITY_TOLERANCE


def test_probabilities_sum_to_one():
    df = load_validation_rows()
    result = bi.predict_email(df["body"].iloc[0], top_k=5)
    assert 0.0 <= result.safe_probability <= 1.0
    assert 0.0 <= result.phishing_probability <= 1.0
    total = result.safe_probability + result.phishing_probability
    assert abs(total - 1.0) < 1e-6, f"probabilities sum to {total}, not ~1"


def test_top_contributions_shape_and_order():
    df = load_validation_rows()
    result = bi.predict_email(df["body"].iloc[0], top_k=5)

    assert isinstance(result.top_contributions, tuple)
    assert 1 <= len(result.top_contributions) <= 5

    values = [abs(c.contribution) for c in result.top_contributions]
    assert values == sorted(values, reverse=True), "contributions not sorted by |value|"

    for c in result.top_contributions:
        assert isinstance(c.token, str) and c.token
        assert c.contribution != 0.0
        expected_direction = (
            "toward_phishing" if c.contribution > 0 else "toward_safe"
        )
        assert c.direction == expected_direction


def test_contributions_are_present_features():
    df = load_validation_rows()
    body = df["body"].iloc[0]
    result = bi.predict_email(body, top_k=10)

    predictor = bi.get_predictor()
    X = predictor.vectorizer.transform([body])
    present = set(X.indices.tolist())
    vocab = predictor.vectorizer.vocabulary_

    for c in result.top_contributions:
        assert vocab.get(c.token) in present, (
            f"token {c.token!r} is not a present feature in this email"
        )


def test_predictor_is_cached():
    assert bi.get_predictor() is bi.get_predictor(), (
        "get_predictor() should return the same cached instance"
    )


def test_input_validation():
    for bad_body in ("", "   \n\t "):
        try:
            bi.predict_email(bad_body)
        except ValueError:
            pass
        else:
            raise AssertionError("empty/whitespace body should raise ValueError")

    try:
        bi.predict_email(None)
    except TypeError:
        pass
    else:
        raise AssertionError("non-string body should raise TypeError")


def test_max_body_length_guard():
    sentinel = "UNIQUE_BODY_MARKER_12345"
    too_long = sentinel + ("x" * bi.MAX_BODY_CHARS)  # exceeds the limit
    try:
        bi.predict_email(too_long)
    except ValueError as exc:
        assert sentinel not in str(exc), "error message must not include body text"
    else:
        raise AssertionError("over-long body should raise ValueError (no truncation)")


def test_matches_existing_prototype():
    try:
        import explain_one_email as prototype
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise SkipTest(f"prototype not importable: {exc}")

    df = load_validation_rows()
    body = df["body"].iloc[0]

    vectorizer, model = prototype.load_artifacts()
    X = vectorizer.transform([body])
    proto_base, proto_shap, proto_space = prototype.compute_shap_explanation(model, X)
    if proto_base is None or proto_shap is None:
        raise SkipTest("prototype SHAP values unavailable in this environment")

    raw_margin = float(model.predict(X, output_margin=True)[0])
    proto_residual = abs(raw_margin - (proto_base + float(np.sum(proto_shap))))

    result = bi.predict_email(body, top_k=10)

    assert result.shap_output_space == proto_space, "output space differs from prototype"
    assert abs(result.shap_base_value - proto_base) < 1e-9, "SHAP base value differs"
    assert abs(result.raw_margin - raw_margin) < 1e-9, "raw margin differs"
    assert abs(result.additivity_residual - proto_residual) < 1e-9, "residual differs"

    classes = np.asarray(model.classes_).tolist()
    positive_col = classes.index(bi.POSITIVE_LABEL)
    probabilities = model.predict_proba(X)[0]
    assert abs(result.phishing_probability - float(probabilities[positive_col])) < 1e-12
    assert abs(result.safe_probability - float(probabilities[1 - positive_col])) < 1e-12


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def main():
    print("=" * 66)
    print("BANTAI baseline inference - dependency-free tests")
    print("=" * 66)

    if not artifacts_present():
        print("SKIPPED: baseline artifacts not found under:")
        print(f"  {ARTIFACTS_DIR}")
        print("No tests were executed (this is not a failure).")
        return 0

    run("row 0 (Phishing): label, probability, output space, residual",
        test_phishing_example)
    run("row 1 (Safe): label, probability, residual", test_safe_example)
    run("probabilities are valid and sum to ~1", test_probabilities_sum_to_one)
    run("top contributions: schema, order, direction",
        test_top_contributions_shape_and_order)
    run("contributions are present features",
        test_contributions_are_present_features)
    run("predictor is cached (single instance)", test_predictor_is_cached)
    run("input validation (empty / whitespace / non-string)", test_input_validation)
    run("MAX_BODY_CHARS guard, no body leakage in errors",
        test_max_body_length_guard)
    run("matches existing explain_one_email prototype (row 0)",
        test_matches_existing_prototype)

    print("-" * 66)
    for status, name, detail in RESULTS:
        line = f"{status:5}  {name}"
        if detail:
            line += f"  [{detail}]"
        print(line)

    counts = {}
    for status, _, _ in RESULTS:
        counts[status] = counts.get(status, 0) + 1
    print("-" * 66)
    print("summary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    failed = counts.get("FAIL", 0) + counts.get("ERROR", 0)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
