#!/usr/bin/env python
"""
test_baseline_inference_robustness.py

Dependency-free robustness tests for
``machine-learning/src/models/baseline_inference.py``.

Complements (does not duplicate) ``test_baseline_inference.py``. It uses small
synthetic inputs plus the existing local artifacts; it never uses the held-out
test set, never processes the full dataset, and never modifies artifacts,
datasets, or configuration.

Fake-explainer cases build a FRESH ``BaselinePredictor`` around the real
vectorizer/model, so the cached singleton, the model, and the vectorizer are
never mutated.

Failure messages never include email body text. For behavior that is not yet
verified, the tests record an observation instead of forcing an assertion.

Usage (from the repository root):
    machine-learning\\.venv\\Scripts\\python.exe machine-learning\\tests\\test_baseline_inference_robustness.py
"""

import math
import sys
import tempfile
import uuid
from pathlib import Path

import numpy as np

# Make ``machine-learning/`` importable so ``src.models.baseline_inference``
# can be imported (same pattern as the existing test script).
ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.models import baseline_inference as bi  # noqa: E402

ARTIFACTS_DIR = ML_DIR / "artifacts" / "baseline"

RESULTS = []
OBSERVATIONS = []

# Small synthetic inputs. Tokens are chosen from words already observed in the
# fitted vocabulary; the tests never assert which class they are classified as.
BODY_SHORT = "the way you are"
BODY_COMMON = "please and you to not"
BODY_TINY = "the and"
BODY_UNKNOWN_TOKENS = "a b c"  # single characters are dropped by the tokenizer


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


def predictor():
    """Return the cached predictor, or skip when artifacts are unavailable."""
    if not artifacts_present():
        raise SkipTest(f"baseline artifacts not found under {ARTIFACTS_DIR}")
    return bi.get_predictor()


def expect_raises(exc_type, fn, label):
    """Call fn() and require it to raise exc_type; return the exception."""
    try:
        fn()
    except exc_type as exc:
        return exc
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"{label}: expected {exc_type.__name__}, got {type(exc).__name__}"
        )
    raise AssertionError(f"{label}: expected {exc_type.__name__}, nothing raised")


def assert_valid_result(result, tag):
    """Structural / finite-value / probability invariants (no class claims)."""
    assert result.label in (0, 1), f"{tag}: label {result.label} not 0/1"
    assert result.classification in ("Safe", "Phishing"), f"{tag}: bad classification"
    assert 0.0 <= result.safe_probability <= 1.0, f"{tag}: safe prob out of range"
    assert 0.0 <= result.phishing_probability <= 1.0, f"{tag}: phishing prob out of range"
    total = result.safe_probability + result.phishing_probability
    assert abs(total - 1.0) < 1e-6, f"{tag}: probabilities sum to {total}, not ~1"
    assert math.isfinite(result.shap_base_value), f"{tag}: base value not finite"
    assert math.isfinite(result.raw_margin), f"{tag}: raw margin not finite"
    assert math.isfinite(result.additivity_residual), f"{tag}: residual not finite"
    assert result.additivity_residual <= bi.ADDITIVITY_TOLERANCE, (
        f"{tag}: residual {result.additivity_residual} exceeds tolerance"
    )
    assert result.shap_output_space == bi.OUTPUT_SPACE_RAW, f"{tag}: wrong output space"
    assert isinstance(result.top_contributions, tuple), f"{tag}: contributions not a tuple"
    for c in result.top_contributions:
        assert math.isfinite(c.contribution), f"{tag}: non-finite contribution"
        assert math.isfinite(c.tfidf_value), f"{tag}: non-finite tfidf value"
        assert c.direction in ("toward_phishing", "toward_safe"), f"{tag}: bad direction"
        expected = "toward_phishing" if c.contribution > 0 else "toward_safe"
        assert c.direction == expected, f"{tag}: direction/sign mismatch"


def _fresh_predictor_with(explainer):
    """Build a fresh predictor sharing the real artifacts but a fake explainer.

    The cached singleton, the real model, and the real vectorizer are never
    mutated; only this throwaway instance uses the fake explainer.
    """
    real = predictor()
    return bi.BaselinePredictor(
        real.vectorizer,
        real.model,
        explainer,
        real.classes,
        real.positive_col,
        real.negative_col,
    )


# ---------------------------------------------------------------------------
# R1 - valid inputs stay structurally valid (no class-correctness claims)
# ---------------------------------------------------------------------------
def test_r1_valid_inputs_invariants():
    pred = predictor()
    vocab = pred.vectorizer.vocabulary_
    for tag, body in (("B1", BODY_SHORT), ("B2", BODY_COMMON), ("B4", BODY_TINY)):
        result = pred.predict(body, top_k=10)
        assert_valid_result(result, tag)
        for c in result.top_contributions:
            assert c.token in vocab, f"{tag}: token not in vocabulary"


# ---------------------------------------------------------------------------
# R2 - invalid top_k values are rejected before inference
# ---------------------------------------------------------------------------
def test_r2_invalid_top_k():
    pred = predictor()
    for bad in (0, -1, 2.5, "5", None, True):
        expect_raises(
            ValueError,
            lambda b=bad: pred.predict(BODY_SHORT, top_k=b),
            f"top_k={bad!r}",
        )


# ---------------------------------------------------------------------------
# R3 - extreme top_k values respect the cap
# ---------------------------------------------------------------------------
def test_r3_extreme_top_k():
    pred = predictor()
    r_small = pred.predict(BODY_SHORT, top_k=1)
    assert len(r_small.top_contributions) <= 1, "top_k=1 returned more than 1 item"
    assert_valid_result(r_small, "top_k=1")

    r_huge = pred.predict(BODY_SHORT, top_k=10_000)
    assert len(r_huge.top_contributions) <= 10_000, "top_k=10000 exceeded the cap"
    assert_valid_result(r_huge, "top_k=10000")


# ---------------------------------------------------------------------------
# R4 - determinism and no cross-call state leakage
# ---------------------------------------------------------------------------
def test_r4_determinism_and_no_state():
    pred = predictor()
    a = pred.predict(BODY_COMMON, top_k=10)
    b = pred.predict(BODY_COMMON, top_k=10)

    assert a.label == b.label, "repeat call changed label"
    assert a.classification == b.classification, "repeat call changed classification"
    assert abs(a.phishing_probability - b.phishing_probability) <= 1e-12, (
        "repeat call changed phishing probability"
    )
    assert abs(a.raw_margin - b.raw_margin) <= 1e-12, "repeat call changed raw margin"
    assert abs(a.additivity_residual - b.additivity_residual) <= 1e-12
    assert [c.token for c in a.top_contributions] == [c.token for c in b.top_contributions], (
        "repeat call changed contribution tokens"
    )
    for ca, cb in zip(a.top_contributions, b.top_contributions):
        assert abs(ca.contribution - cb.contribution) <= 1e-12, "contribution drifted"

    # A different top_k must not carry over into a later call.
    one = pred.predict(BODY_COMMON, top_k=1)
    assert len(one.top_contributions) <= 1, "top_k=1 not respected"
    ten = pred.predict(BODY_COMMON, top_k=10)
    assert len(ten.top_contributions) <= 10, "top_k=10 not respected"
    if one.top_contributions and ten.top_contributions:
        assert ten.top_contributions[0].token == one.top_contributions[0].token, (
            "top_k=1 and top_k=10 disagree on the top token"
        )


# ---------------------------------------------------------------------------
# R5 - unicode whitespace variants are treated as empty
# ---------------------------------------------------------------------------
def test_r5_unicode_whitespace():
    for label, body in (("NBSP", "\u00a0"), ("em-space", "\u2003"), ("ideographic", "\u3000")):
        expect_raises(ValueError, lambda b=body: bi._validate_body(b), label)


# ---------------------------------------------------------------------------
# R6 - non-string inputs are rejected
# ---------------------------------------------------------------------------
def test_r6_non_string():
    for label, body in (("None", None), ("bytes", b"bytes"), ("list", ["x"]), ("int", 123)):
        expect_raises(TypeError, lambda b=body: bi._validate_body(b), label)


# ---------------------------------------------------------------------------
# R7 - exact body-length boundary (validation only; no large transform)
# ---------------------------------------------------------------------------
def test_r7_length_boundary():
    # Exactly MAX_BODY_CHARS must be accepted.
    bi._validate_body("x" * bi.MAX_BODY_CHARS)
    # One character over must be rejected, with no body text in the message.
    exc = expect_raises(
        ValueError,
        lambda: bi._validate_body("x" * (bi.MAX_BODY_CHARS + 1)),
        "over-limit body",
    )
    assert str(bi.MAX_BODY_CHARS) in str(exc), "error should name the configured limit"


# ---------------------------------------------------------------------------
# R8 - missing artifacts raise FileNotFoundError (real artifacts untouched)
# ---------------------------------------------------------------------------
def test_r8_missing_artifacts():
    missing = Path(tempfile.gettempdir()) / f"bantai_absent_{uuid.uuid4().hex}"
    assert not missing.exists(), "temp path unexpectedly exists"
    expect_raises(
        FileNotFoundError,
        lambda: bi.BaselinePredictor.load(artifacts_dir=missing),
        "missing artifacts",
    )


# ---------------------------------------------------------------------------
# R9-R12 - SHAP failure / verification guards (isolated fake explainers)
# ---------------------------------------------------------------------------
class _ExplainerRaises:
    model_output = "raw"

    def shap_values(self, X):
        raise RuntimeError("synthetic SHAP failure")


class _ExplainerProbabilitySpace:
    model_output = "probability"

    def shap_values(self, X):
        return np.zeros((1, X.shape[1]))


class _ExplainerBadAdditivity:
    model_output = "raw"
    expected_value = 0.0

    def shap_values(self, X):
        # Deliberately far from the real margin so additivity must fail.
        return np.full((1, X.shape[1]), 1000.0)


class _ExplainerTwoSamples:
    model_output = "raw"
    expected_value = 0.0

    def shap_values(self, X):
        return np.zeros((2, X.shape[1]))


def test_r9_shap_raises():
    pred = _fresh_predictor_with(_ExplainerRaises())
    exc = expect_raises(bi.InferenceError, lambda: pred.predict(BODY_SHORT, top_k=5),
                        "shap failure")
    assert "RuntimeError" in str(exc), "guard should name the underlying error type"


def test_r10_output_space_guard():
    pred = _fresh_predictor_with(_ExplainerProbabilitySpace())
    expect_raises(bi.InferenceError, lambda: pred.predict(BODY_SHORT, top_k=5),
                  "non-raw output space")


def test_r11_additivity_guard():
    pred = _fresh_predictor_with(_ExplainerBadAdditivity())
    expect_raises(bi.InferenceError, lambda: pred.predict(BODY_SHORT, top_k=5),
                  "additivity failure")


def test_r12_malformed_shap_shape():
    pred = _fresh_predictor_with(_ExplainerTwoSamples())
    expect_raises(bi.InferenceError, lambda: pred.predict(BODY_SHORT, top_k=5),
                  "malformed SHAP shape")


# ---------------------------------------------------------------------------
# R13 - input with no known tokens: observe behavior, assert only invariants
# ---------------------------------------------------------------------------
def test_r13_no_known_tokens():
    pred = predictor()
    result = pred.predict(BODY_UNKNOWN_TOKENS, top_k=10)
    assert_valid_result(result, "R13")
    OBSERVATIONS.append(
        "R13: input whose tokens are all dropped -> "
        f"{len(result.top_contributions)} contribution(s) observed; "
        "classification/probability returned without error."
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def main():
    print("=" * 66)
    print("BANTAI baseline inference - robustness tests")
    print("=" * 66)

    if not artifacts_present():
        print("SKIPPED: baseline artifacts not found under:")
        print(f"  {ARTIFACTS_DIR}")
        print("No tests were executed (this is not a failure).")
        return 0

    run("R1  valid inputs: structural/finite/probability invariants",
        test_r1_valid_inputs_invariants)
    run("R2  invalid top_k rejected", test_r2_invalid_top_k)
    run("R3  extreme top_k respected", test_r3_extreme_top_k)
    run("R4  determinism / no cross-call state", test_r4_determinism_and_no_state)
    run("R5  unicode whitespace treated as empty", test_r5_unicode_whitespace)
    run("R6  non-string input rejected", test_r6_non_string)
    run("R7  exact body-length boundary (validation only)", test_r7_length_boundary)
    run("R8  missing artifacts raise FileNotFoundError", test_r8_missing_artifacts)
    run("R9  SHAP failure raises", test_r9_shap_raises)
    run("R10 non-raw output space rejected", test_r10_output_space_guard)
    run("R11 additivity failure rejected", test_r11_additivity_guard)
    run("R12 malformed SHAP shape rejected", test_r12_malformed_shap_shape)
    run("R13 no-known-tokens input (invariants only)", test_r13_no_known_tokens)

    print("-" * 66)
    for status, name, detail in RESULTS:
        line = f"{status:5}  {name}"
        if detail:
            line += f"  [{detail}]"
        print(line)

    if OBSERVATIONS:
        print("-" * 66)
        for note in OBSERVATIONS:
            print(f"observed  {note}")

    counts = {}
    for status, _, _ in RESULTS:
        counts[status] = counts.get(status, 0) + 1
    print("-" * 66)
    print("summary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    failed = counts.get("FAIL", 0) + counts.get("ERROR", 0)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
