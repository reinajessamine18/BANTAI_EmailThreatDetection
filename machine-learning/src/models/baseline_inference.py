#!/usr/bin/env python
"""
baseline_inference.py

Reusable inference component for the BANTAI TF-IDF + XGBoost baseline.

It loads the existing saved artifacts READ-ONLY and provides:

* Safe / Phishing classification,
* Safe and Phishing probabilities (probability space),
* SHAP base value, raw margin, and additivity residual,
* top present-feature token contributions (raw-margin / log-odds space).

It never trains, retunes, or writes artifacts, and it never prints, logs, or
returns the email body text. Threat scores, risk tiers, and any
recommendation/action guidance are intentionally OUT OF SCOPE for the ML
component.

The vectorizer, model, and one SHAP TreeExplainer are loaded once and cached
for reuse, so repeated calls do not reload them.

Usage
-----
    from src.models.baseline_inference import predict_email
    result = predict_email("... email body ...")
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import joblib
import numpy as np
import shap

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ML_DIR = Path(__file__).resolve().parents[2]        # machine-learning/
DEFAULT_ARTIFACTS_DIR = ML_DIR / "artifacts" / "modern_baseline"
VECTORIZER_FILENAME = "tfidf_vectorizer.pkl"
MODEL_FILENAME = "xgboost_model.pkl"

# Project label convention: 0 = Safe, 1 = Phishing.
NEGATIVE_LABEL = 0
POSITIVE_LABEL = 1

DEFAULT_TOP_K = 10
ADDITIVITY_TOLERANCE = 1e-5

# Input guard: reject bodies larger than this instead of silently truncating.
MAX_BODY_CHARS = 200_000

OUTPUT_SPACE_RAW = "raw model output (binary XGBoost margin/log-odds)"

__all__ = [
    "ADDITIVITY_TOLERANCE",
    "MAX_BODY_CHARS",
    "OUTPUT_SPACE_RAW",
    "BaselinePredictor",
    "InferenceError",
    "PredictionResult",
    "TokenContribution",
    "get_predictor",
    "predict_email",
    "warm_up",
]


class InferenceError(RuntimeError):
    """Raised when inference cannot be completed or verified."""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TokenContribution:
    """One SHAP token contribution, in raw-margin (log-odds) units."""

    token: str
    contribution: float
    direction: str          # "toward_phishing" or "toward_safe"
    tfidf_value: float


@dataclass(frozen=True)
class PredictionResult:
    """Structured inference result.

    Probability fields are in probability space. SHAP fields and raw_margin
    are in raw-margin (log-odds) space; they are not probabilities.
    """

    label: int
    classification: str
    safe_probability: float
    phishing_probability: float
    shap_output_space: str
    shap_base_value: float
    raw_margin: float
    additivity_residual: float
    top_contributions: tuple[TokenContribution, ...]


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def _validate_body(body: str) -> None:
    """Validate the input without ever exposing the text in error messages."""
    if not isinstance(body, str):
        raise TypeError("email body must be a string")
    if not body.strip():
        raise ValueError("email body is empty after stripping whitespace")
    if len(body) > MAX_BODY_CHARS:
        raise ValueError(
            f"email body length {len(body)} exceeds MAX_BODY_CHARS "
            f"({MAX_BODY_CHARS}); input is not truncated"
        )


# ---------------------------------------------------------------------------
# SHAP extraction (mirrors the verified logic in explain_one_email.py)
# ---------------------------------------------------------------------------
def _extract_class1_shap(explainer, X):
    """Return (base_value, class_1_shap_vector) in verified raw-margin space.

    Mirrors the verified shape/output-space handling of the single-email
    prototype. Raises InferenceError if SHAP fails, if the output space is
    not verified as raw, or if an unsupported shape is returned.
    """
    try:
        shap_values = explainer.shap_values(X)
    except Exception as exc:
        raise InferenceError(
            f"SHAP computation failed: {type(exc).__name__}"
        ) from exc

    model_output = getattr(explainer, "model_output", None)
    if model_output == "raw":
        output_space = OUTPUT_SPACE_RAW
    elif model_output == "probability":
        output_space = "probability output"
    elif model_output == "log_loss":
        output_space = "log-loss output"
    else:
        output_space = "not verified"

    if output_space != OUTPUT_SPACE_RAW:
        raise InferenceError(
            "SHAP output space could not be verified as raw model output; "
            f"reported space: {output_space!r}"
        )

    expected_value = np.asarray(explainer.expected_value)

    if isinstance(shap_values, list):
        if len(shap_values) != 2:
            raise InferenceError(
                "expected two SHAP outputs for binary classification; "
                f"got {len(shap_values)}"
            )
        shap_arr = np.asarray(shap_values[1])
        if expected_value.ndim == 1 and expected_value.size == 2:
            base_value = float(expected_value[1])
        elif expected_value.ndim == 0 or expected_value.size == 1:
            base_value = float(expected_value.reshape(-1)[0])
        else:
            raise InferenceError(
                "cannot safely select the class-1 expected value from "
                f"shape {expected_value.shape}"
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
                raise InferenceError(
                    "expected value has two class entries, but the SHAP output "
                    "does not unambiguously identify class 1"
                )
        else:
            raise InferenceError(
                f"unsupported expected_value shape: {expected_value.shape}"
            )

    if shap_arr.ndim == 2:
        if shap_arr.shape[0] != 1:
            raise InferenceError(
                f"expected one sample; got SHAP shape {shap_arr.shape}"
            )
        shap_1 = shap_arr[0, :].copy()
    elif shap_arr.ndim == 3:
        if shap_arr.shape[0] != 1 or shap_arr.shape[2] != 2:
            raise InferenceError(
                f"ambiguous 3D SHAP shape {shap_arr.shape}; "
                "expected (1, n_features, 2)"
            )
        shap_1 = shap_arr[0, :, 1].copy()
    elif shap_arr.ndim == 1:
        shap_1 = shap_arr.copy()
    else:
        raise InferenceError(f"unsupported SHAP shape: {shap_arr.shape}")

    if shap_1.ndim != 1 or shap_1.shape[0] != X.shape[1]:
        raise InferenceError(
            f"SHAP feature-count mismatch: vector shape {shap_1.shape}; "
            f"input has {X.shape[1]} features"
        )

    return base_value, shap_1


# ---------------------------------------------------------------------------
# Predictor
# ---------------------------------------------------------------------------
class BaselinePredictor:
    """Holds the loaded baseline artifacts and serves single-email predictions."""

    def __init__(self, vectorizer, model, explainer, classes, positive_col, negative_col):
        self.vectorizer = vectorizer
        self.model = model
        self.explainer = explainer
        self.classes = classes
        self.positive_col = positive_col
        self.negative_col = negative_col

    # -- loading ------------------------------------------------------------
    @classmethod
    def load(cls, artifacts_dir: Path | None = None) -> BaselinePredictor:
        """Load the saved artifacts read-only and build the SHAP explainer."""
        artifacts_dir = (
            Path(artifacts_dir) if artifacts_dir is not None else DEFAULT_ARTIFACTS_DIR
        )
        vectorizer_path = artifacts_dir / VECTORIZER_FILENAME
        if not vectorizer_path.is_file() and (artifacts_dir / "vectorizer.pkl").is_file():
            vectorizer_path = artifacts_dir / "vectorizer.pkl"
        model_path = artifacts_dir / MODEL_FILENAME
        if not model_path.is_file() and (artifacts_dir / "xgboost_model.json").is_file():
            model_path = artifacts_dir / "xgboost_model.json"

        if not vectorizer_path.is_file():
            raise FileNotFoundError(f"vectorizer artifact not found: {vectorizer_path}")
        if not model_path.is_file():
            raise FileNotFoundError(f"model artifact not found: {model_path}")

        # Read-only load. No fit/retrain/tune, no artifact writes.
        vectorizer = joblib.load(vectorizer_path)
        if str(model_path).endswith(".json"):
            import xgboost as xgb
            model = xgb.XGBClassifier()
            model.load_model(str(model_path))
        else:
            model = joblib.load(model_path)

        classes = np.asarray(model.classes_)
        if NEGATIVE_LABEL not in classes or POSITIVE_LABEL not in classes:
            raise InferenceError(
                f"model classes must include {NEGATIVE_LABEL} and {POSITIVE_LABEL}; "
                f"got {classes.tolist()}"
            )
        positive_col = int(np.where(classes == POSITIVE_LABEL)[0][0])
        negative_col = int(np.where(classes == NEGATIVE_LABEL)[0][0])

        try:
            explainer = shap.TreeExplainer(model)
        except Exception as exc:
            raise InferenceError(
                f"could not create SHAP TreeExplainer: {type(exc).__name__}"
            ) from exc

        return cls(vectorizer, model, explainer, classes, positive_col, negative_col)

    # -- prediction ---------------------------------------------------------
    def predict(self, body: str, top_k: int = DEFAULT_TOP_K) -> PredictionResult:
        """Classify one email body and explain the phishing-class margin."""
        _validate_body(body)
        if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k < 1:
            raise ValueError("top_k must be a positive integer")

        # Fitted vectorizer only: transform, never fit.
        X = self.vectorizer.transform([body])

        predicted_label = int(self.model.predict(X)[0])
        if predicted_label not in (NEGATIVE_LABEL, POSITIVE_LABEL):
            raise InferenceError(f"unexpected predicted label: {predicted_label}")

        probabilities = self.model.predict_proba(X)[0]
        phishing_probability = float(probabilities[self.positive_col])
        safe_probability = float(probabilities[self.negative_col])

        raw_margin = float(self.model.predict(X, output_margin=True)[0])

        base_value, shap_1 = _extract_class1_shap(self.explainer, X)

        shap_sum = base_value + float(np.sum(shap_1))
        residual = abs(raw_margin - shap_sum)
        if not np.isfinite(residual) or residual > ADDITIVITY_TOLERANCE:
            raise InferenceError(
                "SHAP additivity check failed: residual "
                f"{residual} exceeds tolerance {ADDITIVITY_TOLERANCE}"
            )

        contributions = self._top_contributions(X, shap_1, top_k)

        return PredictionResult(
            label=predicted_label,
            classification=(
                "Phishing" if predicted_label == POSITIVE_LABEL else "Safe"
            ),
            safe_probability=safe_probability,
            phishing_probability=phishing_probability,
            shap_output_space=OUTPUT_SPACE_RAW,
            shap_base_value=base_value,
            raw_margin=raw_margin,
            additivity_residual=residual,
            top_contributions=tuple(contributions),
        )

    def _top_contributions(self, X, shap_1, top_k):
        """Top present-feature tokens by |SHAP|, in raw-margin units."""
        present_columns = set(X.indices.tolist())

        index_to_word = {}
        for word, idx in self.vectorizer.vocabulary_.items():
            if idx not in index_to_word:
                index_to_word[idx] = word

        contributions = []
        for idx in present_columns:
            word = index_to_word.get(idx)
            if word is None:
                continue
            value = float(shap_1[idx])
            if value == 0.0:
                continue
            contributions.append(
                TokenContribution(
                    token=word,
                    contribution=value,
                    direction=("toward_phishing" if value > 0 else "toward_safe"),
                    tfidf_value=float(X[0, idx]),
                )
            )

        contributions.sort(key=lambda item: abs(item.contribution), reverse=True)
        return contributions[:top_k]


# ---------------------------------------------------------------------------
# Cached access helpers
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def get_predictor() -> BaselinePredictor:
    """Return the process-wide predictor, loading the artifacts once."""
    return BaselinePredictor.load()


def warm_up() -> None:
    """Preload artifact loading + SHAP explainer (e.g., at app startup)."""
    get_predictor()


def predict_email(body: str, top_k: int = DEFAULT_TOP_K) -> PredictionResult:
    """Convenience wrapper: classify and explain one email body."""
    return get_predictor().predict(body, top_k=top_k)
