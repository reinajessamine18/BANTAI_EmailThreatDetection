#!/usr/bin/env python
"""
content_nlp_inference.py

Isolated, production-grade inference component for the BANTAI Content-Only
Email Phishing Detection Model (Candidate V2 EXP-4 Primary Candidate).

Provides:
  - Strict input validation (explicitly rejecting None, empty, whitespace-only,
    oversized, or post-cleaning degenerate inputs).
  - Preprocessing parity using the approved ContentOnlyCleaner.
  - Model and vectorizer provenance and cryptographic SHA-256 verification.
  - Binary classification: 0 = Legitimate, 1 = Phishing (fixed 0.50 decision threshold).
  - Exact class probabilities and raw log-odds margins.
  - Resource-conscious on-demand SHAP TreeExplainer with 1e-5 additivity enforcement.

Strict Boundaries:
  - Consumes only `extracted_body_text: str`.
  - Upstream ingestion handles MIME extraction and attachment exclusion.
  - Does NOT contain MIME parsers, URL fetchers, or header parsers.
  - Does NOT implement threat scores (0-100), risk tiers, or action recommendations.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Tuple

import joblib
import numpy as np
import scipy.special
import shap

from src.preprocessing.content_cleaner import (
    CleanerConfig,
    ContentOnlyCleaner,
)

# ---------------------------------------------------------------------------
# Path Configuration and Defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
ML_DIR = SCRIPT_DIR.parent.parent
DEFAULT_PACKAGE_DIR = ML_DIR / "artifacts" / "packaged_content_nlp"

# Binary Label Mapping Contract
LABEL_LEGITIMATE = 0
LABEL_PHISHING = 1
CLASS_LEGITIMATE = "Legitimate"
CLASS_PHISHING = "Phishing"

# Input Guardrails (Protection against memory exhaustion and ReDoS on 8 GB RAM)
MAX_BODY_CHARS = 200_000
ADDITIVITY_TOLERANCE = 1e-5
DECISION_THRESHOLD = 0.50

# Runtime cleaner configuration matching Candidate V2 training preprocessing
RUNTIME_CLEANER_CONFIG = CleanerConfig(
    url_strategy="remove",              # Excise raw destination URLs
    url_placeholder="",                 # No artificial placeholder tokens
    email_strategy="remove",            # Excise email addresses
    email_placeholder="",               # No artificial placeholder tokens
    normalize_whitespace=True,          # Normalize \r\n, \t, spaces
    normalize_punctuation_spacing=True, # Collapse 'word . ' -> 'word.'
    preserve_case=True,                 # Preserved; vectorizer handles lowercasing
    extract_from_mime=False,            # Upstream parser extracts body text
    preserve_anchor_text=True,          # Visible anchor text retained as prose
)


class InferenceError(RuntimeError):
    """Raised when artifact integrity, dimensional compatibility, or additivity checks fail."""


# ---------------------------------------------------------------------------
# Structured Result Types
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TokenContribution:
    """Individual SHAP token contribution in raw-margin (log-odds) units."""

    token: str
    contribution: float
    direction: str          # "toward_phishing" or "toward_safe"
    tfidf_value: float


@dataclass(frozen=True)
class ContentNLPPrediction:
    """
    Structured prediction result for the content-only NLP model.

    Probabilities are continuous values in [0.0, 1.0]. Raw margins and SHAP
    values are in log-odds space; they are not application threat scores.
    """

    label: int                              # 0 = Legitimate, 1 = Phishing
    classification: str                     # "Legitimate" or "Phishing"
    safe_probability: float                 # P(label = 0 | body) in [0.0, 1.0]
    phishing_probability: float             # P(label = 1 | body) in [0.0, 1.0]
    raw_margin: float                       # log(p / (1 - p))
    decision_threshold: float = 0.50        # Modeling decision threshold
    shap_base_value: float | None = None    # Expected log-odds (phi_0) if explain=True
    additivity_residual: float | None = None # Additivity error if explain=True
    top_positive_tokens: Tuple[TokenContribution, ...] = () # Pushing toward Phishing
    top_negative_tokens: Tuple[TokenContribution, ...] = () # Pushing toward Safe


# ---------------------------------------------------------------------------
# Input Validation Guardrails
# ---------------------------------------------------------------------------
def validate_body_text(body: Any) -> None:
    """
    Validates input string without exposing message contents in exceptions.

    Explicitly rejects None, non-strings, empty strings, whitespace-only,
    and oversized strings. Silent truncation is strictly forbidden.
    """
    if body is None or not isinstance(body, str):
        raise TypeError("email body must be a non-null string")

    if len(body) == 0:
        raise ValueError("email body cannot be empty")

    if body.strip() == "":
        raise ValueError("email body contains only whitespace characters")

    if len(body) > MAX_BODY_CHARS:
        raise ValueError(
            f"email body length ({len(body)} chars) exceeds maximum allowable limit "
            f"({MAX_BODY_CHARS} chars); input rejected without silent truncation"
        )


def compute_sha256(path: Path) -> str:
    """Computes SHA-256 hash of a file on disk."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# Primary Content-Only Predictor Engine
# ---------------------------------------------------------------------------
class ContentNLPPredictor:
    """
    Production-isolated predictor component for Candidate V2 EXP-4.

    Validates packaging integrity upon initialization, applies canonical
    content cleaning, transforms via 25k TF-IDF, classifies via XGBoost,
    and computes on-demand SHAP TreeExplainer attributions.
    """

    def __init__(self, package_dir: Path | str | None = None, lazy_explainer: bool = True) -> None:
        self.package_dir = Path(package_dir) if package_dir is not None else DEFAULT_PACKAGE_DIR
        self.manifest_path = self.package_dir / "model_manifest.json"
        self.model_path = self.package_dir / "model.joblib"
        self.vectorizer_path = self.package_dir / "vectorizer.joblib"

        self._explainer: shap.TreeExplainer | None = None
        self._explainer_base_value: float | None = None

        # 1. Validate files and manifest cryptographic integrity
        self._validate_package_integrity()

        # 2. Load model and vectorizer
        try:
            self.model = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)
        except Exception as exc:
            raise InferenceError(f"Failed to load packaged model artifacts: {type(exc).__name__}: {exc}") from exc

        # 3. Verify dimensional compatibility and classes
        self._verify_compatibility()

        # 4. Cache vocabulary feature names
        self.feature_names = self.vectorizer.get_feature_names_out()

        # 5. Initialize canonical cleaner
        self.cleaner = ContentOnlyCleaner(RUNTIME_CLEANER_CONFIG)

        # 6. Eager or lazy explainer initialization
        if not lazy_explainer:
            self.warm_up()

    def _validate_package_integrity(self) -> None:
        """Verifies artifact presence and SHA-256 checksums against manifest."""
        if not self.package_dir.is_dir():
            raise InferenceError(f"Package directory does not exist: {self.package_dir}")

        if not self.manifest_path.is_file():
            raise InferenceError(f"Missing model manifest: {self.manifest_path}")

        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception as exc:
            raise InferenceError(f"Corrupt or unreadable manifest: {exc}") from exc

        required_artifacts = manifest.get("artifacts", {})
        for key in ["model_joblib", "vectorizer_joblib"]:
            if key not in required_artifacts:
                raise InferenceError(f"Manifest missing required artifact entry: {key}")

            entry = required_artifacts[key]
            fname = entry["filename"]
            expected_sha = entry["sha256"]
            fpath = self.package_dir / fname

            if not fpath.is_file():
                raise InferenceError(f"Packaged artifact file missing on disk: {fpath}")

            actual_sha = compute_sha256(fpath)
            if actual_sha != expected_sha:
                raise InferenceError(
                    f"Cryptographic checksum mismatch for {fname}! "
                    f"Expected: {expected_sha}, Actual: {actual_sha}"
                )

    def _verify_compatibility(self) -> None:
        """Verifies model and vectorizer dimensions and class contracts."""
        n_features_model = getattr(self.model, "n_features_in_", None)
        n_features_vec = len(self.vectorizer.vocabulary_)

        if n_features_model != n_features_vec:
            raise InferenceError(
                f"Feature dimension mismatch between model ({n_features_model}) "
                f"and vectorizer ({n_features_vec})"
            )

        if n_features_model != 25000:
            raise InferenceError(f"Unexpected feature count: {n_features_model} (expected 25,000)")

        classes = list(getattr(self.model, "classes_", []))
        if classes != [0, 1]:
            raise InferenceError(f"Unexpected binary classes contract: {classes} (expected [0, 1])")

        objective = getattr(self.model, "objective", None)
        if objective != "binary:logistic":
            raise InferenceError(f"Unexpected model objective: {objective} (expected 'binary:logistic')")

    def get_explainer(self) -> shap.TreeExplainer:
        """Lazily initializes and caches the SHAP TreeExplainer singleton."""
        if self._explainer is None:
            try:
                self._explainer = shap.TreeExplainer(self.model)
                # Warm up explainer with a dummy sample to finalize expected_value in TreeExplainer
                dummy_x = self.vectorizer.transform(["account security update"])
                _ = self._explainer.shap_values(dummy_x)
                self._explainer_base_value = float(np.ravel(self._explainer.expected_value)[0])
            except Exception as exc:
                raise InferenceError(f"SHAP TreeExplainer initialization failed: {type(exc).__name__}: {exc}") from exc
        return self._explainer

    def warm_up(self) -> None:
        """Pre-loads the explainer and executes a smoke prediction to avoid first-request latency."""
        _ = self.get_explainer()
        _ = self.predict("Please review your account security settings.", explain=True)

    def predict(
        self,
        extracted_body_text: str,
        explain: bool = False,
        top_k: int = 10,
    ) -> ContentNLPPrediction:
        """
        Executes end-to-end content-only inference on extracted email body text.

        Parameters:
            extracted_body_text: The readable body text extracted from the email.
            explain: If True, computes on-demand SHAP TreeExplainer token attributions.
            top_k: Number of positive and negative tokens to return when explain=True.

        Returns:
            ContentNLPPrediction object with label, probabilities, margins, and optional SHAP attributions.
        """
        # 1. Input validation
        validate_body_text(extracted_body_text)

        # 2. Canonical content cleaning
        canonical_text = self.cleaner.clean(extracted_body_text)

        # 3. Post-cleaning degeneracy check
        if not canonical_text or not canonical_text.strip():
            raise ValueError("email body contains no readable natural-language text after canonical cleaning")

        # 4. Feature vectorization
        X = self.vectorizer.transform([canonical_text])

        # 5. Raw margin and probability inference
        margins = self.model.predict(X, output_margin=True)
        raw_margin = float(margins[0])

        probs = self.model.predict_proba(X)
        prob_safe = float(probs[0, 0])
        prob_phish = float(probs[0, 1])

        # Verify logistic link integrity: p = 1 / (1 + exp(-margin))
        expected_sig_prob = float(scipy.special.expit(raw_margin))
        if abs(expected_sig_prob - prob_phish) > 1e-5:
            raise InferenceError(
                f"Probability link consistency failure: sigmoid({raw_margin:.4f}) = "
                f"{expected_sig_prob:.6f} != {prob_phish:.6f}"
            )

        # 6. Binary classification decision
        label = LABEL_PHISHING if prob_phish >= DECISION_THRESHOLD else LABEL_LEGITIMATE
        classification = CLASS_PHISHING if label == LABEL_PHISHING else CLASS_LEGITIMATE

        # Fast path: Return immediately if explanation is not requested
        if not explain:
            return ContentNLPPrediction(
                label=label,
                classification=classification,
                safe_probability=prob_safe,
                phishing_probability=prob_phish,
                raw_margin=raw_margin,
                decision_threshold=DECISION_THRESHOLD,
            )

        # 7. On-demand SHAP Explainability
        explainer = self.get_explainer()
        try:
            shap_values = explainer.shap_values(X)[0]
        except Exception as exc:
            raise InferenceError(f"SHAP explanation failed: {type(exc).__name__}: {exc}") from exc

        base_val = self._explainer_base_value if self._explainer_base_value is not None else float(np.ravel(explainer.expected_value)[0])

        # Verify exact mathematical additivity across all 25,000 features
        sum_all_shap = float(np.sum(shap_values))
        calculated_margin = base_val + sum_all_shap
        residual = float(abs(raw_margin - calculated_margin))

        if residual > ADDITIVITY_TOLERANCE:
            raise InferenceError(
                f"SHAP additivity verification failed: |margin ({raw_margin:.6f}) - "
                f"calculated ({calculated_margin:.6f})| = {residual:.2e} > {ADDITIVITY_TOLERANCE}"
            )

        # Map active present vocabulary tokens (x_j > 0)
        nz_indices = X.nonzero()[1]
        active_tokens = []
        for col_idx in nz_indices:
            tok_name = str(self.feature_names[col_idx])
            tfidf_val = float(X[0, col_idx])
            phi_val = float(shap_values[col_idx])
            active_tokens.append(
                TokenContribution(
                    token=tok_name,
                    contribution=round(phi_val, 6),
                    direction="toward_phishing" if phi_val > 0 else "toward_safe",
                    tfidf_value=round(tfidf_val, 6),
                )
            )

        # Rank positive and negative contributions
        pos_tokens = sorted([t for t in active_tokens if t.contribution > 0], key=lambda x: -x.contribution)
        neg_tokens = sorted([t for t in active_tokens if t.contribution < 0], key=lambda x: x.contribution)

        return ContentNLPPrediction(
            label=label,
            classification=classification,
            safe_probability=prob_safe,
            phishing_probability=prob_phish,
            raw_margin=raw_margin,
            decision_threshold=DECISION_THRESHOLD,
            shap_base_value=round(base_val, 6),
            additivity_residual=round(residual, 8),
            top_positive_tokens=tuple(pos_tokens[:top_k]),
            top_negative_tokens=tuple(neg_tokens[:top_k]),
        )


# ---------------------------------------------------------------------------
# Global Singleton and Convenient Entry Points
# ---------------------------------------------------------------------------
_GLOBAL_PREDICTOR: ContentNLPPredictor | None = None


def get_predictor(package_dir: Path | str | None = None, lazy_explainer: bool = True) -> ContentNLPPredictor:
    """Returns the shared ContentNLPPredictor singleton instance."""
    global _GLOBAL_PREDICTOR
    if _GLOBAL_PREDICTOR is None:
        _GLOBAL_PREDICTOR = ContentNLPPredictor(package_dir=package_dir, lazy_explainer=lazy_explainer)
    return _GLOBAL_PREDICTOR


def predict_email(
    extracted_body_text: str,
    explain: bool = False,
    top_k: int = 10,
    package_dir: Path | str | None = None,
) -> ContentNLPPrediction:
    """Module-level convenience function for content-only email threat detection."""
    predictor = get_predictor(package_dir=package_dir)
    return predictor.predict(extracted_body_text, explain=explain, top_k=top_k)


def warm_up(package_dir: Path | str | None = None) -> ContentNLPPredictor:
    """Warms up the global predictor and explainer cache."""
    predictor = get_predictor(package_dir=package_dir, lazy_explainer=False)
    predictor.warm_up()
    return predictor

