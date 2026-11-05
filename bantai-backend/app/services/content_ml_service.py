"""Bridge to the Phase 7 packaged content-only NLP inference engine.

Loads Candidate V2 EXP-4 from machine-learning/artifacts/packaged_content_nlp/.
Reuses ContentNLPPredictor without reloading artifacts per scan.
Provides thread-safe on-demand SHAP explanations and fails closed without
exposing email body text or filesystem details to clients.
"""

from __future__ import annotations

import logging
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from src.models.content_nlp_inference import ContentNLPPrediction, ContentNLPPredictor

logger = logging.getLogger("bantai.content_ml")

# SHAP's TreeExplainer Python traversal state can encounter race conditions under
# concurrent access in FastAPI's thread pool, so explanations are serialized.
_content_shap_lock = threading.Lock()

_predictor: Optional["ContentNLPPredictor"] = None


@dataclass(frozen=True)
class ContentMlStatus:
    ready: bool
    detail: str  # "ready" | "import_failed" | "artifacts_missing" | "load_failed"


class ContentMlUnavailable(RuntimeError):
    """The content-only candidate model cannot serve predictions right now."""


def load_content_ml(package_dir: Path) -> ContentMlStatus:
    """Import the ML package, instantiate ContentNLPPredictor, and pre-warm SHAP."""
    global _predictor
    package_path = Path(package_dir).resolve()
    ml_root = package_path.parents[1]  # machine-learning/
    ml_root_str = str(ml_root.resolve())

    inserted = False
    if ml_root_str not in sys.path:
        sys.path.insert(0, ml_root_str)
        inserted = True

    try:
        from src.models.content_nlp_inference import (
            ContentNLPPredictor,
            InferenceError,
        )
    except ImportError as exc:
        logger.error("Content ML module could not be imported: %s", type(exc).__name__)
        return ContentMlStatus(False, "import_failed")
    finally:
        if inserted and ml_root_str in sys.path:
            sys.path.remove(ml_root_str)

    try:
        # Load model and vectorizer atomically, then pre-warm TreeExplainer
        predictor = ContentNLPPredictor(package_dir=package_path, lazy_explainer=False)
        predictor.warm_up()
        _predictor = predictor
    except FileNotFoundError:
        logger.error(
            "Content ML artifacts missing under %s",
            package_path.name,
        )
        return ContentMlStatus(False, "artifacts_missing")
    except InferenceError as exc:
        logger.error("Content ML package integrity check failed: %s", type(exc).__name__)
        return ContentMlStatus(False, "load_failed")
    except Exception as exc:  # noqa: BLE001
        logger.error("Content ML model failed to load: %s", type(exc).__name__)
        return ContentMlStatus(False, "load_failed")

    logger.info("Content-only NLP candidate model (EXP-4) loaded and pre-warmed")
    return ContentMlStatus(True, "ready")


def get_content_predictor() -> Optional["ContentNLPPredictor"]:
    """Returns the cached ContentNLPPredictor singleton if loaded."""
    return _predictor


def max_body_chars() -> int:
    """The content-only model's character limit (rejects, never truncates)."""
    try:
        from src.models.content_nlp_inference import MAX_BODY_CHARS

        return MAX_BODY_CHARS
    except ImportError as exc:
        raise ContentMlUnavailable("Content ML module is not importable") from exc


def predict_content(
    body: str,
    explain: bool = True,
    top_k: int = 10,
) -> "ContentNLPPrediction":
    """Classify an extracted email body using Candidate V2 EXP-4.

    The caller must validate that `body` is a non-empty string within `max_body_chars()`.
    """
    global _predictor
    if _predictor is None:
        raise ContentMlUnavailable("Content ML component is not ready")

    from src.models.content_nlp_inference import InferenceError

    try:
        if explain:
            with _content_shap_lock:
                return _predictor.predict(body, explain=True, top_k=top_k)
        return _predictor.predict(body, explain=False, top_k=top_k)
    except (FileNotFoundError, InferenceError) as exc:
        logger.error("Content ML prediction failed: %s", type(exc).__name__)
        raise ContentMlUnavailable("content prediction failed") from exc

