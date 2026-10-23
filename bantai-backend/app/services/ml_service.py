"""Bridge to the ML team's inference module (machine-learning/src/models).

The backend never re-implements TF-IDF, XGBoost or SHAP. It puts the ML package
on sys.path, loads the artifacts once at startup, and (in a later step) calls
`predict_email`. Errors are reduced to short status codes: no file paths, no
stack traces and never any email content reach API clients.
"""

from __future__ import annotations

import logging
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("bantai.ml")


@dataclass(frozen=True)
class MlStatus:
    ready: bool
    detail: str  # "ready" | "import_failed" | "artifacts_missing" | "load_failed"


def load_ml(ml_dir: Path) -> MlStatus:
    """Make the ML package importable and preload the model + SHAP explainer."""
    ml_path = str(Path(ml_dir).resolve())
    if ml_path not in sys.path:
        sys.path.insert(0, ml_path)

    try:
        from src.models.baseline_inference import warm_up
    except ImportError as exc:
        # Wrong BANTAI_ML_DIR, or shap/xgboost/scikit-learn not installed.
        logger.error("ML module could not be imported: %s", type(exc).__name__)
        return MlStatus(False, "import_failed")

    try:
        warm_up()
    except FileNotFoundError:
        logger.error("ML artifacts are missing (expected under <ml_dir>/artifacts/baseline)")
        return MlStatus(False, "artifacts_missing")
    except Exception as exc:  # unpickling/version problems, SHAP init, etc.
        logger.error("ML model failed to load: %s", type(exc).__name__)
        return MlStatus(False, "load_failed")

    logger.info("ML component loaded")
    return MlStatus(True, "ready")


class MlUnavailable(RuntimeError):
    """The model cannot serve a prediction right now. Never carries email content."""


# SHAP's TreeExplainer is not documented as thread-safe and FastAPI runs sync routes in a
# thread pool, so predictions are serialized. Fine for a single-user/dev workload.
_predict_lock = threading.Lock()


def max_body_chars() -> int:
    """The ML module's input limit (it rejects, never truncates)."""
    try:
        from src.models.baseline_inference import MAX_BODY_CHARS
    except ImportError as exc:
        raise MlUnavailable("ML module is not importable") from exc
    return MAX_BODY_CHARS


def predict(body: str, top_k: int):
    """Classify one email body. Returns the ML module's PredictionResult.

    The caller must already have checked the body is non-empty and within
    `max_body_chars()`; a ValueError from the ML module therefore indicates a bug and is
    deliberately not caught here.
    """
    try:
        from src.models.baseline_inference import InferenceError, predict_email
    except ImportError as exc:
        raise MlUnavailable("ML module is not importable") from exc
    try:
        with _predict_lock:
            return predict_email(body, top_k=top_k)
    except (FileNotFoundError, InferenceError) as exc:
        logger.error("ML prediction failed: %s", type(exc).__name__)
        raise MlUnavailable("prediction failed") from exc
