"""The scan pipeline: submission -> parse -> model -> score/explain -> record -> response.

Fail-closed on recording: if the scan/audit rows cannot be written, no result is returned
(the flow requires the audit record before the user sees anything).

The model is injected (`predict_fn`, `max_body_chars_fn`) so the pipeline can be tested
without loading it.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Optional

from sqlalchemy.exc import SQLAlchemyError

from app.services import scan_store
from app.services.guest_scan_quota import complete_guest_scan
from app.services.catalog import CatalogError, load_catalog
from app.services.decision import assess
from app.services.ml_service import MlUnavailable
from app.services.scan_input import ScanInputError, clean_file_name, parse_scan_input
from app.services.scan_result import build_scan_payload

logger = logging.getLogger("bantai.scan")


@dataclass(frozen=True)
class ScanSubmission:
    input_method: str          # 'eml_upload' | 'raw_text'
    content: str
    encoding: str              # 'text' | 'base64'
    file_name: Optional[str] = None


@dataclass(frozen=True)
class ClientInfo:
    ip: Optional[str] = None
    user_agent: Optional[str] = None


class ScanFailure(Exception):
    """A scan that must be answered with an HTTP error. Messages never contain email text."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _audit_rejection(session, client: ClientInfo, user_id, status: int, code: str, context: dict) -> None:
    try:
        scan_store.write_audit(
            session,
            event_type="SCAN_REJECTED",
            http_status=status,
            detail={"code": code, **context},
            user_id=user_id,
            scan_id=None,
            ip_address=client.ip,
            user_agent=client.user_agent,
        )
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.error("could not audit a rejected scan: %s", type(exc).__name__)


def perform_scan(
    session,
    submission: ScanSubmission,
    client: ClientInfo,
    user_id: Optional[int],
    *,
    predict_fn: Callable,
    max_body_chars_fn: Callable[[], int],
    now_fn: Callable[[], str] = _utc_now,
    timer: Callable[[], float] = time.perf_counter,
    guest_reservation_id: Optional[int] = None,
) -> Dict[str, object]:
    file_name = clean_file_name(submission.file_name)
    context = {"input_method": submission.input_method, "content_chars": len(submission.content)}

    def reject(status: int, code: str, message: str):
        _audit_rejection(session, client, user_id, status, code, context)
        raise ScanFailure(status, code, message)

    # 1. parse + sanitize
    try:
        parsed, size_bytes = parse_scan_input(submission.input_method, submission.content, submission.encoding)
    except ScanInputError as exc:
        reject(exc.status, exc.code, exc.message)

    # 2. the model rejects (never truncates) overlong text, so check first
    try:
        limit = max_body_chars_fn()
    except MlUnavailable:
        reject(503, "ml_unavailable", "The analysis model is not available right now.")
    if parsed.body_char_count > limit:
        reject(413, "body_too_long", f"The email text is longer than the {limit}-character analysis limit.")

    # 3. database-held scoring content
    try:
        catalog = load_catalog(session)
    except CatalogError as exc:
        logger.error("scoring catalog invalid: %s", exc)
        reject(500, "configuration_error", "The scoring configuration is invalid.")

    # 4. model
    started = timer()
    try:
        prediction = predict_fn(parsed.body_text, catalog.top_n)
    except MlUnavailable:
        reject(503, "ml_unavailable", "The analysis model is not available right now.")
    inference_ms = max(0, int(round((timer() - started) * 1000)))

    # 5. decision
    assessment = assess(parsed, prediction, catalog)

    # 6. record (fail closed), then answer
    model = scan_store.active_model(session)
    if model is None:
        reject(500, "no_active_model", "No active model is registered.")
    model_version_id, model_tag = model
    scanned_at = now_fn()
    save = user_id is None or scan_store.auto_save_enabled(session, user_id)

    try:
        scan_id = None
        if save:
            scan = scan_store.save_scan(
                session,
                parsed=parsed,
                assessment=assessment,
                catalog=catalog,
                input_method=submission.input_method,
                file_name=file_name,
                file_size_bytes=size_bytes,
                user_id=user_id,
                model_version_id=model_version_id,
                inference_ms=inference_ms,
                scanned_at=scanned_at,
            )
            scan_id = scan.scan_id
        scan_store.write_audit(
            session,
            event_type="SCAN_COMPLETED",
            http_status=200,
            detail={
                "input_method": submission.input_method,
                "risk_tier": assessment.risk_tier,
                "threat_score": assessment.threat_score,
                "url_count": parsed.url_count,
                "model_version": model_tag,
                "inference_ms": inference_ms,
                "saved": save,
            },
            user_id=user_id,
            scan_id=scan_id,
            ip_address=client.ip,
            user_agent=client.user_agent,
        )
        if guest_reservation_id is not None:
            complete_guest_scan(session, guest_reservation_id)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.error("could not record scan: %s", type(exc).__name__)
        raise ScanFailure(
            500, "storage_failed", "The scan could not be recorded, so no result was returned."
        ) from None

    return build_scan_payload(
        parsed=parsed,
        assessment=assessment,
        scan_id=scan_id,
        file_name=file_name,
        scanned_at=scanned_at,
        inference_ms=inference_ms,
        model_version=model_tag,
    )
