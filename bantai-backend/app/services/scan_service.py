"""The scan pipeline: submission -> parse -> model -> score/explain -> record -> response.

Fail-closed on recording: if the scan/audit rows cannot be written, no result is returned
(the flow requires the audit record before the user sees anything).

The model is injected (`predict_fn`, `max_body_chars_fn`) so the pipeline can be tested
without loading it.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Optional

from sqlalchemy.exc import SQLAlchemyError

from app.services import scan_store
from app.services.catalog import CatalogError, load_catalog
from app.services.content_ml_service import ContentMlUnavailable
from app.services.decision import assess
from app.services.explanations import explain_tokens
from app.services.guest_scan_quota import complete_guest_scan, release_guest_scan
from app.services.ml_service import MlUnavailable
from app.services.scan_input import ScanInputError, clean_file_name, parse_scan_input
from app.services.scan_result import SHAP_NOTE, build_scan_payload, word_item
from app.services.threat_scoring import probability_to_score, risk_tier, ui_risk_level

logger = logging.getLogger("bantai.scan")


@dataclass(frozen=True)
class ScanSubmission:
    input_method: str          # 'eml_upload' | 'raw_text'
    content: str
    encoding: str              # 'text' | 'base64'
    file_name: Optional[str] = None


@dataclass(frozen=True)
class ContentScanSubmission:
    body_text: str
    file_name: Optional[str] = None
    explain: bool = True
    top_k: int = 10


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


def perform_content_scan(
    session,
    submission: ContentScanSubmission,
    client: ClientInfo,
    user_id: Optional[int],
    *,
    predict_fn: Callable,
    max_body_chars_fn: Callable[[], int],
    now_fn: Callable[[], str] = _utc_now,
    timer: Callable[[], float] = time.perf_counter,
    guest_reservation_id: Optional[int] = None,
) -> Dict[str, object]:
    """Execute content-only email scanning using Candidate V2 EXP-4.

    Accepts already-extracted readable body text.
    Zero-body privacy: body text is processed transiently and never persisted.
    Guest scans: quota is released on failure and finalized strictly on commit.
    """
    file_name = clean_file_name(submission.file_name)
    body_len = len(submission.body_text) if isinstance(submission.body_text, str) else 0
    context = {"pipeline": "content_only", "input_method": "raw_text", "content_chars": body_len}

    def reject(status: int, code: str, message: str):
        if guest_reservation_id is not None:
            release_guest_scan(session, guest_reservation_id)
        _audit_rejection(session, client, user_id, status, code, context)
        raise ScanFailure(status, code, message)

    # 1. Validate body text input
    if not isinstance(submission.body_text, str):
        reject(422, "invalid_type", "Email body must be a string.")
    if len(submission.body_text) == 0:
        reject(422, "empty_content", "Email body content is required.")
    if submission.body_text.strip() == "":
        reject(422, "whitespace_only", "Email body contains only whitespace.")

    # 2. Check maximum allowable body limit
    try:
        limit = max_body_chars_fn()
    except (ContentMlUnavailable, MlUnavailable):
        reject(503, "ml_unavailable", "The content analysis model is not available right now.")

    if len(submission.body_text) > limit:
        reject(413, "body_too_long", f"The email text is longer than the {limit}-character analysis limit.")

    # 3. Load catalog for scoring policy and token explanation mapping
    try:
        catalog = load_catalog(session)
    except CatalogError as exc:
        logger.error("scoring catalog invalid: %s", exc)
        reject(500, "configuration_error", "The scoring configuration is invalid.")

    # 4. Execute candidate inference
    started = timer()
    try:
        prediction = predict_fn(
            submission.body_text,
            explain=submission.explain,
            top_k=submission.top_k,
        )
    except ContentMlUnavailable:
        reject(503, "ml_unavailable", "The content analysis model is not available right now.")
    except ValueError:
        # e.g., post-cleaning degeneracy check fails: text becomes empty after removing URLs/emails
        reject(422, "degenerate_content", "Email body contains no readable natural-language text after cleaning.")
    except Exception as exc:  # noqa: BLE001
        logger.error("Content inference unexpected failure: %s", type(exc).__name__)
        reject(500, "inference_failed", "The content analysis could not be completed.")
    inference_ms = max(0, int(round((timer() - started) * 1000)))

    # 5. Decision & Scoring
    threat_score = probability_to_score(prediction.phishing_probability)
    risk_tier_val = risk_tier(threat_score, catalog.policy)
    risk_lvl = ui_risk_level(risk_tier_val)
    model_classification = prediction.classification

    # Explain top positive and negative tokens using catalog
    all_tokens = list(prediction.top_positive_tokens) + list(prediction.top_negative_tokens)
    token_explanations = explain_tokens(all_tokens, catalog)

    # 6. Resolve Candidate Model Version
    model = scan_store.candidate_model(session)
    if model is None:
        reject(500, "no_candidate_model", "No candidate model is registered.")
    model_version_id, model_tag = model

    scanned_at = now_fn()
    save = user_id is None or scan_store.auto_save_enabled(session, user_id)
    content_sha256 = hashlib.sha256(submission.body_text.encode("utf-8", "replace")).hexdigest()

    try:
        scan_id = None
        if save:
            scan = scan_store.save_content_scan(
                session,
                user_id=user_id,
                model_version_id=model_version_id,
                file_name=file_name,
                body_char_count=len(submission.body_text),
                content_sha256=content_sha256,
                phishing_probability=prediction.phishing_probability,
                threat_score=threat_score,
                risk_tier=risk_tier_val,
                shap_base_value=prediction.shap_base_value,
                inference_ms=inference_ms,
                scanned_at=scanned_at,
                token_explanations=token_explanations,
            )
            scan_id = scan.scan_id

        scan_store.write_audit(
            session,
            event_type="SCAN_COMPLETED",
            http_status=200,
            detail={
                "pipeline": "content_only",
                "input_method": "raw_text",
                "risk_tier": risk_tier_val,
                "threat_score": threat_score,
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
        if guest_reservation_id is not None:
            release_guest_scan(session, guest_reservation_id)
        logger.error("could not record content scan: %s", type(exc).__name__)
        raise ScanFailure(
            500, "storage_failed", "The scan could not be recorded, so no result was returned."
        ) from None

    word_items = [
        word_item(e.rank, e.token, e.title, e.message, e.insight_type, e.direction, e.contribution)
        for e in token_explanations
    ]

    return {
        "scanId": scan_id,
        "scanCode": f"BNT-{scan_id:04d}" if scan_id is not None else None,
        "pipeline": "content_only",
        "saved": scan_id is not None,
        "riskLevel": risk_lvl,
        "riskTier": risk_tier_val,
        "threatScore": threat_score,
        "phishingProbability": prediction.phishing_probability,
        "safeProbability": prediction.safe_probability,
        "modelClassification": model_classification,
        "decisionThreshold": prediction.decision_threshold,
        "explanations": word_items,
        "shap": {
            "baseValue": prediction.shap_base_value,
            "rawMargin": prediction.raw_margin,
            "additivityResidual": prediction.additivity_residual,
            "unit": "log-odds",
            "note": SHAP_NOTE,
        },
        "links": [],
        "linkCount": 0,
        "linksTruncated": False,
        "auth": {"spf": None, "dkim": None, "dmarc": None},
        "fileName": file_name,
        "scannedAt": scanned_at,
        "inferenceTimeMs": inference_ms,
        "sender": None,
        "subject": "[Content-Only Scan]" if user_id is not None else None,
        "emailBody": submission.body_text,
        "modelVersion": model_tag,
    }
