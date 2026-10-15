"""Database writes for scans and the audit log (SQLAlchemy). Thin by design: all
decisions are made upstream; this module only maps results onto rows.

Privacy:
* The email body is never written. The TF-IDF words stored are the top few SHAP words
  (see scan_token_contributions in schema.sql).
* ANONYMOUS (guest) scans keep domains and the header results but NOT the subject or the
  full sender address, because no account can ever see them and the guest screen promises
  nothing identifying is kept.
* `detail` in audit rows holds counts/codes only.
"""

from __future__ import annotations

import json
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    AuditLog,
    ExtractedUrl,
    ModelVersion,
    Scan,
    ScanFeature,
    ScanTokenContribution,
    UserSettings,
)


def active_model(session: Session) -> Optional[Tuple[int, str]]:
    """(model_version_id, version_tag) of the active model, or None."""
    row = session.execute(
        select(ModelVersion.model_version_id, ModelVersion.version_tag).where(
            ModelVersion.is_active.is_(True)
        )
    ).first()
    return (row[0], row[1]) if row else None


def auto_save_enabled(session: Session, user_id: int) -> bool:
    """Settings > 'Auto-save Scan Logs'. No settings row yet means the default (on)."""
    settings = session.get(UserSettings, user_id)
    return True if settings is None else bool(settings.auto_save_scan_logs)


def save_scan(
    session: Session,
    *,
    parsed,
    assessment,
    catalog,
    input_method: str,
    file_name: Optional[str],
    file_size_bytes: int,
    user_id: Optional[int],
    model_version_id: int,
    inference_ms: int,
    scanned_at: str,
) -> Scan:
    """Insert the scan and its children; flushes so `scan.scan_id` is available."""
    anonymous = user_id is None
    scan = Scan(
        user_id=user_id,
        model_version_id=model_version_id,
        input_method=input_method,
        file_name=file_name,
        file_size_bytes=file_size_bytes,
        content_sha256=parsed.content_sha256,
        body_char_count=parsed.body_char_count,
        subject=None if anonymous else parsed.subject,
        sender_address=None if anonymous else parsed.sender_address,
        sender_domain=parsed.sender_domain,
        return_path_domain=parsed.return_path_domain,
        spf_result=parsed.spf_result,
        dkim_result=parsed.dkim_result,
        dmarc_result=parsed.dmarc_result,
        url_count=parsed.url_count,
        malicious_probability=assessment.phishing_probability,
        threat_score=assessment.threat_score,
        risk_tier=assessment.risk_tier,
        shap_base_value=assessment.shap_base_value,
        inference_ms=inference_ms,
        scanned_at=scanned_at,
        urls=[
            ExtractedUrl(
                position_in_mail=u.position,
                url_defanged=u.url_defanged,
                domain=u.domain,
                tld=u.tld,
                url_length=u.url_length,
                subdomain_count=u.subdomain_count,
                redirect_count=u.redirect_count,
                has_ip_address=u.has_ip_address,
                uses_shortener=u.uses_shortener,
                has_at_symbol=u.has_at_symbol,
                is_https=u.is_https,
                is_suspicious=u.is_suspicious,
            )
            for u in parsed.urls
        ],
        token_contributions=[
            ScanTokenContribution(
                abs_rank=e.rank,
                token=e.token,
                contribution=e.contribution,
                direction=e.direction,
                tfidf_value=e.tfidf_value,
                insight_type=e.insight_type,
                insight_title=e.title,
                insight_message=e.message,
            )
            for e in assessment.token_explanations
        ],
    )
    session.add(scan)
    session.flush()

    for key, value in assessment.indicator_values.items():
        feature = catalog.features.get(key)
        if feature is not None:
            session.add(ScanFeature(scan_id=scan.scan_id, feature_id=feature.feature_id, raw_value=value))
    session.flush()
    return scan


def write_audit(
    session: Session,
    *,
    event_type: str,
    http_status: Optional[int],
    detail: dict,
    user_id: Optional[int],
    scan_id: Optional[int],
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> None:
    """Add an audit row to the session (the caller commits)."""
    session.add(
        AuditLog(
            user_id=user_id,
            scan_id=scan_id,
            event_type=event_type,
            http_status=http_status,
            detail=json.dumps(detail, sort_keys=True, separators=(",", ":")),
            ip_address=(ip_address or None) and ip_address[:64],
            user_agent=(user_agent or None) and user_agent[:300],
        )
    )
