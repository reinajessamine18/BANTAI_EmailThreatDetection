"""SQLAlchemy ORM models mirroring bantai-database/schema.sql (schema version 10).

IMPORTANT: the SQL files are the source of truth. These classes only *describe*
existing tables for querying. Never call `Base.metadata.create_all()`: it would
try to create the read-only `v_scan_history` view as a table and would bypass the
team's schema (CHECK constraints, generated column, partial indexes).

Timestamps are stored as ISO-8601 text ('2026-09-13T13:40:00Z') and are mapped as
plain strings on purpose; SQLAlchemy's DateTime type would not parse the 'Z' form.
"""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

_NOW = text("(strftime('%Y-%m-%dT%H:%M:%SZ','now'))")


class Base(DeclarativeBase):
    pass


# ----------------------------------------------------------------- users
class User(Base):
    __tablename__ = "users"

    user_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    full_name: Mapped[str] = mapped_column(Text)
    email: Mapped[str] = mapped_column(Text)
    password_hash: Mapped[Optional[str]] = mapped_column(Text)
    auth_provider: Mapped[str] = mapped_column(Text, server_default="local")
    sso_subject_id: Mapped[Optional[str]] = mapped_column(Text)
    sso_idp_entity_id: Mapped[Optional[str]] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text, server_default="analyst")
    job_title: Mapped[Optional[str]] = mapped_column(Text)
    tier_label: Mapped[Optional[str]] = mapped_column(Text)
    profile_picture: Mapped[Optional[str]] = mapped_column(Text)   # data URI, <= 400000 chars (DB CHECK)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("1"))
    failed_login_attempts: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    locked_until: Mapped[Optional[str]] = mapped_column(Text)
    last_login_at: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text, server_default=_NOW)
    updated_at: Mapped[str] = mapped_column(Text, server_default=_NOW)


class UserSession(Base):
    __tablename__ = "user_sessions"

    session_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.user_id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(Text)
    ip_address: Mapped[Optional[str]] = mapped_column(Text)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text, server_default=_NOW)
    expires_at: Mapped[str] = mapped_column(Text)
    revoked_at: Mapped[Optional[str]] = mapped_column(Text)


class UserSettings(Base):
    __tablename__ = "user_settings"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.user_id", ondelete="CASCADE"), primary_key=True
    )
    shap_advanced_mode: Mapped[bool] = mapped_column(Boolean, server_default=text("1"))
    auto_save_scan_logs: Mapped[bool] = mapped_column(Boolean, server_default=text("1"))
    updated_at: Mapped[str] = mapped_column(Text, server_default=_NOW)


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    reset_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.user_id", ondelete="CASCADE"))
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    expires_at: Mapped[str] = mapped_column(Text)
    used_at: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text, server_default=_NOW)


class PasswordResetRequest(Base):
    __tablename__ = "password_reset_requests"

    request_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_ip: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text)


class GuestScanReservation(Base):
    __tablename__ = "guest_scan_reservations"

    reservation_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_ip: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text)
    completed_at: Mapped[Optional[str]] = mapped_column(Text)


class SystemSetting(Base):
    __tablename__ = "system_settings"

    setting_key: Mapped[str] = mapped_column(Text, primary_key=True)
    setting_value: Mapped[str] = mapped_column(Text)
    description: Mapped[Optional[str]] = mapped_column(Text)
    updated_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.user_id", ondelete="SET NULL"))
    updated_at: Mapped[str] = mapped_column(Text, server_default=_NOW)


# ------------------------------------------------------- model / features
class ModelVersion(Base):
    __tablename__ = "model_versions"

    model_version_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version_tag: Mapped[str] = mapped_column(Text)
    algorithm: Mapped[str] = mapped_column(Text, server_default="XGBoost")
    explainer_type: Mapped[str] = mapped_column(Text, server_default="shap.TreeExplainer")
    training_dataset: Mapped[Optional[str]] = mapped_column(Text)
    n_training_samples: Mapped[Optional[int]] = mapped_column(Integer)
    accuracy: Mapped[Optional[float]] = mapped_column(Float)
    precision_score: Mapped[Optional[float]] = mapped_column(Float)
    recall_score: Mapped[Optional[float]] = mapped_column(Float)
    f1_score: Mapped[Optional[float]] = mapped_column(Float)
    roc_auc: Mapped[Optional[float]] = mapped_column(Float)
    hyperparameters: Mapped[Optional[str]] = mapped_column(Text)
    model_artifact_path: Mapped[str] = mapped_column(Text)
    scaler_artifact_path: Mapped[Optional[str]] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("0"))
    trained_at: Mapped[Optional[str]] = mapped_column(Text)
    deployed_at: Mapped[Optional[str]] = mapped_column(Text)
    notes: Mapped[Optional[str]] = mapped_column(Text)


class FeatureDefinition(Base):
    __tablename__ = "feature_definitions"

    feature_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    feature_key: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text)
    value_type: Mapped[str] = mapped_column(Text)
    description: Mapped[Optional[str]] = mapped_column(Text)
    insight_type: Mapped[str] = mapped_column(Text, server_default="Educational Insight")
    insight_title: Mapped[Optional[str]] = mapped_column(Text)
    insight_template: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("1"))
    created_at: Mapped[str] = mapped_column(Text, server_default=_NOW)


# ------------------------------------------------------------------ scans
class Scan(Base):
    """One row per scan. Never stores the email body."""

    __tablename__ = "scans"

    scan_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # `scan_code` is a DB-generated column ('BNT-' || printf('%04d', scan_id)); it is
    # exposed as a property below instead of being mapped, so inserts never touch it.
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.user_id", ondelete="SET NULL"))
    model_version_id: Mapped[int] = mapped_column(ForeignKey("model_versions.model_version_id"))

    input_method: Mapped[str] = mapped_column(Text)
    file_name: Mapped[Optional[str]] = mapped_column(Text)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer)
    content_sha256: Mapped[str] = mapped_column(Text)
    body_char_count: Mapped[Optional[int]] = mapped_column(Integer)

    subject: Mapped[Optional[str]] = mapped_column(Text)
    sender_address: Mapped[Optional[str]] = mapped_column(Text)
    sender_domain: Mapped[Optional[str]] = mapped_column(Text)
    return_path_domain: Mapped[Optional[str]] = mapped_column(Text)
    spf_result: Mapped[Optional[str]] = mapped_column(Text)
    dkim_result: Mapped[Optional[str]] = mapped_column(Text)
    dmarc_result: Mapped[Optional[str]] = mapped_column(Text)
    url_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))

    malicious_probability: Mapped[float] = mapped_column(Float)
    threat_score: Mapped[int] = mapped_column(Integer)
    risk_tier: Mapped[str] = mapped_column(Text)
    shap_base_value: Mapped[Optional[float]] = mapped_column(Float)
    inference_ms: Mapped[Optional[int]] = mapped_column(Integer)

    scanned_at: Mapped[str] = mapped_column(Text, server_default=_NOW)

    urls: Mapped[List["ExtractedUrl"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ExtractedUrl.position_in_mail",
    )
    token_contributions: Mapped[List["ScanTokenContribution"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ScanTokenContribution.abs_rank",
    )

    @property
    def scan_code(self) -> Optional[str]:
        return None if self.scan_id is None else f"BNT-{self.scan_id:04d}"


class ScanFeature(Base):
    __tablename__ = "scan_features"

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.scan_id", ondelete="CASCADE"), primary_key=True
    )
    feature_id: Mapped[int] = mapped_column(
        ForeignKey("feature_definitions.feature_id"), primary_key=True
    )
    raw_value: Mapped[float] = mapped_column(Float)
    scaled_value: Mapped[Optional[float]] = mapped_column(Float)


class ShapResult(Base):
    __tablename__ = "shap_results"

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.scan_id", ondelete="CASCADE"), primary_key=True
    )
    feature_id: Mapped[int] = mapped_column(
        ForeignKey("feature_definitions.feature_id"), primary_key=True
    )
    shap_value: Mapped[float] = mapped_column(Float)
    abs_rank: Mapped[int] = mapped_column(Integer)


class Explanation(Base):
    __tablename__ = "explanations"

    explanation_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer)      # composite FK to shap_results lives in SQL
    feature_id: Mapped[int] = mapped_column(Integer)
    display_order: Mapped[int] = mapped_column(Integer)
    insight_type: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text)


class ExtractedUrl(Base):
    __tablename__ = "extracted_urls"

    url_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.scan_id", ondelete="CASCADE"))
    position_in_mail: Mapped[int] = mapped_column(Integer, server_default=text("1"))
    url_defanged: Mapped[str] = mapped_column(Text)
    domain: Mapped[Optional[str]] = mapped_column(Text)
    tld: Mapped[Optional[str]] = mapped_column(Text)
    url_length: Mapped[Optional[int]] = mapped_column(Integer)
    subdomain_count: Mapped[Optional[int]] = mapped_column(Integer)
    redirect_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    has_ip_address: Mapped[bool] = mapped_column(Boolean, server_default=text("0"))
    uses_shortener: Mapped[bool] = mapped_column(Boolean, server_default=text("0"))
    has_at_symbol: Mapped[bool] = mapped_column(Boolean, server_default=text("0"))
    is_https: Mapped[bool] = mapped_column(Boolean, server_default=text("0"))
    is_suspicious: Mapped[bool] = mapped_column(Boolean, server_default=text("0"))

    scan: Mapped["Scan"] = relationship(back_populates="urls")


class ScanTokenContribution(Base):
    """Word-level SHAP contribution (raw-margin / log-odds units) plus its plain-language text."""

    __tablename__ = "scan_token_contributions"

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.scan_id", ondelete="CASCADE"), primary_key=True
    )
    abs_rank: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    token: Mapped[str] = mapped_column(Text)
    contribution: Mapped[float] = mapped_column(Float)
    direction: Mapped[str] = mapped_column(Text)
    tfidf_value: Mapped[float] = mapped_column(Float)
    insight_type: Mapped[Optional[str]] = mapped_column(Text)
    insight_title: Mapped[Optional[str]] = mapped_column(Text)
    insight_message: Mapped[Optional[str]] = mapped_column(Text)

    scan: Mapped["Scan"] = relationship(back_populates="token_contributions")


class TokenFeatureMap(Base):
    """Education mapping: a SHAP word -> the catalog feature whose insight text explains it."""

    __tablename__ = "token_feature_map"

    token: Mapped[str] = mapped_column(Text, primary_key=True)
    feature_id: Mapped[int] = mapped_column(ForeignKey("feature_definitions.feature_id", ondelete="CASCADE"))

    feature: Mapped["FeatureDefinition"] = relationship()


class ScanFeedback(Base):
    __tablename__ = "scan_feedback"

    feedback_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.scan_id", ondelete="CASCADE"))
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.user_id", ondelete="SET NULL"))
    is_prediction_correct: Mapped[bool] = mapped_column(Boolean)
    suggested_label: Mapped[Optional[str]] = mapped_column(Text)
    explanation_helpful: Mapped[Optional[bool]] = mapped_column(Boolean)
    comment: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text, server_default=_NOW)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    audit_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.user_id", ondelete="SET NULL"))
    actor_email: Mapped[Optional[str]] = mapped_column(Text)
    scan_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scans.scan_id", ondelete="SET NULL"))
    event_type: Mapped[str] = mapped_column(Text)
    http_status: Mapped[Optional[int]] = mapped_column(Integer)
    detail: Mapped[Optional[str]] = mapped_column(Text)   # JSON text; never contains email content
    ip_address: Mapped[Optional[str]] = mapped_column(Text)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(Text, server_default=_NOW)


# ------------------------------------------------------------ read-only view
class ScanHistoryRow(Base):
    """Read-only mapping of the `v_scan_history` VIEW. Query it; never insert."""

    __tablename__ = "v_scan_history"

    scan_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_code: Mapped[str] = mapped_column(String)
    user_id: Mapped[Optional[int]] = mapped_column(Integer)
    scanned_at: Mapped[str] = mapped_column(Text)
    subject: Mapped[Optional[str]] = mapped_column(Text)
    sender_domain: Mapped[Optional[str]] = mapped_column(Text)
    threat_score: Mapped[int] = mapped_column(Integer)
    risk_tier: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(Text)
    confidence_pct: Mapped[float] = mapped_column(Float)
    inference_ms: Mapped[Optional[int]] = mapped_column(Integer)
