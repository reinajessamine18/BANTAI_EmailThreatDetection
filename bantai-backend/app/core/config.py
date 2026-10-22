"""Application settings, read from environment variables (prefix BANTAI_) or backend .env."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]   # bantai-backend/
REPO_ROOT = BACKEND_DIR.parent                      # repository root


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BANTAI_",
        env_file=BACKEND_DIR / ".env",
        extra="ignore",
    )

    app_name: str = "BANTAI API"
    api_prefix: str = "/api/v1"

    # Where the ML package lives. Default is repo-relative (no machine-specific paths).
    ml_dir: Path = REPO_ROOT / "machine-learning"
    # If True, startup fails when the ML model cannot be loaded.
    ml_required: bool = False

    # SQLite file (created automatically on first start) and the team's SQL files.
    database_path: Path = BACKEND_DIR / "bantai.db"
    sql_dir: Path = REPO_ROOT / "bantai-database"

    # Requests larger than this (Content-Length) are refused with 413 before being read.
    # 8 MB leaves room for a 5 MB .eml sent as base64 (about 6.7 MB).
    max_request_bytes: int = 8 * 1024 * 1024

    # Vite dev server by default.
    cors_origins: list[str] = ["http://localhost:5173"]

    # Authentication emails use SMTP STARTTLS. Unprefixed aliases support the
    # documented deployment variable names while retaining BANTAI_ compatibility.
    smtp_host: str | None = Field(
        default=None,
        validation_alias=AliasChoices("SMTP_HOST", "BANTAI_SMTP_HOST"),
    )
    smtp_port: int = Field(
        default=587,
        ge=1,
        le=65535,
        validation_alias=AliasChoices("SMTP_PORT", "BANTAI_SMTP_PORT"),
    )
    smtp_username: str | None = Field(
        default=None,
        validation_alias=AliasChoices("SMTP_USERNAME", "BANTAI_SMTP_USERNAME"),
    )
    smtp_password: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("SMTP_PASSWORD", "BANTAI_SMTP_PASSWORD"),
    )
    smtp_sender: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "SMTP_FROM_EMAIL", "BANTAI_SMTP_FROM_EMAIL", "BANTAI_SMTP_SENDER"
        ),
    )
    frontend_base_url: str = "http://localhost:5173"
    password_reset_token_ttl_minutes: int = Field(default=30, ge=5, le=1440)
    password_reset_requests_per_hour: int = Field(default=5, ge=1, le=100)
    google_client_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GOOGLE_CLIENT_ID", "BANTAI_GOOGLE_CLIENT_ID"),
    )
    google_client_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "GOOGLE_CLIENT_SECRET", "BANTAI_GOOGLE_CLIENT_SECRET"
        ),
    )
    google_redirect_uri: str = Field(
        default="http://localhost:8000/api/v1/auth/google/callback",
        validation_alias=AliasChoices(
            "GOOGLE_REDIRECT_URI", "BANTAI_GOOGLE_REDIRECT_URI"
        ),
    )
    extension_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices("BANTAI_EXTENSION_ID", "EXTENSION_ID"),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
