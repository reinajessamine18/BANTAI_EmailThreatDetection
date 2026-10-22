"""Local email/password authentication and Google OpenID Connect."""

from __future__ import annotations

import hmac
import logging
import re
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import urlencode

import requests
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.auth_security import hash_password, new_token, token_hash, verify_password
from app.api.deps import get_current_user
from app.core.config import Settings, get_settings
from app.db.models import (
    AuditLog,
    EmailOtpChallenge,
    OAuthLoginTicket,
    OAuthState,
    PasswordResetRequest,
    PasswordResetToken,
    SystemSetting,
    User,
    UserSession,
    UserSettings,
)
from app.db.session import get_db
from app.services import auth_policy
from app.services.auth_mailer import is_configured as mailer_is_configured
from app.services.auth_mailer import send_otp_email

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)

Password = Annotated[str, Field(min_length=10, max_length=128)]
OtpCode = Annotated[str, StringConstraints(pattern=r"^\d{6}$")]
USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$")
OTP_TTL_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_SECONDS = 60
OTP_MAX_SENDS_PER_HOUR = 5
RESET_AUTH_TTL_MINUTES = 10
OAUTH_STATE_TTL_MINUTES = 10
OAUTH_TICKET_TTL_MINUTES = 2


def _normalized_email(value: str) -> str:
    value = value.strip().lower()
    if len(value) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ValueError("Enter a valid email address.")
    return value


def _normalized_username(value: str) -> str:
    value = value.strip().lower()
    if not USERNAME_RE.fullmatch(value):
        raise ValueError("Use 3–32 letters, numbers, dots, underscores, or hyphens.")
    return value


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    email: str
    password: Password
    confirm_password: Password
    full_name: str | None = Field(default=None, max_length=120)

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        return _normalized_username(value)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        return _normalized_email(value)

    @model_validator(mode="after")
    def matching_passwords(self) -> "RegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    identifier: str | None = Field(default=None, min_length=1, max_length=254)
    email: str | None = Field(default=None, min_length=1, max_length=254)
    password: Annotated[str, Field(min_length=1, max_length=128)]

    @model_validator(mode="after")
    def require_identifier(self) -> "LoginRequest":
        if not (self.identifier or self.email):
            raise ValueError("Enter a username or email address.")
        return self

    @property
    def login_identifier(self) -> str:
        return (self.identifier or self.email or "").strip().lower()


class EmailBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        return _normalized_email(value)


class OtpVerificationBody(EmailBody):
    code: OtpCode


class PasswordResetConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: Annotated[str, StringConstraints(min_length=32, max_length=128)]
    new_password: Password
    confirm_password: Password

    @model_validator(mode="after")
    def matching_passwords(self) -> "PasswordResetConfirmBody":
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class GooglePasswordSetupBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    code: OtpCode
    password: Password
    confirm_password: Password

    @field_validator("username")
    @classmethod
    def valid_username(cls, value: str) -> str:
        return _normalized_username(value)

    @model_validator(mode="after")
    def matching_passwords(self) -> "GooglePasswordSetupBody":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class GoogleTicketBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ticket: Annotated[str, StringConstraints(min_length=32, max_length=128)]


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _audit(
    db: Session,
    request: Request,
    user_id: int | None,
    event_type: str,
    status: int,
) -> None:
    db.add(
        AuditLog(
            user_id=user_id,
            event_type=event_type,
            http_status=status,
            ip_address=request.client.host[:64] if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:300] or None,
        )
    )


def _load_policy(db: Session) -> auth_policy.AuthPolicy:
    rows = db.execute(select(SystemSetting.setting_key, SystemSetting.setting_value)).all()
    return auth_policy.policy_from_settings({key: value for key, value in rows})


def _issue_session(
    db: Session,
    user: User,
    request: Request,
    policy: auth_policy.AuthPolicy,
) -> tuple[str, str]:
    token = new_token()
    expires = auth_policy.session_expiry(_now(), policy)
    db.add(
        UserSession(
            user_id=user.user_id,
            token_hash=token_hash(token),
            ip_address=request.client.host[:64] if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:300] or None,
            expires_at=expires,
        )
    )
    return token, expires


def _user_json(user: User) -> dict[str, object]:
    return {
        "userId": user.user_id,
        "fullName": user.full_name,
        "email": user.email,
        "username": user.username,
        "role": user.role,
        "authProvider": user.auth_provider,
        "hasPassword": user.password_hash is not None,
        "createdAt": user.created_at,
    }


def _error(code: str, message: str, status: int) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": message})


def _check_mail_configuration(settings: Settings) -> None:
    if not mailer_is_configured(settings):
        raise _error(
            "email_delivery_unavailable",
            "Email verification is not configured on this server.",
            503,
        )


def _deliver_otp(settings: Settings, email: str, code: str, purpose: str) -> bool:
    try:
        send_otp_email(settings, email, code, purpose, OTP_TTL_MINUTES)
    except (OSError, ValueError, smtplib.SMTPException) as exc:
        logger.error("Authentication email delivery failed (%s)", type(exc).__name__)
        return False
    return True


def _new_otp(
    db: Session,
    user: User,
    request: Request,
    purpose: str,
    now: datetime,
) -> str | None:
    now_text = _timestamp(now)
    cutoff = _timestamp(now - timedelta(hours=1))
    recent = db.scalar(
        select(func.count())
        .select_from(EmailOtpChallenge)
        .where(
            EmailOtpChallenge.user_id == user.user_id,
            EmailOtpChallenge.purpose == purpose,
            EmailOtpChallenge.created_at >= cutoff,
        )
    ) or 0
    latest = db.scalar(
        select(EmailOtpChallenge)
        .where(
            EmailOtpChallenge.user_id == user.user_id,
            EmailOtpChallenge.purpose == purpose,
        )
        .order_by(EmailOtpChallenge.challenge_id.desc())
        .limit(1)
    )
    if recent >= OTP_MAX_SENDS_PER_HOUR:
        return None
    if latest is not None:
        last_sent = datetime.strptime(latest.created_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        if (now - last_sent).total_seconds() < OTP_RESEND_SECONDS:
            return None
        latest.consumed_at = now_text

    code = f"{secrets.randbelow(1_000_000):06d}"
    db.add(
        EmailOtpChallenge(
            user_id=user.user_id,
            email=user.email,
            purpose=purpose,
            code_hash=hash_password(code),
            client_ip=request.client.host[:64] if request.client else None,
            attempts=0,
            expires_at=_timestamp(now + timedelta(minutes=OTP_TTL_MINUTES)),
        )
    )
    return code


def _verify_otp(
    db: Session,
    user: User | None,
    email: str,
    purpose: str,
    code: str,
    now: datetime,
) -> EmailOtpChallenge:
    now_text = _timestamp(now)
    challenge = None
    if user is not None:
        challenge = db.scalar(
            select(EmailOtpChallenge)
            .where(
                EmailOtpChallenge.user_id == user.user_id,
                EmailOtpChallenge.email == email,
                EmailOtpChallenge.purpose == purpose,
                EmailOtpChallenge.consumed_at.is_(None),
                EmailOtpChallenge.expires_at > now_text,
                EmailOtpChallenge.attempts < OTP_MAX_ATTEMPTS,
            )
            .order_by(EmailOtpChallenge.challenge_id.desc())
            .limit(1)
        )
    if challenge is None or not verify_password(code, challenge.code_hash):
        if challenge is not None:
            challenge.attempts += 1
            if challenge.attempts >= OTP_MAX_ATTEMPTS:
                challenge.consumed_at = now_text
        db.commit()
        raise _error("invalid_otp", "The code is invalid or has expired.", 400)
    challenge.consumed_at = now_text
    return challenge


def _check_reset_ip_limit(db: Session, request: Request, settings: Settings, now: datetime) -> None:
    cutoff = _timestamp(now - timedelta(hours=1))
    client_ip = request.client.host[:64] if request.client else "unknown"
    db.execute(delete(PasswordResetRequest).where(PasswordResetRequest.created_at < cutoff))
    count = db.scalar(
        select(func.count())
        .select_from(PasswordResetRequest)
        .where(
            PasswordResetRequest.client_ip == client_ip,
            PasswordResetRequest.created_at >= cutoff,
        )
    ) or 0
    if count >= settings.password_reset_requests_per_hour:
        db.rollback()
        raise _error(
            "password_reset_rate_limited",
            "Too many password reset requests. Try again later.",
            429,
        )
    db.add(PasswordResetRequest(client_ip=client_ip, created_at=_timestamp(now)))
    db.commit()


def _generic_reset_response() -> dict[str, str]:
    return {
        "message": (
            "If the address is eligible, a code may be delivered. "
            "Check your inbox and spam folder before trying again."
        )
    }


@router.post("/register", status_code=202)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    settings = get_settings()
    _check_mail_configuration(settings)
    email = body.email
    if db.scalar(
        select(User.user_id).where(func.lower(User.email) == email)
    ) is not None:
        raise _error(
            "email_already_registered",
            "An account with this email already exists.",
            409,
        )
    if db.scalar(
        select(User.user_id).where(func.lower(User.username) == body.username)
    ) is not None:
        raise _error(
            "username_already_registered",
            "That username is already in use.",
            409,
        )

    now = _now()
    user = User(
        full_name=(body.full_name or body.username).strip() or body.username,
        email=email,
        username=body.username,
        password_hash=hash_password(body.password),
        auth_provider="local",
        role="analyst",
        is_active=False,
    )
    try:
        db.add(user)
        db.flush()
        db.add(UserSettings(user_id=user.user_id, auto_save_scan_logs=True))
        code = _new_otp(db, user, request, "registration", now)
        if code is None:
            raise _error(
                "verification_rate_limited",
                "A verification code was recently requested. Try again later.",
                429,
            )
        _audit(db, request, user.user_id, "USER_REGISTERED", 202)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise _error(
            "account_already_registered",
            "That username or email address is already in use.",
            409,
        ) from None
    except SQLAlchemyError:
        db.rollback()
        raise _error(
            "registration_failed",
            "The account could not be created.",
            500,
        ) from None
    if not _deliver_otp(settings, email, code, "registration"):
        raise _error(
            "email_delivery_failed",
            "The account is pending verification, but the code could not be delivered. Try resending it later.",
            503,
        )
    return {"message": "If email delivery succeeded, enter the code to verify your account."}


@router.post("/register/resend", status_code=202)
def resend_registration_code(body: EmailBody, request: Request, db: Session = Depends(get_db)):
    settings = get_settings()
    _check_mail_configuration(settings)
    user = db.scalar(
        select(User).where(
            User.email == body.email,
            User.auth_provider == "local",
            User.is_active.is_(False),
            User.email_verified_at.is_(None),
        )
    )
    if user is None:
        return {"message": "If the account is pending verification, a new code may be delivered."}

    code = _new_otp(db, user, request, "registration", _now())
    if code is None:
        raise _error(
            "verification_rate_limited",
            "A verification code was recently requested. Try again later.",
            429,
        )
    db.commit()
    if not _deliver_otp(settings, body.email, code, "registration"):
        raise _error(
            "email_delivery_failed",
            "The verification code could not be delivered. Try again later.",
            503,
        )
    return {"message": "If email delivery succeeded, a new code was issued."}


@router.post("/register/verify")
def verify_registration(body: OtpVerificationBody, request: Request, db: Session = Depends(get_db)):
    now = _now()
    user = db.scalar(
        select(User).where(
            User.email == body.email,
            User.auth_provider == "local",
            User.email_verified_at.is_(None),
        )
    )
    challenge = _verify_otp(db, user, body.email, "registration", body.code, now)
    if user is None or user.is_active:
        db.rollback()
        raise _error("invalid_otp", "The code is invalid or has expired.", 400)

    stamp = _timestamp(now)
    user.email_verified_at = stamp
    user.is_active = True
    user.updated_at = stamp
    user.last_login_at = stamp
    policy = _load_policy(db)
    token, expires = _issue_session(db, user, request, policy)
    _audit(db, request, user.user_id, "LOGIN_SUCCESS", 200)
    db.commit()
    return {
        "accessToken": token,
        "tokenType": "bearer",
        "expiresAt": expires,
        "user": _user_json(user),
    }


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    policy = _load_policy(db)
    now = _now()
    identifier = body.login_identifier
    user = db.scalar(
        select(User).where(
            (func.lower(User.email) == identifier)
            | (func.lower(User.username) == identifier)
        )
    )
    usable = user is not None and user.auth_provider in {"local", "google"}
    locked = usable and auth_policy.is_locked(user.locked_until, auth_policy.iso(now))
    password_ok = (
        verify_password(body.password, user.password_hash)
        if usable and not locked and user.password_hash
        else False
    )
    if not usable or locked or not user.password_hash:
        auth_policy.dummy_verify(body.password)
        password_ok = False
    if not password_ok:
        if usable and not locked:
            user.failed_login_attempts, user.locked_until = auth_policy.register_failure(
                user.failed_login_attempts or 0, policy, now
            )
        _audit(db, request, user.user_id if user else None, "LOGIN_FAILED", 401)
        db.commit()
        raise HTTPException(
            status_code=401,
            detail={
                "code": "invalid_credentials",
                "message": (
                    "Username or email and password are incorrect, or the account "
                    "is temporarily locked."
                ),
            },
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise _error(
            "email_not_verified",
            "Verify your email address before signing in.",
            403,
        )
    if user.email_verified_at is None:
        raise _error(
            "email_not_verified",
            "Verify your email address before signing in.",
            403,
        )

    stamp = auth_policy.iso(now)
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = stamp
    user.updated_at = stamp
    token, expires = _issue_session(db, user, request, policy)
    _audit(db, request, user.user_id, "LOGIN_SUCCESS", 200)
    db.commit()
    return {
        "accessToken": token,
        "tokenType": "bearer",
        "expiresAt": expires,
        "user": _user_json(user),
    }


@router.post("/password-reset/request", status_code=202)
def request_password_reset(
    body: EmailBody,
    request: Request,
    db: Session = Depends(get_db),
):
    settings = get_settings()
    _check_mail_configuration(settings)
    now = _now()
    _check_reset_ip_limit(db, request, settings, now)
    user = db.scalar(
        select(User).where(
            User.email == body.email,
            User.is_active.is_(True),
            User.email_verified_at.is_not(None),
            User.password_hash.is_not(None),
            User.auth_provider.in_(("local", "google")),
        )
    )
    if user is None:
        return _generic_reset_response()

    code = _new_otp(db, user, request, "password_reset", now)
    if code is not None:
        db.commit()
        _deliver_otp(settings, user.email, code, "password_reset")
    else:
        db.rollback()
    return _generic_reset_response()


@router.post("/password-reset/resend", status_code=202)
def resend_password_reset_code(
    body: EmailBody,
    request: Request,
    db: Session = Depends(get_db),
):
    return request_password_reset(body, request, db)


@router.post("/password-reset/verify")
def verify_password_reset_code(body: OtpVerificationBody, db: Session = Depends(get_db)):
    user = db.scalar(
        select(User).where(
            User.email == body.email,
            User.is_active.is_(True),
            User.email_verified_at.is_not(None),
            User.password_hash.is_not(None),
            User.auth_provider.in_(("local", "google")),
        )
    )
    now = _now()
    challenge = _verify_otp(db, user, body.email, "password_reset", body.code, now)
    token = new_token()
    reset = PasswordResetToken(
        user_id=challenge.user_id,
        token_hash=token_hash(token),
        expires_at=_timestamp(now + timedelta(minutes=RESET_AUTH_TTL_MINUTES)),
    )
    db.add(reset)
    db.commit()
    return {"resetAuthorization": token, "expiresInSeconds": RESET_AUTH_TTL_MINUTES * 60}


@router.post("/password-reset/confirm")
def confirm_password_reset(
    body: PasswordResetConfirmBody,
    request: Request,
    db: Session = Depends(get_db),
):
    now_text = _timestamp(_now())
    claimed = db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == token_hash(body.token),
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now_text,
        )
        .values(used_at=now_text)
    )
    if claimed.rowcount != 1:
        db.rollback()
        raise _error(
            "invalid_reset_authorization",
            "The password reset authorization is invalid or expired. Request a new code.",
            400,
        )
    reset = db.scalar(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash(body.token)
        )
    )
    user = db.get(User, reset.user_id) if reset else None
    if (
        user is None
        or user.auth_provider not in {"local", "google"}
        or user.password_hash is None
        or user.email_verified_at is None
    ):
        db.rollback()
        raise _error(
            "invalid_reset_authorization",
            "The password reset authorization is invalid or expired. Request a new code.",
            400,
        )

    user.password_hash = hash_password(body.new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    user.updated_at = now_text
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.user_id,
            PasswordResetToken.reset_id != reset.reset_id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=now_text)
    )
    db.execute(
        update(UserSession)
        .where(
            UserSession.user_id == user.user_id,
            UserSession.revoked_at.is_(None),
        )
        .values(revoked_at=now_text)
    )
    _audit(db, request, user.user_id, "PASSWORD_RESET", 200)
    db.commit()
    return {"message": "Password reset successfully. Sign in with your new password."}


@router.post("/google-password-setup/request", status_code=202)
def request_google_password_setup(
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    settings = get_settings()
    _check_mail_configuration(settings)
    user = db.get(User, user_id)
    if (
        user is None
        or user.auth_provider != "google"
        or user.password_hash is not None
        or user.email_verified_at is None
        or not user.is_active
    ):
        raise _error(
            "password_setup_unavailable",
            "Password setup is only available for an active Google account without a local password.",
            409,
        )
    code = _new_otp(db, user, request, "google_password_setup", _now())
    if code is None:
        db.rollback()
        raise _error(
            "verification_rate_limited",
            "A verification code was recently requested. Try again later.",
            429,
        )
    db.commit()
    if not _deliver_otp(settings, user.email, code, "google_password_setup"):
        raise _error(
            "email_delivery_failed",
            "The verification code could not be delivered. Try again later.",
            503,
        )
    return {"message": "If email delivery succeeded, enter the code to set up password sign-in."}


@router.post("/google-password-setup/confirm")
def confirm_google_password_setup(
    body: GooglePasswordSetupBody,
    request: Request,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user),
):
    user = db.get(User, user_id)
    if (
        user is None
        or user.auth_provider != "google"
        or user.password_hash is not None
        or user.email_verified_at is None
        or not user.is_active
    ):
        raise _error(
            "password_setup_unavailable",
            "Password setup is only available for an active Google account without a local password.",
            409,
        )
    duplicate = db.scalar(
        select(User.user_id).where(
            func.lower(User.username) == body.username,
            User.user_id != user.user_id,
        )
    )
    if duplicate is not None:
        raise _error(
            "username_already_registered",
            "That username is already in use.",
            409,
        )
    challenge = _verify_otp(
        db, user, user.email, "google_password_setup", body.code, _now()
    )
    user.username = body.username
    user.password_hash = hash_password(body.password)
    user.updated_at = _timestamp(_now())
    db.add(challenge)
    _audit(db, request, user.user_id, "PASSWORD_CHANGED", 200)
    db.commit()
    return {"user": _user_json(user)}


def _google_is_configured(settings: Settings) -> bool:
    return bool(
        settings.google_client_id
        and settings.google_client_secret
        and settings.google_client_secret.get_secret_value()
        and settings.google_redirect_uri
    )


def _google_error_redirect(settings: Settings, code: str) -> RedirectResponse:
    url = f"{settings.frontend_base_url.rstrip('/')}/login?{urlencode({'error': code})}"
    return RedirectResponse(
        url,
        status_code=303,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@router.get("/google/start", name="google_start")
def google_start(request: Request, db: Session = Depends(get_db)):
    settings = get_settings()
    if not _google_is_configured(settings):
        return _google_error_redirect(settings, "google_login_unavailable")
    state = new_token()
    nonce = new_token()
    now = _now()
    db.add(
        OAuthState(
            state_hash=token_hash(state),
            nonce_hash=token_hash(nonce),
            expires_at=_timestamp(now + timedelta(minutes=OAUTH_STATE_TTL_MINUTES)),
        )
    )
    db.commit()
    query = urlencode(
        {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.google_redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
        }
    )
    return RedirectResponse(
        f"https://accounts.google.com/o/oauth2/v2/auth?{query}",
        status_code=302,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


def _consume_google_state(db: Session, state: str, now: datetime) -> OAuthState | None:
    now_text = _timestamp(now)
    result = db.execute(
        update(OAuthState)
        .where(
            OAuthState.state_hash == token_hash(state),
            OAuthState.consumed_at.is_(None),
            OAuthState.expires_at > now_text,
        )
        .values(consumed_at=now_text)
    )
    if result.rowcount != 1:
        db.rollback()
        return None
    record = db.scalar(
        select(OAuthState).where(OAuthState.state_hash == token_hash(state))
    )
    return record


def _google_claims(code: str, nonce_hash: str, settings: Settings) -> dict[str, object]:
    if not settings.google_client_id or not settings.google_client_secret:
        raise ValueError("Google OAuth configuration is incomplete.")
    response = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret.get_secret_value(),
            "redirect_uri": settings.google_redirect_uri,
            "grant_type": "authorization_code",
        },
        timeout=10,
    )
    response.raise_for_status()
    credentials = response.json()
    raw_id_token = credentials.get("id_token") if isinstance(credentials, dict) else None
    if not isinstance(raw_id_token, str):
        raise ValueError("Google token response did not include an identity token.")
    claims = id_token.verify_oauth2_token(
        raw_id_token,
        GoogleRequest(),
        settings.google_client_id,
    )
    if not isinstance(claims, dict):
        raise ValueError("Google identity token claims were invalid.")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    expires = claims.get("exp")
    if (
        settings.google_client_id not in audiences
        or claims.get("iss") not in {"accounts.google.com", "https://accounts.google.com"}
        or not isinstance(expires, (int, float))
        or expires <= _now().timestamp()
        or not isinstance(claims.get("nonce"), str)
        or not hmac.compare_digest(token_hash(claims["nonce"]), nonce_hash)
        or claims.get("email_verified") is not True
    ):
        raise ValueError("Google identity token claims failed validation.")
    if not isinstance(claims.get("sub"), str) or not isinstance(claims.get("email"), str):
        raise ValueError("Google identity token is missing required claims.")
    return claims


def _google_username(db: Session, email: str) -> str:
    local = email.split("@", 1)[0].lower()
    base = re.sub(r"[^a-z0-9._-]+", "-", local).strip("._-")[:24] or "google-user"
    candidate = base if len(base) >= 3 else f"user-{base}"
    if db.scalar(select(User.user_id).where(func.lower(User.username) == candidate)) is None:
        return candidate
    for _ in range(10):
        suffix = secrets.token_hex(2)
        candidate = f"{base[:27]}-{suffix}"
        if db.scalar(
            select(User.user_id).where(func.lower(User.username) == candidate)
        ) is None:
            return candidate
    raise _error("google_account_unavailable", "Google sign-in could not be completed.", 409)


def _get_or_create_google_user(
    db: Session,
    claims: dict[str, object],
    now_text: str,
) -> User:
    subject = str(claims["sub"])
    email = _normalized_email(str(claims["email"]))
    user = db.scalar(
        select(User).where(
            User.auth_provider == "google",
            User.sso_subject_id == subject,
        )
    )
    if user is not None:
        if not user.is_active:
            raise _error(
                "google_account_unavailable",
                "This Google account is not active.",
                403,
            )
        return user

    existing = db.scalar(
        select(User.user_id).where(func.lower(User.email) == email)
    )
    if existing is not None:
        raise _error(
            "google_account_link_required",
            "Sign in to the existing account before linking another sign-in method.",
            409,
        )
    name = claims.get("name")
    user = User(
        full_name=str(name or email).strip()[:120],
        email=email,
        username=_google_username(db, email),
        email_verified_at=now_text,
        auth_provider="google",
        sso_subject_id=subject,
        sso_idp_entity_id="google",
        role="analyst",
        is_active=True,
    )
    db.add(user)
    db.flush()
    db.add(UserSettings(user_id=user.user_id, auto_save_scan_logs=True))
    return user


@router.get("/google/callback", name="google_callback")
def google_callback(
    request: Request,
    state: Annotated[str, Field(min_length=32, max_length=128)],
    code: Annotated[str | None, Field(max_length=4096)] = None,
    error: Annotated[str | None, Field(max_length=128)] = None,
    db: Session = Depends(get_db),
):
    settings = get_settings()
    if not _google_is_configured(settings):
        raise _error(
            "google_login_unavailable",
            "Google sign-in is not configured on this server.",
            503,
        )
    state_record = _consume_google_state(db, state, _now())
    if state_record is None:
        return _google_error_redirect(settings, "google_state_invalid")
    db.commit()
    if error or not code:
        return _google_error_redirect(settings, "google_sign_in_cancelled")
    try:
        claims = _google_claims(code, state_record.nonce_hash, settings)
        now = _now()
        user = _get_or_create_google_user(db, claims, _timestamp(now))
        ticket = new_token()
        db.add(
            OAuthLoginTicket(
                ticket_hash=token_hash(ticket),
                user_id=user.user_id,
                expires_at=_timestamp(now + timedelta(minutes=OAUTH_TICKET_TTL_MINUTES)),
            )
        )
        db.commit()
    except (requests.RequestException, GoogleAuthError, ValueError) as exc:
        db.rollback()
        logger.warning("Google sign-in failed (%s)", type(exc).__name__)
        return _google_error_redirect(settings, "google_sign_in_failed")
    except HTTPException as exc:
        db.rollback()
        code_name = (
            exc.detail.get("code")
            if isinstance(exc.detail, dict)
            else "google_sign_in_failed"
        )
        return _google_error_redirect(settings, str(code_name))
    except IntegrityError:
        db.rollback()
        return _google_error_redirect(settings, "google_account_link_required")

    url = (
        f"{settings.frontend_base_url.rstrip('/')}/login?"
        f"{urlencode({'oauth_ticket': ticket})}"
    )
    return RedirectResponse(
        url,
        status_code=303,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@router.post("/google/exchange")
def exchange_google_ticket(
    body: GoogleTicketBody,
    request: Request,
    db: Session = Depends(get_db),
):
    now = _now()
    now_text = _timestamp(now)
    claim = db.execute(
        update(OAuthLoginTicket)
        .where(
            OAuthLoginTicket.ticket_hash == token_hash(body.ticket),
            OAuthLoginTicket.consumed_at.is_(None),
            OAuthLoginTicket.expires_at > now_text,
        )
        .values(consumed_at=now_text)
    )
    if claim.rowcount != 1:
        db.rollback()
        raise _error(
            "invalid_oauth_ticket",
            "Google sign-in has expired. Please try again.",
            400,
        )
    ticket = db.scalar(
        select(OAuthLoginTicket).where(
            OAuthLoginTicket.ticket_hash == token_hash(body.ticket)
        )
    )
    user = db.get(User, ticket.user_id) if ticket else None
    if user is None or not user.is_active:
        db.rollback()
        raise _error(
            "invalid_oauth_ticket",
            "Google sign-in has expired. Please try again.",
            400,
        )
    policy = _load_policy(db)
    stamp = auth_policy.iso(now)
    user.last_login_at = stamp
    user.updated_at = stamp
    token, expires = _issue_session(db, user, request, policy)
    _audit(db, request, user.user_id, "LOGIN_SUCCESS", 200)
    db.commit()
    return {
        "accessToken": token,
        "tokenType": "bearer",
        "expiresAt": expires,
        "user": _user_json(user),
    }


@router.get("/me")
def me(user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise _error("invalid_token", "The session is invalid.", 401)
    return {"user": _user_json(user)}


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    user_id: int = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session_id = getattr(request.state, "auth_session_id", None)
    session = db.get(UserSession, session_id) if session_id else None
    if session is not None and session.user_id == user_id and session.revoked_at is None:
        session.revoked_at = _timestamp(_now())
        _audit(db, request, user_id, "LOGOUT", 204)
        db.commit()
    return Response(status_code=204)
