"""Local account registration, login, current-user, and logout endpoints."""
from __future__ import annotations
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from app.api.auth_security import hash_password, new_token, token_hash, verify_password
from app.api.deps import get_current_user, get_current_user_optional
from app.db.models import AuditLog, SystemSetting, User, UserSession, UserSettings
from app.db.session import get_db
from app.services import auth_policy  # [S7b] lockout + session length

router = APIRouter(prefix="/auth", tags=["Authentication"])
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=2, max_length=120)]
Password = Annotated[str, Field(min_length=10, max_length=128)]

class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    full_name: Name
    email: str
    password: Password

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        value = value.strip().lower()
        if len(value) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Enter a valid email address.")
        return value

class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    password: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        value = value.strip().lower()
        if len(value) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Enter a valid email address.")
        return value

class UserResponse(BaseModel):
    user_id: int
    full_name: str
    email: str
    role: str
    created_at: str

def _user_json(user: User) -> dict:
    return {"userId": user.user_id, "fullName": user.full_name, "email": user.email, "role": user.role, "createdAt": user.created_at}

def _audit(db: Session, request: Request, user_id: int | None, event_type: str, status: int) -> None:
    db.add(AuditLog(user_id=user_id, event_type=event_type, http_status=status,
        ip_address=(request.client.host[:64] if request.client else None),
        user_agent=request.headers.get("user-agent", "")[:300] or None))

def _load_policy(db: Session) -> auth_policy.AuthPolicy:
    # [S7b] lockout / session length come from system_settings (seed.sql) instead of being hardcoded
    rows = db.execute(select(SystemSetting.setting_key, SystemSetting.setting_value)).all()
    return auth_policy.policy_from_settings({key: value for key, value in rows})

def _issue_session(db: Session, user: User, request: Request, policy: auth_policy.AuthPolicy) -> tuple[str, str]:
    token = new_token()
    expires = auth_policy.session_expiry(datetime.now(timezone.utc), policy)
    db.add(UserSession(user_id=user.user_id, token_hash=token_hash(token),
        ip_address=(request.client.host[:64] if request.client else None),
        user_agent=request.headers.get("user-agent", "")[:300] or None, expires_at=expires))
    return token, expires

@router.post("/register", status_code=201)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    policy = _load_policy(db)
    email = str(body.email).strip().lower()
    if db.scalar(select(User.user_id).where(User.email == email)) is not None:
        raise HTTPException(status_code=409, detail={"code":"email_already_registered", "message":"An account with this email already exists."})
    user = User(full_name=body.full_name.strip(), email=email, password_hash=hash_password(body.password), auth_provider="local", role="analyst", is_active=True)
    try:
        db.add(user); db.flush()
        db.add(UserSettings(user_id=user.user_id))
        token, expires = _issue_session(db, user, request, policy)
        _audit(db, request, user.user_id, "USER_REGISTERED", 201)
        db.commit(); db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail={"code":"email_already_registered", "message":"An account with this email already exists."}) from None
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail={"code":"registration_failed", "message":"The account could not be created."}) from None
    return {"accessToken":token, "tokenType":"bearer", "expiresAt":expires, "user":_user_json(user)}

@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    # [S7b] Brute-force lockout + equal timing. Every failure path (wrong password, unknown email,
    # locked account) returns the SAME response and costs the same time, so neither is detectable.
    policy = _load_policy(db)
    now = datetime.now(timezone.utc)
    email = str(body.email).strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    usable = user is not None and user.auth_provider == "local"
    locked = usable and auth_policy.is_locked(user.locked_until, auth_policy.iso(now))
    if usable and not locked:
        password_ok = verify_password(body.password, user.password_hash)
    else:
        auth_policy.dummy_verify(body.password)
        password_ok = False
    if not password_ok:
        if usable and not locked:
            user.failed_login_attempts, user.locked_until = auth_policy.register_failure(
                user.failed_login_attempts or 0, policy, now)
        _audit(db, request, user.user_id if user else None, "LOGIN_FAILED", 401)
        db.commit()
        raise HTTPException(status_code=401, detail={"code":"invalid_credentials", "message":"Email or password is incorrect, or the account is temporarily locked."}, headers={"WWW-Authenticate":"Bearer"})
    if not user.is_active:
        raise HTTPException(status_code=403, detail={"code":"inactive_account", "message":"This account is disabled."})
    stamp = auth_policy.iso(now)
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = stamp
    user.updated_at = stamp
    token, expires = _issue_session(db, user, request, policy)
    _audit(db, request, user.user_id, "LOGIN_SUCCESS", 200)
    db.commit()
    return {"accessToken":token, "tokenType":"bearer", "expiresAt":expires, "user":_user_json(user)}

@router.get("/me")
def me(user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=401, detail={"code":"invalid_token", "message":"The session is invalid."})
    return {"user":_user_json(user)}

@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, user_id: int = Depends(get_current_user), db: Session = Depends(get_db)):
    session_id = getattr(request.state, "auth_session_id", None)
    session = db.get(UserSession, session_id) if session_id else None
    if session is not None and session.user_id == user_id and session.revoked_at is None:
        session.revoked_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _audit(db, request, user_id, "LOGOUT", 204)
        db.commit()
    return Response(status_code=204)
