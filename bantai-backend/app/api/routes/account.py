from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.schemas.account import PasswordChange, PreferencesUpdate, ProfileUpdate
from app.services import account_repo, account_service, auth_policy, scan_store
from app.services.account_service import AccountError
from app.services.history_repo import session_runner

router = APIRouter(prefix="/account", tags=["Account"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _http(exc: AccountError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message})


def _audit(db: Session, request: Request, user_id: int, event: str, detail: dict) -> None:
    scan_store.write_audit(
        db, event_type=event, http_status=200, detail=detail, user_id=user_id, scan_id=None,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()


@router.get("/profile", response_model=None)
def get_profile(response: Response, db: Session = Depends(get_db), user_id: int = Depends(get_current_user)):
    profile = account_service.get_profile(session_runner(db), user_id)
    if profile is None:
        raise HTTPException(404, detail={"code": "not_found", "message": "Account not found."})
    response.headers["Cache-Control"] = "no-store"
    return profile


@router.patch("/profile", response_model=None)
def update_profile(
    body: ProfileUpdate, request: Request, response: Response,
    db: Session = Depends(get_db), user_id: int = Depends(get_current_user),
):
    """Change name, job title, picture or email. Changing the email needs `currentPassword`."""
    changes = {name: getattr(body, name) for name in body.model_fields_set}
    run = session_runner(db)
    try:
        policy = auth_policy.policy_from_settings(account_repo.system_settings(run))
        profile = account_service.update_profile(run, user_id, changes, policy, _now())
        db.commit()
    except AccountError as exc:
        db.commit()               # keep the failed-password counter even though the request fails
        raise _http(exc) from None
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, detail={"code": "email_already_registered",
                                         "message": "An account with this email already exists."}) from None
    changed = sorted(k for k in changes if k != "current_password")
    if changed:
        _audit(db, request, user_id, "PROFILE_UPDATED", {"fields": changed})     # names only, never values
    response.headers["Cache-Control"] = "no-store"
    return profile


@router.post("/password", response_model=None)
def change_password(
    body: PasswordChange, request: Request, response: Response,
    db: Session = Depends(get_db), user_id: int = Depends(get_current_user),
):
    """Change your password. Every other signed-in session is signed out; this one stays."""
    run = session_runner(db)
    try:
        policy = auth_policy.policy_from_settings(account_repo.system_settings(run))
        account_service.change_password(
            run, user_id, getattr(request.state, "auth_session_id", None),
            body.current_password, body.new_password, policy, _now(),
        )
        db.commit()
    except AccountError as exc:
        db.commit()
        raise _http(exc) from None
    _audit(db, request, user_id, "PASSWORD_CHANGED", {})
    response.headers["Cache-Control"] = "no-store"
    return {"changed": True}


@router.get("/settings", response_model=None)
def get_settings(response: Response, db: Session = Depends(get_db), user_id: int = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    return account_service.get_preferences(session_runner(db), user_id)


@router.patch("/settings", response_model=None)
def update_settings(
    body: PreferencesUpdate, request: Request, response: Response,
    db: Session = Depends(get_db), user_id: int = Depends(get_current_user),
):
    """Display preferences: shapAdvancedMode, autoSaveScanLogs (off = scans leave only an audit entry)."""
    changes = {name: getattr(body, name) for name in body.model_fields_set if getattr(body, name) is not None}
    result = account_service.update_preferences(session_runner(db), user_id, changes, _now())
    db.commit()
    if changes:
        _audit(db, request, user_id, "SETTINGS_UPDATED", {"fields": sorted(changes)})
    response.headers["Cache-Control"] = "no-store"
    return result
