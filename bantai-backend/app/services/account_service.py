"""Profile, email, password and preference changes for the signed-in user.

Security rules:
* Changing the password or the email requires the CURRENT password. Wrong guesses count toward
  the same lockout as login, so a stolen session token cannot be used to brute-force it.
* After a password change every OTHER session is revoked; the current one stays.
* Error messages never say which of "wrong password" / "locked" happened.
* The audit log (written by the route) records field NAMES only, never values.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Mapping, Optional

from app.api.auth_security import hash_password, verify_password
from app.services import account_repo as repo
from app.services import auth_policy
from app.services.account_rules import clean_text, is_valid_picture, normalize_email
from app.services.history_repo import Execute

MIN_PASSWORD, MAX_PASSWORD = 10, 128
_WRONG = "The current password is incorrect, or the account is temporarily locked."


class AccountError(Exception):
    def __init__(self, code: str, message: str, status: int = 422):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _profile(row: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "userId": row["user_id"],
        "fullName": row["full_name"],
        "email": row["email"],
        "role": row["role"],
        "jobTitle": row["job_title"],
        "tierLabel": row["tier_label"],
        "profilePicture": row["profile_picture"],
    }


def get_profile(execute: Execute, user_id: int) -> Optional[Dict[str, Any]]:
    row = repo.get_user(execute, user_id)
    return _profile(row) if row else None


def _require_current_password(execute: Execute, row: Mapping[str, Any], supplied: Optional[str],
                              policy: auth_policy.AuthPolicy, now: datetime) -> None:
    if auth_policy.is_locked(row["locked_until"], auth_policy.iso(now)):
        auth_policy.dummy_verify(supplied or "")
        raise AccountError("invalid_current_password", _WRONG, 403)
    if not supplied or not verify_password(supplied, row["password_hash"]):
        attempts, locked_until = auth_policy.register_failure(row["failed_login_attempts"] or 0, policy, now)
        repo.set_lock_state(execute, row["user_id"], attempts, locked_until)
        raise AccountError("invalid_current_password", _WRONG, 403)


def update_profile(execute: Execute, user_id: int, changes: Mapping[str, Any],
                   policy: auth_policy.AuthPolicy, now: datetime) -> Dict[str, Any]:
    """`changes` holds only the fields the client actually sent (None means 'clear')."""
    row = repo.get_user(execute, user_id)
    if row is None:
        raise AccountError("not_found", "Account not found.", 404)

    fields: Dict[str, Any] = {}
    if "full_name" in changes:
        name = clean_text(changes["full_name"], 120)
        if len(name) < 2:
            raise AccountError("invalid_name", "Name must be 2 to 120 characters.")
        fields["full_name"] = name
    if "job_title" in changes:
        fields["job_title"] = clean_text(changes["job_title"], 120) or None
    if "profile_picture" in changes:
        picture = changes["profile_picture"]
        if picture is not None and not is_valid_picture(picture):
            raise AccountError("invalid_picture", "Use a PNG, JPEG, WebP or GIF image under about 300 KB.")
        fields["profile_picture"] = picture

    if "email" in changes:
        email = normalize_email(changes["email"])
        if email is None:
            raise AccountError("invalid_email", "Enter a valid email address.")
        if email != (row["email"] or "").lower():
            if not changes.get("current_password"):
                raise AccountError("password_required", "Enter your current password to change your email.")
            _require_current_password(execute, row, changes.get("current_password"), policy, now)
            owner = repo.email_owner(execute, email)
            if owner is not None and owner != user_id:
                raise AccountError("email_already_registered", "An account with this email already exists.", 409)
            fields["email"] = email

    repo.update_user(execute, user_id, fields, auth_policy.iso(now))
    return get_profile(execute, user_id)


def change_password(execute: Execute, user_id: int, session_id: Optional[int], current: str,
                    new: str, policy: auth_policy.AuthPolicy, now: datetime) -> None:
    if not (MIN_PASSWORD <= len(new) <= MAX_PASSWORD):
        raise AccountError("weak_password", f"The new password must be {MIN_PASSWORD} to {MAX_PASSWORD} characters.")
    row = repo.get_user(execute, user_id)
    if row is None:
        raise AccountError("not_found", "Account not found.", 404)
    _require_current_password(execute, row, current, policy, now)
    if verify_password(new, row["password_hash"]):
        raise AccountError("password_unchanged", "The new password must be different from the current one.")
    now_iso = auth_policy.iso(now)
    repo.set_password(execute, user_id, hash_password(new), now_iso)
    repo.revoke_other_sessions(execute, user_id, session_id, now_iso)


def get_preferences(execute: Execute, user_id: int) -> Dict[str, bool]:
    row = repo.get_preferences(execute, user_id)       # no row yet = the defaults (both on)
    return {
        "shapAdvancedMode": True if row is None else bool(row["shap_advanced_mode"]),
        "autoSaveScanLogs": True if row is None else bool(row["auto_save_scan_logs"]),
    }


def update_preferences(execute: Execute, user_id: int, changes: Mapping[str, bool], now: datetime) -> Dict[str, bool]:
    current = get_preferences(execute, user_id)
    shap = changes.get("shap_advanced_mode", current["shapAdvancedMode"])
    auto = changes.get("auto_save_scan_logs", current["autoSaveScanLogs"])
    repo.upsert_preferences(execute, user_id, 1 if shap else 0, 1 if auto else 0, auth_policy.iso(now))
    return get_preferences(execute, user_id)
