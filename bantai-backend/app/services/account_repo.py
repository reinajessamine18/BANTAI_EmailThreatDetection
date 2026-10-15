"""SQL for profile, password, sessions and preferences (same `Execute` seam as history_repo).

Column names in UPDATE statements come from a fixed whitelist, never from request keys.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from app.services.history_repo import Execute

_PROFILE_COLUMNS = ("full_name", "job_title", "profile_picture", "email")


def get_user(execute: Execute, user_id: int) -> Optional[Dict[str, Any]]:
    rows = execute(
        "SELECT user_id, full_name, email, role, job_title, tier_label, profile_picture, "
        "password_hash, auth_provider, failed_login_attempts, locked_until "
        "FROM users WHERE user_id = :uid",
        {"uid": user_id},
    )
    return rows[0] if rows else None


def email_owner(execute: Execute, email: str) -> Optional[int]:
    rows = execute("SELECT user_id FROM users WHERE lower(email) = :email", {"email": email})
    return rows[0]["user_id"] if rows else None


def update_user(execute: Execute, user_id: int, fields: Mapping[str, Any], now_iso: str) -> None:
    columns = [c for c in _PROFILE_COLUMNS if c in fields]
    if not columns:
        return
    assignments = ", ".join(f"{c} = :{c}" for c in columns)
    execute(
        f"UPDATE users SET {assignments}, updated_at = :now WHERE user_id = :uid",
        {**{c: fields[c] for c in columns}, "now": now_iso, "uid": user_id},
    )


def set_lock_state(execute: Execute, user_id: int, attempts: int, locked_until: Optional[str]) -> None:
    execute(
        "UPDATE users SET failed_login_attempts = :attempts, locked_until = :locked WHERE user_id = :uid",
        {"attempts": attempts, "locked": locked_until, "uid": user_id},
    )


def set_password(execute: Execute, user_id: int, new_hash: str, now_iso: str) -> None:
    execute(
        "UPDATE users SET password_hash = :hash, failed_login_attempts = 0, locked_until = NULL, "
        "updated_at = :now WHERE user_id = :uid",
        {"hash": new_hash, "now": now_iso, "uid": user_id},
    )


def revoke_other_sessions(execute: Execute, user_id: int, keep_session_id: Optional[int], now_iso: str) -> None:
    execute(
        "UPDATE user_sessions SET revoked_at = :now "
        "WHERE user_id = :uid AND revoked_at IS NULL AND session_id != :keep",
        {"now": now_iso, "uid": user_id, "keep": -1 if keep_session_id is None else keep_session_id},
    )


def get_preferences(execute: Execute, user_id: int) -> Optional[Dict[str, Any]]:
    rows = execute(
        "SELECT shap_advanced_mode, auto_save_scan_logs FROM user_settings WHERE user_id = :uid",
        {"uid": user_id},
    )
    return rows[0] if rows else None


def upsert_preferences(execute: Execute, user_id: int, shap: int, autosave: int, now_iso: str) -> None:
    execute(
        "INSERT INTO user_settings (user_id, shap_advanced_mode, auto_save_scan_logs, updated_at) "
        "VALUES (:uid, :shap, :auto, :now) "
        "ON CONFLICT (user_id) DO UPDATE SET shap_advanced_mode = excluded.shap_advanced_mode, "
        "auto_save_scan_logs = excluded.auto_save_scan_logs, updated_at = excluded.updated_at",
        {"uid": user_id, "shap": shap, "auto": autosave, "now": now_iso},
    )


def system_settings(execute: Execute) -> Dict[str, str]:
    return {r["setting_key"]: r["setting_value"] for r in
            execute("SELECT setting_key, setting_value FROM system_settings", {})}
