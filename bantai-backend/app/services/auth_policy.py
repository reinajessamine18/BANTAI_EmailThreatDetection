"""Login lockout and session-length rules (pure; no database, no web framework).

Values come from `system_settings` (seeded in seed.sql, ASSUMED defaults): max_failed_logins=5,
lockout_minutes=15, session_ttl_hours=8. Invalid or missing settings fall back to those defaults.

Known trade-off: lockout is per account, so someone who knows an email can lock that account
for `lockout_minutes` (a denial of service). There is no per-IP rate limit yet.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Mapping, Optional, Tuple

from app.api.auth_security import hash_password, verify_password

_FMT = "%Y-%m-%dT%H:%M:%SZ"


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(_FMT)


@dataclass(frozen=True)
class AuthPolicy:
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    session_ttl_hours: int = 8


def _bounded(raw: Optional[str], default: int, low: int, high: int) -> int:
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if low <= value <= high else default


def policy_from_settings(settings: Mapping[str, str]) -> AuthPolicy:
    return AuthPolicy(
        max_failed_logins=_bounded(settings.get("max_failed_logins"), 5, 1, 100),
        lockout_minutes=_bounded(settings.get("lockout_minutes"), 15, 1, 1440),
        session_ttl_hours=_bounded(settings.get("session_ttl_hours"), 8, 1, 720),
    )


def is_locked(locked_until: Optional[str], now_iso: str) -> bool:
    return bool(locked_until) and locked_until > now_iso


def register_failure(attempts: int, policy: AuthPolicy, now: datetime) -> Tuple[int, Optional[str]]:
    """New (failed_attempts, locked_until) after one more failure. Locking resets the counter."""
    attempts += 1
    if attempts >= policy.max_failed_logins:
        return 0, iso(now + timedelta(minutes=policy.lockout_minutes))
    return attempts, None


def session_expiry(now: datetime, policy: AuthPolicy) -> str:
    return iso(now + timedelta(hours=policy.session_ttl_hours))


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return hash_password("dummy-" + secrets.token_urlsafe(8))


def dummy_verify(password: str) -> None:
    """Spend the same time as a real check, so an unknown or locked account is not detectable by timing."""
    verify_password(password, _dummy_hash())
