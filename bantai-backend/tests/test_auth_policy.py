from datetime import datetime, timedelta, timezone

import pytest

from app.api.auth_security import verify_password
from app.services import auth_policy
from app.services.auth_policy import (
    AuthPolicy, dummy_verify, is_locked, iso, policy_from_settings, register_failure, session_expiry,
)

NOW = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)


def test_defaults_when_settings_missing():
    assert policy_from_settings({}) == AuthPolicy(5, 15, 8)


def test_valid_settings_are_used():
    p = policy_from_settings({"max_failed_logins": "3", "lockout_minutes": " 30 ", "session_ttl_hours": "12"})
    assert p == AuthPolicy(3, 30, 12)


@pytest.mark.parametrize("bad", ["abc", "", "0", "-5", "1.5", "99999", None])
def test_invalid_or_out_of_range_settings_fall_back_to_defaults(bad):
    p = policy_from_settings({"max_failed_logins": bad, "lockout_minutes": bad, "session_ttl_hours": bad})
    assert p == AuthPolicy(5, 15, 8)


def test_five_failures_lock_the_account_and_reset_the_counter():
    policy, attempts = AuthPolicy(), 0
    for expected in (1, 2, 3, 4):
        attempts, locked = register_failure(attempts, policy, NOW)
        assert (attempts, locked) == (expected, None)
    attempts, locked = register_failure(attempts, policy, NOW)
    assert attempts == 0 and locked == "2026-10-13T12:15:00Z"


def test_one_attempt_policy_locks_immediately():
    assert register_failure(0, AuthPolicy(max_failed_logins=1), NOW) == (0, "2026-10-13T12:15:00Z")


def test_is_locked_is_strictly_in_the_future():
    now = iso(NOW)
    assert not is_locked(None, now) and not is_locked("", now)
    assert is_locked("2026-10-13T12:00:01Z", now)
    assert not is_locked("2026-10-13T12:00:00Z", now)          # lock ends exactly now
    assert not is_locked("2026-10-13T11:00:00Z", now)


def test_lock_expires_with_time():
    _, locked = register_failure(4, AuthPolicy(), NOW)
    assert is_locked(locked, iso(NOW + timedelta(minutes=14)))
    assert not is_locked(locked, iso(NOW + timedelta(minutes=16)))


def test_session_expiry_uses_the_configured_hours():
    assert session_expiry(NOW, AuthPolicy(session_ttl_hours=8)) == "2026-10-13T20:00:00Z"
    assert session_expiry(NOW, AuthPolicy(session_ttl_hours=1)) == "2026-10-13T13:00:00Z"


def test_dummy_verify_never_raises_and_uses_one_stable_hash():
    for password in ("", "x", "p" * 128, "ünïcode✓"):
        assert dummy_verify(password) is None
    assert auth_policy._dummy_hash() is auth_policy._dummy_hash()
    assert not verify_password("anything", auth_policy._dummy_hash())
