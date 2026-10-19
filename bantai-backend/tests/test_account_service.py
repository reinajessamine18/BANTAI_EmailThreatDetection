"""Profile / email / password / preferences: real SQL on a real SQLite database."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.api.auth_security import hash_password, verify_password
from app.db.init_db import init_db
from app.services import account_service as svc
from app.services.account_service import AccountError
from app.services.auth_policy import AuthPolicy
from tests.helpers import SQL_DIR, sqlite_runner

NOW = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)
POLICY = AuthPolicy()
PASSWORD = "Original passphrase 123!"
HASH = hash_password(PASSWORD)                      # computed once: PBKDF2 is deliberately slow
PNG = "data:image/png;base64,AAAA"


def world(tmp_path):
    db = tmp_path / "acc.db"
    init_db(db, SQL_DIR, None)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("INSERT INTO users (user_id, full_name, email, password_hash, job_title) VALUES"
                 " (1, 'Ana Test', 'ana@example.com', ?, 'Analyst'), (2, 'Ben Other', 'ben@example.com', ?, NULL)",
                 (HASH, HASH))
    conn.execute("INSERT INTO users (user_id, full_name, email, password_hash, auth_provider, sso_subject_id,"
                 " sso_idp_entity_id) VALUES (3, 'Sso User', 'sso@example.com', NULL, 'saml', 's', 'i')")
    for sid, uid in ((10, 1), (11, 1), (20, 2)):
        conn.execute("INSERT INTO user_sessions (session_id, user_id, token_hash, expires_at) VALUES (?, ?, ?, '2030-01-01T00:00:00Z')",
                     (sid, uid, f"hash{sid}"))
    conn.commit()
    return conn, sqlite_runner(conn)


def lock_state(conn, uid=1):
    row = conn.execute("SELECT failed_login_attempts, locked_until FROM users WHERE user_id = ?", (uid,)).fetchone()
    return tuple(row)          # sqlite3.Row does not compare equal to a tuple


def fail(call, code, status):
    with pytest.raises(AccountError) as err:
        call()
    assert (err.value.code, err.value.status) == (code, status)


# ------------------------------------------------------------------------------ profile
def test_get_profile_and_missing_user(tmp_path):
    _, run = world(tmp_path)
    p = svc.get_profile(run, 1)
    assert (p["fullName"], p["email"], p["jobTitle"], p["role"]) == ("Ana Test", "ana@example.com", "Analyst", "analyst")
    assert "password" not in str(p).lower() and svc.get_profile(run, 99) is None


def test_update_name_job_title_and_picture_then_clear(tmp_path):
    _, run = world(tmp_path)
    p = svc.update_profile(run, 1, {"full_name": "  Ana   B. Test ", "job_title": "Lead", "profile_picture": PNG}, POLICY, NOW)
    assert (p["fullName"], p["jobTitle"], p["profilePicture"]) == ("Ana B. Test", "Lead", PNG)
    p = svc.update_profile(run, 1, {"job_title": "  ", "profile_picture": None}, POLICY, NOW)
    assert p["jobTitle"] is None and p["profilePicture"] is None and p["fullName"] == "Ana B. Test"


@pytest.mark.parametrize("changes,code", [
    ({"full_name": "A"}, "invalid_name"), ({"full_name": "\x00\x01"}, "invalid_name"), ({"full_name": None}, "invalid_name"),
    ({"profile_picture": "data:image/svg+xml;base64,PHN2Zz4="}, "invalid_picture"),
    ({"email": "not-an-email"}, "invalid_email"),
])
def test_invalid_profile_values_are_rejected_and_nothing_is_written(tmp_path, changes, code):
    conn, run = world(tmp_path)
    fail(lambda: svc.update_profile(run, 1, changes, POLICY, NOW), code, 422)
    assert conn.execute("SELECT full_name FROM users WHERE user_id = 1").fetchone()[0] == "Ana Test"


def test_unknown_user_is_404(tmp_path):
    _, run = world(tmp_path)
    fail(lambda: svc.update_profile(run, 99, {"full_name": "Zed Zed"}, POLICY, NOW), "not_found", 404)


def test_changes_only_touch_the_callers_row(tmp_path):
    _, run = world(tmp_path)
    svc.update_profile(run, 1, {"full_name": "Changed Name"}, POLICY, NOW)
    assert svc.get_profile(run, 2)["fullName"] == "Ben Other"


# -------------------------------------------------------------------------------- email
def test_email_change_requires_the_current_password(tmp_path):
    conn, run = world(tmp_path)
    fail(lambda: svc.update_profile(run, 1, {"email": "new@example.com"}, POLICY, NOW), "password_required", 422)
    assert lock_state(conn) == (0, None)                          # not a guess, so it is not counted
    fail(lambda: svc.update_profile(run, 1, {"email": "new@example.com", "current_password": "wrong"}, POLICY, NOW),
         "invalid_current_password", 403)
    assert lock_state(conn) == (1, None)
    p = svc.update_profile(run, 1, {"email": " New@Example.COM ", "current_password": PASSWORD}, POLICY, NOW)
    assert p["email"] == "new@example.com"


def test_email_taken_and_unchanged_email(tmp_path):
    _, run = world(tmp_path)
    fail(lambda: svc.update_profile(run, 1, {"email": "BEN@example.com", "current_password": PASSWORD}, POLICY, NOW),
         "email_already_registered", 409)
    p = svc.update_profile(run, 1, {"email": "ANA@example.com"}, POLICY, NOW)       # same address: no password needed
    assert p["email"] == "ana@example.com"


# ----------------------------------------------------------------------------- lockout
def test_repeated_wrong_passwords_lock_the_account_for_fifteen_minutes(tmp_path):
    conn, run = world(tmp_path)
    for _ in range(5):
        fail(lambda: svc.change_password(run, 1, 10, "wrong", "Brand new passphrase 9!", POLICY, NOW),
             "invalid_current_password", 403)
    attempts, locked_until = lock_state(conn)
    assert attempts == 0 and locked_until == "2026-10-13T12:15:00Z"
    # the correct password is refused while locked, and does not extend the lock
    fail(lambda: svc.change_password(run, 1, 10, PASSWORD, "Brand new passphrase 9!", POLICY, NOW + timedelta(minutes=1)),
         "invalid_current_password", 403)
    assert lock_state(conn) == (0, "2026-10-13T12:15:00Z")
    svc.change_password(run, 1, 10, PASSWORD, "Brand new passphrase 9!", POLICY, NOW + timedelta(minutes=16))
    assert lock_state(conn) == (0, None)


def test_a_locked_account_cannot_change_its_email_either(tmp_path):
    conn, run = world(tmp_path)
    conn.execute("UPDATE users SET locked_until = '2026-10-13T12:30:00Z' WHERE user_id = 1")
    conn.commit()
    fail(lambda: svc.update_profile(run, 1, {"email": "x@example.com", "current_password": PASSWORD}, POLICY, NOW),
         "invalid_current_password", 403)


# --------------------------------------------------------------------------- password
def test_password_change_rotates_the_hash_and_signs_out_other_sessions(tmp_path):
    conn, run = world(tmp_path)
    conn.execute("UPDATE users SET failed_login_attempts = 3 WHERE user_id = 1")
    conn.commit()
    svc.change_password(run, 1, 10, PASSWORD, "Brand new passphrase 9!", POLICY, NOW)
    stored = conn.execute("SELECT password_hash FROM users WHERE user_id = 1").fetchone()[0]
    assert verify_password("Brand new passphrase 9!", stored) and not verify_password(PASSWORD, stored)
    assert "Brand new" not in stored
    revoked = dict(conn.execute("SELECT session_id, revoked_at IS NOT NULL FROM user_sessions"))
    assert revoked == {10: 0, 11: 1, 20: 0}                       # current kept, other own session out, Ben untouched
    assert lock_state(conn) == (0, None)


@pytest.mark.parametrize("current,new,code,status", [
    ("wrong password", "Brand new passphrase 9!", "invalid_current_password", 403),
    (PASSWORD, PASSWORD, "password_unchanged", 422),
    (PASSWORD, "short", "weak_password", 422),
    (PASSWORD, "x" * 129, "weak_password", 422),
])
def test_password_change_refusals(tmp_path, current, new, code, status):
    conn, run = world(tmp_path)
    fail(lambda: svc.change_password(run, 1, 10, current, new, POLICY, NOW), code, status)
    assert verify_password(PASSWORD, conn.execute("SELECT password_hash FROM users WHERE user_id = 1").fetchone()[0])
    assert conn.execute("SELECT COUNT(*) FROM user_sessions WHERE revoked_at IS NOT NULL").fetchone()[0] == 0


def test_sso_account_without_a_password_cannot_use_password_change(tmp_path):
    _, run = world(tmp_path)
    fail(lambda: svc.change_password(run, 3, None, "anything", "Brand new passphrase 9!", POLICY, NOW),
         "invalid_current_password", 403)


# ------------------------------------------------------------------------ preferences
def test_preferences_default_auto_save_to_on_then_update_partially(tmp_path):
    conn, run = world(tmp_path)
    assert svc.get_preferences(run, 1) == {"shapAdvancedMode": True, "autoSaveScanLogs": True}
    assert svc.update_preferences(run, 1, {"auto_save_scan_logs": False}, NOW) == {"shapAdvancedMode": True, "autoSaveScanLogs": False}
    assert svc.update_preferences(run, 1, {"shap_advanced_mode": False}, NOW) == {"shapAdvancedMode": False, "autoSaveScanLogs": False}
    assert svc.update_preferences(run, 1, {}, NOW) == {"shapAdvancedMode": False, "autoSaveScanLogs": False}
    assert conn.execute("SELECT COUNT(*) FROM user_settings").fetchone()[0] == 1
    assert svc.get_preferences(run, 2) == {"shapAdvancedMode": True, "autoSaveScanLogs": True}
