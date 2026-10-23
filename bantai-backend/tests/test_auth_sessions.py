"""Session lookup and bearer parsing. Real SQL on a real SQLite database; no web stack needed."""

import sqlite3

import pytest

from app.api.auth_security import hash_password, new_token, token_hash, verify_password
from app.db.init_db import init_db
from app.services.auth_sessions import find_active_session, parse_bearer
from tests.helpers import SQL_DIR, seed_users, sqlite_runner

NOW = "2026-10-13T12:00:00Z"


def world(tmp_path):
    db = tmp_path / "a.db"
    init_db(db, SQL_DIR, None)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    seed_users(conn, 2)
    return conn, sqlite_runner(conn)


def add_session(conn, user_id, token, *, expires="2026-10-13T20:00:00Z", revoked=None):
    cursor = conn.execute(
        "INSERT INTO user_sessions (user_id, token_hash, expires_at, revoked_at) VALUES (?, ?, ?, ?)",
        (user_id, token_hash(token), expires, revoked),
    )
    conn.commit()
    return cursor.lastrowid


def test_valid_session_is_found_through_the_whole_token_round_trip(tmp_path):
    conn, run = world(tmp_path)
    token = new_token()
    sid = add_session(conn, 1, token)
    bearer = parse_bearer(f"Bearer {token}")
    assert bearer == token
    assert find_active_session(run, token_hash(bearer), NOW) == {"session_id": sid, "user_id": 1}


@pytest.mark.parametrize("kwargs", [
    {"expires": "2026-10-13T11:59:59Z"},          # expired a second ago
    {"revoked": "2026-10-13T10:00:00Z"},          # logged out
])
def test_expired_or_revoked_sessions_are_rejected(tmp_path, kwargs):
    conn, run = world(tmp_path)
    token = new_token()
    add_session(conn, 1, token, **kwargs)
    assert find_active_session(run, token_hash(token), NOW) is None


def test_disabled_user_loses_access_immediately(tmp_path):
    conn, run = world(tmp_path)
    token = new_token()
    add_session(conn, 1, token)
    conn.execute("UPDATE users SET is_active = 0 WHERE user_id = 1")
    conn.commit()
    assert find_active_session(run, token_hash(token), NOW) is None


def test_unknown_and_plaintext_tokens_do_not_match(tmp_path):
    conn, run = world(tmp_path)
    token = new_token()
    add_session(conn, 1, token)
    assert find_active_session(run, token_hash(new_token()), NOW) is None
    assert find_active_session(run, token, NOW) is None            # only the HASH is stored
    stored = conn.execute("SELECT token_hash FROM user_sessions").fetchone()[0]
    assert stored != token and len(stored) == 64


def test_each_user_gets_their_own_session(tmp_path):
    conn, run = world(tmp_path)
    t1, t2 = new_token(), new_token()
    add_session(conn, 1, t1)
    add_session(conn, 2, t2)
    assert find_active_session(run, token_hash(t1), NOW)["user_id"] == 1
    assert find_active_session(run, token_hash(t2), NOW)["user_id"] == 2


@pytest.mark.parametrize("header", [
    None, "", "Bearer", "Bearer ", "Basic abc", "Bearer short", "Bearer a b c", "Token " + "a" * 43,
    "Bearer " + "a" * 43 + "!", "Bearer null", "Bearer undefined", "Bearer " + "a" * 500,
])
def test_malformed_authorization_headers_are_rejected(header):
    assert parse_bearer(header) is None


def test_generated_tokens_always_parse():
    for _ in range(300):
        token = new_token()
        assert parse_bearer(f"Bearer {token}") == token
        assert parse_bearer(f"bearer {token}") == token            # scheme is case-insensitive


def test_existing_password_hashing_still_behaves():
    stored = hash_password("A long passphrase 123!")
    assert stored.startswith("pbkdf2_sha256$") and "passphrase" not in stored
    assert verify_password("A long passphrase 123!", stored) and not verify_password("x", stored)
    assert not verify_password("anything", None) and not verify_password("anything", "garbage")
