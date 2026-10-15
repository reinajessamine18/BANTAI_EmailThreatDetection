"""Login flow over HTTP with the existing auth router + the rebuilt session dependency.

Needs FastAPI + SQLAlchemy. Uses a fake ML model (same helper as the scan tests).
"""

import sqlite3

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from app.core.config import get_settings  # noqa: E402
from tests.test_scans_api import make_client  # noqa: E402

API = "/api/v1"
PASSWORD = "Correct horse battery 42!"
CONTENT = "Subject: Verify now\n\nPlease verify your password at http://203.0.113.9/x immediately."


def register(client, email="a@example.com", password=PASSWORD):
    return client.post(f"{API}/auth/register", json={"full_name": "Ana Test", "email": email, "password": password})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def db_rows(sql, args=()):
    conn = sqlite3.connect(get_settings().database_path)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def test_register_login_use_logout_flow(monkeypatch):
    with make_client(monkeypatch) as client:
        reg = register(client)
        assert reg.status_code == 201
        token = reg.json()["accessToken"]
        assert reg.json()["user"]["email"] == "a@example.com" and "password" not in reg.text

        assert client.get(f"{API}/auth/me", headers=bearer(token)).json()["user"]["fullName"] == "Ana Test"
        scan = client.post(f"{API}/scans", headers=bearer(token),
                           json={"inputMethod": "raw_text", "content": CONTENT})
        assert scan.status_code == 200 and scan.json()["saved"] is True
        history = client.get(f"{API}/scans", headers=bearer(token)).json()
        assert history["total"] == 1 and history["items"][0]["subject"] == "Verify now"
        assert client.get(f"{API}/dashboard/summary", headers=bearer(token)).json()["metrics"]["totalScanned"] == 1

        assert client.post(f"{API}/auth/logout", headers=bearer(token)).status_code == 204
        assert client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 401
        assert client.get(f"{API}/scans", headers=bearer(token)).status_code == 401

        login = client.post(f"{API}/auth/login", json={"email": "A@Example.com ", "password": PASSWORD})
        assert login.status_code == 200
        assert client.get(f"{API}/auth/me", headers=bearer(login.json()["accessToken"])).status_code == 200

    events = {row[0] for row in db_rows("SELECT event_type FROM audit_logs")}
    assert {"USER_REGISTERED", "LOGIN_SUCCESS", "LOGOUT", "SCAN_COMPLETED"} <= events


def test_registration_stores_a_hash_and_creates_the_settings_row(monkeypatch):
    with make_client(monkeypatch) as client:
        register(client)
    [(stored,)] = db_rows("SELECT password_hash FROM users")
    assert stored.startswith("pbkdf2_sha256$") and PASSWORD not in stored
    assert db_rows("SELECT auto_save_scan_logs FROM user_settings") == [(1,)]


def test_bad_credentials_get_one_generic_answer(monkeypatch):
    with make_client(monkeypatch) as client:
        register(client)
        wrong = client.post(f"{API}/auth/login", json={"email": "a@example.com", "password": "nope-nope-nope"})
        unknown = client.post(f"{API}/auth/login", json={"email": "who@example.com", "password": "nope-nope-nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() and wrong.headers["www-authenticate"] == "Bearer"
    assert "LOGIN_FAILED" in {row[0] for row in db_rows("SELECT event_type FROM audit_logs")}


@pytest.mark.parametrize("payload,status", [
    ({"full_name": "Ana", "email": "a@example.com", "password": "short"}, 422),
    ({"full_name": "Ana", "email": "not-an-email", "password": PASSWORD}, 422),
    ({"full_name": "Ana", "email": "a@example.com", "password": PASSWORD, "role": "admin"}, 422),
])
def test_registration_validation(monkeypatch, payload, status):
    with make_client(monkeypatch) as client:
        assert client.post(f"{API}/auth/register", json=payload).status_code == status
    assert db_rows("SELECT COUNT(*) FROM users") == [(0,)]


def test_duplicate_email_is_409(monkeypatch):
    with make_client(monkeypatch) as client:
        assert register(client).status_code == 201
        assert register(client, email="A@EXAMPLE.COM").status_code == 409
    assert db_rows("SELECT COUNT(*) FROM users") == [(1,)]


def test_guests_still_scan_but_cannot_see_history(monkeypatch):
    with make_client(monkeypatch) as client:
        guest = client.post(f"{API}/scans", json={"inputMethod": "raw_text", "content": CONTENT})
        assert guest.status_code == 200
        assert client.get(f"{API}/scans").status_code == 401
        assert client.get(f"{API}/auth/me").status_code == 401
    assert db_rows("SELECT user_id, subject FROM scans") == [(None, None)]


@pytest.mark.parametrize("header", ["Bearer " + "a" * 43, "Bearer null", "Basic abc", "Bearer"])
def test_a_bad_token_is_401_not_silently_a_guest(monkeypatch, header):
    with make_client(monkeypatch) as client:
        resp = client.post(f"{API}/scans", headers={"Authorization": header},
                           json={"inputMethod": "raw_text", "content": CONTENT})
    assert resp.status_code == 401 and resp.json()["detail"]["code"] == "invalid_token"


def test_expired_session_is_rejected(monkeypatch):
    with make_client(monkeypatch) as client:
        token = register(client).json()["accessToken"]
        conn = sqlite3.connect(get_settings().database_path)
        conn.execute("UPDATE user_sessions SET expires_at = '2020-01-01T00:00:00Z'")
        conn.commit()
        conn.close()
        assert client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 401
