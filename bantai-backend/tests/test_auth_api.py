"""Login flow over HTTP with the existing auth router + the rebuilt session dependency.

Needs FastAPI + SQLAlchemy. Uses a fake ML model (same helper as the scan tests).
"""

import sqlite3
from contextlib import contextmanager

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from app.core.config import get_settings  # noqa: E402
from tests.test_scans_api import make_client as make_scan_client  # noqa: E402

API = "/api/v1"
PASSWORD = "Correct horse battery 42!"
CONTENT = "Subject: Verify now\n\nPlease verify your password at http://203.0.113.9/x immediately."


@contextmanager
def make_client(monkeypatch):
    with make_scan_client(monkeypatch, authenticated=False) as client:
        yield client


def register(client, email="a@example.com", password=PASSWORD):
    username = "ana-test" if email.lower() == "a@example.com" else f"user-{email.split('@')[0]}"
    registration = client.post(
        f"{API}/auth/register",
        json={
            "full_name": "Ana Test",
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        },
    )
    if registration.status_code != 202:
        return registration
    return client.post(
        f"{API}/auth/register/verify",
        json={"email": email, "code": client.otp_codes[-1]},
    )


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
        assert reg.status_code == 200
        token = reg.json()["accessToken"]
        assert reg.json()["user"]["email"] == "a@example.com" and "password" not in reg.text

        assert client.get(f"{API}/auth/me", headers=bearer(token)).json()["user"]["fullName"] == "Ana Test"
        assert client.get(f"{API}/account/settings", headers=bearer(token)).json()["autoSaveScanLogs"] is True
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
        user = register(client)
    [(stored, active, verified_at)] = db_rows(
        "SELECT password_hash, is_active, email_verified_at FROM users"
    )
    assert stored.startswith("pbkdf2_sha256$") and PASSWORD not in stored
    assert active == 1 and verified_at is not None
    assert user.json()["user"]["username"] == "ana-test"
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
        assert register(client).status_code == 200
        conn = sqlite3.connect(get_settings().database_path)
        conn.execute("UPDATE users SET email = 'A@EXAMPLE.COM'")
        conn.commit()
        conn.close()
        assert register(client, email="A@EXAMPLE.COM").status_code == 409
    assert db_rows("SELECT COUNT(*) FROM users") == [(1,)]


def test_registration_stays_inactive_until_email_verification(monkeypatch):
    with make_client(monkeypatch) as client:
        response = client.post(
            f"{API}/auth/register",
            json={
                "username": "pending-user",
                "email": "pending@example.com",
                "password": PASSWORD,
                "confirm_password": PASSWORD,
            },
        )
        assert response.status_code == 202
        blocked = client.post(
            f"{API}/auth/login",
            json={"identifier": "pending-user", "password": PASSWORD},
        )
        assert blocked.status_code == 403
        verified = client.post(
            f"{API}/auth/register/verify",
            json={"email": "pending@example.com", "code": client.otp_codes[-1]},
        )
        assert verified.status_code == 200
        assert verified.json()["user"]["email"] == "pending@example.com"
    assert db_rows("SELECT is_active, email_verified_at IS NOT NULL FROM users") == [(1, 1)]


def test_registration_otp_attempts_are_limited_and_challenge_is_consumed(monkeypatch):
    with make_client(monkeypatch) as client:
        response = client.post(
            f"{API}/auth/register",
            json={
                "username": "otp-limited",
                "email": "otp-limited@example.com",
                "password": PASSWORD,
                "confirm_password": PASSWORD,
            },
        )
        assert response.status_code == 202
        correct_code = client.otp_codes[-1]
        wrong_code = f"{(int(correct_code) + 1) % 1_000_000:06d}"
        for _ in range(5):
            invalid = client.post(
                f"{API}/auth/register/verify",
                json={"email": "otp-limited@example.com", "code": wrong_code},
            )
            assert invalid.status_code == 400
        replay = client.post(
            f"{API}/auth/register/verify",
            json={"email": "otp-limited@example.com", "code": correct_code},
        )
    assert replay.status_code == 400
    assert db_rows("SELECT attempts, consumed_at IS NOT NULL FROM email_otp_challenges") == [
        (5, 1)
    ]
    assert db_rows("SELECT is_active FROM users") == [(0,)]


def test_registration_resend_is_rate_limited(monkeypatch):
    with make_client(monkeypatch) as client:
        response = client.post(
            f"{API}/auth/register",
            json={
                "username": "resend-user",
                "email": "resend@example.com",
                "password": PASSWORD,
                "confirm_password": PASSWORD,
            },
        )
        assert response.status_code == 202
        resend = client.post(
            f"{API}/auth/register/resend",
            json={"email": "resend@example.com"},
        )
    assert resend.status_code == 429
    assert resend.json()["detail"]["code"] == "verification_rate_limited"
    assert db_rows("SELECT COUNT(*) FROM email_otp_challenges") == [(1,)]


def test_duplicate_username_is_rejected_case_insensitively(monkeypatch):
    with make_client(monkeypatch) as client:
        first = client.post(
            f"{API}/auth/register",
            json={
                "username": "same-name",
                "email": "first@example.com",
                "password": PASSWORD,
                "confirm_password": PASSWORD,
            },
        )
        second = client.post(
            f"{API}/auth/register",
            json={
                "username": "SAME-NAME",
                "email": "second@example.com",
                "password": PASSWORD,
                "confirm_password": PASSWORD,
            },
        )
    assert first.status_code == 202
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "username_already_registered"


def test_guests_cannot_scan_or_see_history(monkeypatch):
    with make_client(monkeypatch) as client:
        guest = client.post(f"{API}/scans", json={"inputMethod": "raw_text", "content": CONTENT})
        assert guest.status_code == 401
        assert client.get(f"{API}/scans").status_code == 401
        assert client.get(f"{API}/auth/me").status_code == 401
    assert db_rows("SELECT COUNT(*) FROM scans") == [(0,)]


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


def test_web_handoff_issues_a_single_use_session_for_the_same_user(monkeypatch):
    with make_client(monkeypatch) as client:
        original = register(client)
        original_user_id = original.json()["user"]["userId"]
        original_token = original.json()["accessToken"]
        created = client.post(
            f"{API}/auth/web-handoff",
            headers=bearer(original_token),
        )
        assert created.status_code == 200
        ticket = created.json()["ticket"]
        assert ticket.startswith("web_")
        [(stored_hash,)] = db_rows("SELECT ticket_hash FROM oauth_login_tickets")
        assert stored_hash != ticket

        google_exchange = client.post(
            f"{API}/auth/google/exchange",
            json={"ticket": ticket},
        )
        exchanged = client.post(
            f"{API}/auth/web-handoff/exchange",
            json={"ticket": ticket},
        )
        replay = client.post(
            f"{API}/auth/web-handoff/exchange",
            json={"ticket": ticket},
        )
        exchanged_token = exchanged.json()["accessToken"]
        me = client.get(
            f"{API}/auth/me",
            headers=bearer(exchanged_token),
        )

    assert google_exchange.status_code == 400
    assert google_exchange.json()["detail"]["code"] == "invalid_oauth_ticket"
    assert exchanged.status_code == 200
    assert me.status_code == 200
    assert me.json()["user"]["userId"] == original_user_id
    assert replay.status_code == 400
    assert replay.json()["detail"]["code"] == "invalid_web_handoff"
    assert db_rows("SELECT COUNT(*) FROM user_sessions") == [(2,)]


def test_web_handoff_requires_a_valid_unexpired_ticket_and_signed_in_user(monkeypatch):
    with make_client(monkeypatch) as client:
        guest_request = client.post(f"{API}/auth/web-handoff")
        assert guest_request.status_code == 401

        original = register(client)
        token = original.json()["accessToken"]
        created = client.post(
            f"{API}/auth/web-handoff",
            headers=bearer(token),
        )
        ticket = created.json()["ticket"]
        conn = sqlite3.connect(get_settings().database_path)
        conn.execute(
            "UPDATE oauth_login_tickets SET expires_at = '2020-01-01T00:00:00Z'"
        )
        conn.commit()
        conn.close()
        expired = client.post(
            f"{API}/auth/web-handoff/exchange",
            json={"ticket": ticket},
        )

        wrong_kind = client.post(
            f"{API}/auth/web-handoff/exchange",
            json={"ticket": "x" * 40},
        )

    assert expired.status_code == 400
    assert expired.json()["detail"]["code"] == "invalid_web_handoff"
    assert wrong_kind.status_code == 400
    assert wrong_kind.json()["detail"]["code"] == "invalid_web_handoff"
