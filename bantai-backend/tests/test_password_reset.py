"""OTP password recovery only changes a password after a verified reset code."""

import sqlite3

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from app.api.auth_security import verify_password  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from tests.test_auth_api import API, PASSWORD, bearer, db_rows, register  # noqa: E402
from tests.test_scans_api import make_client  # noqa: E402

NEW_PASSWORD = "New correct horse battery 84!"
RESET_REQUEST = f"{API}/auth/password-reset/request"
RESET_VERIFY = f"{API}/auth/password-reset/verify"
RESET_CONFIRM = f"{API}/auth/password-reset/confirm"


def test_reset_request_is_generic_and_stores_only_an_otp_hash(monkeypatch):
    with make_client(monkeypatch) as client:
        register(client)
        known = client.post(RESET_REQUEST, json={"email": "a@example.com"})
        reset_code = client.otp_codes[-1]
        unknown = client.post(RESET_REQUEST, json={"email": "nobody@example.com"})

        assert known.status_code == unknown.status_code == 202
        assert known.json() == unknown.json()
        assert reset_code not in str(db_rows("SELECT code_hash FROM email_otp_challenges"))
        assert db_rows(
            "SELECT purpose FROM email_otp_challenges ORDER BY challenge_id"
        ) == [("registration",), ("password_reset",)]


def test_reset_code_issues_single_use_authorization_and_revokes_sessions(monkeypatch):
    with make_client(monkeypatch) as client:
        registration = register(client)
        old_session = registration.json()["accessToken"]
        client.post(RESET_REQUEST, json={"email": "a@example.com"})
        verification = client.post(
            RESET_VERIFY,
            json={"email": "a@example.com", "code": client.otp_codes[-1]},
        )
        assert verification.status_code == 200
        authorization = verification.json()["resetAuthorization"]
        assert len(authorization) >= 32

        reset = client.post(
            RESET_CONFIRM,
            json={
                "token": authorization,
                "new_password": NEW_PASSWORD,
                "confirm_password": NEW_PASSWORD,
            },
        )
        assert reset.status_code == 200
        assert client.get(f"{API}/auth/me", headers=bearer(old_session)).status_code == 401
        replay = client.post(
            RESET_CONFIRM,
            json={
                "token": authorization,
                "new_password": NEW_PASSWORD,
                "confirm_password": NEW_PASSWORD,
            },
        )
        assert replay.status_code == 400
        assert client.post(
            f"{API}/auth/login",
            json={"identifier": "ana-test", "password": NEW_PASSWORD},
        ).status_code == 200

    [(password_hash,)] = db_rows("SELECT password_hash FROM users")
    assert verify_password(NEW_PASSWORD, password_hash)
    sessions = db_rows("SELECT revoked_at FROM user_sessions ORDER BY session_id")
    assert sessions[0][0] is not None
    assert db_rows(
        "SELECT event_type FROM audit_logs WHERE event_type = 'PASSWORD_RESET'"
    ) == [("PASSWORD_RESET",)]


def test_expired_otp_cannot_issue_reset_authorization(monkeypatch):
    with make_client(monkeypatch) as client:
        register(client)
        client.post(RESET_REQUEST, json={"email": "a@example.com"})
        code = client.otp_codes[-1]
        conn = sqlite3.connect(get_settings().database_path)
        conn.execute(
            "UPDATE email_otp_challenges SET expires_at = '2000-01-01T00:00:00Z' "
            "WHERE purpose = 'password_reset'"
        )
        conn.commit()
        conn.close()
        response = client.post(
            RESET_VERIFY,
            json={"email": "a@example.com", "code": code},
        )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_otp"


def test_reset_requests_are_rate_limited_by_client_ip(monkeypatch):
    with make_client(monkeypatch) as client:
        for _ in range(5):
            response = client.post(RESET_REQUEST, json={"email": "nobody@example.com"})
            assert response.status_code == 202
        limited = client.post(RESET_REQUEST, json={"email": "nobody@example.com"})
    assert limited.status_code == 429
    assert limited.json()["detail"]["code"] == "password_reset_rate_limited"



def test_reset_configuration_failure_is_the_same_for_known_and_unknown_addresses(monkeypatch):
    with make_client(monkeypatch) as client:
        register(client)

        # Override values loaded from .env so this test has no SMTP host or sender.
        monkeypatch.setenv("SMTP_HOST", "")
        monkeypatch.setenv("SMTP_FROM_EMAIL", "")
        get_settings.cache_clear()

        known = client.post(RESET_REQUEST, json={"email": "a@example.com"})
        unknown = client.post(RESET_REQUEST, json={"email": "nobody@example.com"})

    get_settings.cache_clear()

    assert known.status_code == unknown.status_code == 503
    assert known.json() == unknown.json()
