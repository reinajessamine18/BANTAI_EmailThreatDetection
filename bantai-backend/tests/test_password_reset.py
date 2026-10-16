"""Password recovery requires an emailed, one-use token and revokes sessions."""

import sqlite3
from urllib.parse import parse_qs, urlparse

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from app.api.auth_security import verify_password  # noqa: E402
from app.api.routes import auth as auth_routes  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from tests.test_auth_api import API, PASSWORD, bearer, db_rows, register  # noqa: E402
from tests.test_scans_api import make_client  # noqa: E402

RESET_REQUEST = f"{API}/auth/password-reset/request"
RESET_CONFIRM = f"{API}/auth/password-reset/confirm"
NEW_PASSWORD = "New correct horse battery 84!"


def configure_mail(monkeypatch, sender):
    monkeypatch.setenv("BANTAI_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("BANTAI_SMTP_SENDER", "no-reply@example.test")
    monkeypatch.setenv("BANTAI_FRONTEND_BASE_URL", "https://bantai.example.test")
    get_settings.cache_clear()
    monkeypatch.setattr(auth_routes, "send_password_reset_email", sender)


def token_from_link(link):
    return parse_qs(urlparse(link).query)["token"][0]


def test_reset_request_does_not_disclose_account_existence_and_stores_hash(monkeypatch):
    deliveries = []
    configure_mail(monkeypatch, lambda _settings, email, link: deliveries.append((email, link)))
    with make_client(monkeypatch) as client:
        assert register(client).status_code == 201
        known = client.post(RESET_REQUEST, json={"email": "a@example.com"})
        unknown = client.post(RESET_REQUEST, json={"email": "nobody@example.com"})

    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()
    assert len(deliveries) == 1 and deliveries[0][0] == "a@example.com"
    assert deliveries[0][1].startswith("https://bantai.example.test/reset-password?")
    token = token_from_link(deliveries[0][1])
    [(stored_hash, expires_at, used_at)] = db_rows(
        "SELECT token_hash, expires_at, used_at FROM password_reset_tokens"
    )
    assert stored_hash != token and len(stored_hash) == 64
    assert expires_at.endswith("Z") and used_at is None


def test_reset_token_is_single_use_changes_password_and_revokes_sessions(monkeypatch):
    deliveries = []
    configure_mail(monkeypatch, lambda _settings, _email, link: deliveries.append(link))
    with make_client(monkeypatch) as client:
        registration = register(client)
        old_session = registration.json()["accessToken"]
        assert client.post(RESET_REQUEST, json={"email": "a@example.com"}).status_code == 202
        token = token_from_link(deliveries[0])

        reset = client.post(
            RESET_CONFIRM,
            json={"token": token, "new_password": NEW_PASSWORD},
        )
        assert reset.status_code == 200
        assert client.get(f"{API}/auth/me", headers=bearer(old_session)).status_code == 401
        assert client.post(
            RESET_CONFIRM,
            json={"token": token, "new_password": NEW_PASSWORD},
        ).status_code == 400
        assert client.post(
            f"{API}/auth/login",
            json={"email": "a@example.com", "password": NEW_PASSWORD},
        ).status_code == 200

    [(password_hash,)] = db_rows("SELECT password_hash FROM users")
    assert verify_password(NEW_PASSWORD, password_hash)
    sessions = db_rows("SELECT revoked_at FROM user_sessions ORDER BY session_id")
    assert sessions[0][0] is not None and sessions[1][0] is None
    assert db_rows(
        "SELECT event_type FROM audit_logs WHERE event_type = 'PASSWORD_RESET'"
    ) == [("PASSWORD_RESET",)]


def test_expired_reset_token_is_rejected(monkeypatch):
    deliveries = []
    configure_mail(monkeypatch, lambda _settings, _email, link: deliveries.append(link))
    with make_client(monkeypatch) as client:
        register(client)
        client.post(RESET_REQUEST, json={"email": "a@example.com"})
        token = token_from_link(deliveries[0])
        conn = sqlite3.connect(get_settings().database_path)
        conn.execute(
            "UPDATE password_reset_tokens SET expires_at = '2000-01-01T00:00:00Z'"
        )
        conn.commit()
        conn.close()
        response = client.post(
            RESET_CONFIRM,
            json={"token": token, "new_password": NEW_PASSWORD},
        )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_reset_token"


def test_reset_requests_are_rate_limited_by_client_ip(monkeypatch):
    configure_mail(monkeypatch, lambda *_args: None)
    with make_client(monkeypatch) as client:
        for _ in range(5):
            response = client.post(RESET_REQUEST, json={"email": "nobody@example.com"})
            assert response.status_code == 202
        limited = client.post(RESET_REQUEST, json={"email": "nobody@example.com"})
    assert limited.status_code == 429
    assert limited.json()["detail"]["code"] == "password_reset_rate_limited"


def test_reset_is_disabled_without_smtp_for_known_and_unknown_accounts(monkeypatch):
    get_settings.cache_clear()
    with make_client(monkeypatch) as client:
        register(client)
        known = client.post(RESET_REQUEST, json={"email": "a@example.com"})
        unknown = client.post(RESET_REQUEST, json={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 503
    assert known.json() == unknown.json()
