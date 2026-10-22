"""Google OAuth state, identity validation, account reuse, and password setup."""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from app.api import auth_security  # noqa: E402
from app.api.routes import auth as auth_routes  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from tests.test_auth_api import API, PASSWORD, bearer, db_rows, register  # noqa: E402
from tests.test_scans_api import make_client  # noqa: E402

GOOGLE_START = f"{API}/auth/google/start"
GOOGLE_CALLBACK = f"{API}/auth/google/callback"
GOOGLE_EXCHANGE = f"{API}/auth/google/exchange"


def configure_google(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv(
        "GOOGLE_REDIRECT_URI",
        "http://localhost:8000/api/v1/auth/google/callback",
    )
    monkeypatch.setenv("BANTAI_EXTENSION_ID", "abcdefghijklmnopabcdefghijklmnop")
    get_settings.cache_clear()


def claims(**overrides):
    return {
        "sub": "stable-google-subject",
        "email": "google-user@example.com",
        "email_verified": True,
        "iss": "https://accounts.google.com",
        "aud": "test-client-id",
        "exp": time.time() + 300,
        "nonce": "expected-nonce",
        "name": "Google User",
        **overrides,
    }


def begin_google_login(client, **params):
    response = client.get(GOOGLE_START, params=params, follow_redirects=False)
    assert response.status_code == 302
    redirect = urlparse(response.headers["location"])
    query = parse_qs(redirect.query)
    assert query["prompt"] == ["select_account"]
    return query["state"][0], query["nonce"][0]


def callback(client, state):
    return client.get(
        GOOGLE_CALLBACK,
        params={"state": state, "code": "authorization-code"},
        follow_redirects=False,
    )


def test_google_callback_reuses_subject_and_ticket_is_single_use(monkeypatch):
    configure_google(monkeypatch)
    monkeypatch.setattr(
        auth_routes,
        "_google_claims",
        lambda _code, _nonce_hash, _settings: claims(),
    )
    with make_client(monkeypatch) as client:
        state, _nonce = begin_google_login(client)
        first = callback(client, state)
        assert first.status_code == 303
        redirect = urlparse(first.headers["location"])
        assert redirect.path == "/login"
        ticket = parse_qs(redirect.query)["oauth_ticket"][0]
        login = client.post(GOOGLE_EXCHANGE, json={"ticket": ticket})
        replay = client.post(GOOGLE_EXCHANGE, json={"ticket": ticket})

        second_state, _nonce = begin_google_login(client)
        second = callback(client, second_state)
        second_ticket = parse_qs(urlparse(second.headers["location"]).query)["oauth_ticket"][0]
        second_login = client.post(GOOGLE_EXCHANGE, json={"ticket": second_ticket})

    assert login.status_code == 200
    assert replay.status_code == 400
    assert replay.json()["detail"]["code"] == "invalid_oauth_ticket"
    assert second_login.status_code == 200
    assert login.json()["user"]["userId"] == second_login.json()["user"]["userId"]
    assert db_rows("SELECT COUNT(*) FROM users") == [(1,)]
    assert db_rows("SELECT COUNT(*) FROM user_sessions") == [(2,)]


def test_google_extension_return_is_allowlisted_and_bound_to_state(monkeypatch):
    configure_google(monkeypatch)
    extension_uri = "https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/oauth2"
    monkeypatch.setattr(
        auth_routes,
        "_google_claims",
        lambda _code, _nonce_hash, _settings: claims(),
    )
    with make_client(monkeypatch) as client:
        rejected = client.get(
            GOOGLE_START,
            params={"extension_redirect_uri": "https://attacker.example/oauth2"},
            follow_redirects=False,
        )
        state, _nonce = begin_google_login(
            client, extension_redirect_uri=extension_uri
        )
        result = callback(client, state)

    assert rejected.status_code == 303
    assert parse_qs(urlparse(rejected.headers["location"]).query) == {
        "error": ["google_extension_not_configured"]
    }
    assert result.status_code == 303
    redirect = urlparse(result.headers["location"])
    assert f"{redirect.scheme}://{redirect.netloc}{redirect.path}" == extension_uri
    assert len(parse_qs(redirect.query)["oauth_ticket"][0]) >= 32


def test_unconfigured_google_login_returns_to_frontend_with_safe_error(monkeypatch):
    for key in (
        "GOOGLE_CLIENT_ID",
        "BANTAI_GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "BANTAI_GOOGLE_CLIENT_SECRET",
    ):
        monkeypatch.setenv(key, "")
    get_settings.cache_clear()
    with make_client(monkeypatch) as client:
        response = client.get(GOOGLE_START, follow_redirects=False)
    assert response.status_code == 303
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query == {"error": ["google_login_unavailable"]}


def test_google_email_collision_does_not_link_local_account(monkeypatch):
    configure_google(monkeypatch)
    monkeypatch.setattr(
        auth_routes,
        "_google_claims",
        lambda _code, _nonce_hash, _settings: claims(),
    )
    with make_client(monkeypatch) as client:
        local = register(client, email="google-user@example.com")
        assert local.status_code == 200
        original_user_id = local.json()["user"]["userId"]
        state, _nonce = begin_google_login(client)
        result = callback(client, state)
    query = parse_qs(urlparse(result.headers["location"]).query)
    assert result.status_code == 303
    assert query["error"] == ["google_account_link_required"]
    assert db_rows("SELECT user_id, auth_provider FROM users") == [
        (original_user_id, "local")
    ]


def test_google_state_is_required_and_consumed_once(monkeypatch):
    configure_google(monkeypatch)
    monkeypatch.setattr(
        auth_routes,
        "_google_claims",
        lambda _code, _nonce_hash, _settings: claims(),
    )
    with make_client(monkeypatch) as client:
        state, _nonce = begin_google_login(client)
        first = callback(client, state)
        replay = callback(client, state)
        invalid = client.get(
            GOOGLE_CALLBACK,
            params={"state": "x" * 40, "code": "authorization-code"},
            follow_redirects=False,
        )
    assert first.status_code == replay.status_code == invalid.status_code == 303
    assert parse_qs(urlparse(replay.headers["location"]).query)["error"] == [
        "google_state_invalid"
    ]
    assert parse_qs(urlparse(invalid.headers["location"]).query)["error"] == [
        "google_state_invalid"
    ]


@pytest.mark.parametrize(
    "change",
    [
        {"aud": "another-client"},
        {"iss": "https://attacker.example"},
        {"exp": time.time() - 1},
        {"nonce": "different-nonce"},
        {"email_verified": False},
    ],
)
def test_google_identity_claims_are_checked(monkeypatch, change):
    configure_google(monkeypatch)
    identity = claims(**change)

    class TokenResponse:
        def raise_for_status(self):
            pass

        @staticmethod
        def json():
            return {"id_token": "signed-id-token"}

    monkeypatch.setattr(auth_routes.requests, "post", lambda *_args, **_kwargs: TokenResponse())
    monkeypatch.setattr(
        auth_routes.id_token,
        "verify_oauth2_token",
        lambda _raw, _request, _audience: identity,
    )

    with pytest.raises(ValueError):
        auth_routes._google_claims(
            "auth-code",
            auth_security.token_hash("expected-nonce"),
            get_settings(),
        )


def test_google_identity_claims_accept_a_valid_verified_token(monkeypatch):
    configure_google(monkeypatch)
    identity = claims()

    class TokenResponse:
        def raise_for_status(self):
            pass

        @staticmethod
        def json():
            return {"id_token": "signed-id-token"}

    monkeypatch.setattr(auth_routes.requests, "post", lambda *_args, **_kwargs: TokenResponse())
    monkeypatch.setattr(
        auth_routes.id_token,
        "verify_oauth2_token",
        lambda _raw, _request, _audience: identity,
    )

    verified = auth_routes._google_claims(
        "auth-code",
        auth_security.token_hash("expected-nonce"),
        get_settings(),
    )
    assert verified["sub"] == "stable-google-subject"


def test_existing_google_user_can_add_password_without_changing_account_id(monkeypatch):
    configure_google(monkeypatch)
    monkeypatch.setattr(
        auth_routes,
        "_google_claims",
        lambda _code, _nonce_hash, _settings: claims(),
    )
    with make_client(monkeypatch) as client:
        state, _nonce = begin_google_login(client)
        result = callback(client, state)
        ticket = parse_qs(urlparse(result.headers["location"]).query)["oauth_ticket"][0]
        login = client.post(GOOGLE_EXCHANGE, json={"ticket": ticket})
        token = login.json()["accessToken"]
        headers = bearer(token)

        requested = client.post(
            f"{API}/auth/google-password-setup/request",
            headers=headers,
        )
        setup = client.post(
            f"{API}/auth/google-password-setup/confirm",
            headers=headers,
            json={
                "username": "google-local",
                "code": client.otp_codes[-1],
                "password": PASSWORD,
                "confirm_password": PASSWORD,
            },
        )
        local_login = client.post(
            f"{API}/auth/login",
            json={"identifier": "google-local", "password": PASSWORD},
        )

    assert requested.status_code == 202
    assert setup.status_code == 200
    assert local_login.status_code == 200
    assert setup.json()["user"]["userId"] == login.json()["user"]["userId"]
    assert db_rows("SELECT COUNT(*) FROM users") == [(1,)]
    assert db_rows("SELECT auth_provider FROM users") == [("google",)]
