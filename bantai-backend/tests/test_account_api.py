"""Step 7b over HTTP: login lockout, profile, email, password, preferences. Needs FastAPI + SQLAlchemy."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from app.core.config import get_settings  # noqa: E402
from tests.test_auth_api import CONTENT, PASSWORD, bearer, db_rows, register  # noqa: E402
from tests.test_scans_api import make_client  # noqa: E402

API = "/api/v1"
NEW_PASSWORD = "Brand new passphrase 987!"


def login(client, email="a@example.com", password=PASSWORD):
    return client.post(f"{API}/auth/login", json={"email": email, "password": password})


def sql(statement, args=()):
    conn = sqlite3.connect(get_settings().database_path)
    try:
        conn.execute(statement, args)
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------------------ lockout
def test_five_wrong_passwords_lock_the_account_and_the_answer_never_changes(monkeypatch):
    with make_client(monkeypatch) as client:
        register(client)
        wrong = [login(client, password="nope-nope-nope-1") for _ in range(5)]
        locked_correct = login(client)                                  # right password, but locked
        unknown = login(client, email="who@example.com", password="nope-nope-nope-1")
        assert {r.status_code for r in wrong} == {401} and locked_correct.status_code == 401
        assert locked_correct.json() == wrong[0].json() == unknown.json()
        [(attempts, locked_until)] = db_rows("SELECT failed_login_attempts, locked_until FROM users")
        assert attempts == 0 and locked_until is not None

        sql("UPDATE users SET locked_until = NULL")                     # the lock "expires"
        ok = login(client)
        assert ok.status_code == 200
    assert db_rows("SELECT failed_login_attempts, locked_until FROM users") == [(0, None)]


def test_a_successful_login_resets_the_failure_counter(monkeypatch):
    with make_client(monkeypatch) as client:
        register(client)
        for _ in range(3):
            login(client, password="nope-nope-nope-1")
        assert db_rows("SELECT failed_login_attempts FROM users") == [(3,)]
        assert login(client).status_code == 200
    assert db_rows("SELECT failed_login_attempts FROM users") == [(0,)]


def test_session_length_comes_from_system_settings(monkeypatch):
    with make_client(monkeypatch) as client:
        register(client)
        sql("UPDATE system_settings SET setting_value = '1' WHERE setting_key = 'session_ttl_hours'")
        expires = datetime.strptime(login(client).json()["expiresAt"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    remaining = expires - datetime.now(timezone.utc)
    assert timedelta(minutes=50) < remaining <= timedelta(hours=1, minutes=1)


# -------------------------------------------------------------------------------- login
@pytest.mark.parametrize("method,path,body", [
    ("get", "/account/profile", None), ("patch", "/account/profile", {"fullName": "Ana Test"}),
    ("post", "/account/password", {"currentPassword": "x", "newPassword": NEW_PASSWORD}),
    ("get", "/account/settings", None), ("patch", "/account/settings", {"autoSaveScanLogs": False}),
])
def test_account_endpoints_require_login(monkeypatch, method, path, body):
    with make_client(monkeypatch) as client:
        resp = getattr(client, method)(f"{API}{path}", **({"json": body} if body else {}))
    assert resp.status_code == 401


# ------------------------------------------------------------------------------- profile
def test_profile_read_update_and_audit(monkeypatch):
    with make_client(monkeypatch) as client:
        token = register(client).json()["accessToken"]
        h = bearer(token)
        assert client.get(f"{API}/account/profile", headers=h).json()["email"] == "a@example.com"

        resp = client.patch(f"{API}/account/profile", headers=h,
                            json={"fullName": "Renamed Person", "jobTitle": "SOC Analyst",
                                  "profilePicture": "data:image/png;base64,AAAA"})
        assert resp.status_code == 200
        assert (resp.json()["fullName"], resp.json()["jobTitle"]) == ("Renamed Person", "SOC Analyst")
        cleared = client.patch(f"{API}/account/profile", headers=h, json={"profilePicture": None, "jobTitle": None}).json()
        assert cleared["profilePicture"] is None and cleared["jobTitle"] is None
        assert client.get(f"{API}/auth/me", headers=h).json()["user"]["fullName"] == "Renamed Person"

        for bad in ({"profilePicture": "data:image/svg+xml;base64,PHN2Zz4="}, {"fullName": "A"},
                    {"email": "nope"}, {"role": "admin"}, {"userId": 5}):
            assert client.patch(f"{API}/account/profile", headers=h, json=bad).status_code == 422
    details = [d for e, d in db_rows("SELECT event_type, detail FROM audit_logs") if e == "PROFILE_UPDATED"]
    assert details and all("Renamed Person" not in d and "SOC Analyst" not in d for d in details)


def test_email_change_needs_the_current_password(monkeypatch):
    with make_client(monkeypatch) as client:
        h = bearer(register(client).json()["accessToken"])
        no_pw = client.patch(f"{API}/account/profile", headers=h, json={"email": "new@example.com"})
        assert (no_pw.status_code, no_pw.json()["detail"]["code"]) == (422, "password_required")
        wrong = client.patch(f"{API}/account/profile", headers=h,
                             json={"email": "new@example.com", "currentPassword": "wrong-wrong-1"})
        assert wrong.status_code == 403
        ok = client.patch(f"{API}/account/profile", headers=h,
                          json={"email": "New@Example.com", "currentPassword": PASSWORD})
        assert ok.status_code == 200 and ok.json()["email"] == "new@example.com"
        assert login(client, email="new@example.com").status_code == 200
        assert login(client, email="a@example.com").status_code == 401


def test_email_already_used_by_another_account_is_409(monkeypatch):
    with make_client(monkeypatch) as client:
        register(client, email="other@example.com")
        h = bearer(register(client).json()["accessToken"])
        resp = client.patch(f"{API}/account/profile", headers=h,
                            json={"email": "other@example.com", "currentPassword": PASSWORD})
        assert resp.status_code == 409


# ------------------------------------------------------------------------------ password
def test_password_change_signs_out_other_sessions_but_keeps_this_one(monkeypatch):
    with make_client(monkeypatch) as client:
        first = register(client).json()["accessToken"]
        second = login(client).json()["accessToken"]
        resp = client.post(f"{API}/account/password", headers=bearer(first),
                           json={"currentPassword": PASSWORD, "newPassword": NEW_PASSWORD})
        assert resp.status_code == 200 and resp.json() == {"changed": True}
        assert PASSWORD not in resp.text and NEW_PASSWORD not in resp.text
        assert client.get(f"{API}/auth/me", headers=bearer(first)).status_code == 200
        assert client.get(f"{API}/auth/me", headers=bearer(second)).status_code == 401
        assert login(client).status_code == 401                          # old password is dead
        assert login(client, password=NEW_PASSWORD).status_code == 200
    assert "PASSWORD_CHANGED" in {e for (e,) in db_rows("SELECT event_type FROM audit_logs")}


@pytest.mark.parametrize("body,status,code", [
    ({"currentPassword": "wrong-wrong-1", "newPassword": NEW_PASSWORD}, 403, "invalid_current_password"),
    ({"currentPassword": PASSWORD, "newPassword": PASSWORD}, 422, "password_unchanged"),
    ({"currentPassword": PASSWORD, "newPassword": "short"}, 422, None),
    ({"currentPassword": PASSWORD, "newPassword": NEW_PASSWORD, "extra": 1}, 422, None),
])
def test_password_change_refusals(monkeypatch, body, status, code):
    with make_client(monkeypatch) as client:
        h = bearer(register(client).json()["accessToken"])
        resp = client.post(f"{API}/account/password", headers=h, json=body)
        assert resp.status_code == status
        if code:
            assert resp.json()["detail"]["code"] == code
        assert login(client).status_code == 200                          # password is unchanged


def test_guessing_the_current_password_with_a_stolen_token_gets_locked_out(monkeypatch):
    with make_client(monkeypatch) as client:
        h = bearer(register(client).json()["accessToken"])
        for _ in range(5):
            client.post(f"{API}/account/password", headers=h,
                        json={"currentPassword": "guess-guess-1", "newPassword": NEW_PASSWORD})
        right = client.post(f"{API}/account/password", headers=h,
                            json={"currentPassword": PASSWORD, "newPassword": NEW_PASSWORD})
        assert right.status_code == 403
        assert login(client).status_code == 401                          # the lock also covers login


# --------------------------------------------------------------------------- preferences
def test_preferences_default_update_and_control_whether_scans_are_saved(monkeypatch):
    with make_client(monkeypatch) as client:
        h = bearer(register(client).json()["accessToken"])
        assert client.get(f"{API}/account/settings", headers=h).json() == {"shapAdvancedMode": True, "autoSaveScanLogs": True}

        off = client.patch(f"{API}/account/settings", headers=h, json={"autoSaveScanLogs": False})
        assert off.status_code == 200 and off.json()["autoSaveScanLogs"] is False

        not_saved = client.post(f"{API}/scans", headers=h, json={"inputMethod": "raw_text", "content": CONTENT}).json()
        assert not_saved["saved"] is False and not_saved["scanId"] is None

        assert client.get(f"{API}/scans", headers=h).json()["total"] == 0

        on = client.patch(f"{API}/account/settings", headers=h, json={"autoSaveScanLogs": True})
        assert on.status_code == 200 and on.json() == {"shapAdvancedMode": True, "autoSaveScanLogs": True}
        saved = client.post(f"{API}/scans", headers=h, json={"inputMethod": "raw_text", "content": CONTENT}).json()
        assert saved["saved"] is True
        assert client.get(f"{API}/scans", headers=h).json()["total"] == 1


@pytest.mark.parametrize("body", [{"autoSaveScanLogs": "yes"}, {"shapAdvancedMode": 1}, {"other": True}])
def test_preferences_reject_non_booleans_and_unknown_fields(monkeypatch, body):
    with make_client(monkeypatch) as client:
        h = bearer(register(client).json()["accessToken"])
        assert client.patch(f"{API}/account/settings", headers=h, json=body).status_code == 422
