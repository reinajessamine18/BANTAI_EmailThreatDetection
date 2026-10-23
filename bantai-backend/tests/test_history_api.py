"""Step 6 over HTTP: history, detail, export, feedback, dashboard. Needs FastAPI + SQLAlchemy.

Login does not exist until Step 7, so tests sign in by overriding the user dependency.
"""

import sqlite3

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from app.api.deps import get_current_user_optional  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from tests.test_scans_api import make_client  # noqa: E402

API = "/api/v1"
CONTENT = "Subject: Verify now\n\nPlease verify your password at http://203.0.113.9/x immediately."


def make_user(email):
    conn = sqlite3.connect(get_settings().database_path)
    try:
        cursor = conn.execute("INSERT INTO users (full_name, email, password_hash) VALUES ('T', ?, 'h')", (email,))
        conn.execute(
            "INSERT INTO user_settings (user_id, auto_save_scan_logs) VALUES (?, 1)",
            (cursor.lastrowid,),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def sign_in(client, user_id):
    client.app.dependency_overrides[get_current_user_optional] = lambda: user_id


def audit_rows():
    conn = sqlite3.connect(get_settings().database_path)
    try:
        return conn.execute("SELECT event_type, detail FROM audit_logs").fetchall()
    finally:
        conn.close()


def scan(client):
    resp = client.post(f"{API}/scans", json={"inputMethod": "raw_text", "content": CONTENT})
    assert resp.status_code == 200, resp.text
    return resp.json()["scanId"]


@pytest.mark.parametrize("method,path", [
    ("get", f"{API}/scans"), ("get", f"{API}/scans/1"), ("get", f"{API}/scans/export"),
    ("get", f"{API}/dashboard/summary"), ("post", f"{API}/scans/1/feedback"),
])
def test_everything_here_requires_login(monkeypatch, method, path):
    with make_client(monkeypatch) as client:
        kwargs = {"json": {"isPredictionCorrect": True}} if method == "post" else {}
        resp = getattr(client, method)(path, **kwargs)
    assert resp.status_code == 401 and resp.json()["detail"]["code"] == "not_authenticated"


def test_full_user_flow(monkeypatch):
    with make_client(monkeypatch) as client:
        sign_in(client, make_user("a@example.com"))
        sid = scan(client)

        listing = client.get(f"{API}/scans").json()
        assert listing["total"] == 1 and listing["items"][0]["id"] == sid
        assert listing["items"][0]["threatLevel"] == "phishing" and listing["items"][0]["subject"] == "Verify now"

        detail = client.get(f"{API}/scans/{sid}")
        assert detail.status_code == 200 and detail.headers["cache-control"] == "no-store"
        body = detail.json()
        assert body["emailBody"] is None and body["emailBodyStored"] is False
        assert any(e["kind"] == "word" and e["feature"] == "verify" for e in body["explanations"])

        fb = client.post(f"{API}/scans/{sid}/feedback",
                         json={"isPredictionCorrect": False, "suggestedLabel": "Safe", "comment": "fine"})
        assert fb.status_code == 200 and fb.json()["suggestedLabel"] == "Safe"
        assert client.get(f"{API}/scans/{sid}").json()["feedback"]["comment"] == "fine"

        export = client.get(f"{API}/scans/export?level=phishing")
        assert export.status_code == 200 and export.headers["content-type"].startswith("text/csv")
        assert "attachment" in export.headers["content-disposition"]
        assert export.content.startswith(b"\xef\xbb\xbf") and b"Verify now" in export.content

        dash = client.get(f"{API}/dashboard/summary?range=7").json()
        assert dash["metrics"]["totalScanned"] == 1 and dash["metrics"]["phishingBlocked"] == 1
        assert dash["trend"]["granularity"] == "day" and len(dash["recent"]) == 1

    events = {event for event, _ in audit_rows()}
    assert {"SCAN_COMPLETED", "HISTORY_VIEWED", "HISTORY_EXPORTED", "FEEDBACK_SUBMITTED"} <= events


def test_users_cannot_see_each_others_scans(monkeypatch):
    with make_client(monkeypatch) as client:
        first, second = make_user("a@example.com"), make_user("b@example.com")
        sign_in(client, first)
        sid = scan(client)
        sign_in(client, second)
        assert client.get(f"{API}/scans").json()["total"] == 0
        assert client.get(f"{API}/scans/{sid}").status_code == 404
        assert client.post(f"{API}/scans/{sid}/feedback", json={"isPredictionCorrect": True}).status_code == 404
        assert client.get(f"{API}/dashboard/summary").json()["metrics"]["totalScanned"] == 0


@pytest.mark.parametrize("path", [
    f"{API}/scans?range=bogus", f"{API}/scans?limit=0", f"{API}/scans?level=high", f"{API}/scans/0",
])
def test_bad_query_parameters_are_422(monkeypatch, path):
    with make_client(monkeypatch) as client:
        sign_in(client, make_user("a@example.com"))
        assert client.get(path).status_code == 422


@pytest.mark.parametrize("payload", [
    {"isPredictionCorrect": True, "evil": "x"}, {"isPredictionCorrect": True, "comment": "x" * 1001},
])
def test_feedback_validation(monkeypatch, payload):
    with make_client(monkeypatch) as client:
        sign_in(client, make_user("a@example.com"))
        sid = scan(client)
        assert client.post(f"{API}/scans/{sid}/feedback", json=payload).status_code == 422


def test_search_text_never_reaches_the_audit_log(monkeypatch):
    with make_client(monkeypatch) as client:
        sign_in(client, make_user("a@example.com"))
        client.get(f"{API}/scans?q=TOPSECRETQUERY")
        client.get(f"{API}/scans/export?q=TOPSECRETQUERY")
    assert all("TOPSECRETQUERY" not in detail for _, detail in audit_rows())
