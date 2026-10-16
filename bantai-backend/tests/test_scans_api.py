"""Step 5: POST /api/v1/scans over HTTP. Needs FastAPI + SQLAlchemy.

Uses a fake model, except the last test, which uses the REAL model and is skipped
if the model cannot be loaded.
"""

import base64
import json
import math
import sqlite3

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

import app.main as main_module  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.services import ml_service  # noqa: E402
from app.services.ml_service import MlStatus, MlUnavailable  # noqa: E402
from tests.helpers import FakePrediction, contribution  # noqa: E402

URL = "/api/v1/scans"
EML = (b"From: Support <s@paypal-update.example>\r\nReturn-Path: <b@other.example>\r\n"
       b"Subject: Verify now\r\n\r\nPlease verify your password at http://203.0.113.9/x immediately.\r\n")


def fake_predict(body, top_k):
    return FakePrediction(0.92, "Phishing", (contribution("verify", 1.2), contribution("meeting", -0.4)))


def make_client(monkeypatch, predict=fake_predict):
    monkeypatch.setattr(main_module, "load_ml", lambda _dir: MlStatus(True, "ready"))
    monkeypatch.setattr(ml_service, "predict", predict)
    monkeypatch.setattr(ml_service, "max_body_chars", lambda: 200_000)
    return TestClient(main_module.create_app())


def audit_rows():
    conn = sqlite3.connect(get_settings().database_path)
    try:
        return conn.execute("SELECT event_type, http_status, detail FROM audit_logs").fetchall()
    finally:
        conn.close()


def test_raw_text_scan_returns_the_shape_the_frontend_reads(monkeypatch):
    with make_client(monkeypatch) as client:
        resp = client.post(URL, json={"inputMethod": "raw_text", "content": "Please verify your password now."})
    assert resp.status_code == 200
    body = resp.json()
    for key in ("riskLevel", "threatScore", "explanations", "fileName", "scannedAt",
                "inferenceTimeMs", "sender", "subject", "emailBody"):
        assert key in body
    assert (body["riskLevel"], body["threatScore"]) == ("phishing", 92)
    assert body["explanations"][0]["feature"] == "verify" and body["explanations"][0]["value"] == 1.2
    assert resp.headers["cache-control"] == "no-store"


def test_eml_upload_as_base64_and_as_text(monkeypatch):
    with make_client(monkeypatch) as client:
        a = client.post(URL, json={"inputMethod": "eml_upload", "fileName": "C:\\x\\m.eml",
                                   "encoding": "base64", "content": base64.b64encode(EML).decode()})
        b = client.post(URL, json={"inputMethod": "eml_upload", "content": EML.decode()})
    assert a.status_code == b.status_code == 200
    assert a.json()["fileName"] == "m.eml" and a.json()["subject"] == "Verify now"
    assert a.json()["links"][0]["ipAddress"] is True


def test_unknown_fields_are_rejected_without_echoing_input(monkeypatch):
    with make_client(monkeypatch) as client:
        resp = client.post(URL, json={"inputMethod": "raw_text", "content": "hello", "evil": "SECRET-ECHO"})
    assert resp.status_code == 422 and "SECRET-ECHO" not in resp.text


def test_bad_input_returns_a_stable_error_code(monkeypatch):
    with make_client(monkeypatch) as client:
        resp = client.post(URL, json={"inputMethod": "eml_upload", "encoding": "base64", "content": "!!!"})
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "invalid_base64"
    assert any(event == "SCAN_REJECTED" for event, _, _ in audit_rows())


def test_oversized_request_is_413_and_still_readable_by_the_browser(monkeypatch):
    monkeypatch.setenv("BANTAI_MAX_REQUEST_BYTES", "500")
    get_settings.cache_clear()
    with make_client(monkeypatch) as client:
        resp = client.post(URL, json={"inputMethod": "raw_text", "content": "x" * 2000},
                           headers={"Origin": "http://localhost:5173"})
    assert resp.status_code == 413
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_model_down_gives_503_and_is_audited(monkeypatch):
    def broken(body, top_k):
        raise MlUnavailable("down")

    with make_client(monkeypatch, predict=broken) as client:
        resp = client.post(URL, json={"inputMethod": "raw_text", "content": "hello there"})
    assert resp.status_code == 503 and resp.json()["detail"]["code"] == "ml_unavailable"
    assert ("SCAN_REJECTED", 503) in [(e, s) for e, s, _ in audit_rows()]


def test_guest_scan_limit_rejects_fourth_successful_scan(monkeypatch):
    with make_client(monkeypatch) as client:
        payload = {"inputMethod": "raw_text", "content": "Please verify your password now."}
        responses = [client.post(URL, json=payload) for _ in range(3)]
        limited = client.post(URL, json=payload)

    assert [response.status_code for response in responses] == [200, 200, 200]
    assert limited.status_code == 429
    assert limited.json()["detail"]["code"] == "guest_scan_limit_reached"
    assert limited.headers["cache-control"] == "no-store"
    conn = sqlite3.connect(get_settings().database_path)
    try:
        reservations = conn.execute(
            "SELECT completed_at FROM guest_scan_reservations ORDER BY reservation_id"
        ).fetchall()
    finally:
        conn.close()
    assert len(reservations) == 3 and all(row[0] is not None for row in reservations)


def test_failed_guest_scan_does_not_consume_quota(monkeypatch):
    with make_client(monkeypatch) as client:
        invalid = client.post(
            URL,
            json={"inputMethod": "raw_text", "content": "   "},
        )
        successes = [
            client.post(URL, json={"inputMethod": "raw_text", "content": "Please verify now."})
            for _ in range(3)
        ]

    assert invalid.status_code == 422
    assert [response.status_code for response in successes] == [200, 200, 200]


def test_signed_in_scans_are_not_limited_by_guest_quota(monkeypatch):
    with make_client(monkeypatch) as client:
        payload = {"inputMethod": "raw_text", "content": "Please verify your password now."}
        for _ in range(3):
            assert client.post(URL, json=payload).status_code == 200
        assert client.post(URL, json=payload).status_code == 429
        registration = client.post(
            "/api/v1/auth/register",
            json={
                "full_name": "Ana Test",
                "email": "guest-limit@example.com",
                "password": "Correct horse battery 42!",
            },
        )
        token = registration.json()["accessToken"]
        signed_in_scan = client.post(
            URL,
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )

    assert registration.status_code == 201
    assert signed_in_scan.status_code == 200


def test_real_model_end_to_end(monkeypatch):
    """Real TF-IDF + XGBoost + SHAP. Skipped when the model cannot be loaded."""
    with TestClient(main_module.create_app()) as client:
        if not client.app.state.ml_status.ready:
            pytest.skip("real ML model not available in this environment")
        resp = client.post(URL, json={
            "inputMethod": "raw_text",
            "content": "URGENT: your account is suspended. Verify your password immediately "
                       "at http://203.0.113.9/login to avoid termination.",
        })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert 0 <= body["threatScore"] <= 100 and body["riskLevel"] in ("safe", "suspicious", "phishing")
    words = [e for e in body["explanations"] if e["kind"] == "word"]
    assert words and all(math.isfinite(e["value"]) for e in words)
    assert body["modelVersion"] == "baseline-tfidf-xgb-v1" and body["inferenceTimeMs"] >= 0
    json.dumps(body)
    assert ("SCAN_COMPLETED", 200) in [(e, s) for e, s, _ in audit_rows()]
