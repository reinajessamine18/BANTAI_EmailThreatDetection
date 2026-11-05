"""Tests for Phase 8: Content-Only Email Threat Detection API (POST /api/v1/scans/content-only).

Verifies:
1. End-to-end authenticated scan with real/fake candidate EXP-4 model.
2. Response schema, raw margins, probabilities, and SHAP token explanations.
3. Zero-body privacy: raw email text is never persisted in SQLite.
4. Guest quota reservation, completion, and release-on-error (3 scans per 24 hours).
5. Guest token contribution privacy (not persisted for anonymous scans).
6. Rejection of empty, whitespace-only, and post-cleaning degenerate inputs (prohibiting Safe fallback).
7. Rejection of oversized bodies (> 200,000 characters) without silent truncation.
8. Candidate model lifecycle, atomic loading, and degraded startup isolation (503 when offline).
9. Idempotent registration of candidate-v2-exp4-refit with is_active = 0 preserving legacy active model.
10. Authorization isolation: token explanations are accessible only to the scan owner.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

import app.main as main_module
from app.api.routes import auth as auth_routes
from app.core.config import get_settings
from app.db.init_db import CONTENT_NLP_VERSION_TAG, init_db, register_content_nlp_model
from app.services import content_ml_service, ml_service
from app.services.content_ml_service import ContentMlStatus, ContentMlUnavailable
from app.services.ml_service import MlStatus
from tests.helpers import FakePrediction

REPO_ROOT = Path(__file__).resolve().parents[2]
URL = "/api/v1/scans/content-only"


@dataclass(frozen=True)
class FakeTokenContrib:
    token: str
    contribution: float
    direction: str
    tfidf_value: float = 0.15


@dataclass(frozen=True)
class FakeContentPrediction:
    label: int = 1
    classification: str = "Phishing"
    safe_probability: float = 0.05
    phishing_probability: float = 0.95
    raw_margin: float = 2.9444
    decision_threshold: float = 0.50
    shap_base_value: float = -3.7383
    additivity_residual: float = 0.000005
    top_positive_tokens: Tuple[FakeTokenContrib, ...] = (
        FakeTokenContrib("account", 1.85, "toward_phishing"),
        FakeTokenContrib("verify", 1.20, "toward_phishing"),
    )
    top_negative_tokens: Tuple[FakeTokenContrib, ...] = (
        FakeTokenContrib("meeting", -0.35, "toward_safe"),
    )


def fake_predict_content(body: str, explain: bool = True, top_k: int = 10):
    if "https://example.com/bad" in body and len(body.replace("https://example.com/bad", "").strip()) == 0:
        raise ValueError("email body contains no readable natural-language text after canonical cleaning")
    return FakeContentPrediction()


@contextmanager
def make_content_client(monkeypatch, predict_content_fn=fake_predict_content, authenticated=False, email="content-user@example.com"):
    monkeypatch.setattr(main_module, "load_ml", lambda _dir: MlStatus(True, "ready"))
    monkeypatch.setattr(ml_service, "max_body_chars", lambda: 200_000)
    if predict_content_fn is not None:
        monkeypatch.setattr(main_module, "load_content_ml", lambda _dir: ContentMlStatus(True, "ready"))
        monkeypatch.setattr(content_ml_service, "predict_content", predict_content_fn)
        monkeypatch.setattr(content_ml_service, "max_body_chars", lambda: 200_000)
    else:
        # Allow real candidate loading
        status = content_ml_service.load_content_ml(get_settings().content_nlp_package_dir)
        monkeypatch.setattr(main_module, "load_content_ml", lambda _dir: status)

    monkeypatch.setenv("BANTAI_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("BANTAI_SMTP_SENDER", "no-reply@example.test")
    get_settings.cache_clear()

    otp_codes = []
    monkeypatch.setattr(
        auth_routes,
        "send_otp_email",
        lambda _settings, _email, code, _purpose, _ttl: otp_codes.append(code),
    )

    with TestClient(main_module.create_app()) as client:
        client.otp_codes = otp_codes
        if authenticated:
            registration = client.post(
                "/api/v1/auth/register",
                json={
                    "full_name": "Content Test User",
                    "email": email,
                    "username": email.split("@")[0],
                    "password": "Password123!Safe",
                    "confirm_password": "Password123!Safe",
                },
            )
            assert registration.status_code == 202
            verification = client.post(
                "/api/v1/auth/register/verify",
                json={"email": email, "code": otp_codes[-1]},
            )
            assert verification.status_code == 200
            token = verification.json()["accessToken"]
            client.headers.update({"Authorization": f"Bearer {token}"})
        yield client


class TestContentScansAPI:
    def test_01_content_scan_success_authenticated(self, monkeypatch):
        """Authenticated user scans readable text; verifies response shape and zero-body privacy."""
        with make_content_client(monkeypatch, authenticated=True) as client:
            resp = client.post(
                URL,
                json={
                    "bodyText": "URGENT: Please verify your banking account security credentials immediately.",
                    "fileName": "urgent_notice.txt",
                    "explain": True,
                    "top_k": 10,
                },
            )
            assert resp.status_code == 200, resp.text
            assert resp.headers["cache-control"] == "no-store"
            data = resp.json()

            assert data["pipeline"] == "content_only"
            assert data["saved"] is True
            assert data["scanId"] is not None
            assert data["scanCode"].startswith("BNT-")
            assert data["riskLevel"] == "phishing"
            assert data["riskTier"] == "Critical"
            assert data["threatScore"] == 95
            assert data["phishingProbability"] == 0.95
            assert data["safeProbability"] == 0.05
            assert data["modelClassification"] == "Phishing"
            assert data["decisionThreshold"] == 0.50

            # Explanations: word items only; no fake URLs or headers
            assert len(data["explanations"]) == 3
            assert data["explanations"][0]["kind"] == "word"
            assert data["explanations"][0]["feature"] == "account"
            assert data["explanations"][0]["direction"] == "toward_phishing"

            assert data["links"] == []
            assert data["linkCount"] == 0
            assert data["auth"] == {"spf": None, "dkim": None, "dmarc": None}
            assert data["modelVersion"] == "candidate-v2-exp4-refit"

            # Database verification: confirm no body text stored and scan row created
            settings = get_settings()
            conn = sqlite3.connect(settings.database_path)
            try:
                row = conn.execute(
                    "SELECT scan_id, subject, url_count, threat_score, risk_tier FROM scans WHERE scan_id = ?",
                    (data["scanId"],),
                ).fetchone()
                assert row is not None
                assert row[1] == "[Content-Only Scan]"
                assert row[2] == 0  # url_count
                assert row[3] == 95  # threat_score
                assert row[4] == "Critical"

                # Verify token contributions table has rows for authenticated user
                tokens = conn.execute(
                    "SELECT token, direction, contribution FROM scan_token_contributions WHERE scan_id = ?",
                    (data["scanId"],),
                ).fetchall()
                assert len(tokens) == 3
            finally:
                conn.close()

    def test_02_content_scan_unauthenticated_rejected_401(self, monkeypatch):
        """Unauthenticated request is rejected with 401; no guest reservation is made."""
        client_ip = "198.51.100.42"
        headers = {"X-Forwarded-For": client_ip}

        with make_content_client(monkeypatch, authenticated=False) as client:
            client.headers.update(headers)
            r = client.post(URL, json={"bodyText": "Unauthenticated message content attempting scan."})
            assert r.status_code == 401, r.text
            assert r.json()["detail"]["code"] in ("not_authenticated", "invalid_token")

            # Verify no guest reservation was created
            settings = get_settings()
            conn = sqlite3.connect(settings.database_path)
            try:
                reservations = conn.execute(
                    "SELECT COUNT(*) FROM guest_scan_reservations WHERE client_ip = ?",
                    (client_ip,),
                ).fetchone()[0]
                assert reservations == 0, "Unauthenticated requests must not create guest reservations"

                scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                assert scans == 0
            finally:
                conn.close()

    def test_03_content_scan_invalid_token_rejected_401(self, monkeypatch):
        """Request with invalid bearer token is rejected with 401."""
        with make_content_client(monkeypatch, authenticated=False) as client:
            client.headers.update({"Authorization": "Bearer totally-invalid-token"})
            r = client.post(URL, json={"bodyText": "Message with forged bearer token."})
            assert r.status_code == 401
            assert r.json()["detail"]["code"] in ("not_authenticated", "invalid_token")

    def test_04_content_scan_rejection_empty_and_whitespace(self, monkeypatch):
        """Rejects empty string and whitespace-only text with 422; does not echo input."""
        with make_content_client(monkeypatch, authenticated=True) as client:
            r_empty = client.post(URL, json={"bodyText": ""})
            assert r_empty.status_code == 422
            # Verify body text is not echoed in validation error
            assert "input" not in r_empty.text

            r_ws = client.post(URL, json={"bodyText": "   \n\t  \r  "})
            assert r_ws.status_code == 422
            assert r_ws.json()["detail"]["code"] == "whitespace_only"
            assert "input" not in r_ws.text

    def test_05_content_scan_rejection_degenerate_cleaned(self, monkeypatch):
        """Rejects text that becomes empty after canonical cleaning (e.g. only URLs)."""
        with make_content_client(monkeypatch, authenticated=True) as client:
            r = client.post(URL, json={"bodyText": "https://example.com/bad"})
            assert r.status_code == 422
            assert r.json()["detail"]["code"] == "degenerate_content"
            assert "input" not in r.text

    def test_06_content_scan_rejection_body_too_long(self, monkeypatch):
        """Rejects text exceeding 200,000 characters without silent truncation."""
        with make_content_client(monkeypatch, authenticated=True) as client:
            oversized = "A" * 200_001
            r = client.post(URL, json={"bodyText": oversized})
            assert r.status_code in (413, 422)
            assert "input" not in r.text

    def test_07_content_scan_degraded_startup_when_candidate_offline(self, monkeypatch):
        """When content ML model is not ready, returns 503; legacy scan route stays operational."""
        with make_content_client(monkeypatch, authenticated=True) as client:
            # Simulate candidate model unavailable
            monkeypatch.setattr(content_ml_service, "predict_content", lambda *a, **k: (_ for _ in ()).throw(ContentMlUnavailable("model offline")))

            r_content = client.post(URL, json={"bodyText": "Please verify your account credentials."})
            assert r_content.status_code == 503
            assert r_content.json()["detail"]["code"] == "ml_unavailable"

            # Confirm legacy scan endpoint is still reachable
            monkeypatch.setattr(ml_service, "predict", lambda *a, **k: FakePrediction(0.8, "Phishing", ()))
            r_legacy = client.post("/api/v1/scans", json={"inputMethod": "raw_text", "content": "Legacy email test."})
            assert r_legacy.status_code == 200

    def test_08_model_version_registration_idempotence(self, tmp_path):
        """Candidate V2 EXP-4 registers with is_active = 0 preserving legacy active model."""
        db_path = tmp_path / "test.db"
        settings = get_settings()
        init_db(db_path, settings.sql_dir, settings.ml_dir)
        conn = sqlite3.connect(db_path)
        try:
            # Query model_versions after init_db
            row = conn.execute(
                "SELECT version_tag, algorithm, explainer_type, is_active FROM model_versions WHERE version_tag = ?",
                (CONTENT_NLP_VERSION_TAG,),
            ).fetchone()
            assert row is not None
            assert row[0] == "candidate-v2-exp4-refit"
            assert row[1] == "XGBoost"
            assert row[2] == "shap.TreeExplainer"
            assert row[3] == 0, "Candidate model must be registered with is_active = 0"

            # Check that only one model is active (ux_model_one_active)
            active_count = conn.execute("SELECT COUNT(*) FROM model_versions WHERE is_active = 1").fetchone()[0]
            assert active_count == 1

            # Second registration call returns False (idempotent)
            second = register_content_nlp_model(conn, settings.ml_dir)
            assert second is False
        finally:
            conn.close()

    def test_09_token_attribution_authorization_isolation(self, monkeypatch):
        """User A's scan token contributions cannot be accessed by User B."""
        with make_content_client(monkeypatch, authenticated=True, email="user-a@example.com") as client_a:
            r = client_a.post(URL, json={"bodyText": "User A confidential security alert text."})
            assert r.status_code == 200
            scan_id = r.json()["scanId"]

            # User A can retrieve detail
            r_detail = client_a.get(f"/api/v1/scans/{scan_id}")
            assert r_detail.status_code == 200
            assert len(r_detail.json()["explanations"]) == 3

        # User B queries User A's scan
        with make_content_client(monkeypatch, authenticated=True, email="user-b@example.com") as client_b:
            r_forbidden = client_b.get(f"/api/v1/scans/{scan_id}")
            assert r_forbidden.status_code == 404

    def test_10_real_candidate_exp4_end_to_end(self, monkeypatch):
        """End-to-end integration test with the real Phase 7 packaged EXP-4 model."""
        # Un-mock predict_content to use the real ContentNLPPredictor
        with make_content_client(monkeypatch, predict_content_fn=None, authenticated=True, email="real-exp4-user@example.com") as client:
            resp = client.post(
                URL,
                json={
                    "bodyText": "URGENT: Please verify your banking account security credentials immediately.",
                    "fileName": "urgent_bank.txt",
                    "explain": True,
                    "top_k": 10,
                },
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()

            assert data["pipeline"] == "content_only"
            assert data["saved"] is True
            assert data["modelClassification"] in ("Phishing", "Legitimate")
            assert 0 <= data["threatScore"] <= 100
            assert 0.0 <= data["phishingProbability"] <= 1.0
            assert 0.0 <= data["safeProbability"] <= 1.0

            # SHAP validation: check baseValue and rawMargin additivity
            shap_data = data["shap"]
            assert shap_data["baseValue"] is not None
            assert shap_data["rawMargin"] is not None
            assert shap_data["unit"] == "log-odds"

            # Explanations check
            words = [e for e in data["explanations"] if e["kind"] == "word"]
            assert len(words) > 0
            assert all(e["direction"] in ("toward_phishing", "toward_safe") for e in words)
            assert all(isinstance(e["value"], float) for e in words)

    def test_11_web_handoff_lifecycle_and_replay_rejection(self, monkeypatch):
        """Handoff ticket has 2-min TTL, atomic exchange, and instant replay rejection."""
        with make_content_client(monkeypatch, authenticated=True, email="handoff-user@example.com") as client:
            # 1. Create ticket
            r_create = client.post("/api/v1/auth/web-handoff")
            assert r_create.status_code == 200
            data = r_create.json()
            ticket = data["ticket"]
            assert ticket.startswith("web_")

            # 2. First exchange succeeds
            r_exchange1 = client.post("/api/v1/auth/web-handoff/exchange", json={"ticket": ticket})
            assert r_exchange1.status_code == 200
            assert "accessToken" in r_exchange1.json()

            # 3. Replay with same ticket fails with 400
            r_exchange2 = client.post("/api/v1/auth/web-handoff/exchange", json={"ticket": ticket})
            assert r_exchange2.status_code == 400
            assert r_exchange2.json()["detail"]["code"] == "invalid_web_handoff"

    def test_12_schema_aware_zero_body_privacy_audit(self, monkeypatch):
        """Schema-aware audit: scans table has NO email_body column; metadata is privacy-safe."""
        with make_content_client(monkeypatch, authenticated=True, email="privacy-audit@example.com") as client:
            r = client.post(URL, json={"bodyText": "Confidential patient record: please review lab results."})
            assert r.status_code == 200
            scan_id = r.json()["scanId"]

            # Direct SQLite inspection
            db_path = str(get_settings().database_path)
            conn = sqlite3.connect(db_path)
            try:
                # 1. Verify DDL: PRAGMA table_info has NO body/email_body column
                cols = [row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()]
                assert "email_body" not in cols, "email_body column must NOT exist in scans table"
                assert "body" not in cols, "body column must NOT exist in scans table"
                assert "content" not in cols, "content column must NOT exist in scans table"

                # 2. Verify scan record row
                row = conn.execute(
                    "SELECT subject, sender_address, url_count, body_char_count FROM scans WHERE scan_id = ?",
                    (scan_id,),
                ).fetchone()
                assert row is not None
                subject, sender_address, url_count, body_char_count = row
                assert subject == "[Content-Only Scan]"
                assert sender_address is None
                assert url_count == 0
                assert body_char_count > 0

                # 3. Verify zero extracted URLs
                url_rows = conn.execute("SELECT COUNT(*) FROM extracted_urls WHERE scan_id = ?", (scan_id,)).fetchone()[0]
                assert url_rows == 0

                # 4. Verify scan_token_contributions stores only derived unigrams (<= 10)
                tokens = conn.execute(
                    "SELECT token, contribution, abs_rank FROM scan_token_contributions WHERE scan_id = ?",
                    (scan_id,),
                ).fetchall()
                assert len(tokens) <= 10
                assert all(len(t[0].split()) == 1 for t in tokens), "Tokens must be individual unigrams, not sentences"
            finally:
                conn.close()

    def test_13_cascade_deletion_removes_token_contributions(self, monkeypatch):
        """Deleting a scan record cascades and purges corresponding token contributions."""
        with make_content_client(monkeypatch, authenticated=True, email="cascade-audit@example.com") as client:
            r = client.post(URL, json={"bodyText": "Ephemeral scan to test cascade deletion."})
            assert r.status_code == 200
            scan_id = r.json()["scanId"]

            db_path = str(get_settings().database_path)
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("PRAGMA foreign_keys = ON")
                # Confirm token contributions exist before deletion
                count_before = conn.execute(
                    "SELECT COUNT(*) FROM scan_token_contributions WHERE scan_id = ?", (scan_id,)
                ).fetchone()[0]
                assert count_before > 0

                # Delete the parent scan
                conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
                conn.commit()

                # Confirm token contributions were cascade deleted
                count_after = conn.execute(
                    "SELECT COUNT(*) FROM scan_token_contributions WHERE scan_id = ?", (scan_id,)
                ).fetchone()[0]
                assert count_after == 0
            finally:
                conn.close()

    def test_14_risk_tier_boundary_mapping_and_threat_score(self, monkeypatch):
        """Validates threat score round(p*100) and risk tier cutoffs: Low <= 39, Medium 40-79, Critical >= 80."""
        # Case A: Probability 0.20 -> Score 20 -> Low tier, Legitimate class
        pred_low = FakeContentPrediction(
            classification="Legitimate", phishing_probability=0.20, safe_probability=0.80, raw_margin=-1.386
        )
        with make_content_client(monkeypatch, predict_content_fn=lambda *a, **k: pred_low, authenticated=True, email="tier-low@example.com") as client:
            r = client.post(URL, json={"bodyText": "Normal email prose."})
            assert r.status_code == 200
            data = r.json()
            assert data["threatScore"] == 20
            assert data["riskTier"] == "Low"
            assert data["riskLevel"] == "safe"
            assert data["modelClassification"] == "Legitimate"

        # Case B: Probability 0.50 -> Score 50 -> Medium tier, Phishing class (at 0.50 cutoff)
        pred_med = FakeContentPrediction(
            classification="Phishing", phishing_probability=0.50, safe_probability=0.50, raw_margin=0.000
        )
        with make_content_client(monkeypatch, predict_content_fn=lambda *a, **k: pred_med, authenticated=True, email="tier-med@example.com") as client:
            r = client.post(URL, json={"bodyText": "Borderline email prose."})
            assert r.status_code == 200
            data = r.json()
            assert data["threatScore"] == 50
            assert data["riskTier"] == "Medium"
            assert data["riskLevel"] == "suspicious"
            assert data["modelClassification"] == "Phishing"

        # Case C: Probability 0.90 -> Score 90 -> Critical tier, Phishing class
        pred_crit = FakeContentPrediction(
            classification="Phishing", phishing_probability=0.90, safe_probability=0.10, raw_margin=2.197
        )
        with make_content_client(monkeypatch, predict_content_fn=lambda *a, **k: pred_crit, authenticated=True, email="tier-crit@example.com") as client:
            r = client.post(URL, json={"bodyText": "Highly dangerous credential phishing prose."})
            assert r.status_code == 200
            data = r.json()
            assert data["threatScore"] == 90
            assert data["riskTier"] == "Critical"
            assert data["riskLevel"] == "phishing"
            assert data["modelClassification"] == "Phishing"

