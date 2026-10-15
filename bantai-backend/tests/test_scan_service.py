"""Step 5: the scan pipeline against a real database, with a FAKE model.

Needs SQLAlchemy (skipped automatically if absent).
"""

import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy.exc import SQLAlchemyError  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.db.init_db import init_db  # noqa: E402
from app.db.models import User, UserSettings  # noqa: E402
from app.db.session import build_engine  # noqa: E402
from app.services import scan_store  # noqa: E402
from app.services.ml_service import MlUnavailable  # noqa: E402
from app.services.scan_service import (  # noqa: E402
    ClientInfo,
    ScanFailure,
    ScanSubmission,
    perform_scan,
)
from tests.helpers import FakePrediction, contribution  # noqa: E402

SQL_DIR = Path(__file__).resolve().parents[2] / "bantai-database"
SECRET = "ZEBRA-SECRET-PHRASE-42"
BODY = (
    "From: Support <support@paypal-update.example>\n"
    "Return-Path: <bounce@mailer-x91.example>\n"
    "Subject: URGENT verify your account\n"
    "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail\n\n"
    f"Dear customer, {SECRET}. Verify your password immediately at http://203.0.113.9/login now!\n"
)


def fake_predict(body, top_k):
    return FakePrediction(
        0.92, "Phishing",
        (contribution("verify", 1.2), contribution("urgent", 0.9), contribution("meeting", -0.4)),
    )


@pytest.fixture()
def env(tmp_path):
    path = tmp_path / "svc.db"
    init_db(path, SQL_DIR, None)
    engine = build_engine(path)
    with Session(engine) as session:
        yield session, path
    engine.dispose()


def run(session, content=BODY, *, user_id=None, method="raw_text", encoding="text",
        predict=fake_predict, max_chars=200_000, file_name="m.eml"):
    return perform_scan(
        session,
        ScanSubmission(method, content, encoding, file_name),
        ClientInfo("127.0.0.1", "pytest"),
        user_id,
        predict_fn=predict,
        max_body_chars_fn=lambda: max_chars,
    )


def q(path, sql, args=()):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def make_user(session, email="u@example.com"):
    user = User(full_name="U", email=email, password_hash="h")
    session.add(user)
    session.commit()
    return user.user_id


def test_guest_scan_is_recorded_without_identifying_text(env):
    session, path = env
    result = run(session)
    assert (result["riskLevel"], result["threatScore"]) == ("phishing", 92)
    assert result["saved"] is True and result["scanCode"].startswith("BNT-")

    [row] = q(path, "SELECT user_id, subject, sender_address, sender_domain, spf_result, url_count,"
                    " risk_tier, content_sha256, file_name, inference_ms FROM scans")
    user_id, subject, sender, domain, spf, url_count, tier, sha, file_name, ms = row
    assert user_id is None and subject is None and sender is None      # guest privacy
    assert domain == "paypal-update.example" and spf == "fail" and url_count == 1
    assert tier == "Critical" and len(sha) == 64 and file_name == "m.eml" and ms >= 0


def test_children_rows_are_written(env):
    session, path = env
    run(session)
    assert q(path, "SELECT COUNT(*) FROM extracted_urls")[0][0] == 1
    assert q(path, "SELECT COUNT(*) FROM scan_features")[0][0] == 20
    tokens = q(path, "SELECT abs_rank, token, direction, insight_title FROM scan_token_contributions ORDER BY abs_rank")
    assert [t[1] for t in tokens] == ["verify", "urgent", "meeting"]
    assert tokens[0][3] == "Request for Sensitive Information"
    [(event, status, scan_id, detail)] = q(path, "SELECT event_type, http_status, scan_id, detail FROM audit_logs")
    assert (event, status) == ("SCAN_COMPLETED", 200) and scan_id is not None
    assert '"risk_tier":"Critical"' in detail


def test_signed_in_user_keeps_subject_and_sender(env):
    session, path = env
    uid = make_user(session)
    run(session, user_id=uid)
    [(user_id, subject, sender)] = q(path, "SELECT user_id, subject, sender_address FROM scans")
    assert user_id == uid and subject == "URGENT verify your account"
    assert sender == "support@paypal-update.example"


def test_auto_save_off_records_audit_only(env):
    session, path = env
    uid = make_user(session)
    session.add(UserSettings(user_id=uid, auto_save_scan_logs=False))
    session.commit()
    result = run(session, user_id=uid)
    assert result["saved"] is False and result["scanId"] is None and result["threatScore"] == 92
    assert q(path, "SELECT COUNT(*) FROM scans")[0][0] == 0
    [(event, scan_id, detail)] = q(path, "SELECT event_type, scan_id, detail FROM audit_logs")
    assert event == "SCAN_COMPLETED" and scan_id is None and '"saved":false' in detail


@pytest.mark.parametrize("content,method,encoding,status,code", [
    ("   \n ", "raw_text", "text", 422, "unparseable"),
    ("!!!", "eml_upload", "base64", 422, "invalid_base64"),
])
def test_rejected_input_is_audited_and_not_stored(env, content, method, encoding, status, code):
    session, path = env
    with pytest.raises(ScanFailure) as err:
        run(session, content, method=method, encoding=encoding)
    assert (err.value.status, err.value.code) == (status, code)
    assert q(path, "SELECT COUNT(*) FROM scans")[0][0] == 0
    [(event, http, detail)] = q(path, "SELECT event_type, http_status, detail FROM audit_logs")
    assert event == "SCAN_REJECTED" and http == status and code in detail


def test_overlong_body_is_413(env):
    session, path = env
    with pytest.raises(ScanFailure) as err:
        run(session, max_chars=10)
    assert (err.value.status, err.value.code) == (413, "body_too_long")
    assert q(path, "SELECT COUNT(*) FROM scans")[0][0] == 0


def test_model_unavailable_is_503_and_audited(env):
    session, path = env

    def broken(body, top_k):
        raise MlUnavailable("down")

    with pytest.raises(ScanFailure) as err:
        run(session, predict=broken)
    assert (err.value.status, err.value.code) == (503, "ml_unavailable")
    [(event, http)] = q(path, "SELECT event_type, http_status FROM audit_logs")
    assert (event, http) == ("SCAN_REJECTED", 503)


def test_no_email_text_reaches_the_database(env):
    session, path = env
    uid = make_user(session)
    run(session)                      # guest
    run(session, user_id=uid)         # signed in
    conn = sqlite3.connect(path)
    try:
        dump = "\n".join(conn.iterdump())
    finally:
        conn.close()
    assert SECRET not in dump


def test_storage_failure_fails_closed(env, monkeypatch):
    session, path = env

    def boom(*args, **kwargs):
        raise SQLAlchemyError("disk full")

    monkeypatch.setattr(scan_store, "save_scan", boom)
    with pytest.raises(ScanFailure) as err:
        run(session)
    assert (err.value.status, err.value.code) == (500, "storage_failed")
    assert q(path, "SELECT COUNT(*) FROM scans")[0][0] == 0
    assert q(path, "SELECT COUNT(*) FROM audit_logs WHERE event_type = 'SCAN_COMPLETED'")[0][0] == 0
