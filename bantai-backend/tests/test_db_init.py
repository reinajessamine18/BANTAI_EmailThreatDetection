"""Step 3 tests: database creation from the team's SQL files. Standard library only."""

import json
import re
import shutil
import sqlite3
from pathlib import Path

import pytest

from app.db.init_db import BASELINE_VERSION_TAG, DatabaseInitError, init_db

REPO_ROOT = Path(__file__).resolve().parents[2]
SQL_DIR = REPO_ROOT / "bantai-database"
ML_DIR = REPO_ROOT / "machine-learning"
HAVE_ARTIFACTS = (ML_DIR / "artifacts" / "baseline" / "xgboost_model.pkl").is_file()

EXPECTED_TABLES = {
    "users", "user_sessions", "user_settings", "system_settings", "model_versions",
    "feature_definitions", "scans", "scan_features", "shap_results", "explanations",
    "extracted_urls", "scan_feedback", "audit_logs",
    "scan_token_contributions", "token_feature_map", "password_reset_tokens",
    "password_reset_requests", "guest_scan_reservations", "email_otp_challenges",
    "oauth_states", "oauth_login_tickets",
}


def _connect(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _one(db: Path, sql: str, args=()):
    conn = _connect(db)
    try:
        return conn.execute(sql, args).fetchone()
    finally:
        conn.close()


def _all(db: Path, sql: str, args=()):
    conn = _connect(db)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def _new_scan(conn) -> int:
    conn.execute(
        "INSERT INTO scans (model_version_id, input_method, content_sha256,"
        " malicious_probability, threat_score, risk_tier)"
        " VALUES (1, 'raw_text', 'x', 0.9, 90, 'Critical')"
    )
    return conn.execute("SELECT MAX(scan_id) FROM scans").fetchone()[0]


# ------------------------------------------------------------------ structure
def test_fresh_database_has_all_tables_view_and_seed(tmp_path):
    db = tmp_path / "t.db"
    result = init_db(db, SQL_DIR, ML_DIR)
    assert result.created
    names = {r[0] for r in _all(db, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert EXPECTED_TABLES <= names
    assert _one(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name='v_scan_history'")[0] == 1
    assert _one(db, "SELECT COUNT(*) FROM feature_definitions")[0] > 0
    assert _one(db, "SELECT setting_value FROM system_settings WHERE setting_key='risk_low_max'")[0] == "39"


def test_schema_version_matches_schema_sql(tmp_path):
    db = tmp_path / "t.db"
    result = init_db(db, SQL_DIR, None)
    declared = int(re.search(r"PRAGMA\s+user_version\s*=\s*(\d+)",
                             (SQL_DIR / "schema.sql").read_text(encoding="utf-8"), re.I).group(1))
    assert result.schema_version == declared
    assert _one(db, "PRAGMA user_version")[0] == declared


def test_no_building_file_left_behind(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, ML_DIR)
    assert [p.name for p in tmp_path.iterdir()] == ["t.db"]


# --------------------------------------------------------------- model record
@pytest.mark.skipif(not HAVE_ARTIFACTS, reason="ML artifacts not present")
def test_baseline_model_registered_with_real_recorded_metrics(tmp_path):
    db = tmp_path / "t.db"
    result = init_db(db, SQL_DIR, ML_DIR)
    assert result.model_registered
    active = _all(
        db,
        "SELECT version_tag, accuracy, f1_score, roc_auc, n_training_samples, model_artifact_path"
        " FROM model_versions WHERE is_active = 1",
    )
    placeholder_active = _one(db, "SELECT is_active FROM model_versions WHERE version_tag = 'xgb-dev-0.0.0'")[0]
    cfg = json.loads((ML_DIR / "artifacts" / "baseline" / "experiment_config.json").read_text())
    m = cfg["validation_metrics"]
    assert len(active) == 1
    tag, acc, f1, auc, n, path = active[0]
    assert tag == BASELINE_VERSION_TAG
    assert (acc, f1, auc) == (m["accuracy"], m["f1_score"], m["roc_auc"])
    assert n == cfg["train_rows"]
    assert not path.startswith(("/", "\\")) and ":" not in path  # no machine-specific path
    assert placeholder_active == 0


def test_missing_artifacts_keeps_placeholder_model_active(tmp_path):
    db = tmp_path / "t.db"
    result = init_db(db, SQL_DIR, tmp_path / "no_ml_here")
    assert result.created and not result.model_registered
    assert _one(db, "SELECT version_tag FROM model_versions WHERE is_active = 1")[0] == "xgb-dev-0.0.0"


# ------------------------------------------------------- idempotency / versions
def test_second_run_is_a_no_op(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, ML_DIR)
    before = _one(db, "SELECT COUNT(*) FROM model_versions")[0]
    again = init_db(db, SQL_DIR, ML_DIR)
    assert not again.created and not again.model_registered
    assert _one(db, "SELECT COUNT(*) FROM model_versions")[0] == before


def test_revision_two_database_migrates_without_losing_users(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, None)
    conn = _connect(db)
    conn.execute(
        "INSERT INTO users (full_name, email, password_hash) VALUES ('Ana', 'a@example.com', 'hash')"
    )
    conn.execute(
        "INSERT INTO user_settings (user_id, auto_save_scan_logs) VALUES (1, 1)"
    )
    conn.execute("DROP TABLE password_reset_requests")
    conn.execute("DROP TABLE password_reset_tokens")
    conn.execute("DROP TABLE guest_scan_reservations")
    conn.execute("DROP TABLE oauth_login_tickets")
    conn.execute("DROP TABLE oauth_states")
    conn.execute("DROP TABLE email_otp_challenges")
    conn.execute("DROP INDEX ux_users_username")
    conn.execute("ALTER TABLE users DROP COLUMN email_verified_at")
    conn.execute("ALTER TABLE users DROP COLUMN username")
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()

    result = init_db(db, SQL_DIR, None)
    assert not result.created
    assert _one(db, "PRAGMA user_version")[0] == 11
    assert _one(db, "SELECT email FROM users WHERE user_id = 1")[0] == "a@example.com"
    assert _one(db, "SELECT auto_save_scan_logs FROM user_settings WHERE user_id = 1")[0] == 1
    auto_save_column = next(
        row for row in _all(db, "PRAGMA table_info(user_settings)")
        if row[1] == "auto_save_scan_logs"
    )
    assert auto_save_column[4] == "1"
    names = {row[0] for row in _all(db, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {
        "password_reset_tokens",
        "password_reset_requests",
        "guest_scan_reservations",
    } <= names


def test_google_sso_version_nine_database_migrates_without_losing_records(tmp_path):
    db = tmp_path / "google-v9.db"
    init_db(db, SQL_DIR, None)
    conn = _connect(db)
    conn.execute(
        "INSERT INTO users (full_name, email, auth_provider, sso_subject_id, sso_idp_entity_id)"
        " VALUES ('Google User', 'google@example.com', 'google', 'subject-1', 'google')"
    )
    conn.execute(
        "INSERT INTO user_settings (user_id, auto_save_scan_logs) VALUES (1, 0)"
    )
    conn.execute(
        "INSERT INTO user_sessions (user_id, token_hash, expires_at)"
        " VALUES (1, 'token-hash', '2030-01-01T00:00:00Z')"
    )
    scan_id = _new_scan(conn)
    conn.execute("UPDATE scans SET user_id = 1 WHERE scan_id = ?", (scan_id,))

    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.executescript("""
        DROP TABLE oauth_login_tickets;
        DROP TABLE oauth_states;
        DROP TABLE email_otp_challenges;
        DROP INDEX ux_users_username;
        CREATE TABLE users_legacy (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            auth_provider TEXT NOT NULL DEFAULT 'google' CHECK (auth_provider = 'google'),
            sso_subject_id TEXT NOT NULL,
            sso_idp_entity_id TEXT NOT NULL DEFAULT 'google',
            role TEXT NOT NULL DEFAULT 'analyst',
            job_title TEXT,
            tier_label TEXT,
            profile_picture TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            last_login_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        INSERT INTO users_legacy (
            user_id, full_name, email, auth_provider, sso_subject_id, sso_idp_entity_id,
            role, job_title, tier_label, profile_picture, is_active, last_login_at,
            created_at, updated_at
        )
        SELECT
            user_id, full_name, email, auth_provider, sso_subject_id, sso_idp_entity_id,
            role, job_title, tier_label, profile_picture, is_active, last_login_at,
            created_at, updated_at
        FROM users;
        DROP TABLE users;
        ALTER TABLE users_legacy RENAME TO users;
        CREATE UNIQUE INDEX ux_users_sso ON users (sso_idp_entity_id, sso_subject_id);
        DROP TABLE password_reset_requests;
        DROP TABLE password_reset_tokens;
        DROP TABLE guest_scan_reservations;
        PRAGMA user_version = 9;
    """)
    conn.commit()
    conn.close()

    result = init_db(db, SQL_DIR, None)

    assert not result.created and result.schema_version == 11
    assert _one(db, "PRAGMA user_version")[0] == 11
    assert _one(db, "SELECT email, auth_provider, password_hash FROM users WHERE user_id = 1") == (
        "google@example.com", "google", None
    )
    assert _one(db, "SELECT auto_save_scan_logs FROM user_settings WHERE user_id = 1")[0] == 0
    assert _one(db, "SELECT token_hash FROM user_sessions WHERE user_id = 1")[0] == "token-hash"
    assert _one(db, "SELECT user_id FROM scans WHERE scan_id = ?", (scan_id,))[0] == 1
    assert _all(db, "PRAGMA foreign_key_check") == []


def test_database_with_old_schema_version_is_rejected_with_clear_message(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, None)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA user_version = 1")
    conn.close()
    with pytest.raises(DatabaseInitError) as err:
        init_db(db, SQL_DIR, None)
    assert "migration" in str(err.value) and "t.db" in str(err.value)


def test_schema_without_version_declaration_is_rejected(tmp_path):
    bad = tmp_path / "sql"
    shutil.copytree(SQL_DIR, bad)
    text = (bad / "schema.sql").read_text(encoding="utf-8")
    (bad / "schema.sql").write_text(re.sub(r"PRAGMA\s+user_version\s*=\s*\d+;", "", text, flags=re.I),
                                    encoding="utf-8")
    with pytest.raises(DatabaseInitError):
        init_db(tmp_path / "t.db", bad, None)
    assert not (tmp_path / "t.db").exists()


def test_broken_sql_leaves_no_database_file(tmp_path):
    bad = tmp_path / "bad_sql"
    shutil.copytree(SQL_DIR, bad)
    (bad / "schema.sql").write_text("CREATE TABLE ok (a INTEGER); THIS IS NOT SQL; PRAGMA user_version = 2;")
    db = tmp_path / "t.db"
    with pytest.raises(DatabaseInitError):
        init_db(db, bad, None)
    assert not db.exists()
    assert not (tmp_path / "t.db.building").exists()


def test_missing_sql_file_is_a_clear_error(tmp_path):
    with pytest.raises(DatabaseInitError):
        init_db(tmp_path / "t.db", tmp_path / "nowhere", None)
    assert not (tmp_path / "t.db").exists()


# ----------------------------------------------------------------- sample data
def test_sample_data_loads_and_history_view_works(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, None, with_sample=True)
    row = _one(db, "SELECT scan_code, classification, threat_score FROM v_scan_history WHERE scan_id = 8486")
    assert row == ("BNT-8486", "Phishing", 92)
    assert _all(db, "PRAGMA foreign_key_check") == []


# ------------------------------------------------------------- integrity rules
def test_foreign_keys_and_checks_are_enforced(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, None)
    conn = _connect(db)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO scans (model_version_id, input_method, content_sha256,"
                " malicious_probability, threat_score, risk_tier)"
                " VALUES (999, 'raw_text', 'x', 0.5, 50, 'Medium')"
            )
    finally:
        conn.close()


def test_token_contributions_cascade_direction_check_and_insight_columns(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, None)
    conn = _connect(db)
    try:
        scan_id = _new_scan(conn)
        conn.execute(
            "INSERT INTO scan_token_contributions (scan_id, abs_rank, token, contribution, direction,"
            " tfidf_value, insight_type, insight_title, insight_message)"
            " VALUES (?, 1, 'verify', 0.8, 'toward_phishing', 0.2, 'Educational Insight', 'T', 'M')",
            (scan_id,),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO scan_token_contributions (scan_id, abs_rank, token, contribution, direction,"
                " tfidf_value) VALUES (?, 2, 'x', 0.1, 'sideways', 0.1)",
                (scan_id,),
            )
        conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        assert conn.execute("SELECT COUNT(*) FROM scan_token_contributions").fetchone()[0] == 0
    finally:
        conn.close()


def test_new_audit_event_types_accepted_and_unknown_rejected(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, None)
    conn = _connect(db)
    try:
        for event in ("USER_REGISTERED", "PROFILE_UPDATED", "PASSWORD_CHANGED", "PASSWORD_RESET", "SCAN_COMPLETED"):
            conn.execute("INSERT INTO audit_logs (event_type) VALUES (?)", (event,))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO audit_logs (event_type) VALUES ('SOMETHING_ELSE')")
    finally:
        conn.close()


def test_profile_picture_column_and_size_cap(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, None)
    conn = _connect(db)
    try:
        conn.execute("INSERT INTO users (full_name, email, password_hash, profile_picture)"
                     " VALUES ('A', 'a@x.example', 'h', 'data:image/png;base64,AAAA')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO users (full_name, email, password_hash, profile_picture)"
                         " VALUES ('B', 'b@x.example', 'h', ?)", ("x" * 400001,))
    finally:
        conn.close()


# ------------------------------------------------------- seed content (new in R2)
def test_education_mapping_is_consistent(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, None)
    rows = _all(
        db,
        "SELECT t.token, f.feature_key, f.category, f.insight_template FROM token_feature_map t"
        " JOIN feature_definitions f USING (feature_id)",
    )
    assert len(rows) > 0
    assert {r[1] for r in rows} == {"urgency_keyword_count", "credential_request_count"}
    assert all(r[2] == "text" and r[3] for r in rows)
    assert all(r[0] == r[0].lower() for r in rows)
    conn = _connect(db)
    try:
        with pytest.raises(sqlite3.IntegrityError):  # uppercase tokens are rejected
            conn.execute("INSERT INTO token_feature_map VALUES ('URGENT', 1)")
    finally:
        conn.close()


def test_generic_insight_and_auth_settings_seeded(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, None)
    settings = dict(_all(db, "SELECT setting_key, setting_value FROM system_settings"))
    assert "{token}" in settings["insight_generic_phishing"]
    assert "{token}" in settings["insight_generic_safe"]
    for key in ("session_ttl_hours", "max_failed_logins", "lockout_minutes", "top_n_explanations"):
        assert settings[key].isdigit()


def test_unmeasurable_features_are_inactive(tmp_path):
    db = tmp_path / "t.db"
    init_db(db, SQL_DIR, None)
    inactive = {r[0] for r in _all(db, "SELECT feature_key FROM feature_definitions WHERE is_active = 0")}
    assert inactive == {"url_redirect_count", "sentiment_score", "html_to_text_ratio"}
