-- =====================================================================
-- BANTAI: XGBoost-Based Email Threat Detection and Analysis Engine
-- Database schema (SQLite 3.31+)  |  Group 11
--
-- Privacy rule from the paper: the email BODY is never stored.
-- Only metadata, numeric features, SHAP values, and explanations are kept.
--
-- REVISION 2 (backend integration). Changes are marked "[R2]":
--   * The deployed model is TF-IDF + XGBoost over the email body, so its SHAP
--     values belong to WORDS, not to the hand-built feature catalog. They are kept
--     in scan_token_contributions. shap_results / explanations are reserved for a
--     feature-engineered model and are NOT populated by the current baseline.
--   * scan_features holds the rule-based indicators extracted from headers/URLs/text.
--   * users.profile_picture, extra audit event types, token_feature_map.
--   * PRAGMA user_version (end of file) marks the schema version; the backend
--     refuses to run against a database with a different version.
-- REVISION 3 adds hashed, expiring password-reset tokens and short-lived
-- per-IP request counters. Existing revision-2 databases migrate in place.
-- REVISION 4 defaults Auto-save Scan Logs to off; existing saved preferences
-- remain unchanged during migration.
-- REVISION 5 enables Auto-save Scan Logs by default for all accounts.
-- REVISION 5 enforces the guest scan allowance on the server.
-- REVISION 10 preserves legacy Google SSO identities alongside local accounts.
-- REVISION 11 adds usernames, email verification, OTPs, and Google OAuth state.
-- =====================================================================
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- 1. USERS  (Login screen: email/password or SSO-SAML; Settings: profile)
-- ---------------------------------------------------------------------
CREATE TABLE users (
    user_id               INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name             TEXT    NOT NULL,
    email                 TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    username              TEXT,
    email_verified_at     TEXT,
    password_hash         TEXT,                                   -- bcrypt/argon2 hash; NULL for SSO-only users
    auth_provider         TEXT    NOT NULL DEFAULT 'local'
                          CHECK (auth_provider IN ('local','saml','google')),
    sso_subject_id        TEXT,                                   -- SAML NameID from the IdP
    sso_idp_entity_id     TEXT,                                   -- which IdP issued it
    role                  TEXT    NOT NULL DEFAULT 'analyst'
                          CHECK (role IN ('admin','analyst','viewer')),   -- authorization level
    job_title             TEXT,                                   -- display only, e.g. 'SOC Analyst'
    tier_label            TEXT,                                   -- display only, e.g. 'SecOps Tier 1'
    profile_picture       TEXT CHECK (profile_picture IS NULL OR length(profile_picture) <= 400000),  -- [R2] data URI; size cap is an ASSUMPTION
    is_active             INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    failed_login_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    locked_until          TEXT,
    last_login_at         TEXT,
    created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    CHECK (auth_provider <> 'local' OR password_hash IS NOT NULL),
    CHECK (auth_provider NOT IN ('saml','google') OR sso_subject_id IS NOT NULL)
);
CREATE UNIQUE INDEX ux_users_sso
    ON users (sso_idp_entity_id, sso_subject_id) WHERE sso_subject_id IS NOT NULL;
CREATE UNIQUE INDEX ux_users_username
    ON users (username COLLATE NOCASE) WHERE username IS NOT NULL;

-- ---------------------------------------------------------------------
-- 2. USER_SESSIONS  (Login / Logout -> "Terminate Secure Session")
-- ---------------------------------------------------------------------
CREATE TABLE user_sessions (
    session_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash   TEXT    NOT NULL UNIQUE,        -- SHA-256 of the session/refresh token (never the raw token)
    ip_address   TEXT,
    user_agent   TEXT,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at   TEXT    NOT NULL,
    revoked_at   TEXT                             -- set on Logout
);
CREATE INDEX ix_sessions_user ON user_sessions (user_id);

-- ---------------------------------------------------------------------
-- 3. USER_SETTINGS  (Settings > Display Preferences toggles)
-- ---------------------------------------------------------------------
CREATE TABLE user_settings (
    user_id             INTEGER PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    shap_advanced_mode  INTEGER NOT NULL DEFAULT 1 CHECK (shap_advanced_mode IN (0,1)),
    auto_save_scan_logs INTEGER NOT NULL DEFAULT 1 CHECK (auto_save_scan_logs IN (0,1)),
    updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- ---------------------------------------------------------------------
-- 4. SYSTEM_SETTINGS  (global config, e.g. risk-tier thresholds)
-- ---------------------------------------------------------------------
CREATE TABLE system_settings (
    setting_key    TEXT PRIMARY KEY,
    setting_value  TEXT NOT NULL,
    description    TEXT,
    updated_by     INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- ---------------------------------------------------------------------
-- 5. MODEL_VERSIONS  (CRISP-DM "Deployment": serialized model + scaler)
-- ---------------------------------------------------------------------
CREATE TABLE model_versions (
    model_version_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    version_tag         TEXT    NOT NULL UNIQUE,            -- e.g. 'xgb-v1.0.0'
    algorithm           TEXT    NOT NULL DEFAULT 'XGBoost',
    explainer_type      TEXT    NOT NULL DEFAULT 'shap.TreeExplainer',
    training_dataset    TEXT,
    n_training_samples  INTEGER,
    accuracy            REAL CHECK (accuracy      BETWEEN 0 AND 1),
    precision_score     REAL CHECK (precision_score BETWEEN 0 AND 1),
    recall_score        REAL CHECK (recall_score  BETWEEN 0 AND 1),
    f1_score            REAL CHECK (f1_score      BETWEEN 0 AND 1),
    roc_auc             REAL CHECK (roc_auc       BETWEEN 0 AND 1),
    hyperparameters     TEXT,                               -- JSON (incl. L1/L2 regularization)
    model_artifact_path  TEXT NOT NULL,                     -- .bin / .pkl
    scaler_artifact_path TEXT,                              -- fitted Scikit-Learn scaler
    is_active           INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0,1)),
    trained_at          TEXT,
    deployed_at         TEXT,
    notes               TEXT
);
CREATE UNIQUE INDEX ux_model_one_active ON model_versions (is_active) WHERE is_active = 1;

-- ---------------------------------------------------------------------
-- 6. FEATURE_DEFINITIONS  (catalog of model features + SHAP -> education text)
-- ---------------------------------------------------------------------
CREATE TABLE feature_definitions (
    feature_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    feature_key      TEXT NOT NULL UNIQUE,                  -- machine name, matches model column
    display_name     TEXT NOT NULL,                         -- 'Sender Domain Mismatch'
    category         TEXT NOT NULL CHECK (category IN ('header','url','text')),
    value_type       TEXT NOT NULL CHECK (value_type IN ('binary','count','ratio','score')),
    description      TEXT,
    insight_type     TEXT NOT NULL DEFAULT 'Educational Insight'
                     CHECK (insight_type IN ('Educational Insight','Security Tip')),
    insight_title    TEXT,
    insight_template TEXT NOT NULL,                         -- plain-language explanation shown to users
    is_active        INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- ---------------------------------------------------------------------
-- 7. SCANS  (one row per Scan Email click; metadata only, NO body)
-- ---------------------------------------------------------------------
CREATE TABLE scans (
    scan_id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_code             TEXT GENERATED ALWAYS AS ('BNT-' || printf('%04d', scan_id)) VIRTUAL,  -- 'BNT-8492'
    user_id               INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    model_version_id      INTEGER NOT NULL REFERENCES model_versions(model_version_id),

    -- input
    input_method          TEXT NOT NULL CHECK (input_method IN ('eml_upload','raw_text')),
    file_name             TEXT,                              -- 'MicTest.eml'
    file_size_bytes       INTEGER CHECK (file_size_bytes >= 0),
    content_sha256        TEXT NOT NULL,                     -- fingerprint for dedupe; body itself is discarded
    body_char_count       INTEGER CHECK (body_char_count >= 0),

    -- parsed header metadata (Parsed Payload Viewer / History table)
    subject               TEXT,
    sender_address        TEXT,
    sender_domain         TEXT,
    return_path_domain    TEXT,
    spf_result            TEXT,
    dkim_result           TEXT,
    dmarc_result          TEXT,
    url_count             INTEGER NOT NULL DEFAULT 0 CHECK (url_count >= 0),

    -- decision output
    malicious_probability REAL    NOT NULL CHECK (malicious_probability BETWEEN 0 AND 1),
    threat_score          INTEGER NOT NULL CHECK (threat_score BETWEEN 0 AND 100),
    risk_tier             TEXT    NOT NULL CHECK (risk_tier IN ('Low','Medium','Critical')),
    shap_base_value       REAL,                              -- SHAP expected value (for waterfall/force plots)
    inference_ms          INTEGER CHECK (inference_ms >= 0), -- 'Inference Speed: 42ms'

    scanned_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX ix_scans_user_time ON scans (user_id, scanned_at DESC);
CREATE INDEX ix_scans_time      ON scans (scanned_at DESC);
CREATE INDEX ix_scans_risk      ON scans (risk_tier);
CREATE INDEX ix_scans_domain    ON scans (sender_domain);
CREATE INDEX ix_scans_hash      ON scans (content_sha256);

-- ---------------------------------------------------------------------
-- 8. SCAN_FEATURES  (the numeric feature vector fed to XGBoost)
-- ---------------------------------------------------------------------
CREATE TABLE scan_features (
    scan_id       INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    feature_id    INTEGER NOT NULL REFERENCES feature_definitions(feature_id),
    raw_value     REAL NOT NULL,                             -- value before scaling
    scaled_value  REAL,                                      -- value after the Scikit-Learn scaler
    PRIMARY KEY (scan_id, feature_id)
) WITHOUT ROWID;
CREATE INDEX ix_scan_features_feature ON scan_features (feature_id);

-- ---------------------------------------------------------------------
-- 9. SHAP_RESULTS  (Shapley value for every feature of every scan)
-- ---------------------------------------------------------------------
CREATE TABLE shap_results (
    scan_id     INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    feature_id  INTEGER NOT NULL REFERENCES feature_definitions(feature_id),
    shap_value  REAL    NOT NULL,                            -- + pushes toward phishing, - toward safe
    abs_rank    INTEGER NOT NULL CHECK (abs_rank >= 1),      -- 1 = largest |shap_value|
    PRIMARY KEY (scan_id, feature_id)
) WITHOUT ROWID;
CREATE INDEX ix_shap_rank ON shap_results (scan_id, abs_rank);

-- ---------------------------------------------------------------------
-- 10. EXPLANATIONS  (plain-language text for the top SHAP contributors)
-- ---------------------------------------------------------------------
CREATE TABLE explanations (
    explanation_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    feature_id      INTEGER NOT NULL,
    display_order   INTEGER NOT NULL CHECK (display_order >= 1),
    insight_type    TEXT    NOT NULL CHECK (insight_type IN ('Educational Insight','Security Tip')),
    title           TEXT    NOT NULL,                        -- 'SENDER DOMAIN MISMATCH'
    message         TEXT    NOT NULL,                        -- rendered text with this scan's values filled in
    UNIQUE (scan_id, feature_id),
    FOREIGN KEY (scan_id, feature_id) REFERENCES shap_results(scan_id, feature_id) ON DELETE CASCADE
);
CREATE INDEX ix_explanations_scan ON explanations (scan_id, display_order);

-- ---------------------------------------------------------------------
-- 11. EXTRACTED_URLS  (Regex-extracted links; defanged and query-stripped)
-- ---------------------------------------------------------------------
CREATE TABLE extracted_urls (
    url_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    position_in_mail INTEGER NOT NULL DEFAULT 1,
    url_defanged     TEXT    NOT NULL,                       -- 'hxxp://x[.]com/login' (no query string/tokens)
    domain           TEXT,
    tld              TEXT,
    url_length       INTEGER CHECK (url_length >= 0),
    subdomain_count  INTEGER CHECK (subdomain_count >= 0),
    redirect_count   INTEGER NOT NULL DEFAULT 0 CHECK (redirect_count >= 0),
    has_ip_address   INTEGER NOT NULL DEFAULT 0 CHECK (has_ip_address  IN (0,1)),
    uses_shortener   INTEGER NOT NULL DEFAULT 0 CHECK (uses_shortener  IN (0,1)),
    has_at_symbol    INTEGER NOT NULL DEFAULT 0 CHECK (has_at_symbol   IN (0,1)),
    is_https         INTEGER NOT NULL DEFAULT 0 CHECK (is_https        IN (0,1)),
    is_suspicious    INTEGER NOT NULL DEFAULT 0 CHECK (is_suspicious   IN (0,1))
);
CREATE INDEX ix_urls_scan   ON extracted_urls (scan_id);
CREATE INDEX ix_urls_domain ON extracted_urls (domain);

-- ---------------------------------------------------------------------
-- 11b. SCAN_TOKEN_CONTRIBUTIONS  [R2]  (word-level SHAP of the TF-IDF + XGBoost model)
-- contribution is in raw-margin (log-odds) units: NOT percent, does not sum to 100.
-- Privacy: `token` is one vocabulary word from the body (top_n_explanations rows per
-- scan at most). If the team decides even single words must not be persisted, drop
-- this table; the live API response is unaffected.
-- ---------------------------------------------------------------------
CREATE TABLE scan_token_contributions (
    scan_id         INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    abs_rank        INTEGER NOT NULL CHECK (abs_rank >= 1),         -- 1 = largest |contribution|
    token           TEXT    NOT NULL,
    contribution    REAL    NOT NULL,
    direction       TEXT    NOT NULL CHECK (direction IN ('toward_phishing','toward_safe')),
    tfidf_value     REAL    NOT NULL,
    insight_type    TEXT    CHECK (insight_type IN ('Educational Insight','Security Tip')),
    insight_title   TEXT,                                           -- plain-language text shown to the user
    insight_message TEXT,
    PRIMARY KEY (scan_id, abs_rank)
) WITHOUT ROWID;

-- ---------------------------------------------------------------------
-- 11c. TOKEN_FEATURE_MAP  [R2]  (education mapping: word -> catalog feature)
-- When a top SHAP word is listed here, its explanation reuses that feature's
-- insight_title / insight_template. Words not listed get the generic text in
-- system_settings (insight_generic_*). Editable content, no code change needed.
-- ---------------------------------------------------------------------
CREATE TABLE token_feature_map (
    token       TEXT    PRIMARY KEY CHECK (token = lower(token)),   -- vectorizer lowercases
    feature_id  INTEGER NOT NULL REFERENCES feature_definitions(feature_id) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE INDEX ix_token_feature ON token_feature_map (feature_id);

-- ---------------------------------------------------------------------
-- 12. SCAN_FEEDBACK  (user feedback on a result; feeds retraining/evaluation)
-- ---------------------------------------------------------------------
CREATE TABLE scan_feedback (
    feedback_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id              INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    user_id              INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    is_prediction_correct INTEGER NOT NULL CHECK (is_prediction_correct IN (0,1)),
    suggested_label      TEXT CHECK (suggested_label IN ('Safe','Suspicious','Phishing')),
    explanation_helpful  INTEGER CHECK (explanation_helpful IN (0,1)),
    comment              TEXT,
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE (scan_id, user_id)
);

-- ---------------------------------------------------------------------
-- 13. AUDIT_LOGS  (compliance trail: logins, scans, exports, settings, purges)
-- ---------------------------------------------------------------------
CREATE TABLE audit_logs (
    audit_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    actor_email  TEXT,                                       -- snapshot; also covers failed logins by unknown emails
    scan_id      INTEGER REFERENCES scans(scan_id) ON DELETE SET NULL,
    event_type   TEXT NOT NULL CHECK (event_type IN (
                    'LOGIN_SUCCESS','LOGIN_FAILED','LOGOUT',
                    'SCAN_SUBMITTED','SCAN_COMPLETED','SCAN_REJECTED',
                    'HISTORY_VIEWED','HISTORY_EXPORTED',
                    'SETTINGS_UPDATED','FEEDBACK_SUBMITTED','LOGS_PURGED',
                    'USER_REGISTERED','PROFILE_UPDATED','PASSWORD_CHANGED','PASSWORD_RESET')),  -- [R2] last four
    http_status  INTEGER,                                    -- e.g. 400 for rejected payloads
    detail       TEXT,                                       -- JSON; never contains email body
    ip_address   TEXT,
    user_agent   TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Guest scan quota reservations count only successful scans and short-lived
-- in-flight requests. Client IPs are retained only for the rolling quota window.
CREATE TABLE guest_scan_reservations (
    reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip      TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    completed_at   TEXT
);
CREATE INDEX ix_guest_scan_reservations_ip_created
    ON guest_scan_reservations (client_ip, created_at);
CREATE INDEX ix_guest_scan_reservations_ip_completed
    ON guest_scan_reservations (client_ip, completed_at);
CREATE INDEX ix_audit_time  ON audit_logs (created_at DESC);
CREATE INDEX ix_audit_event ON audit_logs (event_type);
CREATE INDEX ix_audit_user  ON audit_logs (user_id);

-- ---------------------------------------------------------------------
-- VIEW: feeds the Threat History & Audit Logs table (Figure 7)
-- Classification label is derived from risk_tier, so it is never stored twice.
-- ---------------------------------------------------------------------
CREATE VIEW v_scan_history AS
SELECT  s.scan_id,
        s.scan_code,
        s.user_id,
        s.scanned_at,
        s.subject,
        s.sender_domain,
        s.threat_score,
        s.risk_tier,
        CASE s.risk_tier WHEN 'Critical' THEN 'Phishing'
                         WHEN 'Medium'   THEN 'Suspicious'
                         ELSE 'Safe' END                              AS classification,
        ROUND(MAX(s.malicious_probability, 1 - s.malicious_probability) * 100, 2) AS confidence_pct,
        s.inference_ms
FROM scans s;

-- ---------------------------------------------------------------------
-- 15. PASSWORD RECOVERY (only SHA-256 token hashes are persisted)
-- ---------------------------------------------------------------------
CREATE TABLE password_reset_tokens (
    reset_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX ix_password_reset_user ON password_reset_tokens (user_id);

CREATE TABLE password_reset_requests (
    request_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip   TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX ix_password_reset_requests_ip_time
    ON password_reset_requests (client_ip, created_at);

-- ---------------------------------------------------------------------
-- 16. EMAIL OTP AND GOOGLE OAUTH TRANSACTIONS
-- ---------------------------------------------------------------------
CREATE TABLE email_otp_challenges (
    challenge_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    email        TEXT NOT NULL COLLATE NOCASE,
    purpose      TEXT NOT NULL CHECK (purpose IN ('registration','password_reset','google_password_setup')),
    code_hash    TEXT NOT NULL,
    client_ip    TEXT,
    attempts     INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    expires_at   TEXT NOT NULL,
    consumed_at  TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX ix_email_otp_user_purpose
    ON email_otp_challenges (user_id, purpose, created_at);
CREATE INDEX ix_email_otp_ip_purpose
    ON email_otp_challenges (client_ip, purpose, created_at);

CREATE TABLE oauth_states (
    state_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    state_hash  TEXT NOT NULL UNIQUE,
    nonce_hash  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    consumed_at TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE oauth_login_tickets (
    ticket_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_hash TEXT NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    expires_at  TEXT NOT NULL,
    consumed_at TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Schema version. Bump this whenever a table/column/CHECK changes.
PRAGMA user_version = 11;
