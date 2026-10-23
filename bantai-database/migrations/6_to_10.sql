PRAGMA foreign_keys = OFF;
BEGIN IMMEDIATE;

CREATE TABLE users_new (
    user_id               INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name             TEXT    NOT NULL,
    email                 TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash         TEXT,
    auth_provider         TEXT    NOT NULL DEFAULT 'local'
                          CHECK (auth_provider IN ('local','saml','google')),
    sso_subject_id        TEXT,
    sso_idp_entity_id     TEXT,
    role                  TEXT    NOT NULL DEFAULT 'analyst'
                          CHECK (role IN ('admin','analyst','viewer')),
    job_title             TEXT,
    tier_label            TEXT,
    profile_picture       TEXT CHECK (profile_picture IS NULL OR length(profile_picture) <= 400000),
    is_active             INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
    failed_login_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    locked_until          TEXT,
    last_login_at         TEXT,
    created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    CHECK (auth_provider <> 'local' OR password_hash IS NOT NULL),
    CHECK (auth_provider NOT IN ('saml','google') OR sso_subject_id IS NOT NULL)
);

INSERT INTO users_new (
    user_id, full_name, email, password_hash, auth_provider, sso_subject_id,
    sso_idp_entity_id, role, job_title, tier_label, profile_picture, is_active,
    failed_login_attempts, locked_until, last_login_at, created_at, updated_at
)
SELECT
    user_id, full_name, email, password_hash, auth_provider, sso_subject_id,
    sso_idp_entity_id, role, job_title, tier_label, profile_picture, is_active,
    failed_login_attempts, locked_until, last_login_at, created_at, updated_at
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
CREATE UNIQUE INDEX ux_users_sso
    ON users (sso_idp_entity_id, sso_subject_id) WHERE sso_subject_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    reset_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS ix_password_reset_user ON password_reset_tokens (user_id);

CREATE TABLE IF NOT EXISTS password_reset_requests (
    request_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip   TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_password_reset_requests_ip_time
    ON password_reset_requests (client_ip, created_at);

CREATE TABLE IF NOT EXISTS guest_scan_reservations (
    reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip      TEXT    NOT NULL,
    created_at     TEXT    NOT NULL,
    completed_at   TEXT
);
CREATE INDEX IF NOT EXISTS ix_guest_scan_reservations_ip_created
    ON guest_scan_reservations (client_ip, created_at);
CREATE INDEX IF NOT EXISTS ix_guest_scan_reservations_ip_completed
    ON guest_scan_reservations (client_ip, completed_at);

PRAGMA user_version = 10;
COMMIT;
PRAGMA foreign_keys = ON;
