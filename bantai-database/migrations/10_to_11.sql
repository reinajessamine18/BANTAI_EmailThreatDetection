BEGIN IMMEDIATE;

ALTER TABLE users ADD COLUMN username TEXT;
ALTER TABLE users ADD COLUMN email_verified_at TEXT;

UPDATE users
SET username = 'bantai-user-' || user_id,
    email_verified_at = CASE
        WHEN is_active = 1 THEN COALESCE(created_at, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        ELSE NULL
    END
WHERE username IS NULL;

CREATE UNIQUE INDEX ux_users_username
    ON users (username COLLATE NOCASE) WHERE username IS NOT NULL;

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

PRAGMA user_version = 11;
COMMIT;
