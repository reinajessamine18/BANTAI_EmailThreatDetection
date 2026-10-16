BEGIN IMMEDIATE;

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

PRAGMA user_version = 3;
COMMIT;
