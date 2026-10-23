BEGIN IMMEDIATE;

CREATE TABLE user_settings_new (
    user_id             INTEGER PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    shap_advanced_mode  INTEGER NOT NULL DEFAULT 1 CHECK (shap_advanced_mode IN (0,1)),
    auto_save_scan_logs INTEGER NOT NULL DEFAULT 1 CHECK (auto_save_scan_logs IN (0,1)),
    updated_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

INSERT INTO user_settings_new (user_id, shap_advanced_mode, auto_save_scan_logs, updated_at)
SELECT user_id, shap_advanced_mode, 1, updated_at
FROM user_settings;

DROP TABLE user_settings;
ALTER TABLE user_settings_new RENAME TO user_settings;

PRAGMA user_version = 6;
COMMIT;
