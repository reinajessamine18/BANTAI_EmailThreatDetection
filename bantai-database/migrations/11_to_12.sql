BEGIN IMMEDIATE;

ALTER TABLE oauth_states ADD COLUMN extension_redirect_uri TEXT;

PRAGMA user_version = 12;
COMMIT;
