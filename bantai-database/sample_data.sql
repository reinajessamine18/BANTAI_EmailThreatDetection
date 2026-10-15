-- =====================================================================
-- BANTAI sample data (DEMO ONLY). Run AFTER schema.sql and seed.sql.
-- Mirrors the paper's mockups: Figure 6 (scan BNT-8486, "MicTest.eml")
-- and Figure 7 (history rows BNT-8487 .. BNT-8492).
-- No email bodies are stored, matching the privacy rule.
-- =====================================================================
PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- users
-- password_hash values are PLACEHOLDERS. Replace with real bcrypt/argon2 hashes from your backend.
INSERT INTO users (user_id, full_name, email, password_hash, auth_provider, sso_subject_id, sso_idp_entity_id,
                   role, job_title, tier_label, last_login_at, created_at) VALUES
 (1, 'Admin User',      'admin@bantai-sec.io',   'DEMO_ONLY_REPLACE_WITH_REAL_HASH', 'local', NULL, NULL,
     'admin',   'SOC Analyst', 'SecOps Tier 1', '2026-09-15T08:55:00Z', '2026-08-20T02:00:00Z'),
 (2, 'Maria Santos',    'maria.santos@tdcx.example', 'DEMO_ONLY_REPLACE_WITH_REAL_HASH', 'local', NULL, NULL,
     'analyst', 'Security Analyst', 'SecOps Tier 1', '2026-09-14T06:50:00Z', '2026-08-22T02:00:00Z'),
 (3, 'Juan Dela Cruz',  'juan.delacruz@tdcx.example', NULL, 'saml', 'jdelacruz@tdcx.example', 'https://idp.tdcx.example/saml',
     'viewer',  'Customer Support Agent', NULL, '2026-09-13T07:30:00Z', '2026-08-25T02:00:00Z');

INSERT INTO user_settings (user_id, shap_advanced_mode, auto_save_scan_logs) VALUES
 (1, 1, 1),
 (2, 1, 1),
 (3, 0, 1);   -- simplified score-only view for a non-technical viewer

INSERT INTO user_sessions (user_id, token_hash, ip_address, user_agent, created_at, expires_at, revoked_at) VALUES
 (1, lower(hex(randomblob(32))), '10.0.0.15', 'Mozilla/5.0 (Windows NT 10.0) Chrome/126', '2026-09-15T08:55:00Z', '2026-09-15T16:55:00Z', NULL),
 (2, lower(hex(randomblob(32))), '10.0.0.22', 'Mozilla/5.0 (Macintosh) Firefox/128',      '2026-09-14T06:50:00Z', '2026-09-14T14:50:00Z', '2026-09-14T10:05:00Z');

-- ------------------------------------------------------- system settings
-- Shipped in seed.sql; here we record that the admin tuned one value.
UPDATE system_settings SET updated_by = 1, updated_at = '2026-09-01T03:00:00Z' WHERE setting_key = 'top_n_explanations';

-- ---------------------------------------------------------------- scans
-- Explicit scan_ids so scan_code matches the mockups (BNT-8486 ... BNT-8492).
-- model_version_id 1 = placeholder model row from seed.sql.
INSERT INTO scans (scan_id, user_id, model_version_id, input_method, file_name, file_size_bytes, content_sha256, body_char_count,
                   subject, sender_address, sender_domain, return_path_domain, spf_result, dkim_result, dmarc_result, url_count,
                   malicious_probability, threat_score, risk_tier, shap_base_value, inference_ms, scanned_at) VALUES
 -- Figure 6: the detailed result screen
 (8486, 1, 1, 'eml_upload', 'MicTest.eml', 4821, lower(hex(randomblob(32))), 412,
  'URGENT Account Update Required', 'support@paypal-update.com', 'paypal-update.com', 'mailer-x91.ru', 'fail', 'none', 'fail', 1,
  0.92, 92, 'Critical', -0.5, 42, '2026-09-13T13:40:00Z'),
 -- Figure 7: threat history rows
 (8487, 2, 1, 'eml_upload', 'weekly_update.eml', 18344, lower(hex(randomblob(32))), 1860,
  'Weekly Marketing Update', 'newsletter@globalbrand.com', 'globalbrand.com', 'globalbrand.com', 'pass', 'pass', 'none', 1,
  0.45, 45, 'Medium', -0.5, 38, '2026-09-13T15:10:00Z'),
 (8488, 1, 1, 'raw_text', NULL, NULL, lower(hex(randomblob(32))), 530,
  'Your Account is Compromised', 'alert@system-security.biz', 'system-security.biz', 'bulk-relay.xyz', 'fail', 'fail', 'fail', 1,
  0.99, 99, 'Critical', -0.5, 45, '2026-09-13T19:22:00Z'),
 (8489, 3, 1, 'eml_upload', 'storage_notice.eml', 9120, lower(hex(randomblob(32))), 640,
  'Cloud Storage Limit Reached', 'no-reply@cloudstorage.io', 'cloudstorage.io', 'cloudstorage.io', 'pass', 'pass', 'pass', 1,
  0.08, 8, 'Low', -0.5, 36, '2026-09-14T07:30:00Z'),
 (8490, 2, 1, 'eml_upload', 'invoice.eml', 25410, lower(hex(randomblob(32))), 320,
  'Invoice Attached', 'billing@unknown-host.net', 'unknown-host.net', 'unknown-host.net', 'pass', 'fail', 'none', 1,
  0.65, 65, 'Medium', -0.5, 41, '2026-09-14T09:15:00Z'),
 (8491, 1, 1, 'raw_text', NULL, NULL, lower(hex(randomblob(32))), 905,
  'Project Guidelines', 'professor@plp.edu.ph', 'plp.edu.ph', 'plp.edu.ph', 'pass', 'pass', 'pass', 0,
  0.12, 12, 'Low', -0.5, 33, '2026-09-15T11:48:00Z'),
 (8492, 1, 1, 'eml_upload', 'password_reset.eml', 6212, lower(hex(randomblob(32))), 468,
  'URGENT: Password Reset', 'security@paypal-update.com', 'paypal-update.com', 'mailer-x91.ru', 'fail', 'none', 'fail', 1,
  0.96, 96, 'Critical', -0.5, 44, '2026-09-15T14:02:00Z');

-- ------------------------------------------ features + SHAP (staging table)
-- Sample stores only the top contributors per scan. A real scan stores every feature.
-- Columns: scan_id, feature_key, raw_value, shap_value, abs_rank
CREATE TEMP TABLE tmp_sample (scan_id INTEGER, fkey TEXT, raw REAL, shap REAL, rnk INTEGER);
INSERT INTO tmp_sample VALUES
 -- 8486  (Figure 6: +0.42 and +0.31 are the two SHAP bars shown in the mockup)
 (8486,'sender_domain_mismatch',1,0.42,1),(8486,'has_ip_url',1,0.31,2),(8486,'urgency_keyword_count',3,0.12,3),
 (8486,'credential_request_count',2,0.09,4),(8486,'spf_fail',1,0.07,5),(8486,'generic_greeting',1,0.05,6),
 (8486,'url_count',1,0.02,7),(8486,'uses_url_shortener',0,-0.01,8),
 -- 8487 Medium
 (8487,'html_to_text_ratio',0.82,0.13,1),(8487,'spf_fail',0,-0.11,2),(8487,'url_count',6,0.09,3),(8487,'generic_greeting',1,0.06,4),
 -- 8488 Critical
 (8488,'sender_domain_mismatch',1,0.51,1),(8488,'uses_url_shortener',1,0.33,2),(8488,'urgency_keyword_count',5,0.27,3),
 (8488,'credential_request_count',3,0.15,4),(8488,'exclamation_count',4,0.08,5),(8488,'uppercase_ratio',0.31,0.05,6),
 -- 8489 Low
 (8489,'spf_fail',0,-0.28,1),(8489,'url_has_at_symbol',0,-0.14,2),(8489,'non_https_url',0,-0.10,3),
 -- 8490 Medium
 (8490,'dkim_fail',1,0.21,1),(8490,'attachment_count',1,0.17,2),(8490,'spf_fail',0,-0.12,3),(8490,'urgency_keyword_count',1,0.08,4),
 -- 8491 Low
 (8491,'spf_fail',0,-0.31,1),(8491,'sender_domain_mismatch',0,-0.22,2),(8491,'urgency_keyword_count',0,-0.15,3),
 -- 8492 Critical
 (8492,'sender_domain_mismatch',1,0.48,1),(8492,'urgency_keyword_count',4,0.29,2),(8492,'credential_request_count',2,0.18,3),
 (8492,'dmarc_fail',1,0.11,4),(8492,'generic_greeting',1,0.04,5);

INSERT INTO scan_features (scan_id, feature_id, raw_value)
SELECT t.scan_id, f.feature_id, t.raw FROM tmp_sample t JOIN feature_definitions f ON f.feature_key = t.fkey;

INSERT INTO shap_results (scan_id, feature_id, shap_value, abs_rank)
SELECT t.scan_id, f.feature_id, t.shap, t.rnk FROM tmp_sample t JOIN feature_definitions f ON f.feature_key = t.fkey;

DROP TABLE tmp_sample;

-- ---------------------------------------------------------- explanations
-- Top 5 risk-increasing features for Medium/Critical scans, text taken from the feature catalog.
INSERT INTO explanations (scan_id, feature_id, display_order, insight_type, title, message)
SELECT scan_id, feature_id, ord, insight_type, title, message FROM (
    SELECT sr.scan_id, sr.feature_id,
           ROW_NUMBER() OVER (PARTITION BY sr.scan_id ORDER BY sr.abs_rank) AS ord,
           fd.insight_type, COALESCE(fd.insight_title, fd.display_name) AS title, fd.insight_template AS message
    FROM shap_results sr
    JOIN scans s ON s.scan_id = sr.scan_id
    JOIN feature_definitions fd ON fd.feature_id = sr.feature_id
    WHERE sr.shap_value > 0 AND s.risk_tier IN ('Medium','Critical')
) WHERE ord <= 5;

-- Personalize one message with this scan's actual value (as in Figure 6)
UPDATE explanations
SET message = 'Official institutions rarely use raw IP addresses (e.g., 192.168.1.45) in login links. Hover over links before clicking to reveal their true destination in the bottom corner of your browser.'
WHERE scan_id = 8486 AND feature_id = (SELECT feature_id FROM feature_definitions WHERE feature_key = 'has_ip_url');

-- --------------------------------------------------------- extracted URLs
INSERT INTO extracted_urls (scan_id, position_in_mail, url_defanged, domain, tld, url_length, subdomain_count, redirect_count,
                            has_ip_address, uses_shortener, has_at_symbol, is_https, is_suspicious) VALUES
 (8486, 1, 'hxxp://192[.]168[.]1[.]45/login',          '192.168.1.45',      NULL,  31, 0, 2, 1, 0, 0, 0, 1),
 (8487, 1, 'hxxps://globalbrand[.]com/newsletter',     'globalbrand.com',   'com', 36, 0, 0, 0, 0, 0, 1, 0),
 (8488, 1, 'hxxp://bit[.]ly/3xKq9',                    'bit.ly',            'ly',  20, 0, 3, 0, 1, 0, 0, 1),
 (8489, 1, 'hxxps://cloudstorage[.]io/manage',         'cloudstorage.io',   'io',  31, 0, 0, 0, 0, 0, 1, 0),
 (8490, 1, 'hxxp://unknown-host[.]net/invoice.php',    'unknown-host.net',  'net', 37, 0, 1, 0, 0, 0, 0, 1),
 (8492, 1, 'hxxps://paypal-update[.]com/reset',        'paypal-update.com', 'com', 34, 0, 1, 0, 0, 0, 1, 1);

-- -------------------------------------------------------------- feedback
INSERT INTO scan_feedback (scan_id, user_id, is_prediction_correct, suggested_label, explanation_helpful, comment, created_at) VALUES
 (8486, 1, 1, NULL,   1, 'Clear explanation. The IP-address link was the giveaway.', '2026-09-13T13:45:00Z'),
 (8487, 2, 0, 'Safe', 1, 'Legitimate newsletter from a known vendor (false positive).', '2026-09-13T15:20:00Z'),
 (8492, 1, 1, NULL,   0, 'Correct result, but I would like more detail on the sender mismatch.', '2026-09-15T14:10:00Z');

-- ------------------------------------------------------------ audit logs
INSERT INTO audit_logs (user_id, actor_email, scan_id, event_type, http_status, detail, ip_address, created_at) VALUES
 (NULL, 'unknown@evil.example', NULL, 'LOGIN_FAILED',     401, '{"reason":"invalid credentials"}',                         '203.0.113.7', '2026-09-13T13:30:00Z'),
 (1, 'admin@bantai-sec.io',     NULL, 'LOGIN_SUCCESS',    200, '{"method":"password"}',                                    '10.0.0.15',   '2026-09-13T13:35:00Z'),
 (1, 'admin@bantai-sec.io',     8486, 'SCAN_SUBMITTED',   202, '{"input_method":"eml_upload","file_name":"MicTest.eml"}',  '10.0.0.15',   '2026-09-13T13:40:00Z'),
 (1, 'admin@bantai-sec.io',     8486, 'SCAN_COMPLETED',   200, '{"threat_score":92,"risk_tier":"Critical","inference_ms":42}', '10.0.0.15', '2026-09-13T13:40:01Z'),
 (1, 'admin@bantai-sec.io',     NULL, 'SCAN_REJECTED',    400, '{"reason":"payload failed Pydantic validation"}',          '10.0.0.15',   '2026-09-13T13:52:00Z'),
 (1, 'admin@bantai-sec.io',     8486, 'FEEDBACK_SUBMITTED',200,'{"is_prediction_correct":1}',                              '10.0.0.15',   '2026-09-13T13:45:00Z'),
 (2, 'maria.santos@tdcx.example', 8490, 'SCAN_COMPLETED', 200, '{"threat_score":65,"risk_tier":"Medium","inference_ms":41}', '10.0.0.22', '2026-09-14T09:15:01Z'),
 (2, 'maria.santos@tdcx.example', NULL, 'HISTORY_EXPORTED',200,'{"format":"csv","rows":6}',                                 '10.0.0.22',   '2026-09-14T09:30:00Z'),
 (1, 'admin@bantai-sec.io',     NULL, 'SETTINGS_UPDATED', 200, '{"shap_advanced_mode":1,"auto_save_scan_logs":1}',        '10.0.0.15',   '2026-09-15T09:00:00Z'),
 (1, 'admin@bantai-sec.io',     8492, 'SCAN_COMPLETED',   200, '{"threat_score":96,"risk_tier":"Critical","inference_ms":44}', '10.0.0.15', '2026-09-15T14:02:01Z'),
 (2, 'maria.santos@tdcx.example', NULL, 'LOGOUT',         200, NULL,                                                       '10.0.0.22',   '2026-09-14T10:05:00Z');
