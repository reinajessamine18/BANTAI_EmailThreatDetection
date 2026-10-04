-- Seed data for BANTAI. Run AFTER schema.sql.
PRAGMA foreign_keys = ON;

-- Risk tier thresholds (ASSUMED values: adjust after model evaluation)
--   Low: 0-39 | Medium: 40-79 | Critical: 80-100
INSERT INTO system_settings (setting_key, setting_value, description) VALUES
 ('risk_low_max',    '39', 'Highest threat score still classed as Low (Safe)'),
 ('risk_medium_max', '79', 'Highest threat score still classed as Medium (Suspicious); above this is Critical (Phishing)'),
 ('max_upload_bytes','5242880', 'Maximum accepted .eml size (5 MB)'),
 ('top_n_explanations','5', 'How many top SHAP contributors get a plain-language explanation');

-- Placeholder model row so scans can be recorded before the real model is trained.
INSERT INTO model_versions (version_tag, model_artifact_path, scaler_artifact_path, is_active, notes)
VALUES ('xgb-dev-0.0.0', 'models/xgb_model.bin', 'models/scaler.pkl', 1,
        'Placeholder. Replace with real metrics and paths after CRISP-DM Evaluation.');

-- Starter feature catalog (header / url / text), matching the indicators named in the paper.
INSERT INTO feature_definitions
 (feature_key, display_name, category, value_type, description, insight_type, insight_title, insight_template) VALUES
-- HEADER
('sender_domain_mismatch','Sender Domain Mismatch','header','binary',
 'Visible From domain differs from Return-Path domain.','Educational Insight','Sender Domain Mismatch',
 'The visible From address does not match the hidden Return-Path. Phishers use this to forge trusted identities. Always verify the real sending domain before acting.'),
('spf_fail','SPF Check Failed','header','binary',
 'SPF authentication did not pass.','Educational Insight','SPF Check Failed',
 'The sending server is not authorized to send mail for this domain, which often means the sender is spoofed.'),
('dkim_fail','DKIM Signature Failed','header','binary',
 'DKIM signature missing or invalid.','Educational Insight','DKIM Signature Failed',
 'The message lacks a valid digital signature, so it may have been forged or altered in transit.'),
('dmarc_fail','DMARC Check Failed','header','binary',
 'DMARC policy evaluation failed.','Educational Insight','DMARC Check Failed',
 'The domain owner''s policy for rejecting spoofed mail was not satisfied by this message.'),
('reply_to_mismatch','Reply-To Differs From Sender','header','binary',
 'Reply-To domain differs from From domain.','Educational Insight','Reply-To Differs From Sender',
 'Replies would go to a different domain than the one shown as sender, a common trick to capture responses.'),
('free_mail_sender','Free-Mail Sender Domain','header','binary',
 'Sender uses a free webmail provider while claiming to be an organization.','Educational Insight','Free-Mail Sender',
 'Organizations rarely email official requests from free webmail addresses.'),
-- URL
('url_count','Number of Links','url','count',
 'Total hyperlinks in the email.','Educational Insight','Unusually Many Links',
 'This email contains an unusually high number of links, a pattern often seen in mass phishing.'),
('max_url_length','Longest URL Length','url','count',
 'Character length of the longest URL.','Educational Insight','Very Long URL',
 'Very long URLs are often used to hide the true destination behind extra characters.'),
('has_ip_url','IP Address Used as Link Target','url','binary',
 'At least one URL uses a raw IP address instead of a domain.','Security Tip','Suspicious Lexical URL Target',
 'Official institutions rarely use raw IP addresses in login links. Hover over links before clicking to reveal the true destination.'),
('uses_url_shortener','URL Shortener Detected','url','binary',
 'At least one URL uses a link-shortening service.','Security Tip','URL Shortener Detected',
 'Shortened links hide where you will land. Expand them with a trusted tool before opening.'),
('url_redirect_count','Redirect Count','url','count',
 'Maximum number of redirects observed in a URL chain.','Educational Insight','Multiple Redirects',
 'Chains of redirects are used to bypass filters and hide the final phishing page.'),
('url_has_at_symbol','"@" Symbol in URL','url','binary',
 'At least one URL contains an @ symbol.','Educational Insight','"@" in Link',
 'An @ in a URL can disguise the real host; everything before it is ignored by the browser.'),
('url_subdomain_count','Excessive Subdomains','url','count',
 'Maximum subdomain depth across URLs.','Educational Insight','Excessive Subdomains',
 'Many subdomains can imitate a trusted brand (e.g. paypal.secure.example.com).'),
('non_https_url','Non-HTTPS Link','url','binary',
 'At least one link does not use HTTPS.','Security Tip','Non-HTTPS Link',
 'Legitimate login pages use HTTPS. Be cautious with links that do not.'),
('link_text_mismatch','Link Text Does Not Match Target','url','binary',
 'Displayed link text points to a different domain than the actual href.','Educational Insight','Misleading Link Text',
 'The visible link text shows one address but the link opens another, a classic deception technique.'),
-- TEXT
('urgency_keyword_count','Urgency Language','text','count',
 'Count of urgency/threat phrases (e.g. "immediately", "suspended").','Educational Insight','Urgent or Threatening Language',
 'Phishers create time pressure to rush you into acting without thinking.'),
('credential_request_count','Credential / Payment Requests','text','count',
 'Count of phrases asking to verify, confirm, or enter credentials or payment details.','Educational Insight','Request for Sensitive Information',
 'Legitimate organizations do not ask you to confirm passwords or card details by email.'),
('sentiment_score','Message Sentiment','text','score',
 'Negative/fear sentiment score of the body text.','Educational Insight','Fear-Based Tone',
 'A strongly negative or alarming tone is used to trigger emotional reactions.'),
('exclamation_count','Exclamation Marks','text','count',
 'Number of exclamation marks in subject and body.','Educational Insight','Excessive Exclamation Marks',
 'Excessive punctuation is typical of high-pressure scam messages.'),
('uppercase_ratio','ALL-CAPS Ratio','text','ratio',
 'Proportion of uppercase characters in subject and body.','Educational Insight','Excessive Capital Letters',
 'Shouting in all caps is used to grab attention and signal false urgency.'),
('generic_greeting','Generic Greeting','text','binary',
 'Starts with a generic greeting such as "Dear Customer".','Educational Insight','Generic Greeting',
 'Real organizations usually address you by name; generic greetings suggest a mass mailing.'),
('html_to_text_ratio','HTML-to-Text Ratio','text','ratio',
 'Ratio of HTML markup size to visible text size.','Educational Insight','Heavy HTML With Little Text',
 'Mostly-markup emails can hide content or imitate branded templates.'),
('attachment_count','Attachment Count','text','count',
 'Number of attachments (names/types only; contents are not analyzed).','Security Tip','Unexpected Attachment',
 'Do not open unexpected attachments. Verify with the sender through a separate channel.');
