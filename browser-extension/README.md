# BANTAI Chrome extension

This Manifest V3 extension provides BANTAI's email scanning workflow. It uses
the existing `/api/v1/auth/*` and `/api/v1/scans` endpoints. Email scanning is
available only in the extension; the website provides the dashboard, threat
history, scan details, and system settings.

## Load the extension for local development

1. Start the BANTAI backend from `bantai-backend`:

   ```powershell
   cd bantai-backend
   .\.venv\Scripts\Activate.ps1
   uvicorn app.main:app --reload --port 8000
   ```

2. In Chrome, open `chrome://extensions`, enable **Developer mode**, and select
   **Load unpacked**.
3. Select the repository's `browser-extension` folder.
4. Log in with the same BANTAI username or email and password used on the
   website. New users can select the website registration link in the extension;
   registration and email verification take place on the BANTAI website.
   Forgot-password OTP recovery and Continue with Google are also available in
   the extension. For local development the API defaults to
   `http://127.0.0.1:8000/api/v1`.
5. Open an individual email in Gmail (`mail.google.com`), then open the BANTAI
   extension and choose **Scan Email for Threats**. This includes email
   notifications sent by Google Docs, such as comment or sharing alerts.

## Behavior and privacy

- Gmail message text is read from the active tab only after the user opens the
  extension and requests a scan. The extension submits the active message's
  visible body, available sender/subject, and HTTP(S) link destinations to
  BANTAI as plain text.
- Message contents are held in popup memory for the current interaction and are
  not written to extension storage. The backend handles analysis, results, and
  its existing scan-history/audit behavior.
- The extension stores the existing BANTAI bearer session token and connection
  URLs using `chrome.storage.local`; it never stores the user's password.
- Dashboard, Threat History, and System Settings open the configured BANTAI
  website with a short-lived, single-use sign-in link. The extension token is
  never placed in the website URL; the website removes the handoff ticket from
  the URL before exchanging it for its own session.
- Password reset uses the backend's Brevo SMTP OTP flow. The backend does not
  reveal whether a reset email address exists.
- Google sign-in uses the backend's OAuth callback and a short-lived, single-use
  login ticket. The extension never receives the Google client secret.
- Remote API URLs must use HTTPS. The extension does not expose connection
  settings in its popup.
- Gmail is supported in Chrome, including messages sent by Google services.
  Google Docs pages themselves, Outlook, other browsers, production
  publishing/signing, and production API hosting are not included.

## Google OAuth setup for the extension

After loading the unpacked extension, copy its ID from `chrome://extensions` to
the backend's ignored `bantai-backend/.env` as `BANTAI_EXTENSION_ID`, then restart
the backend. This is used as a server-side allowlist for the extension redirect.
The browser's runtime redirect URI is
`https://<extension-id>.chromiumapp.org/oauth2`; the Google OAuth client
continues to use the backend callback URI configured by `GOOGLE_REDIRECT_URI`
(by default, `http://localhost:8000/api/v1/auth/google/callback`). Register that
backend callback URI in Google Cloud Console, not the `chromiumapp.org` URI.

The extension reuses the backend's trained model, scoring, and explanation
response. It does not run the model or calculate SHAP in the browser.
