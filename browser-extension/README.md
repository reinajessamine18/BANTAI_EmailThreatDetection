# BANTAI Chrome extension

This Manifest V3 extension adds Gmail scanning as another interface to the existing
BANTAI application. It uses the existing `/api/v1/auth/*` and `/api/v1/scans`
endpoints and does not replace the web application or its `.eml` and pasted-text
submission methods.

## Load the extension for local development

1. Start the BANTAI backend from `bantai-backend`:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   uvicorn app.main:app --reload --port 8000
   ```

2. In Chrome, open `chrome://extensions`, enable **Developer mode**, and select
   **Load unpacked**.
3. Select the repository's `browser-extension` folder.
4. Sign in using an existing BANTAI account, or register an account using the
   extension. For local development the API defaults to
   `http://127.0.0.1:8000/api/v1`.
5. Open an individual email in Gmail (`mail.google.com`), then open the BANTAI
   extension and choose **Scan Email for Threats**.

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
- Remote API URLs must use HTTPS. Saving a non-default API URL prompts Chrome for
  permission to contact that specific host.
- This first implementation supports Gmail in Chrome. Outlook, other browsers,
  production publishing/signing, and production API hosting are not included.

The extension reuses the backend's trained model, scoring, and explanation
response. It does not run the model or calculate SHAP in the browser.
