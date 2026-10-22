# BANTAI Backend

FastAPI service for the BANTAI email threat detection system.

## Setup (Windows, Git Bash)

```bash
cd bantai-backend
python -m venv .venv
source .venv/Scripts/activate        # cmd: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
cp .env.example .env                 # optional
```

The ML artifacts (`tfidf_vectorizer.pkl`, `xgboost_model.pkl`) must exist in
`machine-learning/artifacts/baseline/` (see `machine-learning/BACKEND_INTEGRATION_GUIDE.md`, section 4).

## Run

```bash
uvicorn app.main:app --reload --port 8000
```

- Health check: http://localhost:8000/api/v1/health
- Interactive API docs: http://localhost:8000/docs

## Scan API

`POST /api/v1/scans` (sign-in required)

```json
{ "inputMethod": "eml_upload" | "raw_text",
  "content": "<file text, base64 of the file, or pasted text>",
  "encoding": "text" | "base64",          // default "text"; base64 only for eml_upload
  "fileName": "MicTest.eml" }              // optional
```

Success (200): `riskLevel` (`safe`/`suspicious`/`phishing`), `riskTier`, `threatScore`,
`explanations[]` (SHAP words with `value` in log-odds, then rule-based indicators with
`value: null`), `links[]`, `sender`, `subject`, `emailBody`, `fileName`, `scannedAt`,
`inferenceTimeMs`, `modelVersion`, `saved`, `scanId`/`scanCode`.

Errors: `{"detail": {"code": "...", "message": "..."}}` with 401 (`not_authenticated`,
`invalid_token`), 413 (`too_large`, `body_too_long`), 422 (`unparseable`,
`invalid_base64`, `invalid_encoding`, ...), 500 (`storage_failed`,
`configuration_error`), 503 (`ml_unavailable`).

Signed-in users with "Auto-save Scan Logs" off get an audit entry only. New accounts
default to auto-save on; existing saved preferences are preserved through schema migration.
If the record cannot be written, no result is returned.

## History, dashboard and feedback (sign-in required)

These endpoints return **401** without a valid sign-in. The tests authenticate by
overriding `get_current_user_optional`. Every query is scoped to the signed-in user.

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/scans?q=&level=&range=&limit=&offset=` | History table. `level`: all/safe/suspicious/phishing. `range`: 7/30/year/all |
| `GET /api/v1/scans/export` | CSV with the same filters (max 10,000 rows; formula-injection safe) |
| `GET /api/v1/scans/{id}` | One scan: SHAP words, indicators, links. `emailBody` is always null (never stored) |
| `POST /api/v1/scans/{id}/feedback` | `{isPredictionCorrect, suggestedLabel?, explanationHelpful?, comment?}`; one per user per scan |
| `GET /api/v1/dashboard/summary?range=` | Metric cards, risk distribution, trend, recent scans |

## Database

The SQLite file is created automatically on first start from
`bantai-database/schema.sql` + `seed.sql`. To (re)create it by hand,
with optional demo data (new databases only):

```bash
python -m app.db.init_db --with-sample
```

Supported schema upgrades run forward from `bantai-database/migrations/` when the server
starts. The current schema is version 11. Upgrade migrations preserve existing user IDs,
sessions, scans, and audit records; the version-10-to-11 migration adds local-auth and
OTP/OAuth support without rebuilding the existing Google SSO accounts. Back up
`bantai-backend/bantai.db` before applying a migration. The server never deletes an
existing database to upgrade it; it refuses to start if a migration path is missing or
the database is newer than the application.

## Authentication and email

Registration creates an inactive local account and emails a six-digit verification code.
The account becomes active only after the code is verified. Login accepts a username or
email address. Password recovery uses a separately verified OTP and a short-lived,
single-use reset authorization; passwords are never written to browser storage.

Copy `.env.example` to `.env` and configure the placeholders locally. SMTP delivery uses
STARTTLS and requires `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and
`SMTP_FROM_EMAIL`. The documented unprefixed names and the equivalent `BANTAI_SMTP_*`
names are accepted. Brevo SMTP values belong only in this backend environment file; do
not commit `.env`. Registration and Google-account password setup remain unavailable when
email delivery is not configured.

Google sign-in requires `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and
`GOOGLE_REDIRECT_URI`. Register this exact development callback in Google Cloud Console:

```text
http://localhost:8000/api/v1/auth/google/callback
```

Set `BANTAI_FRONTEND_BASE_URL` to the frontend origin (default
`http://localhost:5173`). The client secret is backend-only. OAuth uses a server-validated
state and nonce, Google ID-token verification, the stable Google subject ID, and a
single-use short-lived ticket exchanged by the frontend. An existing account with a
matching email is not linked automatically. Existing Google accounts retain their IDs
and data; signed-in Google users without a password can verify their email and add local
password sign-in to the same account in Settings.

Implementation defaults (not research requirements): OTPs expire after 10 minutes, are
single-use, and have a five-attempt limit. Resends are throttled to one per minute and
five per hour. Password-reset responses are generic for known and unknown addresses to
reduce account enumeration; the password reset authorization expires after 10 minutes.
Only OTP/token hashes are stored, and a successful password reset revokes active sessions.

## Test

```bash
pytest -v
```

## Build status

| Step   |                    Part                          | Status |
|--------|--------------------------------------------------|--------|
| 1      | Foundation: config, app, CORS, ML bridge, health | done   |
| 2      | Email parsing + sanitization                     | done   |
| 3      | Database layer (SQLAlchemy)                      | done   |
| 4      | Threat scoring + educational explanations        | done   |
| 5      | Scan endpoint + audit logging                    | done   |
| 6      | History / dashboard / feedback endpoints         | done   |
| 7      | Auth + settings                                  | done   |
