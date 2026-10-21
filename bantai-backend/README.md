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

Supported schema upgrades run from `bantai-database/migrations/` when the server starts.
The version-9 Google SSO database is upgraded to version 10 while preserving existing
users, sessions, scans, and audit records. Existing Google SSO accounts have no password
hashes; this application does not implement Google sign-in, so those accounts cannot use
password sign-in until an account recovery/setup flow is available. Back up the database
before deploying schema changes. The server never deletes an existing database to upgrade
it; it refuses to start if a migration path is missing or the database is newer than the
application.

## Password recovery

Password recovery sends a single-use link to the account's registered email address.
The email address by itself is not sufficient to change a password. Configure SMTP
STARTTLS in `bantai-backend/.env` using the `BANTAI_SMTP_*` variables in `.env.example`,
and set `BANTAI_FRONTEND_BASE_URL` to the trusted frontend origin. Recovery remains
disabled until SMTP host and sender are configured.

Implementation defaults (not research requirements): reset links expire after 30 minutes,
and each client IP may request up to 5 links per hour. Only a SHA-256 token hash is stored;
successful resets revoke all active sessions. The request endpoint gives the same response
for known and unknown email addresses to reduce account enumeration.

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
