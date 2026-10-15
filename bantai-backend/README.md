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

`POST /api/v1/scans` (guest access until Step 7 adds login)

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

Errors: `{"detail": {"code": "...", "message": "..."}}` with 413 (`too_large`,
`body_too_long`), 422 (`unparseable`, `invalid_base64`, `invalid_encoding`, ...),
500 (`storage_failed`, `configuration_error`), 503 (`ml_unavailable`).

Guest scans are recorded without subject or full sender address. Signed-in users with
"Auto-save Scan Logs" off get an audit entry only. If the record cannot be written, no
result is returned.

## History, dashboard and feedback (sign-in required)

Until Step 7 adds login these return **401**; the tests sign in by overriding
`get_current_user_optional`. Every query is scoped to the signed-in user.

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

To start over, stop the server and delete `bantai.db`. This is also required whenever
`schema.sql` changes its `PRAGMA user_version`: the server refuses to start on a database
with a different schema version and tells you to delete the file.

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
| 6      | History / dashboard / feedback endpoints         | this drop |
| 7      | Auth + settings                                  | pending |
