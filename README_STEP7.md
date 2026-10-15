# BANTAI Step 7 — Local Authentication and Session Management

This step replaces the Step 5 guest-only authentication dependency and adds local account registration, login, current-user, and logout endpoints. It is designed to be layered on top of Steps 1–6.

## Endpoints

- `POST /api/v1/auth/register` — create local account; password must be 10–128 characters. Returns a bearer token and safe user profile.
- `POST /api/v1/auth/login` — verify credentials and issue a bearer token.
- `GET /api/v1/auth/me` — return the authenticated profile.
- `POST /api/v1/auth/logout` — revoke the current session token.

Send `Authorization: Bearer <accessToken>` to authenticated endpoints. Tokens are generated with Python's `secrets`, only SHA-256 token hashes are stored in `user_sessions`, and passwords are stored as salted PBKDF2-HMAC-SHA256 hashes using the standard library. Sessions expire after 12 hours. This does not implement SAML SSO or password reset.

## Integrate

1. Back up your current `bantai-backend` folder.
2. Copy `app/api/auth_security.py` into `app/api/`.
3. Copy `app/api/routes/auth.py` into `app/api/routes/`.
4. Replace `app/api/deps.py` with the included version so existing history/feedback routes can resolve the bearer token to a user ID.
5. Merge the included `app/main.py` into your current Step 6 `main.py`. It preserves health, scans, history, feedback, lifespan, request size limits, CORS, and validation handling, and registers the auth router.
6. Ensure the Step 3 database schema is initialized and includes `users`, `user_sessions`, `user_settings`, and `audit_logs`. This step does not modify schema.sql.

## Test in PowerShell

From `bantai-backend` with your virtual environment activated:

```powershell
python -m pytest -v tests/test_step7_auth_security.py
python -m compileall -q app
python -m pytest -v
uvicorn app.main:app --reload --port 8000
```

Open `http://127.0.0.1:8000/docs` and try register/login/me/logout. For `/me`, include the bearer token returned by register/login. After logout, the same token should return HTTP 401.

## Security notes

- Use HTTPS outside local development.
- Do not store bearer tokens in localStorage for production web apps; prefer a carefully configured Secure, HttpOnly, SameSite cookie or a backend-for-frontend pattern. Frontend integration is intentionally separate from this backend step.
- Add rate limiting and account lockout policy before public deployment. Existing `failed_login_attempts` / `locked_until` fields are not changed by this initial implementation.
- Password reset and SAML SSO are not included.
- Do not log passwords, raw tokens, or email bodies.
