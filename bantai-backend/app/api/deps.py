"""Shared FastAPI dependencies: who is calling?

Rebuilt in Step 7a from the contract the existing auth router (app/api/routes/auth.py)
relies on: `get_current_user` (401 when not signed in) and `get_current_user_optional`
(None for guests), with the session id stored on `request.state.auth_session_id` so logout
can revoke it.

Rules:
* No Authorization header            -> guest (None)
* Header present but token not valid -> 401 (a stale token is never silently treated as a guest)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.auth_security import token_hash
from app.db.session import get_db
from app.services.auth_sessions import find_active_session, parse_bearer
from app.services.history_repo import session_runner


def _unauthorized(code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail={"code": code, "message": message},
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user_optional(request: Request, db: Session = Depends(get_db)) -> Optional[int]:
    """The signed-in user's id, or None for a guest."""
    header = request.headers.get("authorization")
    if header is None:
        return None
    token = parse_bearer(header)
    if token is None:
        raise _unauthorized("invalid_token", "The Authorization header is not a valid Bearer token.")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    found = find_active_session(session_runner(db), token_hash(token), now)
    if found is None:
        raise _unauthorized("invalid_token", "The session is invalid or has expired. Please sign in again.")
    request.state.auth_session_id = found["session_id"]
    return found["user_id"]


def get_current_user(user_id: Optional[int] = Depends(get_current_user_optional)) -> int:
    """Like get_current_user_optional, but guests get 401."""
    if user_id is None:
        raise _unauthorized("not_authenticated", "Sign in to continue.")
    return user_id


# Name used by the history / dashboard routes written in Step 6.
get_current_user_required = get_current_user
