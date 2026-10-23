"""Session lookup for bearer tokens (pure SQL through the `Execute` seam; no web framework).

A token is valid only if its SHA-256 hash is in `user_sessions`, the session is not revoked,
has not expired, and the user is active. The plaintext token is never stored or logged.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from app.services.history_repo import Execute

# secrets.token_urlsafe(32) -> 43 characters of [A-Za-z0-9_-]
_BEARER = re.compile(r"^[Bb]earer ([A-Za-z0-9_\-]{20,200})$")


def parse_bearer(header: Optional[str]) -> Optional[str]:
    """The token from an 'Authorization: Bearer <token>' header, or None if malformed."""
    if not header:
        return None
    match = _BEARER.match(header.strip())
    return match.group(1) if match else None


def find_active_session(execute: Execute, token_digest: str, now_iso: str) -> Optional[Dict[str, Any]]:
    rows = execute(
        "SELECT s.session_id, s.user_id FROM user_sessions s "
        "JOIN users u ON u.user_id = s.user_id "
        "WHERE s.token_hash = :digest AND s.revoked_at IS NULL "
        "AND s.expires_at > :now AND u.is_active = 1",
        {"digest": token_digest, "now": now_iso},
    )
    return rows[0] if rows else None
