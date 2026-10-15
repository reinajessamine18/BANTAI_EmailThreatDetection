"""Validation for profile fields (pure)."""

from __future__ import annotations

import re
from typing import Optional

MAX_PICTURE_CHARS = 400_000          # matches the CHECK on users.profile_picture
# Raster formats only. SVG is refused on purpose: it can carry scripts.
_PICTURE_RE = re.compile(r"data:image/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/]+={0,2}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")


def is_valid_picture(value: str) -> bool:
    # fullmatch, not match: '$' would also accept a trailing newline
    return len(value) <= MAX_PICTURE_CHARS and bool(_PICTURE_RE.fullmatch(value))


def clean_text(value: Optional[str], limit: int) -> str:
    """Single line, no control characters, trimmed, capped."""
    return re.sub(r"\s+", " ", _CONTROL.sub(" ", value or "")).strip()[:limit]


def normalize_email(value: Optional[str]) -> Optional[str]:
    email = (value or "").strip().lower()
    return email if 0 < len(email) <= 254 and _EMAIL_RE.fullmatch(email) else None
