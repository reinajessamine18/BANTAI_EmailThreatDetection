"""Decode and parse what the client submitted (pure; no FastAPI / database).

Accepted combinations:
    eml_upload + text    -> the .eml file's text (UTF-8)
    eml_upload + base64  -> the .eml file's raw bytes, base64-encoded (binary-safe)
    raw_text   + text    -> pasted email text (full message or just a body)
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Optional, Tuple

from app.services.email_parser import MAX_RAW_BYTES, ParsedEmail, ParseError, parse_eml, parse_text

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ScanInputError(ValueError):
    """The submission is unusable. `message` never contains email content."""

    def __init__(self, code: str, message: str, status: int = 422):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def clean_file_name(name: Optional[str]) -> Optional[str]:
    """Base name only (no client path), control characters removed, max 255 chars."""
    if not name:
        return None
    base = re.split(r"[\\/]", name)[-1]
    base = _CONTROL.sub("", base).strip()[:255]
    return base or None


def parse_scan_input(
    input_method: str,
    content: str,
    encoding: str,
    max_bytes: int = MAX_RAW_BYTES,
) -> Tuple[ParsedEmail, int]:
    """Return (parsed email, size in bytes of what was submitted)."""
    too_large = ScanInputError("too_large", f"Email exceeds the {max_bytes}-byte limit.", status=413)

    if encoding == "base64":
        if input_method != "eml_upload":
            raise ScanInputError("invalid_encoding", "base64 is only valid for .eml uploads.")
        if len(content) * 3 // 4 > max_bytes + 3:       # cheap pre-check before decoding
            raise too_large
        try:
            raw = base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError):
            raise ScanInputError("invalid_base64", "The file content is not valid base64.") from None
    elif encoding == "text":
        raw = content.encode("utf-8", "replace")
    else:
        raise ScanInputError("invalid_encoding", "encoding must be 'text' or 'base64'.")

    if len(raw) > max_bytes:
        raise too_large

    try:
        if input_method == "eml_upload":
            parsed = parse_eml(raw, max_bytes)
        elif input_method == "raw_text":
            parsed = parse_text(raw.decode("utf-8", "replace"), max_bytes)
        else:
            raise ScanInputError("invalid_input_method", "Unknown input method.")
    except ParseError as exc:
        raise ScanInputError("unparseable", str(exc)) from exc
    return parsed, len(raw)
