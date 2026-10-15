"""Email ingestion: .eml / pasted-text parsing, sanitization and URL extraction.

Pure Python (standard library + BeautifulSoup4). It has no FastAPI, database or ML
dependency, and it never makes network requests (links are analyzed as text only).

Output is a `ParsedEmail`. Its `body_text` is plain text with all HTML removed, so
nothing downstream (ML, database, JSON response) ever handles raw markup.

Privacy:
* `body_text` is excluded from the dataclass repr so an accidental log of the object
  cannot leak the email.
* `ParseError` messages never contain email content.
* URLs are stored defanged, with userinfo, query string and fragment removed.

Caveat on SPF/DKIM/DMARC: these are read from headers inside the submitted file.
They are only trustworthy if the receiving mail server wrote them; a sender can
forge such headers. Treat them as indicators, not proof.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import message_from_bytes, message_from_string, policy
from email.utils import parseaddr
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Limits. ASSUMPTIONS (implementation decisions, not research requirements).
# MAX_RAW_BYTES mirrors `max_upload_bytes` in bantai-database/seed.sql.
# ---------------------------------------------------------------------------
MAX_RAW_BYTES = 5 * 1024 * 1024
MAX_SUBJECT_CHARS = 300
MAX_ADDRESS_CHARS = 320
MAX_URLS = 100
MAX_DEFANGED_PATH_CHARS = 100

# Assumed list; extend as needed. Used only for the `uses_shortener` indicator.
URL_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
})

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_URL_RE = re.compile(r"https?://[^\s<>\"'\u00a0]+", re.IGNORECASE)
_URL_TRAILING = ".,;:!?)]}'\""
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+)$", re.IGNORECASE)
_HTML_HINT = re.compile(r"<\s*(html|body|a\s|div|p|table|br|span)\b", re.IGNORECASE)
_DOMAIN_IN_TEXT = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", re.IGNORECASE)
_AUTH_RE = {
    name: re.compile(rf"\b{name}\s*=\s*([a-z]+)", re.IGNORECASE)
    for name in ("spf", "dkim", "dmarc")
}
# Second-level labels used under two-letter country TLDs (co.uk, com.ph, edu.ph...).
# Heuristic only; no public-suffix list is bundled.
_SLD_LABELS = frozenset({"co", "com", "org", "net", "edu", "gov", "ac"})
_KNOWN_HEADERS = frozenset({
    "from", "to", "subject", "received", "return-path", "message-id",
    "reply-to", "authentication-results", "mime-version", "date",
})


class ParseError(ValueError):
    """The submitted email cannot be parsed. Messages never contain email content."""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ExtractedUrl:
    position: int
    url_defanged: str
    domain: Optional[str]
    tld: Optional[str]
    url_length: int
    subdomain_count: int
    redirect_count: int          # always 0: links are never fetched, so unknown
    has_ip_address: bool
    uses_shortener: bool
    has_at_symbol: bool
    is_https: bool
    is_suspicious: bool          # rule-based flag (ip / shortener / @ / punycode), NOT a model output
    link_text_mismatch: bool     # visible link text names a different host than the href


@dataclass(frozen=True)
class ParsedEmail:
    subject: Optional[str]
    sender_address: Optional[str]
    sender_domain: Optional[str]
    return_path_domain: Optional[str]
    reply_to_domain: Optional[str]
    spf_result: str
    dkim_result: str
    dmarc_result: str
    body_text: str = field(repr=False)
    body_char_count: int
    content_sha256: str
    urls: Tuple[ExtractedUrl, ...]
    urls_truncated: bool
    attachment_count: int
    had_headers: bool
    had_html: bool

    @property
    def url_count(self) -> int:
        return len(self.urls)


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------
def _clean_text(text: str) -> str:
    """Remove control characters, normalize newlines/whitespace. Leaves no markup handling."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_CHARS.sub("", text)
    lines = [line.rstrip() for line in text.split("\n")]
    text = "\n".join(lines)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _clean_header(value: object, limit: int) -> Optional[str]:
    """Single-line, control-character-free, length-capped header value."""
    if value is None:
        return None
    text = _CONTROL_CHARS.sub("", str(value))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] or None


def _html_to_text(html: str) -> Tuple[str, List[Tuple[str, str]]]:
    """Return (visible text, [(href, link_text)]). Scripts/styles are dropped, never executed."""
    soup = BeautifulSoup(html, "html.parser")
    anchors = [
        (a["href"].strip(), a.get_text(" ", strip=True))
        for a in soup.find_all("a", href=True)
    ]
    for tag in soup(["script", "style", "head", "noscript", "template"]):
        tag.decompose()
    return soup.get_text("\n"), anchors


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------
def _header(msg, name: str) -> Optional[str]:
    try:
        value = msg[name]
    except Exception:  # malformed header objects can raise on access
        return None
    return None if value is None else str(value)


def _address_parts(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """(address, domain) from a raw address header, both lowercase, or (None, None)."""
    if not value:
        return None, None
    _, addr = parseaddr(value)
    addr = _CONTROL_CHARS.sub("", addr).strip().lower()
    if not addr:
        return None, None
    domain = addr.rpartition("@")[2].strip(".") if "@" in addr else ""
    return addr[:MAX_ADDRESS_CHARS], (domain[:255] or None)


def _auth_result(msg, name: str) -> str:
    """First `spf=` / `dkim=` / `dmarc=` verdict found; 'none' when absent."""
    try:
        for header in msg.get_all("Authentication-Results", []):
            match = _AUTH_RE[name].search(str(header))
            if match:
                return match.group(1).lower()[:20]
        if name == "spf":
            received = _header(msg, "Received-SPF")
            if received and received.split():
                return re.sub(r"[^a-z]", "", received.split()[0].lower())[:20] or "none"
    except Exception:
        pass
    return "none"


# ---------------------------------------------------------------------------
# URL extraction and analysis
# ---------------------------------------------------------------------------
def _base_domain_labels(labels: List[str]) -> int:
    """Number of trailing labels forming the registrable domain (heuristic)."""
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SLD_LABELS:
        return 3
    return min(2, len(labels))


def _strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def _text_mismatch(link_text: str, href_host: str) -> bool:
    match = _DOMAIN_IN_TEXT.search(link_text or "")
    if not match:
        return False
    shown = _strip_www(match.group(1).lower())
    actual = _strip_www(href_host)
    if shown == actual or shown.endswith("." + actual) or actual.endswith("." + shown):
        return False
    return True


def analyze_url(url: str, position: int = 1, link_text: str = "") -> Optional[ExtractedUrl]:
    """Lexical analysis of one http(s) URL. Returns None if it is not analyzable."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None

    is_https = parts.scheme.lower() == "https"
    has_at = "@" in parts.netloc

    is_ip = bool(_NUMERIC_HOST.match(host))
    if not is_ip:
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            pass

    if is_ip:
        domain, tld, subdomain_count = host, None, 0
    else:
        labels = host.split(".")
        base = _base_domain_labels(labels)
        domain = ".".join(labels[-base:])
        tld = labels[-1]
        subdomain_count = max(0, len(labels) - base)

    uses_shortener = (not is_ip) and domain in URL_SHORTENERS
    punycode = "xn--" in host
    mismatch = _text_mismatch(link_text, host) if link_text else False

    defanged = (
        f"{'hxxps' if is_https else 'hxxp'}://{host.replace('.', '[.]')}"
        f"{f':{port}' if port else ''}{parts.path[:MAX_DEFANGED_PATH_CHARS]}"
    )

    return ExtractedUrl(
        position=position,
        url_defanged=defanged,
        domain=domain,
        tld=tld,
        url_length=len(url),
        subdomain_count=subdomain_count,
        redirect_count=0,
        has_ip_address=is_ip,
        uses_shortener=uses_shortener,
        has_at_symbol=has_at,
        is_https=is_https,
        is_suspicious=is_ip or uses_shortener or has_at or punycode,
        link_text_mismatch=mismatch,
    )


def _extract_urls(
    texts: List[str], anchors: List[Tuple[str, str]]
) -> Tuple[Tuple[ExtractedUrl, ...], bool]:
    """Collect unique http(s) URLs from text bodies and HTML anchors, in order of appearance."""
    ordered: List[str] = []
    link_texts = {}
    for href, shown in anchors:
        if href.lower().startswith(("http://", "https://")):
            ordered.append(href)
            link_texts.setdefault(href, []).append(shown)
    for text in texts:
        for match in _URL_RE.finditer(text):
            ordered.append(match.group(0).rstrip(_URL_TRAILING))

    seen = set()
    results: List[ExtractedUrl] = []
    truncated = False
    for url in ordered:
        if url in seen:
            continue
        seen.add(url)
        analyzed = None
        for shown in link_texts.get(url, [""]):
            candidate = analyze_url(url, position=len(results) + 1, link_text=shown)
            if candidate is not None and (analyzed is None or candidate.link_text_mismatch):
                analyzed = candidate
        if analyzed is None:
            continue
        if len(results) >= MAX_URLS:
            truncated = True
            break
        results.append(analyzed)
    return tuple(results), truncated


# ---------------------------------------------------------------------------
# Public parsing API
# ---------------------------------------------------------------------------
def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:  # unknown charset, undecodable payload, ...
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", "replace")


def _finish(*, msg, digest: str, plain: str, html: str, had_headers: bool) -> ParsedEmail:
    html_text, anchors = _html_to_text(html) if html.strip() else ("", [])
    body = _clean_text(plain if plain.strip() else html_text)
    if not body:
        raise ParseError("email has no readable body text")

    urls, truncated = _extract_urls([plain, html_text], anchors)

    sender_address, sender_domain = _address_parts(_header(msg, "From")) if msg else (None, None)
    _, return_path_domain = _address_parts(_header(msg, "Return-Path")) if msg else (None, None)
    _, reply_to_domain = _address_parts(_header(msg, "Reply-To")) if msg else (None, None)

    attachment_count = 0
    if msg is not None:
        try:
            attachment_count = sum(
                1 for part in msg.walk() if part.get_content_disposition() == "attachment"
            )
        except Exception:
            attachment_count = 0

    return ParsedEmail(
        subject=_clean_header(_header(msg, "Subject"), MAX_SUBJECT_CHARS) if msg else None,
        sender_address=sender_address,
        sender_domain=sender_domain,
        return_path_domain=return_path_domain,
        reply_to_domain=reply_to_domain,
        spf_result=_auth_result(msg, "spf") if msg else "none",
        dkim_result=_auth_result(msg, "dkim") if msg else "none",
        dmarc_result=_auth_result(msg, "dmarc") if msg else "none",
        body_text=body,
        body_char_count=len(body),
        content_sha256=digest,
        urls=urls,
        urls_truncated=truncated,
        attachment_count=attachment_count,
        had_headers=had_headers,
        had_html=bool(html.strip()),
    )


def parse_eml(raw: bytes, max_bytes: int = MAX_RAW_BYTES) -> ParsedEmail:
    """Parse the raw bytes of an .eml file (RFC 5322 / MIME)."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ParseError("raw email must be bytes")
    if not raw.strip():
        raise ParseError("email is empty")
    if len(raw) > max_bytes:
        raise ParseError(f"email exceeds the {max_bytes}-byte limit")

    digest = hashlib.sha256(bytes(raw)).hexdigest()
    try:
        msg = message_from_bytes(bytes(raw), policy=policy.default)
    except Exception as exc:
        raise ParseError(f"email could not be parsed ({type(exc).__name__})") from exc

    plain_part = msg.get_body(preferencelist=("plain",))
    html_part = msg.get_body(preferencelist=("html",))
    return _finish(
        msg=msg,
        digest=digest,
        plain=_part_text(plain_part) if plain_part is not None else "",
        html=_part_text(html_part) if html_part is not None else "",
        had_headers=True,
    )


def parse_text(text: str, max_bytes: int = MAX_RAW_BYTES) -> ParsedEmail:
    """Parse pasted text. Accepts a full message with headers, or just a body."""
    if not isinstance(text, str):
        raise ParseError("pasted email must be text")
    if not text.strip():
        raise ParseError("email is empty")
    encoded = text.encode("utf-8", "replace")
    if len(encoded) > max_bytes:
        raise ParseError(f"email exceeds the {max_bytes}-byte limit")

    digest = hashlib.sha256(encoded).hexdigest()
    try:
        msg = message_from_string(text, policy=policy.default)
    except Exception as exc:
        raise ParseError(f"email could not be parsed ({type(exc).__name__})") from exc

    has_headers = any(key.lower() in _KNOWN_HEADERS for key in msg.keys())
    if has_headers:
        plain_part = msg.get_body(preferencelist=("plain",))
        html_part = msg.get_body(preferencelist=("html",))
        return _finish(
            msg=msg,
            digest=digest,
            plain=_part_text(plain_part) if plain_part is not None else "",
            html=_part_text(html_part) if html_part is not None else "",
            had_headers=True,
        )

    # Body only. If the user pasted HTML, treat it as HTML.
    if _HTML_HINT.search(text):
        return _finish(msg=None, digest=digest, plain="", html=text, had_headers=False)
    return _finish(msg=None, digest=digest, plain=text, html="", had_headers=False)
