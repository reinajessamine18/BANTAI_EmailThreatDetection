"""
content_cleaner.py

Modular, general-purpose content-only email cleaning engine for BANTAI.

Extracts readable natural-language email content while excluding headers,
HTML/CSS markup, hidden script elements, raw URL destination structures,
and non-content formatting artifacts.
"""

from __future__ import annotations

import email
import email.policy
import html
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Literal


URLStrategy = Literal["placeholder", "remove", "keep"]
EmailStrategy = Literal["placeholder", "remove", "keep"]


@dataclass(frozen=True)
class CleanerConfig:
    """Configuration options for the ContentOnlyCleaner."""

    url_strategy: URLStrategy = "remove"
    url_placeholder: str = "[URL]"
    email_strategy: EmailStrategy = "remove"
    email_placeholder: str = "[EMAIL_ADDRESS]"
    normalize_whitespace: bool = True
    normalize_punctuation_spacing: bool = True
    preserve_case: bool = True
    lowercase: bool = False
    extract_from_mime: bool = True
    preserve_anchor_text: bool = True


class _HTMLToTextParser(HTMLParser):
    """
    Robust, dependency-free HTML-to-text parser.

    Drops scripts, styles, metadata, and hidden tags while preserving visible
    text, anchor text, and natural paragraph layout.
    """

    CONTAINER_IGNORABLE_TAGS = frozenset({
        "script",
        "style",
        "title",
        "noscript",
        "svg",
        "canvas",
        "template",
        "iframe",
        "applet",
        "object",
    })

    VOID_TAGS = frozenset({
        "meta",
        "link",
        "img",
        "br",
        "hr",
        "input",
        "source",
        "track",
        "wbr",
        "area",
        "col",
        "base",
    })

    BLOCK_TAGS = frozenset({
        "p",
        "div",
        "br",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "li",
        "tr",
        "blockquote",
        "hr",
        "section",
        "article",
        "header",
        "footer",
        "table",
        "tbody",
        "thead",
        "td",
        "th",
    })

    # Qualifying body-level start tags that implicitly close an unclosed <head>
    # per WHATWG HTML5 section 13.2.6.4.4 ('in head' insertion mode fallback)
    _BODY_LEVEL_FALLBACK_TAGS = frozenset({
        "center",
        "table",
        "thead",
        "tbody",
        "tr",
        "td",
        "th",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "p",
        "div",
        "ul",
        "ol",
        "li",
        "blockquote",
        "section",
        "article",
        "main",
        "nav",
        "header",
        "footer",
        "span",
        "font",
        "b",
        "strong",
        "i",
        "em",
        "u",
        "a",
    })

    _HIDDEN_STYLE_REGEX = re.compile(
        r"(?:display\s*:\s*none|visibility\s*:\s*hidden)",
        re.IGNORECASE,
    )

    def __init__(
        self,
        preserve_anchor_text: bool = True,
        url_strategy: URLStrategy = "remove",
        url_placeholder: str = "[URL]",
    ) -> None:
        super().__init__(convert_charrefs=True)
        self.preserve_anchor_text = preserve_anchor_text
        self.url_strategy = url_strategy
        self.url_placeholder = url_placeholder
        self._pieces: list[str] = []
        self._ignore_depth = 0
        self._in_head: bool = False
        self._hidden_tag_stack: list[str] = []
        self._current_href: str | None = None
        self._anchor_text_pieces: list[str] = []
        self._in_anchor = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()

        # 1. Head tag handling: track head state and ignore container
        if t == "head":
            self._in_head = True
            self._ignore_depth += 1
            return

        # 2. WHATWG implicit head closure:
        # If inside unclosed <head> and a body-level element or <body> arrives,
        # close the head context and decrement ignore depth.
        if self._in_head:
            if t == "body":
                self._in_head = False
                self._ignore_depth = 0
            elif t in self._BODY_LEVEL_FALLBACK_TAGS:
                self._in_head = False
                if self._ignore_depth > 0:
                    self._ignore_depth -= 1
                # Fall through so the qualifying body-level tag is parsed normally
        elif t == "body":
            # Explicit body tag outside of in_head resets any stray depth
            self._ignore_depth = 0

        # 3. Container ignorable tag handling (increments depth for paired tags)
        if t in self.CONTAINER_IGNORABLE_TAGS:
            self._ignore_depth += 1
            return

        # 4. Void tags (e.g. meta, link) never have closing tags; do NOT increment depth
        if t in self.VOID_TAGS:
            return

        if self._ignore_depth > 0:
            return

        # 5. Hidden element detection (style='display:none', hidden, aria-hidden, etc.)
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        is_hidden = False
        if "hidden" in attr_dict:
            is_hidden = True
        elif attr_dict.get("aria-hidden") == "true":
            is_hidden = True
        elif "style" in attr_dict and self._HIDDEN_STYLE_REGEX.search(attr_dict["style"]):
            is_hidden = True

        if is_hidden:
            self._hidden_tag_stack.append(t)
            return

        if self._hidden_tag_stack:
            return

        # 6. Anchor tag handling
        if t == "a":
            self._in_anchor = True
            self._anchor_text_pieces = []
            self._current_href = attr_dict.get("href")

        # 7. Block tags insert whitespace / line breaks
        if t in self.BLOCK_TAGS:
            self._pieces.append("\n")

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()

        # Handle head closing
        if t == "head":
            self._in_head = False
            if self._ignore_depth > 0:
                self._ignore_depth -= 1
            return

        # Handle container ignorable closing
        if t in self.CONTAINER_IGNORABLE_TAGS:
            if self._ignore_depth > 0:
                self._ignore_depth -= 1
            return

        # Void tags have no end tags
        if t in self.VOID_TAGS:
            return

        if self._ignore_depth > 0:
            return

        # Handle hidden tag closing
        if self._hidden_tag_stack:
            if t == self._hidden_tag_stack[-1]:
                self._hidden_tag_stack.pop()
            return

        # Handle anchor closing
        if t == "a":
            self._in_anchor = False
            anchor_content = "".join(self._anchor_text_pieces).strip()
            if self._current_href:
                is_url_already = bool(re.match(r"^(?:https?://|www\.)", anchor_content, re.IGNORECASE))
                if not is_url_already:
                    if self.url_strategy == "placeholder":
                        self._pieces.append(f" {self.url_placeholder}")
                    elif self.url_strategy == "keep":
                        self._pieces.append(f" ({self._current_href})")
                    # If url_strategy == "remove": do not append placeholder or href
            self._current_href = None
            self._anchor_text_pieces = []

        if t in self.BLOCK_TAGS:
            self._pieces.append("\n")

    def handle_data(self, data: str) -> None:
        if self._ignore_depth > 0 or self._hidden_tag_stack:
            return
        if not data:
            return
        self._pieces.append(data)
        if self._in_anchor:
            self._anchor_text_pieces.append(data)

    def get_text(self) -> str:
        raw = "".join(self._pieces)
        return raw


class ContentOnlyCleaner:
    """
    Deterministic Content-Only Email Cleaning Engine.

    Transforms raw plain-text, HTML, or MIME email inputs into sanitized,
    readable natural-language text suitable for feature extraction.
    """

    # URL regex matching http, https, ftp, and www prefixes, separating trailing punctuation
    _URL_REGEX = re.compile(
        r"(?:https?://|www\.)[^\s<>'\"`]+",
        flags=re.IGNORECASE,
    )

    # Email address regex matching standard user@domain.tld
    _EMAIL_REGEX = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        flags=re.IGNORECASE,
    )

    # Pre-tokenized spaced email pattern found in some legacy corpora: "user @ domain . com"
    _SPACED_EMAIL_REGEX = re.compile(
        r"\b[A-Za-z0-9._%+-]+(?:\s+@\s*|\s*@\s+)[A-Za-z0-9.-]+(?:\s*\.\s*)[A-Za-z]{2,}\b"
        r"|"
        r"\b[A-Za-z0-9._%+-]+(?:\s*@\s*)[A-Za-z0-9.-]+(?:\s+\.\s*)[A-Za-z]{2,}\b",
        flags=re.IGNORECASE,
    )

    # Common HTML indicator tags
    _HTML_DETECT_REGEX = re.compile(
        r"<\s*(?:!doctype|html|head|body|p|div|br|span|a|table|table|font|b|i)\b",
        flags=re.IGNORECASE,
    )

    # MIME header block indicator (top of message)
    _MIME_DETECT_REGEX = re.compile(
        r"^(?:received|from|to|subject|date|message-id|mime-version|content-type):",
        flags=re.IGNORECASE | re.MULTILINE,
    )

    def __init__(self, config: CleanerConfig | None = None) -> None:
        self.config = config or CleanerConfig()

    def clean(self, raw_input: str | None) -> str:
        """
        Execute deterministic content cleaning on the input email string.

        Args:
            raw_input: Raw email body, HTML snippet, or MIME message string.

        Returns:
            Cleaned, readable natural-language text.
        """
        if not raw_input or not isinstance(raw_input, str):
            return ""

        text = raw_input

        # 1. MIME email parsing (if input is a complete RFC 822 / MIME message)
        if self.config.extract_from_mime and self._is_mime_message(text):
            text = self._extract_body_from_mime(text)

        # 2. HTML extraction and markup stripping
        if self._is_html(text):
            text = self._extract_visible_html_text(text)

        # 3. HTML Entity decoding (e.g., &amp; -> &, &quot; -> ", &nbsp; -> space)
        text = html.unescape(text)

        # 4. Normalize punctuation-spacing artifacts (e.g. from Enron pre-tokenization)
        if self.config.normalize_punctuation_spacing:
            text = self._normalize_punctuation_spacing(text)

        # 5. Email address handling (inside body)
        text = self._handle_email_addresses(text)

        # 6. URL handling (destination structure removal / placeholder)
        text = self._handle_urls(text)

        # 7. Whitespace and layout normalization
        if self.config.normalize_whitespace:
            text = self._normalize_whitespace(text)

        # 8. Casing adjustment (if explicitly configured)
        if self.config.lowercase:
            text = text.lower()

        return text.strip()

    def _is_mime_message(self, text: str) -> bool:
        """Detect whether the text appears to be a raw MIME or RFC 822 formatted message."""
        # Require header match within the first 2,000 characters and an empty line separating headers from body
        first_chunk = text[:2000]
        matches = self._MIME_DETECT_REGEX.findall(first_chunk)
        return len(matches) >= 2 and ("\n\n" in text or "\r\n\r\n" in text)

    def _extract_body_from_mime(self, raw_mime: str) -> str:
        """Parse raw MIME message and extract body content, strictly excluding headers."""
        try:
            msg = email.message_from_string(raw_mime, policy=email.policy.default)
            # Prefer non-empty plain text part
            plain_part = msg.get_body(preferencelist=("plain",))
            if plain_part is not None:
                content = plain_part.get_content()
                if isinstance(content, str) and content.strip():
                    return content
            # Fallback to html part if plain text part is missing or whitespace-only
            html_part = msg.get_body(preferencelist=("html",))
            if html_part is not None:
                content = html_part.get_content()
                if isinstance(content, str):
                    return content
        except Exception:  # noqa: BLE001
            # Fallback: if MIME parser fails, split on first double newline to drop headers
            parts = re.split(r"\r?\n\r?\n", raw_mime, maxsplit=1)
            if len(parts) > 1:
                return parts[1]
        return raw_mime

    def _is_html(self, text: str) -> bool:
        """Detect if the string contains HTML markup elements."""
        return bool(self._HTML_DETECT_REGEX.search(text))

    def _extract_visible_html_text(self, html_text: str) -> str:
        """Parse HTML string and return visible, readable text with anchor text preserved."""
        parser = _HTMLToTextParser(
            preserve_anchor_text=self.config.preserve_anchor_text,
            url_strategy=self.config.url_strategy,
            url_placeholder=self.config.url_placeholder,
        )
        try:
            parser.feed(html_text)
            parser.close()
            return parser.get_text()
        except Exception:  # noqa: BLE001
            # Fallback regex strip if HTMLParser encounters an unrecoverable format
            stripped = re.sub(r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", " ", html_text, flags=re.IGNORECASE)
            stripped = re.sub(r"<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>", " ", stripped, flags=re.IGNORECASE)
            stripped = re.sub(r"<[^>]+>", " ", stripped)
            return stripped

    def _normalize_punctuation_spacing(self, text: str) -> str:
        """
        Normalize space-padded punctuation artifacts produced by pre-tokenized corpora.

        Converts artifacts like 'word . ' -> 'word. ', 'word , ' -> 'word, ',
        'don \' t' -> 'don\'t', 'user @ enron . com' -> 'user@enron.com' while
        preserving mathematical and natural language formatting.
        """
        s = text

        # 0. Collapse pre-tokenized spaced emails: user . name @ domain . com -> user.name@domain.com
        spaced_email_pattern = re.compile(
            r"\b([A-Za-z0-9._%+-]+(?:\s+\.\s+[A-Za-z0-9._%+-]+)*)\s+@\s+([A-Za-z0-9.-]+(?:\s+\.\s+[A-Za-z0-9.-]+)+)\b",
            re.IGNORECASE,
        )
        s = spaced_email_pattern.sub(lambda m: re.sub(r"\s+", "", m.group(0)), s)

        # 1. Collapse space before standard punctuation marks: . , ! ? : ; ) ] }
        s = re.sub(r"\s+([.,!?:;\)\]\}])", r"\1", s)

        # 2. Collapse space after opening brackets: ( [ {
        s = re.sub(r"([\(\[\{])\s+", r"\1", s)

        # 3. Collapse spaced contractions and possessives: word ' s -> word's, don ' t -> don't
        s = re.sub(r"(\b[A-Za-z]+)\s+(['’])\s+([A-Za-z]+\b)", r"\1\2\3", s)

        return s

    def _handle_email_addresses(self, text: str) -> str:
        """Apply configured email address handling strategy."""
        strategy = self.config.email_strategy
        if strategy == "keep":
            return text

        replacement = self.config.email_placeholder if strategy == "placeholder" else ""

        # First replace any spaced emails if present
        s = self._SPACED_EMAIL_REGEX.sub(replacement, text)
        # Then replace standard email addresses
        s = self._EMAIL_REGEX.sub(replacement, s)
        return s

    def _handle_urls(self, text: str) -> str:
        """Apply configured URL handling strategy while preserving trailing sentence punctuation."""
        strategy = self.config.url_strategy
        if strategy == "keep":
            return text

        def _replace_url(match: re.Match[str]) -> str:
            raw_url = match.group(0)
            # Separate trailing punctuation that belongs to the sentence rather than the URL
            trailing_punct = ""
            while raw_url and raw_url[-1] in ".,!?;:)>]}'\"":
                trailing_punct = raw_url[-1] + trailing_punct
                raw_url = raw_url[:-1]

            if strategy == "placeholder":
                return self.config.url_placeholder + trailing_punct
            # strategy == "remove"
            return trailing_punct

        return self._URL_REGEX.sub(_replace_url, text)

    def _normalize_whitespace(self, text: str) -> str:
        """Normalize line endings, horizontal spaces, and paragraph breaks."""
        # Normalize newlines
        s = text.replace("\r\n", "\n").replace("\r", "\n")

        # Replace non-breaking spaces and tabs with standard space
        s = re.sub(r"[ \t\u00a0\u2000-\u200b]+", " ", s)

        # Collapse space at beginning or end of lines
        s = re.sub(r" *\n *", "\n", s)

        # Limit consecutive blank lines to at most 2 (preserving paragraph breaks)
        s = re.sub(r"\n{3,}", "\n\n", s)

        return s


def clean_email_content(
    raw_input: str | None,
    config: CleanerConfig | None = None,
) -> str:
    """
    Convenience function to clean email content using default or custom config.

    Args:
        raw_input: Raw email content string.
        config: Optional custom CleanerConfig.

    Returns:
        Cleaned, readable plain-text content.
    """
    cleaner = ContentOnlyCleaner(config=config)
    return cleaner.clean(raw_input)
