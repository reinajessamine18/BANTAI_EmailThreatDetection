"""
dataset_sanitizer.py

Dataset-specific processing and sanitization utilities for BANTAI.

Separates dataset-specific artifact handling (mbox headers, Enron internal
forwarding blocks, Mailman footer boilerplate) from general-purpose runtime cleaning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from src.preprocessing.content_cleaner import (
    CleanerConfig,
    ContentOnlyCleaner,
)


@dataclass
class SanitizedRecordResult:
    """Detailed audit result of a dataset-specific sanitization operation."""

    original_text: str
    cleaned_text: str
    is_quarantined: bool = False
    quarantine_reason: str | None = None
    char_count_original: int = 0
    char_count_cleaned: int = 0
    word_count_original: int = 0
    word_count_cleaned: int = 0
    flags: list[str] = field(default_factory=list)


class DatasetSanitizer:
    """
    Dataset-Specific Sanitization and Quarantine Manager.

    Contains audited, transparent rules to sanitize historical training corpora
    without modifying raw files or hardcoding dataset-specific rules into the runtime cleaner.
    """

    # Mbox folder internal data marker
    _MBOX_MARKER_REGEX = re.compile(
        r"DON'?T DELETE THIS MESSAGE\s*--\s*FOLDER INTERNAL DATA",
        flags=re.IGNORECASE,
    )

    # Extreme base64 attachment indicator
    _BASE64_BLOCK_REGEX = re.compile(
        r"(?:[A-Za-z0-9+/]{60,}\s*\n?){50,}",
    )

    # Enron internal forwarded block header pattern
    # e.g., "- - - - - forwarded by sabrae zajac / hou / ect on 05 / 30 / 2001 12 : 07 pm - - - - -"
    _ENRON_FORWARDED_HEADER_REGEX = re.compile(
        r"^\s*-\s*-\s*-\s*-\s*-\s*(?:forwarded by|original message)[\s\S]*?-\s*-\s*-\s*-\s*-\s*\n?",
        flags=re.IGNORECASE | re.MULTILINE,
    )

    # SpamAssassin Mailman list footer pattern
    # Standard boilerplate ending mailing list digests
    _SA_MAILMAN_FOOTER_REGEX = re.compile(
        r"(?:--+\s*\n)?(?:Sponsored by:[\s\S]*?|This SF\.net email is sponsored by:[\s\S]*?|_______________________________________________[\s\S]*?)?(?:https?://[^\s]+(?:/mailman/listinfo/|/lists/listinfo/)[^\s]*)[\s\S]*$",
        flags=re.IGNORECASE,
    )

    # Targeted collector domain regex (demonstrably non-content collector signature)
    _COLLECTOR_DOMAIN_REGEX = re.compile(
        r"\b(?:[A-Za-z0-9._%+-]+@)?(?:[A-Za-z0-9.-]+\.)?monkey\.org\b",
        flags=re.IGNORECASE,
    )

    # Targeted honeypot decoy email regex (decoy address lacking a standard dot-TLD)
    _HONEYPOT_DECOY_REGEX = re.compile(
        r"\b[A-Za-z0-9._%+-]+@pot\b",
        flags=re.IGNORECASE,
    )

    def __init__(self, cleaner: ContentOnlyCleaner | None = None) -> None:
        self.cleaner = cleaner or ContentOnlyCleaner()

    def sanitize_nazario_record(
        self,
        row: dict[str, Any],
        body_col: str = "body",
        subject_col: str = "subject",
        strip_collector_domain: bool = False,
    ) -> SanitizedRecordResult:
        """
        Sanitize a record from Nazario.csv.

        Identifies and quarantines the two known mbox metadata records and
        extreme base64 attachment outliers. Preserves natural phishing body
        content, authentic victim/collector domain personalization in prose
        ('monkey.org'), and genuine names/locations (such as 'jose' / 'San Jose').
        Removes raw email addresses and URLs containing the collector domain
        via the general ContentOnlyCleaner engine.
        """
        raw_body = str(row.get(body_col, "") or "")
        raw_subj = str(row.get(subject_col, "") or "")
        combined_check = f"{raw_subj} {raw_body}"

        # 1. Quarantine check: Mbox internal folder metadata delimiter
        if self._MBOX_MARKER_REGEX.search(combined_check):
            return SanitizedRecordResult(
                original_text=raw_body,
                cleaned_text="",
                is_quarantined=True,
                quarantine_reason="mbox_metadata_folder_header",
                char_count_original=len(raw_body),
                char_count_cleaned=0,
                word_count_original=len(raw_body.split()),
                word_count_cleaned=0,
                flags=["quarantine:mbox_metadata"],
            )

        # 2. Quarantine check: Extreme base64 payload attachment (e.g. > 500,000 chars)
        if len(raw_body) > 500_000 and (self._BASE64_BLOCK_REGEX.search(raw_body) or "base64" in raw_body.lower()):
            return SanitizedRecordResult(
                original_text=raw_body,
                cleaned_text="",
                is_quarantined=True,
                quarantine_reason="extreme_base64_attachment_outlier",
                char_count_original=len(raw_body),
                char_count_cleaned=0,
                word_count_original=len(raw_body.split()),
                word_count_cleaned=0,
                flags=["quarantine:base64_payload_outlier"],
            )

        # 3. Clean valid body using general-purpose cleaner
        cleaned = self.cleaner.clean(raw_body)

        flags = []
        # In the multi-source primary corpus, authentic visible lures ('monkey.org support team', 'all monkey.org users')
        # are preserved intact. We record an audit flag rather than destructively mutating lure syntax.
        if "monkey.org" in cleaned.lower():
            flags.append("audit:recipient_domain_personalization_present")
        elif "monkey.org" in raw_body.lower():
            flags.append("audit:recipient_domain_email_or_url_handled")

        if strip_collector_domain and self._COLLECTOR_DOMAIN_REGEX.search(cleaned):
            cleaned = self._COLLECTOR_DOMAIN_REGEX.sub("", cleaned)
            cleaned = re.sub(r"[ \t]+", " ", cleaned).strip()
            flags.append("sanitized:collector_domain_stripped")

        return SanitizedRecordResult(
            original_text=raw_body,
            cleaned_text=cleaned,
            is_quarantined=False,
            quarantine_reason=None,
            char_count_original=len(raw_body),
            char_count_cleaned=len(cleaned),
            word_count_original=len(raw_body.split()),
            word_count_cleaned=len(cleaned.split()),
            flags=flags,
        )

    def sanitize_phishing_pot_record(
        self,
        record: str | dict[str, Any],
        body_col: str = "body",
        strip_honeypot_decoys: bool = True,
    ) -> SanitizedRecordResult:
        """
        Sanitize a record from Phishing Pot (honeypot emails).

        Cleans MIME/HTML email and scrubs non-standard honeypot decoy addresses
        (such as 'phishing@pot' or user@pot lacking standard dot-TLDs) while
        strictly preserving genuine natural-language phishing body content.
        """
        if isinstance(record, dict):
            raw_text = str(record.get(body_col, "") or "")
        else:
            raw_text = str(record or "")

        flags = []
        cleaned = self.cleaner.clean(raw_text)

        if strip_honeypot_decoys and self._HONEYPOT_DECOY_REGEX.search(cleaned):
            cleaned = self._HONEYPOT_DECOY_REGEX.sub("", cleaned)
            cleaned = re.sub(r"[ \t]+", " ", cleaned).strip()
            flags.append("sanitized:honeypot_decoy_stripped")
        elif self._HONEYPOT_DECOY_REGEX.search(raw_text):
            flags.append("sanitized:honeypot_decoy_stripped")

        return SanitizedRecordResult(
            original_text=raw_text,
            cleaned_text=cleaned,
            is_quarantined=False,
            quarantine_reason=None,
            char_count_original=len(raw_text),
            char_count_cleaned=len(cleaned),
            word_count_original=len(raw_text.split()),
            word_count_cleaned=len(cleaned.split()),
            flags=flags,
        )

    def sanitize_enron_record(
        self,
        row: dict[str, Any],
        body_col: str = "body",
        strip_forwarding_headers: bool = True,
    ) -> SanitizedRecordResult:
        """
        Sanitize a record from Enron.csv.

        Normalizes space-padded punctuation artifacts and optionally strips
        internal Lotus Notes forwarded routing header blocks while preserving
        meaningful natural language and corporate terms (such as 'enron').
        """
        raw_body = str(row.get(body_col, "") or "")
        text = raw_body
        flags = []

        # 1. Optionally strip internal forwarded header lines
        if strip_forwarding_headers and self._ENRON_FORWARDED_HEADER_REGEX.search(text):
            text = self._ENRON_FORWARDED_HEADER_REGEX.sub("", text)
            flags.append("sanitized:forwarded_header_stripped")

        # 2. Clean with general-purpose cleaner (which handles punctuation spacing normalization)
        cleaned = self.cleaner.clean(text)

        if "enron" in cleaned.lower():
            flags.append("retained:enron_term")
        if re.search(r"\bect\b", cleaned, re.IGNORECASE):
            flags.append("retained:ect_term")

        return SanitizedRecordResult(
            original_text=raw_body,
            cleaned_text=cleaned,
            is_quarantined=False,
            quarantine_reason=None,
            char_count_original=len(raw_body),
            char_count_cleaned=len(cleaned),
            word_count_original=len(raw_body.split()),
            word_count_cleaned=len(cleaned.split()),
            flags=flags,
        )

    def sanitize_spamassassin_record(
        self,
        row: dict[str, Any],
        body_col: str = "body",
        strip_mailman_footers: bool = True,
    ) -> SanitizedRecordResult:
        """
        Sanitize a record from SpamAssasin.csv.

        Detects and strips Mailman mailing-list unsubscription footer blocks
        while strictly preserving legitimate technical language (including 'linux').
        """
        raw_body = str(row.get(body_col, "") or "")
        text = raw_body
        flags = []

        # 1. Detect and strip Mailman footer block
        if strip_mailman_footers and self._SA_MAILMAN_FOOTER_REGEX.search(text):
            text = self._SA_MAILMAN_FOOTER_REGEX.sub("", text)
            flags.append("sanitized:mailman_footer_stripped")

        # 2. Clean with general-purpose cleaner
        cleaned = self.cleaner.clean(text)

        if re.search(r"\blinux\b", cleaned, re.IGNORECASE):
            flags.append("retained:linux_term")

        return SanitizedRecordResult(
            original_text=raw_body,
            cleaned_text=cleaned,
            is_quarantined=False,
            quarantine_reason=None,
            char_count_original=len(raw_body),
            char_count_cleaned=len(cleaned),
            word_count_original=len(raw_body.split()),
            word_count_cleaned=len(cleaned.split()),
            flags=flags,
        )

