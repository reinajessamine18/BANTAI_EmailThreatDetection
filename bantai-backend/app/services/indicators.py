"""Rule-based indicators from the parsed email (headers, URLs, text habits).

These are NOT inputs to the XGBoost model (it only sees TF-IDF word weights). They are
transparent, human-checkable findings that are shown beside the model's result and
stored in `scan_features`. They never change the threat score.

All thresholds below are ASSUMED starter values, not validated against data; adjust
after evaluation. Known limitations:
* SPF/DKIM/DMARC are read from headers inside the submitted file and can be forged.
* An explicit failure counts; a MISSING result is treated as "unknown", not failure
  (a pasted body has no Authentication-Results header at all).
* Legitimate mailing services often use a different Return-Path domain, so
  `sender_domain_mismatch` has false positives.
* `free_mail_sender` is stored but never surfaced alone: ordinary personal mail would
  be flagged. `url_redirect_count`, `sentiment_score` and `html_to_text_ratio` are not
  computed (inactive in the catalog).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Mapping, Tuple

from app.services.catalog import ScoringCatalog

_FAIL_RESULTS = frozenset({"fail", "softfail", "permerror"})
FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "gmx.com", "mail.com", "yandex.com", "zoho.com",
})

# Minimum value for an indicator to be shown. Binary indicators and anything not listed: 1.
TRIGGER_MIN: Dict[str, float] = {
    "url_count": 10,
    "max_url_length": 100,
    "url_subdomain_count": 3,
    "urgency_keyword_count": 2,
    "credential_request_count": 2,
    "exclamation_count": 3,
    "uppercase_ratio": 0.30,
}
RECORD_ONLY = frozenset({"free_mail_sender"})
MIN_LETTERS_FOR_CAPS_RATIO = 20   # shorter texts give a meaningless ratio

_WORD_RE = re.compile(r"\b\w\w+\b")   # same token pattern as the TF-IDF vectorizer
_GREETING_RE = re.compile(
    r"^\s*(dear|hello|hi)\s+(customer|user|member|client|sir|madam|sir/madam|account\s+holder|"
    r"valued\s+\w+|friend)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class IndicatorFinding:
    feature_id: int
    feature_key: str
    category: str
    value: float
    insight_type: str
    title: str
    message: str


def _related(a: str, b: str) -> bool:
    """Same domain, or one is a subdomain of the other."""
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _differs(a, b) -> float:
    return 1.0 if a and b and not _related(a, b) else 0.0


def compute_indicator_values(parsed, lexicons: Mapping[str, frozenset]) -> Dict[str, float]:
    """Raw value for each computable indicator (always all 20 keys)."""
    urls = parsed.urls
    text = f"{parsed.subject or ''}\n{parsed.body_text}"
    words = _WORD_RE.findall(text.lower())

    letters = [c for c in text if c.isalpha()]
    if len(letters) >= MIN_LETTERS_FOR_CAPS_RATIO:
        caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
    else:
        caps_ratio = 0.0

    def keyword_count(feature_key: str) -> float:
        lexicon = lexicons.get(feature_key, frozenset())
        return float(sum(1 for w in words if w in lexicon))

    return {
        # header
        "sender_domain_mismatch": _differs(parsed.sender_domain, parsed.return_path_domain),
        "spf_fail": 1.0 if parsed.spf_result in _FAIL_RESULTS else 0.0,
        "dkim_fail": 1.0 if parsed.dkim_result in _FAIL_RESULTS else 0.0,
        "dmarc_fail": 1.0 if parsed.dmarc_result in _FAIL_RESULTS else 0.0,
        "reply_to_mismatch": _differs(parsed.sender_domain, parsed.reply_to_domain),
        "free_mail_sender": 1.0 if parsed.sender_domain in FREE_MAIL_DOMAINS else 0.0,
        # url
        "url_count": float(parsed.url_count),
        "max_url_length": float(max((u.url_length for u in urls), default=0)),
        "has_ip_url": 1.0 if any(u.has_ip_address for u in urls) else 0.0,
        "uses_url_shortener": 1.0 if any(u.uses_shortener for u in urls) else 0.0,
        "url_has_at_symbol": 1.0 if any(u.has_at_symbol for u in urls) else 0.0,
        "url_subdomain_count": float(max((u.subdomain_count for u in urls), default=0)),
        "non_https_url": 1.0 if any(not u.is_https for u in urls) else 0.0,
        "link_text_mismatch": 1.0 if any(u.link_text_mismatch for u in urls) else 0.0,
        # text
        "urgency_keyword_count": keyword_count("urgency_keyword_count"),
        "credential_request_count": keyword_count("credential_request_count"),
        "exclamation_count": float(text.count("!")),
        "uppercase_ratio": round(caps_ratio, 4),
        "generic_greeting": 1.0 if _GREETING_RE.match(parsed.body_text[:200]) else 0.0,
        "attachment_count": float(parsed.attachment_count),
    }


def surface_indicators(
    values: Mapping[str, float], catalog: ScoringCatalog
) -> Tuple[IndicatorFinding, ...]:
    """The indicators worth showing the user, in catalog order, with their educational text."""
    findings = []
    for key, value in values.items():
        feature = catalog.features.get(key)
        if feature is None or key in RECORD_ONLY:
            continue
        if value >= TRIGGER_MIN.get(key, 1):
            findings.append(
                IndicatorFinding(
                    feature_id=feature.feature_id,
                    feature_key=key,
                    category=feature.category,
                    value=float(value),
                    insight_type=feature.insight_type,
                    title=feature.title,
                    message=feature.template,
                )
            )
    findings.sort(key=lambda f: f.feature_id)
    return tuple(findings)
