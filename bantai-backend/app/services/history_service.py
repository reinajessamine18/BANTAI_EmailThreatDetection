"""History, scan detail, dashboard and feedback (composes history_repo + pure helpers).

All functions take an `Execute` runner and a `user_id`; every query is scoped to that user.
A scan that belongs to someone else is indistinguishable from one that does not exist.
The email body was never stored, so detail views return `emailBody: null`.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from app.services import history_repo as repo
from app.services.catalog import ScoringCatalog
from app.services.history_filters import (
    TIER_LABEL,
    assemble_trend,
    build_csv,
    level_to_tier,
    like_pattern,
    range_start,
)
from app.services.indicators import surface_indicators
from app.services.scan_result import SHAP_NOTE, indicator_item, word_item
from app.services.threat_scoring import ui_risk_level

EXPORT_MAX_ROWS = 10_000
RECENT_COUNT = 5
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def history_item(row: Dict[str, Any]) -> Dict[str, Any]:
    tier = row["risk_tier"]
    return {
        "id": row["scan_id"],
        "scanCode": f"BNT-{row['scan_id']:04d}",
        "date": row["scanned_at"],
        "subject": row["subject"] or "(no subject)",
        "email": row["sender_address"] or row["sender_domain"] or "",
        "threatLevel": ui_risk_level(tier),
        "classification": TIER_LABEL[tier],
        "result": f"{TIER_LABEL[tier]} ({row['threat_score']}/100)",
        "threatScore": row["threat_score"],
        "riskTier": tier,
        "inferenceMs": row["inference_ms"],
    }


def list_history(execute, user_id: int, *, q: Optional[str], level: str, date_range: str,
                 limit: int, offset: int, now: datetime) -> Dict[str, Any]:
    rows, total = repo.list_scans(
        execute, user_id, range_start(date_range, now), level_to_tier(level),
        like_pattern(q), limit, offset,
    )
    return {"items": [history_item(r) for r in rows], "total": total, "limit": limit, "offset": offset}


def export_history_csv(execute, user_id: int, *, q: Optional[str], level: str, date_range: str,
                       now: datetime) -> Tuple[str, int]:
    rows = repo.export_rows(
        execute, user_id, range_start(date_range, now), level_to_tier(level),
        like_pattern(q), EXPORT_MAX_ROWS,
    )
    return build_csv(rows), len(rows)


def _feedback_dict(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    helpful = row["explanation_helpful"]
    return {
        "isPredictionCorrect": bool(row["is_prediction_correct"]),
        "suggestedLabel": row["suggested_label"],
        "explanationHelpful": None if helpful is None else bool(helpful),
        "comment": row["comment"],
        "createdAt": row["created_at"],
    }


def scan_detail(execute, user_id: int, scan_id: int, catalog: ScoringCatalog) -> Optional[Dict[str, Any]]:
    scan = repo.get_scan(execute, user_id, scan_id)
    if scan is None:
        return None
    words = repo.scan_words(execute, scan_id)
    urls = repo.scan_urls(execute, scan_id)
    values = repo.scan_indicator_values(execute, scan_id)
    probability = scan["malicious_probability"]
    tier = scan["risk_tier"]

    explanations = [
        word_item(
            w["abs_rank"], w["token"], w["insight_title"] or "Wording signal",
            w["insight_message"] or "", w["insight_type"] or "Educational Insight",
            w["direction"], w["contribution"],
        )
        for w in words
    ] + [
        indicator_item(f.feature_key, f.category, f.title, f.message, f.insight_type, f.value)
        for f in surface_indicators(values, catalog)     # current thresholds, stored values
    ]

    is_content_only = bool(scan.get("version_tag") and "candidate-v2" in scan["version_tag"])

    return {
        "scanId": scan["scan_id"],
        "scanCode": f"BNT-{scan['scan_id']:04d}",
        "pipeline": "content_only" if is_content_only else "multimodal",
        "saved": True,
        "riskLevel": ui_risk_level(tier),
        "riskTier": tier,
        "threatScore": scan["threat_score"],
        "phishingProbability": probability,
        "safeProbability": round(1.0 - probability, 4) if probability is not None else None,
        "modelClassification": "Phishing" if probability >= 0.5 else ("Legitimate" if is_content_only else "Safe"),
        "decisionThreshold": 0.5,
        "explanations": explanations,
        "shap": {"baseValue": scan["shap_base_value"], "rawMargin": None, "unit": "log-odds", "note": SHAP_NOTE},
        "links": [
            {
                "url": u["url_defanged"], "domain": u["domain"], "suspicious": bool(u["is_suspicious"]),
                "ipAddress": bool(u["has_ip_address"]), "shortener": bool(u["uses_shortener"]),
                "atSymbol": bool(u["has_at_symbol"]), "https": bool(u["is_https"]),
            }
            for u in urls
        ],
        "linkCount": scan["url_count"],
        "auth": {"spf": scan["spf_result"], "dkim": scan["dkim_result"], "dmarc": scan["dmarc_result"]},
        "fileName": scan["file_name"],
        "scannedAt": scan["scanned_at"],
        "inferenceTimeMs": scan["inference_ms"],
        "sender": scan["sender_address"],
        "subject": scan["subject"],
        "emailBody": None,                 # never stored
        "emailBodyStored": False,
        "modelVersion": scan["version_tag"],
        "feedback": _feedback_dict(repo.get_feedback(execute, user_id, scan_id)),
    }


# ------------------------------------------------------------------------ dashboard
def dashboard_summary(execute, user_id: int, date_range: str, now: datetime) -> Dict[str, Any]:
    since = range_start(date_range, now)

    counts = {"Low": 0, "Medium": 0, "Critical": 0}
    ms_sum = ms_n = 0
    for row in repo.tier_stats(execute, user_id, since):
        counts[row["risk_tier"]] = row["n"]
        ms_sum += row["ms_sum"] or 0
        ms_n += row["ms_n"] or 0

    granularity, width = ("day", 10) if date_range in ("7", "30") else ("month", 7)
    rows = repo.trend_rows(execute, user_id, since, width)
    if date_range in ("7", "30"):
        first = since[:10]
    elif date_range == "year":
        first = f"{now.year:04d}-01"
    else:                                              # all time: from the first month with data
        first = rows[0]["bucket"] if rows else None
    last = now.strftime("%Y-%m-%d" if granularity == "day" else "%Y-%m")

    recent, _ = repo.list_scans(execute, user_id, None, None, None, RECENT_COUNT, 0)
    return {
        "range": date_range,
        "metrics": {
            "totalScanned": sum(counts.values()),
            "phishingBlocked": counts["Critical"],      # tier Critical = classified as phishing
            "suspicious": counts["Medium"],
            "safeEmails": counts["Low"],
            "avgInferenceMs": round(ms_sum / ms_n, 1) if ms_n else None,
        },
        "riskDistribution": {"safe": counts["Low"], "suspicious": counts["Medium"], "phishing": counts["Critical"]},
        "trend": {"granularity": granularity, "points": assemble_trend(rows, granularity, first, last)},
        "recent": [history_item(r) for r in recent],
    }


# ------------------------------------------------------------------------ feedback
def normalize_feedback(*, correct: bool, label: Optional[str], helpful: Optional[bool],
                       comment: Optional[str]) -> Dict[str, Any]:
    """A suggested label only makes sense when the prediction was wrong; comments are one clean line."""
    cleaned = _CONTROL.sub(" ", comment or "").strip()[:1000]
    return {
        "correct": 1 if correct else 0,
        "label": None if correct else label,
        "helpful": None if helpful is None else (1 if helpful else 0),
        "comment": cleaned or None,
    }


def submit_feedback(execute, user_id: int, scan_id: int, *, correct: bool, label: Optional[str],
                    helpful: Optional[bool], comment: Optional[str], now: str) -> Optional[Dict[str, Any]]:
    if repo.get_scan(execute, user_id, scan_id) is None:
        return None
    fields = normalize_feedback(correct=correct, label=label, helpful=helpful, comment=comment)
    repo.upsert_feedback(execute, scan_id=scan_id, user_id=user_id, now=now, **fields)
    return _feedback_dict(repo.get_feedback(execute, user_id, scan_id))
