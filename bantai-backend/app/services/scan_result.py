"""Build the JSON the React screens read (pure; camelCase to match the frontend).

Field names follow AnalysisResults.jsx: riskLevel, threatScore, explanations[{title,
value, insight}], fileName, scannedAt, inferenceTimeMs, sender, subject, emailBody.

`value` on a word explanation is the raw SHAP contribution in LOG-ODDS units (not a
percentage). Rule-based indicators have no SHAP value (`value` is null) and carry
`observed`, the measured number (e.g. link count).

`emailBody` is the sanitized plain text, returned only to the person who submitted it.
It must never be stored or logged; the route sends Cache-Control: no-store.
"""

from __future__ import annotations

from typing import Dict, Optional

SHAP_NOTE = (
    "Values are the model's raw log-odds contributions. They explain how this model "
    "reached its estimate, not whether the email is truly malicious."
)


def word_item(rank, token, title, insight, insight_type, direction, value) -> Dict[str, object]:
    """One SHAP-word explanation as the frontend renders it (`value` is raw log-odds)."""
    return {
        "kind": "word",
        "rank": rank,
        "feature": token,
        "title": title,
        "insight": insight,
        "insightType": insight_type,
        "direction": direction,
        "value": value,
    }


def indicator_item(feature_key, category, title, insight, insight_type, observed) -> Dict[str, object]:
    """One rule-based indicator (no SHAP value; `observed` is the measured number)."""
    return {
        "kind": "indicator",
        "feature": feature_key,
        "category": category,
        "title": title,
        "insight": insight,
        "insightType": insight_type,
        "value": None,
        "observed": observed,
    }


def build_scan_payload(
    *,
    parsed,
    assessment,
    scan_id: Optional[int],
    file_name: Optional[str],
    scanned_at: str,
    inference_ms: int,
    model_version: str,
) -> Dict[str, object]:
    explanations = [
        word_item(e.rank, e.token, e.title, e.message, e.insight_type, e.direction, e.contribution)
        for e in assessment.token_explanations
    ] + [
        indicator_item(f.feature_key, f.category, f.title, f.message, f.insight_type, f.value)
        for f in assessment.indicators
    ]

    return {
        "scanId": scan_id,
        "scanCode": f"BNT-{scan_id:04d}" if scan_id is not None else None,
        "saved": scan_id is not None,
        "riskLevel": assessment.risk_level,
        "riskTier": assessment.risk_tier,
        "threatScore": assessment.threat_score,
        "phishingProbability": assessment.phishing_probability,
        "modelClassification": assessment.model_classification,
        "explanations": explanations,
        "shap": {
            "baseValue": assessment.shap_base_value,
            "rawMargin": assessment.raw_margin,
            "unit": "log-odds",
            "note": SHAP_NOTE,
        },
        "links": [
            {
                "url": u.url_defanged,
                "domain": u.domain,
                "suspicious": u.is_suspicious,
                "ipAddress": u.has_ip_address,
                "shortener": u.uses_shortener,
                "atSymbol": u.has_at_symbol,
                "https": u.is_https,
                "textMismatch": u.link_text_mismatch,
            }
            for u in parsed.urls
        ],
        "linkCount": parsed.url_count,
        "linksTruncated": parsed.urls_truncated,
        "auth": {"spf": parsed.spf_result, "dkim": parsed.dkim_result, "dmarc": parsed.dmarc_result},
        "fileName": file_name,
        "scannedAt": scanned_at,
        "inferenceTimeMs": inference_ms,
        "sender": parsed.sender_address,
        "subject": parsed.subject,
        "emailBody": parsed.body_text,
        "modelVersion": model_version,
    }
