"""SQL for history, dashboard and feedback.

Every query is parameterized (values are always bound, never concatenated). WHERE fragments
are fixed strings chosen in code, never built from user input.

`Execute` is a function (sql, params) -> list of dict rows. In production it wraps a
SQLAlchemy session (`session_runner`); tests run the SAME SQL on a plain sqlite3 connection.
Every query is scoped by user_id: a user can only ever see their own scans.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

Execute = Callable[[str, Mapping[str, Any]], List[Dict[str, Any]]]

_ESC = "ESCAPE '\\'"            # renders as: ESCAPE '\'
_LIST_COLUMNS = (
    "scan_id, scanned_at, subject, sender_address, sender_domain, "
    "threat_score, risk_tier, inference_ms"
)


def session_runner(session) -> Execute:
    """Adapt a SQLAlchemy session to `Execute`. The caller commits writes."""
    from sqlalchemy import text

    def run(sql: str, params: Mapping[str, Any]) -> List[Dict[str, Any]]:
        result = session.execute(text(sql), dict(params))
        return [dict(row._mapping) for row in result] if result.returns_rows else []

    return run


def _where(user_id: int, since: Optional[str], tier: Optional[str], pattern: Optional[str]
           ) -> Tuple[str, Dict[str, Any]]:
    clauses = ["user_id = :user_id"]
    params: Dict[str, Any] = {"user_id": user_id}
    if since:
        clauses.append("scanned_at >= :since")
        params["since"] = since
    if tier:
        clauses.append("risk_tier = :tier")
        params["tier"] = tier
    if pattern:
        clauses.append(
            "(lower(coalesce(subject, '')) LIKE :pat " + _ESC +
            " OR lower(coalesce(sender_address, '')) LIKE :pat " + _ESC +
            " OR lower(coalesce(sender_domain, '')) LIKE :pat " + _ESC + ")"
        )
        params["pat"] = pattern
    return " AND ".join(clauses), params


def list_scans(execute: Execute, user_id: int, since: Optional[str], tier: Optional[str],
               pattern: Optional[str], limit: int, offset: int) -> Tuple[List[Dict[str, Any]], int]:
    where, params = _where(user_id, since, tier, pattern)
    total = execute(f"SELECT COUNT(*) AS n FROM scans WHERE {where}", params)[0]["n"]
    rows = execute(
        f"SELECT {_LIST_COLUMNS} FROM scans WHERE {where} "
        "ORDER BY scanned_at DESC, scan_id DESC LIMIT :limit OFFSET :offset",
        {**params, "limit": limit, "offset": offset},
    )
    return rows, total


def export_rows(execute: Execute, user_id: int, since: Optional[str], tier: Optional[str],
                pattern: Optional[str], max_rows: int) -> List[Dict[str, Any]]:
    where, params = _where(user_id, since, tier, pattern)
    return execute(
        f"SELECT {_LIST_COLUMNS} FROM scans WHERE {where} "
        "ORDER BY scanned_at DESC, scan_id DESC LIMIT :limit",
        {**params, "limit": max_rows},
    )


def get_scan(execute: Execute, user_id: int, scan_id: int) -> Optional[Dict[str, Any]]:
    rows = execute(
        "SELECT s.scan_id, s.scanned_at, s.subject, s.sender_address, s.sender_domain, "
        "s.return_path_domain, s.spf_result, s.dkim_result, s.dmarc_result, s.url_count, "
        "s.malicious_probability, s.threat_score, s.risk_tier, s.shap_base_value, "
        "s.inference_ms, s.file_name, s.input_method, m.version_tag "
        "FROM scans s JOIN model_versions m ON m.model_version_id = s.model_version_id "
        "WHERE s.scan_id = :scan_id AND s.user_id = :user_id",
        {"scan_id": scan_id, "user_id": user_id},
    )
    return rows[0] if rows else None


def scan_urls(execute: Execute, scan_id: int) -> List[Dict[str, Any]]:
    return execute(
        "SELECT url_defanged, domain, has_ip_address, uses_shortener, has_at_symbol, "
        "is_https, is_suspicious FROM extracted_urls WHERE scan_id = :scan_id "
        "ORDER BY position_in_mail",
        {"scan_id": scan_id},
    )


def scan_words(execute: Execute, scan_id: int) -> List[Dict[str, Any]]:
    return execute(
        "SELECT abs_rank, token, contribution, direction, tfidf_value, insight_type, "
        "insight_title, insight_message FROM scan_token_contributions "
        "WHERE scan_id = :scan_id ORDER BY abs_rank",
        {"scan_id": scan_id},
    )


def scan_indicator_values(execute: Execute, scan_id: int) -> Dict[str, float]:
    rows = execute(
        "SELECT f.feature_key, sf.raw_value FROM scan_features sf "
        "JOIN feature_definitions f ON f.feature_id = sf.feature_id WHERE sf.scan_id = :scan_id",
        {"scan_id": scan_id},
    )
    return {r["feature_key"]: r["raw_value"] for r in rows}


def get_feedback(execute: Execute, user_id: int, scan_id: int) -> Optional[Dict[str, Any]]:
    rows = execute(
        "SELECT is_prediction_correct, suggested_label, explanation_helpful, comment, created_at "
        "FROM scan_feedback WHERE scan_id = :scan_id AND user_id = :user_id",
        {"scan_id": scan_id, "user_id": user_id},
    )
    return rows[0] if rows else None


def tier_stats(execute: Execute, user_id: int, since: Optional[str]) -> List[Dict[str, Any]]:
    where, params = _where(user_id, since, None, None)
    return execute(
        "SELECT risk_tier, COUNT(*) AS n, SUM(inference_ms) AS ms_sum, COUNT(inference_ms) AS ms_n "
        f"FROM scans WHERE {where} GROUP BY risk_tier",
        params,
    )


def trend_rows(execute: Execute, user_id: int, since: Optional[str], width: int) -> List[Dict[str, Any]]:
    """`width` = 10 for day buckets ('YYYY-MM-DD'), 7 for month buckets ('YYYY-MM')."""
    where, params = _where(user_id, since, None, None)
    return execute(
        "SELECT substr(scanned_at, 1, :width) AS bucket, risk_tier, COUNT(*) AS n "
        f"FROM scans WHERE {where} GROUP BY bucket, risk_tier ORDER BY bucket",
        {**params, "width": width},
    )


def upsert_feedback(execute: Execute, *, scan_id: int, user_id: int, correct: int,
                    label: Optional[str], helpful: Optional[int], comment: Optional[str],
                    now: str) -> None:
    execute(
        "INSERT INTO scan_feedback (scan_id, user_id, is_prediction_correct, suggested_label, "
        "explanation_helpful, comment, created_at) "
        "VALUES (:scan_id, :user_id, :correct, :label, :helpful, :comment, :now) "
        "ON CONFLICT (scan_id, user_id) DO UPDATE SET "
        "is_prediction_correct = excluded.is_prediction_correct, "
        "suggested_label = excluded.suggested_label, "
        "explanation_helpful = excluded.explanation_helpful, "
        "comment = excluded.comment, created_at = excluded.created_at",
        {"scan_id": scan_id, "user_id": user_id, "correct": correct, "label": label,
         "helpful": helpful, "comment": comment, "now": now},
    )
