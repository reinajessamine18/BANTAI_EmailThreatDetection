"""Pure helpers for history / dashboard / CSV export (no database, no web framework)."""

from __future__ import annotations

import csv
import io
from datetime import date, datetime, timedelta, timezone
from typing import Dict, Iterable, List, Mapping, Optional

RANGES = ("7", "30", "year", "all")
LEVELS = ("all", "safe", "suspicious", "phishing")

_LEVEL_TO_TIER = {"safe": "Low", "suspicious": "Medium", "phishing": "Critical"}
TIER_LABEL = {"Low": "Safe", "Medium": "Suspicious", "Critical": "Phishing"}
_TIER_BUCKET = {"Low": "safe", "Medium": "suspicious", "Critical": "phishing"}

MAX_TREND_BUCKETS = 120
_CSV_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def range_start(range_key: str, now: datetime) -> Optional[str]:
    """Earliest `scanned_at` (ISO text, comparable as a string) for a UI date filter.

    '7' / '30' = the last N days; 'year' = since 1 Jan of the current year (UTC); 'all' = no limit.
    """
    if range_key == "all":
        return None
    if range_key in ("7", "30"):
        return _iso(now - timedelta(days=int(range_key)))
    if range_key == "year":
        return _iso(datetime(now.year, 1, 1, tzinfo=timezone.utc))
    raise ValueError(f"unknown date range: {range_key!r}")


def level_to_tier(level: str) -> Optional[str]:
    """UI threat filter ('safe'/'suspicious'/'phishing') -> risk tier; 'all' -> None."""
    if level == "all":
        return None
    try:
        return _LEVEL_TO_TIER[level]
    except KeyError:
        raise ValueError(f"unknown threat level: {level!r}") from None


def like_pattern(query: Optional[str]) -> Optional[str]:
    """Lower-cased `%query%` pattern with LIKE wildcards escaped (use with ESCAPE '\\')."""
    text = (query or "").strip().lower()[:100]
    if not text:
        return None
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


# ----------------------------------------------------------------------------- CSV
def csv_safe(value: object) -> str:
    """Neutralize spreadsheet formula injection: subjects are attacker-controlled text."""
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text.startswith(_CSV_FORMULA_STARTS) else text


CSV_HEADER = ["Scan ID", "Scanned At (UTC)", "Subject", "Sender", "Sender Domain",
              "Threat Level", "Risk Tier", "Threat Score", "Inference (ms)"]


def build_csv(rows: Iterable[Mapping[str, object]]) -> str:
    """CSV text for `rows` (history rows). Starts with a UTF-8 BOM so Excel reads it correctly."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_HEADER)
    for row in rows:
        tier = str(row["risk_tier"])
        writer.writerow([
            f"BNT-{int(row['scan_id']):04d}",
            csv_safe(row["scanned_at"]),
            csv_safe(row["subject"]),
            csv_safe(row["sender_address"]),
            csv_safe(row["sender_domain"]),
            TIER_LABEL.get(tier, tier),
            tier,
            row["threat_score"],
            "" if row["inference_ms"] is None else row["inference_ms"],
        ])
    return "\ufeff" + buffer.getvalue()


# --------------------------------------------------------------------------- trend
def _bucket_keys(granularity: str, first: str, last: str) -> List[str]:
    keys: List[str] = []
    if granularity == "day":
        day, end = date.fromisoformat(first), date.fromisoformat(last)
        while day <= end:
            keys.append(day.isoformat())
            day += timedelta(days=1)
    elif granularity == "month":
        year, month = int(first[:4]), int(first[5:7])
        end_year, end_month = int(last[:4]), int(last[5:7])
        while (year, month) <= (end_year, end_month):
            keys.append(f"{year:04d}-{month:02d}")
            month += 1
            if month == 13:
                year, month = year + 1, 1
    else:
        raise ValueError(f"unknown granularity: {granularity!r}")
    return keys[-MAX_TREND_BUCKETS:]


def assemble_trend(
    rows: Iterable[Mapping[str, object]],
    granularity: str,
    first_bucket: Optional[str],
    last_bucket: str,
) -> List[Dict[str, object]]:
    """Continuous time series with zero-filled gaps.

    `rows` are {bucket, risk_tier, n}; buckets are 'YYYY-MM-DD' (day) or 'YYYY-MM' (month).
    """
    if first_bucket is None or first_bucket > last_bucket:
        return []
    points = {
        key: {"bucket": key, "total": 0, "safe": 0, "suspicious": 0, "phishing": 0}
        for key in _bucket_keys(granularity, first_bucket, last_bucket)
    }
    for row in rows:
        point = points.get(str(row["bucket"]))
        name = _TIER_BUCKET.get(str(row["risk_tier"]))
        if point is None or name is None:
            continue
        point[name] += int(row["n"])
        point["total"] += int(row["n"])
    return list(points.values())
