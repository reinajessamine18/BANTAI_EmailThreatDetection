from datetime import datetime, timezone

import pytest

from app.services.history_filters import (
    MAX_TREND_BUCKETS, assemble_trend, build_csv, csv_safe, level_to_tier, like_pattern, range_start,
)

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("key,expected", [
    ("all", None), ("7", "2026-10-06T12:00:00Z"), ("30", "2026-09-13T12:00:00Z"), ("year", "2026-01-01T00:00:00Z"),
])
def test_range_start(key, expected):
    assert range_start(key, NOW) == expected


def test_range_start_rejects_unknown():
    with pytest.raises(ValueError):
        range_start("90", NOW)


@pytest.mark.parametrize("level,tier", [("all", None), ("safe", "Low"), ("suspicious", "Medium"), ("phishing", "Critical")])
def test_level_to_tier(level, tier):
    assert level_to_tier(level) == tier


def test_level_to_tier_rejects_unknown():
    with pytest.raises(ValueError):
        level_to_tier("high")


@pytest.mark.parametrize("raw,pattern", [
    (None, None), ("", None), ("   ", None), ("PayPal", "%paypal%"),
    ("100%", "%100\\%%"), ("a_b", "%a\\_b%"), ("c:\\x", "%c:\\\\x%"),
])
def test_like_pattern_escapes_wildcards(raw, pattern):
    assert like_pattern(raw) == pattern


def test_like_pattern_is_length_capped():
    assert len(like_pattern("a" * 500)) == 102          # 100 chars + two %


@pytest.mark.parametrize("value,expected", [
    ("=HYPERLINK(\"http://evil\")", "'=HYPERLINK(\"http://evil\")"), ("+1", "'+1"), ("-2", "'-2"),
    ("@SUM(A1)", "'@SUM(A1)"), ("\tx", "'\tx"), ("normal", "normal"), ("", ""), (None, ""), (5, "5"),
])
def test_csv_safe_blocks_formula_injection(value, expected):
    assert csv_safe(value) == expected


def test_build_csv_has_bom_header_and_safe_cells():
    rows = [{"scan_id": 7, "scanned_at": "2026-10-13T09:00:00Z", "subject": "=cmd|' /C calc'!A0",
             "sender_address": "a@b.example", "sender_domain": "b.example", "threat_score": 92,
             "risk_tier": "Critical", "inference_ms": None}]
    text = build_csv(rows)
    lines = text.split("\r\n")
    assert text.startswith("\ufeffScan ID,")
    assert lines[1].startswith("BNT-0007,") and "'=cmd" in lines[1] and "Phishing,Critical,92," in lines[1]
    assert build_csv([]).count("\r\n") == 1


def test_assemble_trend_fills_gaps_by_day():
    rows = [{"bucket": "2026-10-12", "risk_tier": "Low", "n": 2}, {"bucket": "2026-10-12", "risk_tier": "Critical", "n": 1},
            {"bucket": "2026-10-13", "risk_tier": "Medium", "n": 4}, {"bucket": "2020-01-01", "risk_tier": "Low", "n": 9}]
    pts = assemble_trend(rows, "day", "2026-10-11", "2026-10-13")
    assert [p["bucket"] for p in pts] == ["2026-10-11", "2026-10-12", "2026-10-13"]
    assert pts[0]["total"] == 0
    assert (pts[1]["safe"], pts[1]["phishing"], pts[1]["total"]) == (2, 1, 3)
    assert (pts[2]["suspicious"], pts[2]["total"]) == (4, 4)          # out-of-range rows ignored


def test_assemble_trend_months_across_a_year_boundary():
    pts = assemble_trend([], "month", "2025-11", "2026-02")
    assert [p["bucket"] for p in pts] == ["2025-11", "2025-12", "2026-01", "2026-02"]


def test_assemble_trend_empty_and_capped():
    assert assemble_trend([], "month", None, "2026-10") == []
    assert assemble_trend([], "day", "2026-10-14", "2026-10-13") == []
    assert len(assemble_trend([], "month", "1990-01", "2026-10")) == MAX_TREND_BUCKETS
    with pytest.raises(ValueError):
        assemble_trend([], "week", "2026-10-01", "2026-10-02")
