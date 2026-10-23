"""History / dashboard / feedback: the REAL SQL, run on a real SQLite database (no web stack needed)."""

import sqlite3
from datetime import datetime, timezone

import pytest

from app.db.init_db import init_db
from app.services import history_service as svc
from tests.helpers import SQL_DIR, real_catalog, seed_scan, seed_users, sqlite_runner

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
SECRET_OTHER = "SECRET other user"


def world(tmp_path):
    db = tmp_path / "h.db"
    init_db(db, SQL_DIR, None)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    seed_users(conn, 2)
    ids = {}
    for key, kw in {
        "a": dict(scanned_at="2026-10-13T09:00:00Z", tier="Critical", score=92, subject="URGENT verify your account",
                  sender="support@paypal-update.example", domain="paypal-update.example", inference_ms=50),
        "b": dict(scanned_at="2026-10-12T09:00:00Z", tier="Low", score=5, subject="Lunch tomorrow",
                  sender="ana@school.example", domain="school.example", inference_ms=30),
        "c": dict(scanned_at="2026-10-08T09:00:00Z", tier="Medium", score=55, subject="Invoice 100% due",
                  sender="billing@shop.example", domain="shop.example", inference_ms=40),
        "d": dict(scanned_at="2026-09-20T09:00:00Z", tier="Critical", score=88, subject="Reset your password"),
        "e": dict(scanned_at="2026-03-01T09:00:00Z", tier="Low", score=10, subject="Old mail"),
        "f": dict(scanned_at="2025-12-31T23:00:00Z", tier="Low", score=3, subject="Last year"),
    }.items():
        ids[key] = seed_scan(conn, user_id=1, **kw)
    ids["g"] = seed_scan(conn, user_id=2, scanned_at="2026-10-13T08:00:00Z", tier="Critical", score=99, subject=SECRET_OTHER)
    return conn, sqlite_runner(conn), ids


def listing(run, user=1, **kw):
    args = dict(q=None, level="all", date_range="all", limit=50, offset=0, now=NOW)
    args.update(kw)
    return svc.list_history(run, user, **args)


def test_user_sees_only_own_scans_newest_first(tmp_path):
    _, run, ids = world(tmp_path)
    out = listing(run)
    assert [i["id"] for i in out["items"]] == [ids[k] for k in "abcdef"] and out["total"] == 6
    assert SECRET_OTHER not in str(out)
    assert [i["id"] for i in listing(run, user=2)["items"]] == [ids["g"]]
    assert listing(run, user=99) == {"items": [], "total": 0, "limit": 50, "offset": 0}


def test_pagination(tmp_path):
    _, run, ids = world(tmp_path)
    out = listing(run, limit=2, offset=2)
    assert [i["id"] for i in out["items"]] == [ids["c"], ids["d"]] and out["total"] == 6


@pytest.mark.parametrize("level,keys", [("phishing", "ad"), ("suspicious", "c"), ("safe", "bef")])
def test_threat_level_filter(tmp_path, level, keys):
    _, run, ids = world(tmp_path)
    assert [i["id"] for i in listing(run, level=level)["items"]] == [ids[k] for k in keys]


@pytest.mark.parametrize("rng,keys", [("7", "abc"), ("30", "abcd"), ("year", "abcde"), ("all", "abcdef")])
def test_date_range_filter(tmp_path, rng, keys):
    _, run, ids = world(tmp_path)
    assert [i["id"] for i in listing(run, date_range=rng)["items"]] == [ids[k] for k in keys]


@pytest.mark.parametrize("query,keys", [
    ("paypal", "a"), ("LUNCH", "b"), ("school.example", "b"), ("100%", "c"), ("%", "c"), ("_", ""),
    ("' OR 1=1 --", ""), ("'; DROP TABLE scans; --", ""), ("nomatch", ""),
])
def test_search_is_literal_case_insensitive_and_injection_safe(tmp_path, query, keys):
    conn, run, ids = world(tmp_path)
    assert [i["id"] for i in listing(run, q=query)["items"]] == [ids[k] for k in keys]
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 7        # nothing was dropped


def test_filters_combine(tmp_path):
    _, run, ids = world(tmp_path)
    out = listing(run, q="password", level="phishing", date_range="30")
    assert [i["id"] for i in out["items"]] == [ids["d"]]


def test_history_item_shape_matches_what_the_frontend_renders(tmp_path):
    _, run, ids = world(tmp_path)
    item = listing(run)["items"][0]
    assert item["id"] == ids["a"] and item["scanCode"] == f"BNT-{ids['a']:04d}"
    assert item["date"] == "2026-10-13T09:00:00Z" and item["subject"] == "URGENT verify your account"
    assert item["email"] == "support@paypal-update.example"
    assert (item["threatLevel"], item["classification"], item["result"]) == ("phishing", "Phishing", "Phishing (92/100)")
    assert listing(run, level="safe")["items"][0]["threatLevel"] == "safe"


def test_missing_subject_and_sender_have_readable_fallbacks(tmp_path):
    conn, run, ids = world(tmp_path)
    conn.execute("UPDATE scans SET subject = NULL, sender_address = NULL WHERE scan_id = ?", (ids["a"],))
    item = listing(run)["items"][0]
    assert item["subject"] == "(no subject)" and item["email"] == "paypal-update.example"


# ----------------------------------------------------------------------------- export
def test_export_csv_is_scoped_filtered_and_formula_safe(tmp_path):
    conn, run, ids = world(tmp_path)
    seed_scan(conn, user_id=1, scanned_at="2026-10-13T10:00:00Z", tier="Low", score=1, subject='=HYPERLINK("http://evil")')
    text, count = svc.export_history_csv(run, 1, q=None, level="all", date_range="7", now=NOW)
    assert count == 4 and text.startswith("\ufeff") and SECRET_OTHER not in text
    assert "'=HYPERLINK" in text and ",=HYPERLINK" not in text
    only, n = svc.export_history_csv(run, 1, q=None, level="phishing", date_range="all", now=NOW)
    assert n == 2 and only.count("\r\n") == 3


# ----------------------------------------------------------------------------- detail
def add_children(conn, scan_id):
    conn.execute("INSERT INTO scan_token_contributions (scan_id, abs_rank, token, contribution, direction, tfidf_value,"
                 " insight_type, insight_title, insight_message) VALUES (?,1,'verify',1.2,'toward_phishing',0.2,"
                 " 'Educational Insight','Request for Sensitive Information','msg1'),"
                 " (?,2,'meeting',-0.4,'toward_safe',0.1,'Educational Insight','Wording that lowered the risk estimate','msg2')",
                 (scan_id, scan_id))
    conn.execute("INSERT INTO extracted_urls (scan_id, position_in_mail, url_defanged, domain, has_ip_address, is_suspicious)"
                 " VALUES (?,1,'hxxp://203[.]0[.]113[.]9/login','203.0.113.9',1,1)", (scan_id,))
    for key, value in (("spf_fail", 1.0), ("has_ip_url", 1.0), ("url_count", 1.0), ("dkim_fail", 0.0)):
        conn.execute("INSERT INTO scan_features (scan_id, feature_id, raw_value)"
                     " SELECT ?, feature_id, ? FROM feature_definitions WHERE feature_key = ?", (scan_id, value, key))
    conn.commit()


def test_detail_rebuilds_the_explanations_without_the_body(tmp_path):
    conn, run, ids = world(tmp_path)
    add_children(conn, ids["a"])
    d = svc.scan_detail(run, 1, ids["a"], real_catalog(tmp_path))
    assert (d["riskLevel"], d["threatScore"], d["modelClassification"]) == ("phishing", 92, "Phishing")
    assert d["emailBody"] is None and d["emailBodyStored"] is False and d["feedback"] is None
    kinds = [(e["kind"], e["feature"]) for e in d["explanations"]]
    assert kinds[:2] == [("word", "verify"), ("word", "meeting")]
    assert {("indicator", "spf_fail"), ("indicator", "has_ip_url")} <= set(kinds)
    assert ("indicator", "dkim_fail") not in kinds and ("indicator", "url_count") not in kinds   # 0 / below threshold
    assert d["explanations"][0]["value"] == 1.2 and d["explanations"][1]["direction"] == "toward_safe"
    assert d["links"][0]["ipAddress"] is True and d["modelVersion"] == "xgb-dev-0.0.0"
    assert d["sender"] == "support@paypal-update.example" and d["auth"]["spf"] == "fail"


def test_other_users_and_unknown_scans_are_not_found(tmp_path):
    _, run, ids = world(tmp_path)
    cat = real_catalog(tmp_path)
    assert svc.scan_detail(run, 1, ids["g"], cat) is None           # belongs to user 2
    assert svc.scan_detail(run, 2, ids["a"], cat) is None
    assert svc.scan_detail(run, 1, 99999, cat) is None


# --------------------------------------------------------------------------- dashboard
def test_dashboard_all_time(tmp_path):
    _, run, ids = world(tmp_path)
    s = svc.dashboard_summary(run, 1, "all", NOW)
    assert s["metrics"] == {"totalScanned": 6, "phishingBlocked": 2, "suspicious": 1, "safeEmails": 3,
                            "avgInferenceMs": round((50 + 30 + 40 + 40 + 40 + 40) / 6, 1)}
    assert s["riskDistribution"] == {"safe": 3, "suspicious": 1, "phishing": 2}
    assert [r["id"] for r in s["recent"]] == [ids[k] for k in "abcde"]
    t = s["trend"]
    assert t["granularity"] == "month" and t["points"][0]["bucket"] == "2025-12" and t["points"][-1]["bucket"] == "2026-10"
    assert len(t["points"]) == 11
    assert [p["total"] for p in t["points"] if p["bucket"] == "2026-10"] == [3]
    assert sum(p["total"] for p in t["points"]) == 6


def test_dashboard_seven_days_is_daily_and_zero_filled(tmp_path):
    _, run, _ = world(tmp_path)
    s = svc.dashboard_summary(run, 1, "7", NOW)
    pts = s["trend"]["points"]
    assert s["metrics"]["totalScanned"] == 3 and s["trend"]["granularity"] == "day"
    assert [p["bucket"] for p in pts][0] == "2026-10-06" and pts[-1]["bucket"] == "2026-10-13"
    by = {p["bucket"]: p for p in pts}
    assert by["2026-10-13"]["phishing"] == 1 and by["2026-10-12"]["safe"] == 1 and by["2026-10-08"]["suspicious"] == 1
    assert by["2026-10-07"]["total"] == 0


def test_dashboard_year_starts_in_january(tmp_path):
    _, run, _ = world(tmp_path)
    pts = svc.dashboard_summary(run, 1, "year", NOW)["trend"]["points"]
    assert pts[0]["bucket"] == "2026-01" and pts[-1]["bucket"] == "2026-10" and len(pts) == 10


def test_dashboard_for_a_user_with_no_scans(tmp_path):
    _, run, _ = world(tmp_path)
    s = svc.dashboard_summary(run, 99, "all", NOW)
    assert s["metrics"] == {"totalScanned": 0, "phishingBlocked": 0, "suspicious": 0, "safeEmails": 0, "avgInferenceMs": None}
    assert s["recent"] == [] and s["trend"]["points"] == []
    assert len(svc.dashboard_summary(run, 99, "7", NOW)["trend"]["points"]) == 8


# ---------------------------------------------------------------------------- feedback
def test_feedback_create_then_update_keeps_one_row(tmp_path):
    conn, run, ids = world(tmp_path)
    first = svc.submit_feedback(run, 1, ids["a"], correct=False, label="Suspicious", helpful=True,
                                comment="  looks\nlike a  newsletter ", now="2026-10-13T12:00:00Z")
    assert first == {"isPredictionCorrect": False, "suggestedLabel": "Suspicious", "explanationHelpful": True,
                     "comment": "looks like a  newsletter", "createdAt": "2026-10-13T12:00:00Z"}
    second = svc.submit_feedback(run, 1, ids["a"], correct=True, label="Safe", helpful=None, comment="",
                                 now="2026-10-13T13:00:00Z")
    assert second["isPredictionCorrect"] is True and second["suggestedLabel"] is None     # label dropped
    assert second["explanationHelpful"] is None and second["comment"] is None
    assert conn.execute("SELECT COUNT(*) FROM scan_feedback").fetchone()[0] == 1
    assert svc.scan_detail(run, 1, ids["a"], real_catalog(tmp_path))["feedback"]["isPredictionCorrect"] is True


def test_feedback_on_someone_elses_or_missing_scan_is_refused(tmp_path):
    conn, run, ids = world(tmp_path)
    for scan_id in (ids["g"], 99999):
        assert svc.submit_feedback(run, 1, scan_id, correct=True, label=None, helpful=None,
                                   comment=None, now="2026-10-13T12:00:00Z") is None
    assert conn.execute("SELECT COUNT(*) FROM scan_feedback").fetchone()[0] == 0


def test_normalize_feedback_rules():
    n = svc.normalize_feedback(correct=False, label="Phishing", helpful=False, comment="x" * 2000)
    assert n == {"correct": 0, "label": "Phishing", "helpful": 0, "comment": "x" * 1000}
    assert svc.normalize_feedback(correct=True, label="Phishing", helpful=None, comment=" \x00 ")["label"] is None
