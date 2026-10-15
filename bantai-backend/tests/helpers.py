"""Shared test helpers (no SQLAlchemy needed)."""

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from app.db.init_db import init_db
from app.services.catalog import FeatureInsight, ScoringCatalog, build_catalog

REPO_ROOT = Path(__file__).resolve().parents[2]
SQL_DIR = REPO_ROOT / "bantai-database"


@dataclass(frozen=True)
class FakeContribution:
    token: str
    contribution: float
    direction: str
    tfidf_value: float = 0.1


@dataclass(frozen=True)
class FakePrediction:
    phishing_probability: float
    classification: str
    top_contributions: Tuple[FakeContribution, ...]
    shap_base_value: float = -0.2
    raw_margin: float = 1.0


def contribution(token: str, value: float) -> FakeContribution:
    return FakeContribution(token, value, "toward_phishing" if value > 0 else "toward_safe")


def real_catalog(tmp_path: Path) -> ScoringCatalog:
    """Catalog built from the team's REAL schema.sql + seed.sql via a throwaway database."""
    db = tmp_path / "catalog.db"
    init_db(db, SQL_DIR, None)
    conn = sqlite3.connect(db)
    try:
        settings = dict(conn.execute("SELECT setting_key, setting_value FROM system_settings"))
        features = [
            FeatureInsight(fid, key, cat, itype, title or key, template)
            for fid, key, cat, itype, title, template in conn.execute(
                "SELECT feature_id, feature_key, category, insight_type, insight_title, insight_template"
                " FROM feature_definitions WHERE is_active = 1 ORDER BY feature_id"
            )
        ]
        tokens = list(conn.execute(
            "SELECT t.token, f.feature_key FROM token_feature_map t"
            " JOIN feature_definitions f USING (feature_id)"
        ))
    finally:
        conn.close()
    return build_catalog(settings, features, tokens)


# ---------------------------------------------------------------- history/dashboard helpers
def sqlite_runner(conn):
    """The same `Execute` seam the app uses, backed by a plain sqlite3 connection."""
    conn.row_factory = sqlite3.Row

    def run(sql, params):
        cursor = conn.execute(sql, params)
        rows = [dict(r) for r in cursor.fetchall()] if cursor.description else []
        conn.commit()
        return rows

    return run


def seed_users(conn, count=2):
    for uid in range(1, count + 1):
        conn.execute(
            "INSERT INTO users (user_id, full_name, email, password_hash) VALUES (?, ?, ?, 'h')",
            (uid, f"User {uid}", f"user{uid}@example.com"),
        )
    conn.commit()


def seed_scan(conn, *, user_id, scanned_at, tier, score, subject, sender="x@y.example",
              domain="y.example", inference_ms=40):
    cursor = conn.execute(
        "INSERT INTO scans (user_id, model_version_id, input_method, content_sha256, subject,"
        " sender_address, sender_domain, spf_result, dkim_result, dmarc_result, url_count,"
        " malicious_probability, threat_score, risk_tier, shap_base_value, inference_ms, scanned_at, file_name)"
        " VALUES (?, 1, 'raw_text', 'x', ?, ?, ?, 'fail', 'none', 'fail', 1, ?, ?, ?, -0.2, ?, ?, 'm.eml')",
        (user_id, subject, sender, domain, score / 100, score, tier, inference_ms, scanned_at),
    )
    conn.commit()
    return cursor.lastrowid
