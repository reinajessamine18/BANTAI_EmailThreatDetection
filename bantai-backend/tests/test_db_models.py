"""Step 3 tests: SQLAlchemy models against a database built from the team's SQL.

Needs SQLAlchemy (in requirements.txt). Skipped automatically if it is missing.
"""

from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import func, select, text  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.db.init_db import init_db  # noqa: E402
from app.db.models import (  # noqa: E402
    ExtractedUrl,
    ModelVersion,
    Scan,
    ScanHistoryRow,
    ScanTokenContribution,
)
from app.db.session import build_engine  # noqa: E402

SQL_DIR = Path(__file__).resolve().parents[2] / "bantai-database"


@pytest.fixture()
def session(tmp_path):
    db = tmp_path / "orm.db"
    init_db(db, SQL_DIR, None)
    engine = build_engine(db)
    with Session(engine) as s:
        yield s
    engine.dispose()


def _scan(**overrides):
    values = dict(
        model_version_id=1,
        input_method="raw_text",
        content_sha256="0" * 64,
        body_char_count=120,
        malicious_probability=0.92,
        threat_score=92,
        risk_tier="Critical",
    )
    values.update(overrides)
    return Scan(**values)


def test_foreign_keys_pragma_is_on(session):
    assert session.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_scan_roundtrip_with_children(session):
    scan = _scan(
        urls=[ExtractedUrl(url_defanged="hxxp://203[.]0[.]113[.]9/login", position_in_mail=1,
                           has_ip_address=True)],
        token_contributions=[ScanTokenContribution(abs_rank=1, token="verify", contribution=0.8,
                                                   direction="toward_phishing", tfidf_value=0.2)],
    )
    session.add(scan)
    session.commit()

    assert scan.scan_code == f"BNT-{scan.scan_id:04d}"
    assert scan.scanned_at.endswith("Z")                 # DB default filled in
    assert scan.urls[0].has_ip_address is True
    assert scan.urls[0].is_https is False                # server default 0 -> False
    assert scan.token_contributions[0].token == "verify"


def test_history_view_agrees_with_orm(session):
    scan = _scan()
    session.add(scan)
    session.commit()

    row = session.execute(
        select(ScanHistoryRow).where(ScanHistoryRow.scan_id == scan.scan_id)
    ).scalar_one()
    assert row.scan_code == scan.scan_code               # property matches the DB generated column
    assert row.classification == "Phishing"              # Critical -> Phishing
    assert row.threat_score == 92


def test_deleting_scan_cascades_to_children(session):
    scan = _scan(
        urls=[ExtractedUrl(url_defanged="hxxp://a[.]example/")],
        token_contributions=[ScanTokenContribution(abs_rank=1, token="x", contribution=0.1,
                                                   direction="toward_safe", tfidf_value=0.1)],
    )
    session.add(scan)
    session.commit()
    session.delete(scan)
    session.commit()
    assert session.scalar(select(func.count()).select_from(ExtractedUrl)) == 0
    assert session.scalar(select(func.count()).select_from(ScanTokenContribution)) == 0


def test_database_check_constraint_rejects_unknown_risk_tier(session):
    session.add(_scan(risk_tier="High"))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_exactly_one_active_model(session):
    active = session.scalars(select(ModelVersion).where(ModelVersion.is_active.is_(True))).all()
    assert len(active) == 1


def test_education_mapping_and_profile_picture_columns(session):
    from app.db.models import TokenFeatureMap, User

    mapping = session.get(TokenFeatureMap, "urgent")
    assert mapping is not None
    assert mapping.feature.feature_key == "urgency_keyword_count"

    user = User(full_name="T", email="t@example.com", password_hash="h", profile_picture="data:,x")
    session.add(user)
    session.commit()
    assert user.profile_picture == "data:,x"


def test_token_insight_text_round_trips(session):
    scan = _scan(token_contributions=[
        ScanTokenContribution(abs_rank=1, token="verify", contribution=0.8, direction="toward_phishing",
                              tfidf_value=0.2, insight_type="Educational Insight",
                              insight_title="Request for Sensitive Information", insight_message="msg")])
    session.add(scan)
    session.commit()
    assert scan.token_contributions[0].insight_title == "Request for Sensitive Information"


def test_load_catalog_reads_the_real_seed_through_the_orm(session):
    from app.services.catalog import load_catalog

    cat = load_catalog(session)
    assert (cat.policy.low_max, cat.policy.medium_max, cat.top_n) == (39, 79, 5)
    assert cat.token_features["verify"].title == "Request for Sensitive Information"
    assert "urgent" in cat.lexicons["urgency_keyword_count"]
    assert "sentiment_score" not in cat.features and len(cat.features) == 20
