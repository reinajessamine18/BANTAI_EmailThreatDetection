"""Scoring catalog: the database-held content that scoring and explanations need.

`build_catalog` is a pure function (easy to test). `load_catalog` is the thin ORM
wrapper that reads the rows. The catalog is small (a few dozen rows), so callers
may simply load it per scan; edits to the tables then apply without a restart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, Mapping, Tuple

from app.services.threat_scoring import RiskPolicy


class CatalogError(ValueError):
    """The database content needed for scoring is missing or invalid."""


@dataclass(frozen=True)
class FeatureInsight:
    feature_id: int
    feature_key: str
    category: str          # 'header' | 'url' | 'text'
    insight_type: str      # 'Educational Insight' | 'Security Tip'
    title: str
    template: str


@dataclass(frozen=True)
class ScoringCatalog:
    policy: RiskPolicy
    top_n: int
    generic_phishing: str                       # contains "{token}"
    generic_safe: str                           # contains "{token}"
    features: Mapping[str, FeatureInsight]      # ACTIVE features by feature_key
    token_features: Mapping[str, FeatureInsight]  # SHAP word -> feature whose text explains it
    lexicons: Mapping[str, FrozenSet[str]]      # feature_key -> words (drives keyword-count indicators)


def _int_setting(settings: Mapping[str, str], key: str) -> int:
    try:
        return int(settings[key])
    except KeyError:
        raise CatalogError(f"system setting '{key}' is missing") from None
    except (TypeError, ValueError):
        raise CatalogError(f"system setting '{key}' must be an integer") from None


def _template_setting(settings: Mapping[str, str], key: str) -> str:
    value = settings.get(key)
    if not value or "{token}" not in value:
        raise CatalogError(f"system setting '{key}' must exist and contain {{token}}")
    return value


def build_catalog(
    settings: Mapping[str, str],
    active_features: Iterable[FeatureInsight],
    token_rows: Iterable[Tuple[str, str]],
) -> ScoringCatalog:
    """`token_rows` are (token, feature_key) pairs from token_feature_map."""
    try:
        policy = RiskPolicy(
            low_max=_int_setting(settings, "risk_low_max"),
            medium_max=_int_setting(settings, "risk_medium_max"),
        )
    except ValueError as exc:
        if isinstance(exc, CatalogError):
            raise
        raise CatalogError(f"invalid risk thresholds: {exc}") from exc

    top_n = _int_setting(settings, "top_n_explanations")
    if top_n < 1:
        raise CatalogError("system setting 'top_n_explanations' must be at least 1")

    features: Dict[str, FeatureInsight] = {f.feature_key: f for f in active_features}

    token_features: Dict[str, FeatureInsight] = {}
    words_by_feature: Dict[str, set] = {}
    for token, feature_key in token_rows:
        feature = features.get(feature_key)
        if feature is None:           # mapped to an inactive/unknown feature: ignore
            continue
        token_features[token] = feature
        words_by_feature.setdefault(feature_key, set()).add(token)

    return ScoringCatalog(
        policy=policy,
        top_n=top_n,
        generic_phishing=_template_setting(settings, "insight_generic_phishing"),
        generic_safe=_template_setting(settings, "insight_generic_safe"),
        features=features,
        token_features=token_features,
        lexicons={key: frozenset(words) for key, words in words_by_feature.items()},
    )


def load_catalog(session) -> ScoringCatalog:
    """Read the catalog from the database (SQLAlchemy session)."""
    from sqlalchemy import select

    from app.db.models import FeatureDefinition, SystemSetting, TokenFeatureMap

    settings = {row.setting_key: row.setting_value for row in session.scalars(select(SystemSetting))}
    features = [
        FeatureInsight(
            feature_id=f.feature_id,
            feature_key=f.feature_key,
            category=f.category,
            insight_type=f.insight_type,
            title=f.insight_title or f.display_name,
            template=f.insight_template,
        )
        for f in session.scalars(
            select(FeatureDefinition)
            .where(FeatureDefinition.is_active.is_(True))
            .order_by(FeatureDefinition.feature_id)
        )
    ]
    token_rows = [
        (token, feature_key)
        for token, feature_key in session.execute(
            select(TokenFeatureMap.token, FeatureDefinition.feature_key).join(
                FeatureDefinition, FeatureDefinition.feature_id == TokenFeatureMap.feature_id
            )
        )
    ]
    return build_catalog(settings, features, token_rows)
