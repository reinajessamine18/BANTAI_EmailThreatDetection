"""Decision step: ML prediction + parsed email + catalog -> final threat assessment.

Pure function, no I/O. The caller (the scan endpoint) supplies the parsed email, the
ML module's PredictionResult (duck-typed), and a ScoringCatalog loaded from the database.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Tuple

from app.services.catalog import ScoringCatalog
from app.services.explanations import TokenExplanation, explain_tokens
from app.services.indicators import IndicatorFinding, compute_indicator_values, surface_indicators
from app.services.threat_scoring import probability_to_score, risk_tier, ui_risk_level


@dataclass(frozen=True)
class ThreatAssessment:
    threat_score: int                       # 0-100, from the model probability only
    risk_tier: str                          # 'Low' | 'Medium' | 'Critical'
    risk_level: str                         # 'safe' | 'suspicious' | 'phishing' (frontend names)
    phishing_probability: float
    model_classification: str               # the model's own 0.5-threshold label ('Safe' | 'Phishing')
    shap_base_value: float                  # raw log-odds
    raw_margin: float                       # raw log-odds
    token_explanations: Tuple[TokenExplanation, ...]
    indicators: Tuple[IndicatorFinding, ...]     # rule-based findings worth showing
    indicator_values: Mapping[str, float]        # every computed indicator (-> scan_features)


def assess(parsed, prediction, catalog: ScoringCatalog) -> ThreatAssessment:
    score = probability_to_score(prediction.phishing_probability)
    tier = risk_tier(score, catalog.policy)
    values = compute_indicator_values(parsed, catalog.lexicons)

    return ThreatAssessment(
        threat_score=score,
        risk_tier=tier,
        risk_level=ui_risk_level(tier),
        phishing_probability=float(prediction.phishing_probability),
        model_classification=prediction.classification,
        shap_base_value=float(prediction.shap_base_value),
        raw_margin=float(prediction.raw_margin),
        token_explanations=explain_tokens(prediction.top_contributions, catalog),
        indicators=surface_indicators(values, catalog),
        indicator_values=values,
    )
