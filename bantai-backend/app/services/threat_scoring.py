"""Probability -> threat score (0-100) -> risk tier -> frontend risk level.

The score comes ONLY from the model's phishing probability. Rule-based indicators
(headers, URLs, text habits) are shown to the user but never change the score.

Tier cut-offs come from `system_settings` (risk_low_max / risk_medium_max). The
seeded defaults (0-39 Low, 40-79 Medium, 80-100 Critical) are ASSUMPTIONS that have
not been validated against the model's behaviour.

Note: the tier is derived from the probability alone, so it can differ from the
model's own 0.5-threshold label (e.g. probability 0.60 -> label "Phishing" but
score 60 -> tier "Medium"). Both are exposed so the UI can be honest about it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

TIER_LOW = "Low"
TIER_MEDIUM = "Medium"
TIER_CRITICAL = "Critical"

# Names used by the React screens (AnalysisResults.jsx `riskLevel`).
_UI_LEVEL = {TIER_LOW: "safe", TIER_MEDIUM: "suspicious", TIER_CRITICAL: "phishing"}


@dataclass(frozen=True)
class RiskPolicy:
    """Upper bounds (inclusive) of the Low and Medium tiers; everything above is Critical."""

    low_max: int
    medium_max: int

    def __post_init__(self) -> None:
        for name in ("low_max", "medium_max"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
        if not (0 <= self.low_max < self.medium_max <= 99):
            raise ValueError("thresholds must satisfy 0 <= low_max < medium_max <= 99")


def probability_to_score(probability: float) -> int:
    """Round a phishing probability in [0, 1] to an integer score in [0, 100]."""
    if isinstance(probability, bool):
        raise ValueError("probability must be a number")
    value = float(probability)
    if not math.isfinite(value) or value < 0.0 or value > 1.0:
        raise ValueError("probability must be a finite number between 0 and 1")
    return min(100, int(math.floor(value * 100 + 0.5)))   # round half up


def risk_tier(score: int, policy: RiskPolicy) -> str:
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError("score must be an integer between 0 and 100")
    if score <= policy.low_max:
        return TIER_LOW
    if score <= policy.medium_max:
        return TIER_MEDIUM
    return TIER_CRITICAL


def ui_risk_level(tier: str) -> str:
    """'safe' | 'suspicious' | 'phishing' (the names the frontend uses)."""
    try:
        return _UI_LEVEL[tier]
    except KeyError:
        raise ValueError(f"unknown risk tier: {tier!r}") from None
