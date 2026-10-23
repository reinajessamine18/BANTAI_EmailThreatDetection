"""Turn the model's top SHAP words into plain-language explanations.

Rules (by design):
* Only the top `top_n` words by |contribution| are explained, rank 1 = strongest.
* A word that pushed toward PHISHING and is in `token_feature_map` reuses that
  feature's educational text (e.g. "verify" -> Request for Sensitive Information).
* A word that pushed toward SAFE always gets the neutral "toward safe" sentence, even
  if it appears in the map, so a phishing-flavoured lesson is never attached to a word
  that actually lowered the risk estimate.
* Any other word gets the generic sentence.
* Wording is deliberately non-causal ("pushed the model's estimate"): SHAP explains the
  model's behaviour, not whether the email is truly malicious.
* Contributions stay in raw log-odds units; they are never turned into percentages.
* Substitution uses str.replace, never str.format, so odd characters cannot break it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Tuple

from app.services.catalog import ScoringCatalog

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MAX_TOKEN_CHARS = 64

TITLE_RAISED = "Wording that raised the risk estimate"
TITLE_LOWERED = "Wording that lowered the risk estimate"
_DIRECTIONS = ("toward_phishing", "toward_safe")


@dataclass(frozen=True)
class TokenExplanation:
    rank: int
    token: str
    direction: str          # 'toward_phishing' | 'toward_safe'
    contribution: float     # raw log-odds, NOT a percentage
    tfidf_value: float
    insight_type: str       # 'Educational Insight' | 'Security Tip'
    title: str
    message: str


def _clean_token(token: object) -> str:
    return _CONTROL.sub("", str(token)).strip()[:_MAX_TOKEN_CHARS]


def explain_tokens(contributions: Iterable, catalog: ScoringCatalog) -> Tuple[TokenExplanation, ...]:
    """`contributions` items need: token, contribution, direction, tfidf_value."""
    items = sorted(contributions, key=lambda c: abs(c.contribution), reverse=True)[: catalog.top_n]

    results = []
    for rank, item in enumerate(items, start=1):
        if item.direction not in _DIRECTIONS:
            raise ValueError("unexpected contribution direction")
        token = _clean_token(item.token)
        feature = catalog.token_features.get(token)

        if item.direction == "toward_phishing":
            message = catalog.generic_phishing.replace("{token}", token)
            if feature is not None:
                insight_type, title = feature.insight_type, feature.title
                message = f"{message} {feature.template}"
            else:
                insight_type, title = "Educational Insight", TITLE_RAISED
        else:
            insight_type, title = "Educational Insight", TITLE_LOWERED
            message = catalog.generic_safe.replace("{token}", token)

        results.append(
            TokenExplanation(
                rank=rank,
                token=token,
                direction=item.direction,
                contribution=float(item.contribution),
                tfidf_value=float(item.tfidf_value),
                insight_type=insight_type,
                title=title,
                message=message,
            )
        )
    return tuple(results)
