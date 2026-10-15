from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class FeedbackRequest(BaseModel):
    """Body of POST /scans/{id}/feedback. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    is_prediction_correct: bool = Field(alias="isPredictionCorrect")
    suggested_label: Optional[Literal["Safe", "Suspicious", "Phishing"]] = Field(
        default=None, alias="suggestedLabel"
    )
    explanation_helpful: Optional[bool] = Field(default=None, alias="explanationHelpful")
    comment: Optional[str] = Field(default=None, max_length=1000)
