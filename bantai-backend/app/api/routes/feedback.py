"""Feedback endpoints for user review of scan predictions."""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_optional
from app.db.models import Scan, ScanFeedback, AuditLog
from app.db.session import get_db

router = APIRouter(prefix="/feedback", tags=["feedback"])


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    scan_id: int = Field(alias="scanId", ge=1)
    is_prediction_correct: bool = Field(alias="isPredictionCorrect")
    suggested_label: Optional[Literal["safe", "suspicious", "phishing"]] = Field(default=None, alias="suggestedLabel")
    explanation_helpful: Optional[bool] = Field(default=None, alias="explanationHelpful")
    comment: Optional[str] = Field(default=None, max_length=1000)


@router.post("", status_code=201)
def submit_feedback(
    body: FeedbackRequest,
    request: Request,
    db: Session = Depends(get_db),
    user_id: int | None = Depends(get_current_user_optional),
):
    """Record one feedback submission. Email content is never accepted or logged."""
    scan = db.scalar(select(Scan).where(Scan.scan_id == body.scan_id))
    if scan is None or (user_id is not None and scan.user_id != user_id):
        raise HTTPException(status_code=404, detail={"code": "scan_not_found", "message": "Scan not found."})
    # Anonymous users can only submit feedback for anonymous scans.
    if user_id is None and scan.user_id is not None:
        raise HTTPException(status_code=404, detail={"code": "scan_not_found", "message": "Scan not found."})

    feedback = ScanFeedback(
        scan_id=body.scan_id,
        user_id=user_id,
        is_prediction_correct=body.is_prediction_correct,
        suggested_label=(body.suggested_label.capitalize() if body.suggested_label else None),
        explanation_helpful=body.explanation_helpful,
        comment=body.comment.strip() if body.comment else None,
    )
    try:
        db.add(feedback)
        db.add(AuditLog(
            user_id=user_id, scan_id=body.scan_id, event_type="FEEDBACK_SUBMITTED",
            http_status=201,
            detail='{"has_comment":%s,"is_prediction_correct":%s}' % (
                "true" if bool(body.comment and body.comment.strip()) else "false",
                "true" if body.is_prediction_correct else "false",
            ),
            ip_address=(request.client.host[:64] if request.client else None),
            user_agent=request.headers.get("user-agent", "")[:300] or None,
        ))
        db.commit()
        db.refresh(feedback)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail={"code": "feedback_storage_failed", "message": "Feedback could not be saved."}) from None
    return {"feedbackId": feedback.feedback_id, "scanId": feedback.scan_id, "createdAt": feedback.created_at}


@router.get("/scan/{scan_id}")
def get_scan_feedback(
    scan_id: int,
    db: Session = Depends(get_db),
    user_id: int | None = Depends(get_current_user_optional),
):
    """Feedback is visible only to the owner; guests receive an empty collection."""
    scan = db.scalar(select(Scan).where(Scan.scan_id == scan_id))
    if scan is None or (user_id is not None and scan.user_id != user_id):
        raise HTTPException(status_code=404, detail={"code": "scan_not_found", "message": "Scan not found."})
    if user_id is None and scan.user_id is not None:
        raise HTTPException(status_code=404, detail={"code": "scan_not_found", "message": "Scan not found."})
    rows = db.scalars(select(ScanFeedback).where(ScanFeedback.scan_id == scan_id).order_by(ScanFeedback.created_at.desc())).all()
    return {"items": [{
        "feedbackId": f.feedback_id, "isPredictionCorrect": f.is_prediction_correct,
        "suggestedLabel": f.suggested_label, "explanationHelpful": f.explanation_helpful,
        "comment": f.comment, "createdAt": f.created_at,
    } for f in rows]}
