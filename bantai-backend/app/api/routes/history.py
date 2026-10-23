from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_required
from app.db.session import get_db
from app.schemas.history import FeedbackRequest
from app.services import history_service, scan_store
from app.services.catalog import CatalogError, load_catalog
from app.services.history_repo import session_runner

router = APIRouter(prefix="/scans", tags=["history"])

_NO_STORE = "no-store"
Level = Literal["all", "safe", "suspicious", "phishing"]
DateRange = Literal["7", "30", "year", "all"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _audit(db: Session, request: Request, user_id: int, event: str, detail: dict, scan_id=None) -> None:
    scan_store.write_audit(
        db,
        event_type=event,
        http_status=200,
        detail=detail,
        user_id=user_id,
        scan_id=scan_id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    db.commit()


@router.get("", response_model=None)
def list_history(
    request: Request,
    response: Response,
    q: Optional[str] = Query(default=None, max_length=100),
    level: Level = "all",
    date_range: DateRange = Query(default="all", alias="range"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_required),
):
    """Your scan history, newest first. Search text is never written to the audit log."""
    result = history_service.list_history(
        session_runner(db), user_id, q=q, level=level, date_range=date_range,
        limit=limit, offset=offset, now=_now(),
    )
    if offset == 0:
        _audit(db, request, user_id, "HISTORY_VIEWED",
               {"range": date_range, "level": level, "searched": bool(q), "returned": len(result["items"])})
    response.headers["Cache-Control"] = _NO_STORE
    return result


# Declared before "/{scan_id}" so "export" is not parsed as an id.
@router.get("/export", response_model=None)
def export_history(
    request: Request,
    q: Optional[str] = Query(default=None, max_length=100),
    level: Level = "all",
    date_range: DateRange = Query(default="all", alias="range"),
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_required),
):
    """CSV of your history with the same filters (max 10,000 rows)."""
    text, count = history_service.export_history_csv(
        session_runner(db), user_id, q=q, level=level, date_range=date_range, now=_now(),
    )
    _audit(db, request, user_id, "HISTORY_EXPORTED", {"range": date_range, "level": level, "rows": count})
    return Response(
        content=text.encode("utf-8"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="bantai-history.csv"',
                 "Cache-Control": _NO_STORE},
    )


@router.get("/{scan_id}", response_model=None)
def get_scan_detail(
    request: Request,
    response: Response,
    scan_id: int = Path(ge=1),
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_required),
):
    """One of your scans, with its SHAP words and indicators. The body was never stored."""
    try:
        catalog = load_catalog(db)
    except CatalogError:
        raise HTTPException(500, detail={"code": "configuration_error",
                                         "message": "The scoring configuration is invalid."}) from None
    result = history_service.scan_detail(session_runner(db), user_id, scan_id, catalog)
    if result is None:
        raise HTTPException(404, detail={"code": "not_found", "message": "Scan not found."})
    _audit(db, request, user_id, "HISTORY_VIEWED", {"scan_id": scan_id}, scan_id=scan_id)
    response.headers["Cache-Control"] = _NO_STORE
    return result


@router.post("/{scan_id}/feedback", response_model=None)
def submit_feedback(
    body: FeedbackRequest,
    request: Request,
    response: Response,
    scan_id: int = Path(ge=1),
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_required),
):
    """Say whether the prediction (and its explanation) was right. One entry per user per scan."""
    saved = history_service.submit_feedback(
        session_runner(db), user_id, scan_id,
        correct=body.is_prediction_correct, label=body.suggested_label,
        helpful=body.explanation_helpful, comment=body.comment,
        now=_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    if saved is None:
        db.rollback()
        raise HTTPException(404, detail={"code": "not_found", "message": "Scan not found."})
    db.commit()
    _audit(db, request, user_id, "FEEDBACK_SUBMITTED", {"scan_id": scan_id}, scan_id=scan_id)
    response.headers["Cache-Control"] = _NO_STORE
    return saved
