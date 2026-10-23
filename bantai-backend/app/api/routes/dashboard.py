from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_required
from app.db.session import get_db
from app.services import history_service
from app.services.history_repo import session_runner

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=None)
def dashboard_summary(
    response: Response,
    date_range: Literal["7", "30", "year", "all"] = Query(default="all", alias="range"),
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_required),
):
    """Metric cards, risk distribution, trend and recent scans for the Dashboard screen."""
    result = history_service.dashboard_summary(
        session_runner(db), user_id, date_range, datetime.now(timezone.utc)
    )
    response.headers["Cache-Control"] = "no-store"
    return result
