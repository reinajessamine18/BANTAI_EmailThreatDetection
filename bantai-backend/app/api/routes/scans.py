from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_optional
from app.db.session import get_db
from app.schemas.scan import ScanRequest
from app.services import ml_service
from app.services.guest_scan_quota import (
    GuestScanLimitReached,
    GuestScanQuotaUnavailable,
    release_guest_scan,
    reserve_guest_scan,
)
from app.services.scan_service import ClientInfo, ScanFailure, ScanSubmission, perform_scan

router = APIRouter(prefix="/scans", tags=["scans"])

_NO_STORE = {"Cache-Control": "no-store"}   # responses contain the submitted email's text


@router.post("", response_model=None)
def create_scan(
    body: ScanRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user_id: Optional[int] = Depends(get_current_user_optional),
):
    """Scan one email. Response shape: see app/services/scan_result.py.

    Errors: {"detail": {"code": "...", "message": "..."}} with 413 / 422 / 500 / 503.
    """
    client = ClientInfo(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    submission = ScanSubmission(
        input_method=body.input_method,
        content=body.content,
        encoding=body.encoding,
        file_name=body.file_name,
    )
    reservation_id = None
    if user_id is None:
        if client.ip is None:
            raise HTTPException(
                status_code=503,
                detail={"code": "guest_quota_unavailable", "message": "Guest scanning is temporarily unavailable."},
                headers=_NO_STORE,
            )
        try:
            reservation_id = reserve_guest_scan(db, client.ip)
        except GuestScanLimitReached:
            raise HTTPException(
                status_code=429,
                detail={
                    "code": "guest_scan_limit_reached",
                    "message": "The free guest scan limit has been reached for this IP address.",
                },
                headers=_NO_STORE,
            ) from None
        except GuestScanQuotaUnavailable:
            raise HTTPException(
                status_code=503,
                detail={"code": "guest_quota_unavailable", "message": "Guest scanning is temporarily unavailable."},
                headers=_NO_STORE,
            ) from None
    try:
        # ml_service functions are looked up at call time so tests can substitute them.
        result = perform_scan(
            db,
            submission,
            client,
            user_id,
            predict_fn=ml_service.predict,
            max_body_chars_fn=ml_service.max_body_chars,
            guest_reservation_id=reservation_id,
        )
    except ScanFailure as exc:
        if reservation_id is not None:
            release_guest_scan(db, reservation_id)
        raise HTTPException(
            status_code=exc.status,
            detail={"code": exc.code, "message": exc.message},
            headers=_NO_STORE,
        ) from None
    response.headers["Cache-Control"] = "no-store"
    return result
