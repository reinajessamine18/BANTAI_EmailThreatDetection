from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_optional, get_current_user_required
from app.db.session import get_db
from app.schemas.scan import ContentScanRequest, ScanRequest
from app.services import content_ml_service, ml_service
from app.services.guest_scan_quota import (
    GuestScanLimitReached,
    GuestScanQuotaUnavailable,
    reserve_guest_scan,
)
from app.services.scan_service import (
    ClientInfo,
    ContentScanSubmission,
    ScanFailure,
    ScanSubmission,
    perform_content_scan,
    perform_scan,
)

router = APIRouter(prefix="/scans", tags=["scans"])

_NO_STORE = {"Cache-Control": "no-store"}  # responses contain the submitted email's text


@router.post("", response_model=None)
def create_scan(
    body: ScanRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_required),
):
    """Scan one email for an authenticated user. Response shape: see app/services/scan_result.py.

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
    try:
        # ml_service functions are looked up at call time so tests can substitute them.
        result = perform_scan(
            db,
            submission,
            client,
            user_id,
            predict_fn=ml_service.predict,
            max_body_chars_fn=ml_service.max_body_chars,
        )
    except ScanFailure as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"code": exc.code, "message": exc.message},
            headers=_NO_STORE,
        ) from None
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/content-only", response_model=None)
def create_content_scan(
    body: ContentScanRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user_required),
):
    """Scan an email using strictly the Candidate V2 EXP-4 content-only NLP model.

    Accepts already-extracted readable body text.
    Zero-body privacy: text is never stored in the database.
    Requires a valid authenticated user (HTTP 401 if unauthenticated).
    """
    client_ip = request.headers.get("x-forwarded-for")
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    elif request.client:
        client_ip = request.client.host
    else:
        client_ip = None

    client = ClientInfo(
        ip=client_ip,
        user_agent=request.headers.get("user-agent"),
    )

    submission = ContentScanSubmission(
        body_text=body.body_text,
        file_name=body.file_name,
        explain=body.explain,
        top_k=body.top_k,
    )

    try:
        result = perform_content_scan(
            db,
            submission,
            client,
            user_id,
            predict_fn=content_ml_service.predict_content,
            max_body_chars_fn=content_ml_service.max_body_chars,
            guest_reservation_id=None,
        )
    except ScanFailure as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"code": exc.code, "message": exc.message},
            headers=_NO_STORE,
        ) from None

    response.headers["Cache-Control"] = "no-store"
    return result
