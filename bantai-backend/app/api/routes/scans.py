from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_required
from app.db.session import get_db
from app.schemas.scan import ScanRequest
from app.services import ml_service
from app.services.scan_service import ClientInfo, ScanFailure, ScanSubmission, perform_scan

router = APIRouter(prefix="/scans", tags=["scans"])

_NO_STORE = {"Cache-Control": "no-store"}   # responses contain the submitted email's text


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
