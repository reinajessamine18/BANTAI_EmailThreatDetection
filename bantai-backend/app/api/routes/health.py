from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    ml_ready: bool
    ml_detail: str


@router.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    ml = request.app.state.ml_status
    return HealthResponse(
        status="ok" if ml.ready else "degraded",
        ml_ready=ml.ready,
        ml_detail=ml.detail,
    )
