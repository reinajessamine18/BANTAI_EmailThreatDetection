"""BANTAI FastAPI application entry point.

Run from the bantai-backend/ folder:
    uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import account, auth, dashboard, health, history, scans
from app.core.config import get_settings
from app.db.init_db import DatabaseInitError, init_db
from app.services.content_ml_service import load_content_ml
from app.services.ml_service import load_ml

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    status = load_ml(settings.ml_dir)
    app.state.ml_status = status
    if settings.ml_required and not status.ready:
        raise RuntimeError(f"ML component is required but not ready ({status.detail})")

    # Load Phase 8 Candidate V2 EXP-4 Content-Only ML Service
    content_status = load_content_ml(settings.content_nlp_package_dir)
    app.state.content_ml_status = content_status
    if settings.content_nlp_required and not content_status.ready:
        raise RuntimeError(f"Content NLP candidate component is required but not ready ({content_status.detail})")

    # Create/upgrade the database from bantai-database/*.sql (idempotent). Fail fast:
    # every scan must be audit-logged, so the API must not run without a database.
    try:
        init_db(settings.database_path, settings.sql_dir, settings.ml_dir)
    except DatabaseInitError as exc:
        raise RuntimeError(f"database initialization failed: {exc}") from exc
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, lifespan=lifespan)

    @app.middleware("http")
    async def limit_request_size(request: Request, call_next):
        # Refuse oversized bodies from the Content-Length header, before reading them.
        # (Defined before CORS is added so CORS stays outermost and the browser can read the 413.)
        length = request.headers.get("content-length", "")
        if length.isdigit() and int(length) > settings.max_request_bytes:
            return JSONResponse(
                status_code=413,
                content={"detail": {"code": "too_large", "message": "The request is too large."}},
            )
        return await call_next(request)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        # FastAPI's default 422 echoes the submitted value ("input"). For an email
        # scanner that value can be the email body, so only location/message/type
        # are returned.
        errors = [
            {"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")}
            for e in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    app.include_router(health.router, prefix=settings.api_prefix)
    app.include_router(auth.router, prefix=settings.api_prefix)
    app.include_router(account.router, prefix=settings.api_prefix)
    app.include_router(scans.router, prefix=settings.api_prefix)
    app.include_router(history.router, prefix=settings.api_prefix)
    app.include_router(dashboard.router, prefix=settings.api_prefix)
    return app


app = create_app()
