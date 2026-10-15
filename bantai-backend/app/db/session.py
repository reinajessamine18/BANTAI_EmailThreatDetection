"""SQLAlchemy engine/session wiring for the SQLite database."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterator

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


def build_engine(db_path: Path) -> Engine:
    engine = create_engine(
        URL.create("sqlite", database=str(db_path)),
        # FastAPI runs sync endpoints in a thread pool; sessions are still per-request.
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _record):
        # SQLite ignores FOREIGN KEY / ON DELETE CASCADE unless this is set per connection.
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    return engine


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    return build_engine(get_settings().database_path)


@lru_cache(maxsize=1)
def _session_factory() -> sessionmaker:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request. Callers commit explicitly."""
    session = _session_factory()()
    try:
        yield session
    finally:
        session.close()


def reset_engine() -> None:
    """Dispose the cached engine and forget it (used by tests that switch databases)."""
    if get_engine.cache_info().currsize:
        get_engine().dispose()
    get_engine.cache_clear()
    _session_factory.cache_clear()
