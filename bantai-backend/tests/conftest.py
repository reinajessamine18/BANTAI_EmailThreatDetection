import pytest

from app.core.config import get_settings


def _reset_engine():
    try:
        from app.db.session import reset_engine
    except ImportError:          # SQLAlchemy not installed: nothing cached
        return
    reset_engine()


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    """Every test gets its own throwaway database and fresh settings."""
    monkeypatch.setenv("BANTAI_DATABASE_PATH", str(tmp_path / "test.db"))
    get_settings.cache_clear()
    _reset_engine()
    yield
    _reset_engine()
    get_settings.cache_clear()
