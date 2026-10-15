"""Step 1 tests: health endpoint, startup policy, validation-error privacy.

The ML model itself is NOT loaded here (load_ml is replaced), so these tests run
without artifacts. Real model loading is covered by the optional test at the end.
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field

import app.main as main_module
from app.core.config import get_settings
from app.services.ml_service import MlStatus, load_ml


def _client_with_ml(monkeypatch, status):
    monkeypatch.setattr(main_module, "load_ml", lambda _ml_dir: status)
    return TestClient(main_module.create_app())


def test_health_ok_when_ml_ready(monkeypatch):
    with _client_with_ml(monkeypatch, MlStatus(True, "ready")) as client:
        body = client.get("/api/v1/health").json()
    assert body == {"status": "ok", "ml_ready": True, "ml_detail": "ready"}


def test_health_degraded_when_ml_missing(monkeypatch):
    with _client_with_ml(monkeypatch, MlStatus(False, "artifacts_missing")) as client:
        resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"
    assert resp.json()["ml_detail"] == "artifacts_missing"


def test_startup_fails_when_ml_required_but_not_ready(monkeypatch):
    monkeypatch.setenv("BANTAI_ML_REQUIRED", "true")
    get_settings.cache_clear()
    client = _client_with_ml(monkeypatch, MlStatus(False, "artifacts_missing"))
    with pytest.raises(RuntimeError):
        with client:
            pass


def test_cors_allows_vite_origin(monkeypatch):
    with _client_with_ml(monkeypatch, MlStatus(True, "ready")) as client:
        resp = client.get("/api/v1/health", headers={"Origin": "http://localhost:5173"})
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_validation_errors_do_not_echo_submitted_value(monkeypatch):
    monkeypatch.setattr(main_module, "load_ml", lambda _d: MlStatus(True, "ready"))
    app = main_module.create_app()

    class Payload(BaseModel):
        body: str = Field(max_length=10)

    @app.post("/_test/echo")
    def echo(payload: Payload):
        return {}

    secret = "SECRET-EMAIL-BODY-TEXT-THAT-IS-TOO-LONG"
    with TestClient(app) as client:
        resp = client.post("/_test/echo", json={"body": secret})
    assert resp.status_code == 422
    assert secret not in resp.text
    assert "input" not in resp.json()["detail"][0]


def test_load_ml_reports_import_failed_for_empty_dir(tmp_path, monkeypatch):
    import sys

    for name in [m for m in sys.modules if m == "src" or m.startswith("src.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(sys, "path", list(sys.path))
    assert load_ml(tmp_path) == MlStatus(False, "import_failed")


def test_real_ml_loads_when_artifacts_present():
    """Runs the real ML load. Skipped if shap/xgboost or the artifacts are absent."""
    status = load_ml(get_settings().ml_dir)
    if not status.ready:
        pytest.skip(f"ML not available in this environment ({status.detail})")
    assert status.detail == "ready"
