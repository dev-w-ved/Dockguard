import importlib
import pytest

def test_health_endpoint():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    app = importlib.import_module("dockguard.web").app
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json().get("status") in {"ok", "healthy"}

def test_analyze_endpoint(sample_root):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    app = importlib.import_module("dockguard.web").app
    response = TestClient(app).post("/analyze", json={"path": str(sample_root / "unsafe-flask"), "format": "json"})
    assert response.status_code == 200
    assert "findings" in response.text.lower() or "severity" in response.text.lower()

def test_analyze_endpoint_rejects_missing_path():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    app = importlib.import_module("dockguard.web").app
    response = TestClient(app).post("/analyze", json={"path": "missing/path", "format": "json"})
    assert response.status_code >= 400
