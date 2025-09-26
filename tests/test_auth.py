from fastapi.testclient import TestClient
from app.main import app


def test_missing_key():
    c = TestClient(app)
    r = c.post("/v1/analyze", json={"text": "hi"})
    assert r.status_code == 401


def test_env_key_valid(monkeypatch):
    c = TestClient(app)
    monkeypatch.setenv("GUARDIAN_API_KEY", "ag_env")
    r = c.post("/v1/analyze", headers={"X-API-Key": "ag_env"}, json={"text": "hi"})
    assert r.status_code == 200



