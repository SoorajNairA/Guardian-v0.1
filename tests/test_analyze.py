from fastapi.testclient import TestClient
from app.main import app


def test_analyze_requires_api_key():
    client = TestClient(app)
    res = client.post("/v1/analyze", json={"text": "hello"})
    assert res.status_code == 401


def test_analyze_basic_flow(monkeypatch):
    client = TestClient(app)

    # Allow default key via env
    monkeypatch.setenv("GUARDIAN_API_KEY", "ag_123")

    res = client.post(
        "/v1/analyze",
        headers={"X-API-Key": "ag_123"},
        json={"text": "Click here to reset your password"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "request_id" in data
    assert isinstance(data["risk_score"], int)
    assert isinstance(data["threats_detected"], list)



