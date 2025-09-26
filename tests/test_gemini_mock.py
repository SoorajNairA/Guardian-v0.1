from fastapi.testclient import TestClient
from app.main import app


def test_gemini_mock(monkeypatch):
    from app import gemini as gem

    async def fake_enrich(text, threats, base_score):
        return {"risk_score": 42, "threats": threats}

    monkeypatch.setattr(gem, "gemini_enrich", fake_enrich)

    c = TestClient(app)
    monkeypatch.setenv("GUARDIAN_API_KEY", "k")
    r = c.post("/v1/analyze", headers={"X-API-Key": "k"}, json={"text": "anything"})
    assert r.status_code == 200
    assert r.json()["risk_score"] == 42



