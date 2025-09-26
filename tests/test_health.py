from fastapi.testclient import TestClient
from app.main import app


def test_healthz():
    client = TestClient(app)
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"



