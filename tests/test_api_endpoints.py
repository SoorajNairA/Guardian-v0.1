import pytest
import os
from fastapi.testclient import TestClient
from app.main import app

# Mark all tests in this file as async
pytestmark = pytest.mark.asyncio

class TestAnalyzeEndpoint:
    def test_valid_request(self, test_client: TestClient, mock_supabase, mock_gemini):
        response = test_client.post(
            "/v1/analyze",
            headers={"X-API-Key": "test-key-1"},
            json={"text": "Your account needs to be verified. Click http://fake-bank.com"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "request_id" in data
        assert "risk_score" in data
        assert "threats_detected" in data
        assert len(data["threats_detected"]) > 0
        assert data["threats_detected"][0]["category"] == "phishing_attempt"

    def test_invalid_input_empty_text(self, test_client: TestClient, mock_supabase):
        response = test_client.post(
            "/v1/analyze",
            headers={"X-API-Key": "test-key-1"},
            json={"text": ""}
        )
        assert response.status_code == 422 # Unprocessable Entity
        assert "Input validation failed" in response.json()["detail"]

    def test_invalid_input_missing_text(self, test_client: TestClient, mock_supabase):
        response = test_client.post(
            "/v1/analyze",
            headers={"X-API-Key": "test-key-1"},
            json={}
        )
        assert response.status_code == 422

    def test_rate_limiting(self, clean_environment, mock_redis):
        # Enable rate limiting for this specific test
        os.environ["RATE_LIMIT_ENABLED"] = "True"
        # Use a low limit for testing
        os.environ["DEFAULT_RATE_LIMIT_PER_KEY"] = "2"
        
        client = TestClient(app)

        headers = {"X-API-Key": "test-key-1"}
        payload = {"text": "test"}

        # First two requests should succeed
        assert client.post("/v1/analyze", headers=headers, json=payload).status_code == 200
        assert client.post("/v1/analyze", headers=headers, json=payload).status_code == 200

        # Third request should be rate-limited
        response = client.post("/v1/analyze", headers=headers, json=payload)
        assert response.status_code == 429
        assert "X-RateLimit-Limit" in response.headers

class TestHealthEndpoint:
    def test_healthz_endpoint(self, test_client: TestClient, mock_supabase, mock_redis, mock_gemini):
        response = test_client.get("/healthz")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert len(data["dependencies"]) > 0
        # Check that our mocks are reported as healthy
        assert all(dep["is_healthy"] for dep in data["dependencies"])

class TestMetricsEndpoint:
    def test_metrics_endpoint(self, test_client: TestClient):
        # Note: Prometheus endpoint is tested separately if enabled.
        # This tests the JSON metrics endpoint.
        response = test_client.get("/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "total_requests" in data
        assert "error_rate_percent" in data
        assert "average_latency_ms" in data
