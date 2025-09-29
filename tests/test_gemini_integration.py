import pytest
import httpx
from fastapi.testclient import TestClient

from app.config import settings

# Mark all tests in this file as async
pytestmark = pytest.mark.asyncio

async def test_successful_gemini_enrichment(test_client: TestClient, mock_supabase, mock_gemini):
    """Tests that a successful Gemini response enhances the analysis."""
    # Enable Gemini for this test
    settings.gemini_api_key = "fake-gemini-key"

    response = test_client.post(
        "/v1/analyze",
        headers={"X-API-Key": "test-key-1"},
        json={"text": "A benign text that Gemini will analyze."}
    )

    assert response.status_code == 200
    data = response.json()
    
    # Check for Gemini-specific metadata
    assert data["metadata"]["is_ai_generated"] is False
    assert data["metadata"]["language"] == "en"

    settings.gemini_api_key = "" # Disable again

async def test_gemini_timeout_fallback(test_client: TestClient, mock_supabase, monkeypatch):
    """Tests that the system falls back gracefully when Gemini times out."""
    settings.gemini_api_key = "fake-gemini-key"

    # Mock the HTTP client to raise a timeout
    async def mock_timeout(*args, **kwargs):
        raise httpx.TimeoutException("Request timed out")

    monkeypatch.setattr("httpx.AsyncClient.post", mock_timeout)

    response = test_client.post(
        "/v1/analyze",
        headers={"X-API-Key": "test-key-1"},
        json={"text": "Text for a timing-out request."}
    )

    assert response.status_code == 200
    data = response.json()
    
    # Metadata should be null as Gemini failed
    assert data["metadata"]["is_ai_generated"] is None
    assert data["metadata"]["language"] is None

    settings.gemini_api_key = "" # Disable again

async def test_gemini_rate_limit_fallback(test_client: TestClient, mock_supabase, monkeypatch):
    """Tests that the system falls back after hitting rate limits and exhausting retries."""
    settings.gemini_api_key = "fake-gemini-key"

    # Mock the HTTP client to always return 429
    async def mock_rate_limit(*args, **kwargs):
        return httpx.Response(429, json={"error": "Rate limit exceeded"})

    monkeypatch.setattr("httpx.AsyncClient.post", mock_rate_limit)

    response = test_client.post(
        "/v1/analyze",
        headers={"X-API-Key": "test-key-1"},
        json={"text": "Text for a rate-limited request."}
    )

    assert response.status_code == 200
    data = response.json()
    
    # Check for graceful degradation
    assert data["metadata"]["is_ai_generated"] is None
    assert data["metadata"]["language"] is None
    assert "error" in data["metadata"] # Check for the error field

    settings.gemini_api_key = "" # Disable again

async def test_gemini_caching(test_client: TestClient, mock_supabase, monkeypatch):
    """Tests that the Gemini cache returns a result for an identical text."""
    settings.gemini_api_key = "fake-gemini-key"
    call_count = 0

    async def mock_post_with_counter(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": '```json\n{"propaganda_disinformation_confidence": 0.2, "is_ai_generated": false, "language": "fr"}\n```'}]}}]})

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post_with_counter)

    text = "This is a test text for caching."

    # First request
    test_client.post("/v1/analyze", headers={"X-API-Key": "test-key-1"}, json={"text": text})
    assert call_count == 1

    # Second identical request
    response = test_client.post("/v1/analyze", headers={"X-API-Key": "test-key-1"}, json={"text": text})
    assert response.status_code == 200
    
    # The mock post should not be called again
    assert call_count == 1
    
    # Verify we got the cached data
    data = response.json()
    assert data["metadata"]["language"] == "fr"

    settings.gemini_api_key = "" # Disable again
