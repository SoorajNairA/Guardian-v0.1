"""
Integration tests for the Guardian Threat Detection System.
Tests cover integration between:
- Gemini API module
- FastAPI endpoints
- Frontend connections
- Database interactions
"""

import pytest
from httpx import AsyncClient
from fastapi.testclient import TestClient
from api.app.main import app
from api.app.gemini import gemini_enrich
from api.app.config import settings
from typing import Dict, Any
import json

# Test data
SAMPLE_TEXTS = [
    {
        "text": "Hello, this is a normal message.",
        "expected_threat": "None"
    },
    {
        "text": "URGENT: Your account has been compromised. Click here immediately!",
        "expected_threat": "High"
    },
    {
        "text": "Please verify your identity by sending your social security number.",
        "expected_threat": "Critical"
    }
]

@pytest.fixture
def test_client():
    """Create a test client for FastAPI endpoints"""
    return TestClient(app)

@pytest.fixture
async def async_client():
    """Create an async test client for FastAPI endpoints"""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

@pytest.mark.asyncio
async def test_analyze_endpoint_integration(async_client):
    """Test the /analyze endpoint integration with Gemini"""
    for sample in SAMPLE_TEXTS:
        response = await async_client.post(
            "/v1/analyze",
            json={"text": sample["text"]}
        )
        
        assert response.status_code == 200
        result = response.json()
        
        # Verify response structure
        assert "threatLevel" in result
        assert "confidenceScore" in result
        assert "concerns" in result
        
        # Verify expected threat level
        assert result["threatLevel"] == sample["expected_threat"]
        
        # Verify confidence score is reasonable
        assert 0 <= result["confidenceScore"] <= 100

@pytest.mark.asyncio
async def test_batch_analyze_endpoint_integration(async_client):
    """Test the /batch-analyze endpoint integration"""
    texts = [sample["text"] for sample in SAMPLE_TEXTS]
    
    response = await async_client.post(
        "/v1/batch-analyze",
        json={"texts": texts}
    )
    
    assert response.status_code == 200
    results = response.json()
    
    assert len(results) == len(texts)
    for result in results:
        assert "threatLevel" in result
        assert "confidenceScore" in result
        assert "concerns" in result

@pytest.mark.asyncio
async def test_metrics_endpoint_integration(async_client):
    """Test the /metrics endpoint for Prometheus metrics"""
    # First make some analysis requests to generate metrics
    for sample in SAMPLE_TEXTS:
        await async_client.post(
            "/v1/analyze",
            json={"text": sample["text"]}
        )
    
    response = await async_client.get("/metrics")
    assert response.status_code == 200
    
    metrics_text = response.text
    assert "guardian_requests_total" in metrics_text
    assert "guardian_request_duration_seconds" in metrics_text
    assert "guardian_cache_hits_total" in metrics_text

@pytest.mark.asyncio
async def test_health_check_integration(async_client):
    """Test the health check endpoint integration"""
    response = await async_client.get("/healthz")
    assert response.status_code == 200
    
    result = response.json()
    assert result["status"] == "healthy"
    assert "gemini" in result["components"]
    assert "database" in result["components"]

@pytest.mark.asyncio
async def test_frontend_api_integration(async_client):
    """Test integration with frontend API requirements"""
    # Test with frontend-specific headers
    headers = {
        "X-Frontend-Version": "1.0.0",
        "X-Request-ID": "test-123"
    }
    
    response = await async_client.post(
        "/v1/analyze",
        json={"text": SAMPLE_TEXTS[0]["text"]},
        headers=headers
    )
    
    assert response.status_code == 200
    result = response.json()
    
    # Verify frontend-required fields
    assert "requestId" in result
    assert "timestamp" in result
    assert "threatDetails" in result
    assert isinstance(result["threatDetails"], dict)

@pytest.mark.asyncio
async def test_error_handling_integration(async_client):
    """Test error handling integration across components"""
    # Test rate limiting
    for _ in range(settings.rate_limit_per_minute + 1):
        response = await async_client.post(
            "/v1/analyze",
            json={"text": "test"}
        )
    assert response.status_code == 429
    
    # Test invalid input
    response = await async_client.post(
        "/v1/analyze",
        json={"text": ""}
    )
    assert response.status_code == 400
    
    # Test missing authentication
    response = await async_client.post(
        "/v1/admin/configure",
        json={"setting": "test"}
    )
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_concurrent_requests_handling(async_client):
    """Test handling of concurrent requests"""
    # Create multiple concurrent requests
    texts = [sample["text"] for sample in SAMPLE_TEXTS]
    tasks = []
    
    for text in texts:
        task = async_client.post(
            "/v1/analyze",
            json={"text": text}
        )
        tasks.append(task)
    
    # Execute requests concurrently
    import asyncio
    responses = await asyncio.gather(*tasks)
    
    # Verify all requests were successful
    assert all(response.status_code == 200 for response in responses)
    
    # Verify results are unique (no cross-contamination)
    results = [response.json() for response in responses]
    threat_levels = [result["threatLevel"] for result in results]
    assert len(set(threat_levels)) == len(texts)  # All should be unique

@pytest.mark.asyncio
async def test_caching_integration(async_client):
    """Test caching behavior in integration context"""
    text = SAMPLE_TEXTS[0]["text"]
    
    # First request - should miss cache
    response1 = await async_client.post(
        "/v1/analyze",
        json={"text": text}
    )
    result1 = response1.json()
    
    # Second request - should hit cache
    response2 = await async_client.post(
        "/v1/analyze",
        json={"text": text}
    )
    result2 = response2.json()
    
    assert response2.headers.get("X-Cache-Hit") == "true"
    assert result1 == result2  # Results should be identical