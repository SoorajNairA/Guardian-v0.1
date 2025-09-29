import pytest
from fastapi.testclient import TestClient

# Mark all tests in this file as async
pytestmark = pytest.mark.asyncio

async def test_valid_api_key_succeeds(test_client: TestClient, mock_supabase):
    """Tests that a valid API key from the mock Supabase passes authentication."""
    response = test_client.post(
        "/v1/analyze",
        headers={"X-API-Key": "test-key-1"},
        json={"text": "some text"}
    )
    # Expecting success, not 401/403
    assert response.status_code != 401
    assert response.status_code != 403

async def test_invalid_api_key_fails(test_client: TestClient, mock_supabase):
    """Tests that an invalid API key is rejected."""
    response = test_client.post(
        "/v1/analyze",
        headers={"X-API-Key": "invalid-key"},
        json={"text": "some text"}
    )
    assert response.status_code == 401
    assert "Invalid API key" in response.json()["detail"]

async def test_missing_api_key_fails(test_client: TestClient, mock_supabase):
    """Tests that a request with no API key is rejected."""
    response = test_client.post("/v1/analyze", json={"text": "some text"})
    assert response.status_code == 401
    assert "Missing API key" in response.json()["detail"]

async def test_logging_client_integration(test_client: TestClient, mock_supabase, mock_logging_client):
    """Tests that a successful analysis request creates a log entry."""
    api_key = "test-key-1"
    text_to_analyze = "this is a test"
    
    response = test_client.post(
        "/v1/analyze",
        headers={"X-API-Key": api_key},
        json={"text": text_to_analyze}
    )
    
    assert response.status_code == 200
    
    # Check that the mock logging client captured one log entry
    assert len(mock_logging_client) == 1
    log_entry = mock_logging_client[0]
    
    # Verify the content of the log entry
    assert log_entry.api_key_id == "mock_key_id" # From mock_supabase fixture
    assert log_entry.text_length == len(text_to_analyze)
    assert log_entry.risk_score is not None
    assert "client_ip" in log_entry.request_meta

async def test_supabase_connection_failure(test_client: TestClient, monkeypatch):
    """Tests fallback to env var keys when Supabase connection fails."""
    # Mock the Supabase client to raise an exception
    class MockFailingSupabaseClient:
        def __init__(self, *args, **kwargs):
            raise Exception("Connection failed")

    monkeypatch.setattr("supabase.create_client", lambda *args, **kwargs: MockFailingSupabaseClient())

    # This key exists in the env vars set by the `clean_environment` fixture
    response = test_client.post(
        "/v1/analyze",
        headers={"X-API-Key": "test-key-2"},
        json={"text": "some text"}
    )
    
    # Should succeed using the fallback mechanism
    assert response.status_code == 200
