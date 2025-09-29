"""
Tests for the Guardian Python SDK.

These tests require the SDK to be installed. For PyPI/TestPyPI builds, install:
    pip install guardian-securitysdk==0.2.1

For local development mode, run from repo root:
    pip install -e ./sdk/python
"""

import pytest

# Attempt to import the SDK from the new package name
try:
    from guardian_securitysdk import (
        Guardian,
        GuardianConfig,
        GuardianAPIError,
        GuardianTimeoutError,
        GuardianRateLimitError,
        GuardianValidationError,
    )
except ImportError:
    pytest.fail(
        "The SDK is not installed. Install via `pip install guardian-securitysdk==0.2.1` "
        "or run `pip install -e ./sdk/python` from the repository root."
    )

import httpx

# A mock server or live test server would be ideal for these tests.
# For this example, we will use pytest-httpx to mock the API responses.

API_KEY = "test-sdk-key"
BASE_URL = "http://test-server.com"

@pytest.fixture
def guardian_client(httpx_mock, sdk_installed) -> Guardian:
    config = GuardianConfig(api_key=API_KEY, base_url=BASE_URL, max_retries=1)
    return Guardian(config)

def test_client_initialization(sdk_installed):
    client = Guardian(api_key=API_KEY)
    assert client.api_key == API_KEY

def test_missing_api_key_raises_error(sdk_installed):
    with pytest.raises(GuardianValidationError):
        Guardian(api_key=None)

def test_analyze_success(guardian_client: Guardian, httpx_mock):
    mock_response = {"risk_score": 10, "threats_detected": []}
    httpx_mock.add_response(url=f"{BASE_URL}/v1/analyze", json=mock_response)

    result = guardian_client.analyze(text="a benign text")
    assert result["risk_score"] == 10

def test_analyze_api_error(guardian_client: Guardian, httpx_mock):
    httpx_mock.add_response(url=f"{BASE_URL}/v1/analyze", status_code=400, json={"detail": "Bad request"})

    with pytest.raises(GuardianAPIError) as exc_info:
        guardian_client.analyze(text="test")
    assert exc_info.value.status_code == 400

def test_analyze_rate_limit_error(guardian_client: Guardian, httpx_mock):
    headers = {"Retry-After": "30"}
    httpx_mock.add_response(url=f"{BASE_URL}/v1/analyze", status_code=429, headers=headers, json={})

    with pytest.raises(GuardianRateLimitError) as exc_info:
        guardian_client.analyze(text="test")
    assert exc_info.value.status_code == 429
    assert exc_info.value.retry_after == 30

def test_analyze_timeout_and_retry(guardian_client: Guardian, httpx_mock):
    # Simulate a timeout, then a success
    mock_responses = [
        httpx.TimeoutException("Request timed out"),
        httpx.Response(200, json={"risk_score": 5})
    ]
    httpx_mock.add_callback(lambda request, extensions=None: mock_responses.pop(0))
    # The SDK should retry and eventually succeed
    result = guardian_client.analyze(text="test with retry")
    assert result["risk_score"] == 5

def test_analyze_retry_failure(guardian_client: Guardian, httpx_mock):
    # Simulate persistent timeouts
    httpx_mock.add_exception(httpx.TimeoutException("Request timed out"))

    with pytest.raises(GuardianTimeoutError):
        guardian_client.analyze(text="test with persistent timeout")

def test_context_manager(httpx_mock, sdk_installed):
    httpx_mock.add_response(url=f"{BASE_URL}/v1/analyze", json={})
    with Guardian(api_key=API_KEY, base_url=BASE_URL) as client:
        client.analyze("test")
    # Check if the client is closed
    assert client._client.is_closed