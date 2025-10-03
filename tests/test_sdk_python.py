"""
Tests for the Guardian Python SDK (guardian_securitysdk).

Requires the SDK to be installed in development mode:
  pip install -e ./sdk/python
or from TestPyPI/PyPI:
  pip install guardian-securitysdk==0.2.1
"""

import pytest

# Attempt to import the SDK and provide a helpful error message if it fails
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

API_KEY = "test-sdk-key"
BASE_URL = "http://test-server.com"


@pytest.fixture
def guardian_client(httpx_mock) -> Guardian:
    config = GuardianConfig(api_key=API_KEY, base_url=BASE_URL, max_retries=2)
    return Guardian(config)


def test_client_initialization():
    client = Guardian(api_key=API_KEY)
    assert client.api_key == API_KEY


def test_missing_api_key_raises_error():
    with pytest.raises(GuardianValidationError):
        Guardian(api_key=None)


def test_analyze_success(guardian_client: Guardian, httpx_mock):
    mock_response = {"risk_score": 10, "threats_detected": [], "metadata": {}}
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
    # Simulate a timeout on first attempt, then a success on retry
    httpx_mock.add_exception(httpx.TimeoutException("Request timed out"))
    httpx_mock.add_response(url=f"{BASE_URL}/v1/analyze", json={"risk_score": 5, "threats_detected": [], "metadata": {}})
    # The SDK should retry and eventually succeed
    result = guardian_client.analyze(text="test with retry")
    assert result["risk_score"] == 5


def test_analyze_retry_failure(guardian_client: Guardian, httpx_mock):
    # Simulate persistent timeouts
    httpx_mock.add_exception(httpx.TimeoutException("Request timed out"))
    httpx_mock.add_exception(httpx.TimeoutException("Request timed out"))

    with pytest.raises(GuardianTimeoutError):
        guardian_client.analyze(text="test with persistent timeout")


def test_context_manager(httpx_mock):
    httpx_mock.add_response(url=f"{BASE_URL}/v1/analyze", json={"risk_score": 0, "threats_detected": [], "metadata": {}})
    with Guardian(api_key=API_KEY, base_url=BASE_URL) as client:
        client.analyze("test")
    # Check if the client is closed
    assert client._client.is_closed