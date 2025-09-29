import asyncio
import os
from typing import AsyncGenerator, Generator
import importlib

import pytest
import pytest_asyncio
try:
    import httpx
except ImportError:
    httpx = None
from fastapi.testclient import TestClient
from redis.asyncio import Redis as AsyncRedis
import redis

from app import config
from app.main import app
from app.rate_limiter import get_redis_client
from app.crypto_utils import legacy_hash_api_key

# Fixture to verify SDK installation
@pytest.fixture(scope="session")
def sdk_installed():
    """
    Fixture to check if the guardian_sdk is installed.
    If not, provides a helpful error message.
    """
    try:
        import guardian_sdk
    except ImportError:
        pytest.fail(
            "The `guardian_sdk` is not installed in development mode. "
            "Please run `pip install -e ./sdk/python` from the root directory."
        )

@pytest.fixture
def settings():
    return config.settings

# Fixture to manage environment variables for tests
@pytest.fixture
def clean_environment() -> Generator:
    original_env = os.environ.copy()
    # Set test-specific environment variables
    os.environ["ENV"] = "testing"
    os.environ["SUPABASE_URL"] = ""
    os.environ["RATE_LIMIT_ENABLED"] = "False" # Disable rate limiting for most tests
    os.environ["GUARDIAN_API_KEYS"] = "test-key-1,test-key-2"

    importlib.reload(config)

    yield
    os.environ.clear()
    os.environ.update(original_env)
    importlib.reload(config)

# Fixture to provide a FastAPI TestClient
@pytest.fixture
def test_client(clean_environment: Generator) -> Generator[TestClient, None, None]:
    with TestClient(app) as client:
        yield client

# Fixture to disable rate limiting for specific tests
@pytest.fixture
def disable_rate_limiting(monkeypatch) -> None:
    monkeypatch.setattr(config.settings, "rate_limit_enabled", False)

# Mock Supabase client fixture
@pytest_asyncio.fixture
async def mock_supabase(monkeypatch, settings) -> None:
    class MockSupabaseQueryBuilder:
        def __init__(self, table_name: str):
            self.table_name = table_name
            self.queries = []

        def select(self, *args, **kwargs):
            return self

        def eq(self, column: str, value: str):
            self.queries.append((column, value))
            return self

        def execute(self):
            if self.table_name == "api_keys":
                key_hash_query = next((q for q in self.queries if q[0] == "key_hash"), None)
                hash_type_query = next((q for q in self.queries if q[0] == "hash_type"), None)

                if key_hash_query:
                    # Legacy SHA-256 lookup
                    allowed_keys = [k.strip() for k in settings.guardian_api_keys if k.strip()]
                    for key in allowed_keys:
                        if key_hash_query[1] == legacy_hash_api_key(key):
                            return type("obj", (object,), {"data": [{"id": "mock_key_id", "status": "active", "hash_type": "legacy", "key_hash": key_hash_query[1]}]})()
                
                if hash_type_query and hash_type_query[1] == "argon2":
                    # Argon2 fallback lookup
                    return type("obj", (object,), {"data": [{"id": "mock_argon_key_id", "status": "active", "hash_type": "argon2", "key_hash": "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$R+D7p/ST8+A3d5p/d4a/bA"}]})()

            return type("obj", (object,), {"data": []})()

    class MockSupabaseClient:
        def table(self, table_name: str):
            return MockSupabaseQueryBuilder(table_name)

        def insert(self, data):
            return self # No-op for logging

    monkeypatch.setattr("app.deps._supabase_client", MockSupabaseClient())
    monkeypatch.setattr("app.logging_client.logging_client._supabase", MockSupabaseClient())

# Mock Gemini client fixture
@pytest_asyncio.fixture
async def mock_gemini(monkeypatch) -> None:
    async def mock_post(*args, **kwargs):
        mock_response = httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": '```json\n{"propaganda_disinformation_confidence": 0.1, "is_ai_generated": false, "language": "en"}\n```'
                                }
                            ]
                        }
                    }
                ]
            }
        )
        return mock_response

    monkeypatch.setattr("httpx.AsyncClient.post", mock_post)

# Mock Redis client fixture
@pytest_asyncio.fixture
async def mock_redis(monkeypatch) -> None:
    # This is a simple mock. For complex tests, consider `fakeredis`.
    class MockRedis:
        class exceptions:
            ConnectionError = redis.exceptions.ConnectionError

        async def ping(self):
            return True
        async def zremrangebyscore(self, *args, **kwargs):
            return 0
        async def zadd(self, *args, **kwargs):
            return 1
        async def zcard(self, *args, **kwargs):
            return 1
        async def expire(self, *args, **kwargs):
            return True
        def pipeline(self, *args, **kwargs):
            return self # Return self for pipeline context
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args, **kwargs):
            pass
        async def execute(self):
            return [0, 1, 1, True]
        async def close(self):
            pass

    monkeypatch.setattr("app.rate_limiter.redis.ConnectionPool.from_url", lambda *args, **kwargs: MockRedis())

# Sample texts fixture
@pytest.fixture
def sample_texts() -> dict:
    return {
        "phishing": "Click here to reset your password: http://example-login.com/reset",
        "pii": "My social security number is 123-456-7890.",
        "hate_speech": "I hate people from that country.",
        "benign": "This is a perfectly normal sentence."
    }

# Mock logging client fixture
@pytest.fixture
def mock_logging_client(monkeypatch) -> list:
    captured_logs = []
    async def mock_log_event(entry):
        captured_logs.append(entry)
    
    monkeypatch.setattr("app.logging_client.logging_client.log_event", mock_log_event)
    return captured_logs
