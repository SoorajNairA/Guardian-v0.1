import pytest
import time
from fastapi.testclient import TestClient
import asyncio

# Mark all tests in this file as performance-related
pytestmark = [pytest.mark.performance, pytest.mark.asyncio]

# Use a larger text sample for performance tests
LARGE_TEXT_SAMPLE = """
This is a larger block of text designed to test the performance of the classifier. 
It contains multiple sentences and patterns that might be found in real-world data. 
For example, it might contain a link like http://example.com/login which could be a phishing attempt. 
It also includes some phrases in other languages, like 'por favor' (Spanish) and 's'il vous plaît' (French). 
The goal is to ensure that the regex patterns and analysis logic can handle longer inputs without significant degradation in performance. 
We will repeat this block multiple times to simulate a very large input.
""" * 10

@pytest.mark.parametrize("text_length", [100, 1000, 10000, len(LARGE_TEXT_SAMPLE)])
def test_classifier_performance(benchmark, text_length):
    """Tests the raw performance of the classifier function."""
    from app.classifier import analyze_text
    text = LARGE_TEXT_SAMPLE[:text_length]
    
    async def analyze():
        await analyze_text(text)

    benchmark.pedantic(analyze, rounds=10)


def test_api_endpoint_latency(test_client: TestClient, benchmark, mock_supabase, mock_gemini):
    """Measures the latency of the /v1/analyze endpoint."""
    headers = {"X-API-Key": "test-key-1"}
    payload = {"text": "This is a performance test for the API endpoint."}

    benchmark(test_client.post, "/v1/analyze", headers=headers, json=payload)


async def test_concurrent_requests(test_client: TestClient, mock_supabase, mock_gemini):
    """Simulates multiple concurrent requests to test system stability."""
    num_requests = 50
    headers = {"X-API-Key": "test-key-1"}
    payload = {"text": "Concurrent request test."}

    async def make_request():
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, lambda: test_client.post("/v1/analyze", headers=headers, json=payload)
        )

    start_time = time.time()
    tasks = [make_request() for _ in range(num_requests)]
    responses = await asyncio.gather(*tasks)
    end_time = time.time()

    print(f"Completed {num_requests} concurrent requests in {end_time - start_time:.2f} seconds.")

    for response in responses:
        assert response.status_code == 200

    assert len(responses) == num_requests
