import requests

def test_get_healthz_system_health_status():
    base_url = "http://localhost:8000"
    endpoint = "/healthz"
    url = f"{base_url}{endpoint}"
    headers = {
        "X-API-Key": "WgJOVvPJPe1E7RIy1FvIMbbWFyvEixeE"
    }
    try:
        response = requests.get(url, headers=headers, timeout=30)
        # Validate response status code is either 200 (healthy) or 503 (unhealthy)
        assert response.status_code in (200, 503), f"Unexpected status code {response.status_code}"
        # Optionally response content can be checked if schema known, but PRD doesn't specify
    except requests.RequestException as e:
        assert False, f"Request to {url} failed with exception: {e}"

test_get_healthz_system_health_status()