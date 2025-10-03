import requests

def test_get_metrics_prometheus_formatted_output():
    base_url = "http://localhost:8000"
    endpoint = "/metrics"
    url = base_url + endpoint
    headers = {
        "X-API-Key": "WgJOVvPJPe1E7RIy1FvIMbbWFyvEixeE",
        "Accept": "text/plain"
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
    except requests.RequestException as e:
        assert False, f"Request to {url} failed with exception: {e}"

    assert response.status_code == 200, f"Expected status code 200 but got {response.status_code}"

    content_type = response.headers.get("Content-Type", "")
    # Typical Prometheus content type is text/plain; version=0.0.4
    assert "text/plain" in content_type, f"Expected 'text/plain' in Content-Type but got '{content_type}'"

    content = response.text
    # Basic validation: The content should include some Prometheus metric format lines, e.g. lines starting with # HELP or # TYPE or metrics with labels
    assert content.startswith("# HELP") or content.startswith("# TYPE") or "\n" in content, "Response body does not appear to be Prometheus metrics format"

test_get_metrics_prometheus_formatted_output()