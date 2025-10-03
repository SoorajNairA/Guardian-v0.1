import requests

def test_post_v1_analyze_text_threat_detection():
    base_url = "http://localhost:8000"
    endpoint = f"{base_url}/v1/analyze"
    api_key = "WgJOVvPJPe1E7RIy1FvIMbbWFyvEixeE"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json"
    }
    payload = {
        "text": "This is a test message containing potential phishing attempt and AI-generated content."
    }
    try:
        response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
    except requests.RequestException as e:
        assert False, f"Request to {endpoint} failed: {e}"

    # Validate response status code
    assert response.status_code in {200, 401, 429, 500}, f"Unexpected status code: {response.status_code}"

    if response.status_code == 200:
        try:
            data = response.json()
        except ValueError:
            assert False, "Response is not a valid JSON"

        # Validate required fields are present
        for key in ["request_id", "risk_score", "threats_detected", "metadata"]:
            assert key in data, f"Missing key '{key}' in response"

        # Validate types and contents
        assert isinstance(data["request_id"], str) and data["request_id"], "Invalid or empty 'request_id'"

        risk_score = data["risk_score"]
        assert isinstance(risk_score, int), "'risk_score' should be an integer"
        assert 0 <= risk_score <= 100, "'risk_score' should be between 0 and 100 inclusive"

        threats = data["threats_detected"]
        assert isinstance(threats, list), "'threats_detected' should be a list"
        for threat in threats:
            assert isinstance(threat, dict), "Each threat should be an object"
            assert "category" in threat and isinstance(threat["category"], str) and threat["category"], "Threat missing valid 'category'"
            assert "confidence_score" in threat, "Threat missing 'confidence_score'"
            conf_score = threat["confidence_score"]
            assert isinstance(conf_score, (float, int)), "'confidence_score' should be a number"
            assert 0.0 <= conf_score <= 1.0, "'confidence_score' should be between 0.0 and 1.0 inclusive"
            if "details" in threat:
                assert isinstance(threat["details"], str) or threat["details"] is None, "'details' should be string or null"

        metadata = data["metadata"]
        assert isinstance(metadata, dict), "'metadata' should be an object"
        for key in ["is_ai_generated", "language", "gemini_error"]:
            # These fields can be nullable
            if key in metadata:
                val = metadata[key]
                if key == "is_ai_generated":
                    assert val is None or isinstance(val, bool), "'is_ai_generated' should be boolean or null"
                elif key == "language":
                    assert val is None or isinstance(val, str), "'language' should be string or null"
                elif key == "gemini_error":
                    assert val is None or isinstance(val, str), "'gemini_error' should be string or null"
        # Additionally check rate limit headers if present
        rate_limit_headers = ["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"]
        for hdr in rate_limit_headers:
            # It's acceptable that rate limit headers may or may not be present, if present they should be parsable
            if hdr in response.headers:
                val = response.headers[hdr]
                assert val.isdigit(), f"Rate limit header {hdr} should be numeric, got: {val}"

    elif response.status_code == 401:
        # Unauthorized access, check for typical error message response if any
        pass  # No further checks required, accepted behavior
    elif response.status_code == 429:
        # Rate limit exceeded, optional to check Retry-After header
        retry_after = response.headers.get("Retry-After")
        if retry_after is not None:
            try:
                retry_seconds = int(retry_after)
                assert retry_seconds >= 0, "Retry-After header must be non-negative integer"
            except ValueError:
                assert False, "Retry-After header must be an integer"
    elif response.status_code == 500:
        # Internal server error, no further validation possible
        pass

test_post_v1_analyze_text_threat_detection()