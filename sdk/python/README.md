# Guardian Python SDK

[![PyPI version](https://badge.fury.io/py/guardian-sdk.svg)](https://badge.fury.io/py/guardian-sdk)

The official Python SDK for the Guardian API, providing a convenient and production-ready interface for real-time threat detection.

This SDK includes:
- A simple and intuitive API
- Robust error handling and automatic retries
- High-performance connection pooling
- Structured logging for observability
- Comprehensive configuration options

## Installation

Install the SDK using pip:

```bash
pip install guardian-sdk
```

## Quick Start

Here's a basic example of how to analyze a piece of text:

```python
import os
from guardian_sdk import Guardian, GuardianAPIError

# Initialize the client. API key can be passed directly or set via
# the GUARDIAN_API_KEY environment variable.
client = Guardian(api_key=os.getenv("GUARDIAN_API_KEY"))

text_to_analyze = "URGENT: Your account is locked. Click http://secure-login-portal.com to fix."

try:
    result = client.analyze(text=text_to_analyze)
    print(f"Risk Score: {result['risk_score']}")
    for threat in result['threats_detected']:
        print(f"- Detected Threat: {threat['category']} (Confidence: {threat['confidence_score']})")
except GuardianAPIError as e:
    print(f"API Error: {e.message} (Status: {e.status_code})")
finally:
    client.close() # Gracefully close connections
```

## Configuration

The client can be configured via the `GuardianConfig` class or by passing keyword arguments to the `Guardian` constructor.

```python
from guardian_sdk import Guardian, GuardianConfig
from httpx import Limits

# Advanced configuration
config = GuardianConfig(
    api_key="YOUR_API_KEY",
    base_url="https://api.your-guardian-instance.com",
    timeout_seconds=30.0,
    max_retries=5,
    debug=True, # Enable verbose logging
    limits=Limits(max_connections=200, max_keepalive_connections=40)
)

client = Guardian(config=config)
```

| Parameter         | Type         | Default                                  | Description                                                              |
| :---------------- | :----------- | :--------------------------------------- | :----------------------------------------------------------------------- |
| `api_key`         | `str`        | `os.getenv("GUARDIAN_API_KEY")`            | Your Guardian API key.                                                   |
| `base_url`        | `str`        | `"http://localhost:8000"`                  | The base URL of the Guardian API.                                        |
| `timeout_seconds` | `float`      | `15.0`                                   | Timeout for network requests.                                            |
| `max_retries`     | `int`        | `3`                                      | Maximum number of retries for transient errors (e.g., 5xx, timeouts).    |
| `debug`           | `bool`       | `False`                                  | If `True`, enables verbose structured logging to the console.            |
| `limits`          | `httpx.Limits` | `Limits(max_connections=100, ...)` | Configuration for connection pooling.                                    |

## Error Handling

The SDK raises specific exceptions for different types of errors, all inheriting from `GuardianError`.

- `GuardianValidationError`: Invalid input provided to the SDK (e.g., missing API key, empty text).
- `GuardianAPIError`: A generic error from the API (e.g., 400 Bad Request, 500 Internal Server Error).
- `GuardianRateLimitError`: A `429 Too Many Requests` error. The `retry_after` attribute contains the recommended wait time in seconds.
- `GuardianTimeoutError`: The request failed after exhausting all retries due to network timeouts or transient server issues.

**Example:**

```python
from guardian_sdk import Guardian, GuardianError, GuardianRateLimitError
import time

client = Guardian(api_key="YOUR_API_KEY")

try:
    client.analyze("some text")
except GuardianRateLimitError as e:
    print(f"Rate limited. Waiting for {e.retry_after} seconds.")
    time.sleep(e.retry_after)
except GuardianError as e:
    print(f"An unexpected Guardian error occurred: {e}")
```

## Best Practices

### Use as a Context Manager

For proper resource management, it is recommended to use the client as a context manager. This ensures that network connections are closed gracefully.

```python
with Guardian(api_key="YOUR_API_KEY") as client:
    result = client.analyze("some text")
    print(result)
```

### Singleton Instance

For most applications (e.g., a web server), you should create a single `Guardian` client instance and reuse it for all requests. This is crucial for connection pooling to work effectively.

```python
# In your application's initialization code (e.g., main.py)

from guardian_sdk import Guardian

guardian_client = Guardian(api_key="YOUR_API_KEY")

# In your request handlers:
def handle_request(text):
    return guardian_client.analyze(text)
```

## Logging

The SDK uses the `structlog` library for structured logging. To see detailed logs, including request/response information, enable debug mode:

```python
client = Guardian(api_key="YOUR_API_KEY", debug=True)
```

This will output detailed JSON-formatted logs to the console, which can be invaluable for debugging.