# Guardian API Reference

Welcome to the Guardian API documentation. This guide provides detailed information about the API endpoints, authentication, error handling, and other essential details for integrating with Guardian.

## API Architecture Overview

The Guardian API is a high-performance, asynchronous service built with FastAPI. It uses a multi-layered approach for threat detection:

1.  **Pattern Matching**: A highly optimized regex-based classifier for immediate detection of common threats.
2.  **AI Enrichment**: Google's Gemini model provides deeper analysis, confidence scoring, and language detection.
3.  **Caching**: A Redis-based cache stores recent analysis results to improve performance and reduce latency.
4.  **Rate Limiting**: A distributed Redis-based rate limiter protects the API from abuse.
5.  **Async Logging**: A background worker queues and sends detailed logs to Supabase without blocking requests.

## Authentication

All API requests must be authenticated using an API key. The key must be included in the `X-API-Key` header of your request.

```http
X-API-Key: YOUR_API_KEY
```

API keys can be managed in your Guardian dashboard or configured via environment variables on the server.

## Endpoints

### `POST /v1/analyze`

This is the primary endpoint for analyzing text content.

#### Request Body

| Field      | Type   | Required | Description                                                                 |
| :--------- | :----- | :------- | :-------------------------------------------------------------------------- |
| `text`     | string | Yes      | The text content to analyze. Max length: 100,000 characters.                |
| `config`   | object | No       | Optional configuration for the analysis.                                    |
| `config.model_version` | string | No | Specifies a custom model version for analysis. |
| `config.compliance_mode` | string | No | Adjusts sensitivity. Options: `strict`, `moderate`, `permissive`. |

**Example Request:**

```json
{
  "text": "URGENT: Your bank account has been compromised. Click here to secure it: http://fake-bank-login.com",
  "config": {
    "compliance_mode": "strict"
  }
}
```

#### Response Body

A successful response returns a JSON object with the analysis results.

| Field              | Type    | Description                                                                    |
| :----------------- | :------ | :----------------------------------------------------------------------------- |
| `request_id`       | string  | A unique identifier for the request (corresponds to the correlation ID).       |
| `risk_score`       | integer | An overall risk score from 0 (none) to 100 (critical).                         |
| `threats_detected` | array   | A list of `Threat` objects, one for each detected threat.                      |
| `metadata`         | object  | Additional metadata, including AI enrichment results.                          |

**Example Response:**

```json
{
  "request_id": "corr-12345",
  "risk_score": 85,
  "threats_detected": [
    {
      "category": "phishing_attempt",
      "confidence_score": 0.9,
      "details": "Contains a suspicious link with urgent language."
    }
  ],
  "metadata": {
    "is_ai_generated": false,
    "language": "en"
  }
}
```

## Error Handling

The API uses standard HTTP status codes to indicate the success or failure of a request.

| Status Code | Meaning                 | Description                                                                                             |
| :---------- | :---------------------- | :------------------------------------------------------------------------------------------------------ |
| `200 OK`      | Success                 | The request was successful, and the analysis is in the response body.                                   |
| `401 Unauthorized` | Authentication Error    | The provided API key is missing or invalid.                                                             |
| `422 Unprocessable Entity` | Validation Error        | The request body is malformed (e.g., missing `text` field, text too long). The response includes details. |
| `429 Too Many Requests` | Rate Limit Exceeded     | You have exceeded the number of allowed requests. Check the `Retry-After` header.                     |
| `500 Internal Server Error` | Server Error            | An unexpected error occurred on the server.                                                             |
| `503 Service Unavailable` | Health Check Failure    | A critical dependency (like the database or AI model) is down.                                          |

## Rate Limiting

The API enforces rate limits based on both API key and IP address. When you exceed a rate limit, you will receive a `429 Too Many Requests` response.

Check the following headers in the response to manage your request rate:

- `X-RateLimit-Limit`: The total number of requests allowed in the current window.
- `X-RateLimit-Remaining`: The number of requests remaining in the current window.
- `X-RateLimit-Reset`: The UTC timestamp when the rate limit window will reset.
- `Retry-After`: The number of seconds to wait before making another request.

## Monitoring Endpoints

- `GET /healthz`: Provides a detailed health status of the API and its dependencies (Supabase, Redis, Gemini).
- `GET /metrics`: Returns a JSON summary of application performance metrics. If Prometheus is enabled, this endpoint will serve Prometheus-formatted metrics.
