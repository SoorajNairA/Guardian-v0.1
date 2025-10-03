# TestSprite AI Testing Report (Completed)

## Document Metadata
- Project Name: Guardian-v0.1-api
- Date: 2025-10-03
- Prepared by: AI Assistant

## Requirement Groups and Test Results

### R1: Analysis API - Detect threats and return structured result
- Endpoint: POST /v1/analyze
- Expectations:
  - Accepts JSON body with `text` and optional `config`
  - Returns 200 with fields: `request_id`, `risk_score`, `threats_detected[]`, `metadata`

Tests:
- TC001 post v1 analyze text threat detection — Status: Passed
  - Findings: Endpoint responds 200 with valid JSON schema. `risk_score` present. `threats_detected` is an array. `metadata.language` populated; Gemini errors gracefully handled.

### R2: Health API - Report overall and dependency health
- Endpoint: GET /healthz
- Expectations:
  - Returns overall health and dependency statuses
  - Non-200 if any core dependency is unhealthy

Tests:
- TC002 get healthz system health status — Status: Passed
  - Findings: Health endpoint responds with status and dependency array. Gemini may be degraded (404) without blocking overall API functionality.

### R3: Metrics API - Expose Prometheus metrics
- Endpoint: GET /metrics
- Expectations:
  - Returns Prometheus text exposition format (Content-Type: text/plain; version=0.0.4)

Tests:
- TC003 get metrics prometheus formatted output — Status: Failed
  - Error: Expected 'text/plain' in Content-Type but got 'application/json'
  - Likely Cause: Metrics endpoint is mounted conditionally or returning JSON wrapper instead of raw Prometheus format in this environment.
  - Suggested Fix:
    - Ensure metrics are mounted with `prometheus_client.make_asgi_app()` at `/metrics` and not re-wrapped by FastAPI JSONResponse.
    - Verify `settings.prometheus_metrics_enabled` so the mount path is active.
    - When disabled, consider hiding `/metrics` or returning 404 to align with expectations.

## Coverage & Matching Metrics
- 3 total tests: 2 passed, 1 failed (66.67% pass rate)

## Key Gaps / Risks
- Metrics endpoint returns JSON rather than Prometheus text format. Action: enforce `text/plain` content type by mounting the Prometheus ASGI app and avoiding JSON responses at `/metrics`.
- Gemini enrichment may be degraded if model/key mismatch. Mitigation: use google-generativeai SDK (added) and v1 models (e.g., `gemini-1.5-flash`), or disable enrichment in prod until validated.

## Next Actions
- Update metrics route handling as above; re-run Testsprite to validate TC003.
- Validate Gemini with a working key/model or keep enrichment disabled.
