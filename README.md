# Guardian API

**Guardian** is a high-performance, AI-powered API for real-time threat detection in text content. It provides a robust, scalable, and easy-to-integrate solution for identifying a wide range of security risks before they can harm your users or your platform.

[![CI](https://github.com/your-org/guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/guardian/actions/workflows/ci.yml)

## Table of Contents

- [Key Features](#key-features)
- [Threat Detection Categories](#threat-detection-categories)
- [System Architecture](#system-architecture)
- [Getting Started](#getting-started)
  - [Requirements](#requirements)
  - [Environment Variables](#environment-variables)
  - [Running the API Locally](#running-the-api-locally)
- [Documentation](#documentation)
- [SDKs](#sdks)
- [Deployment](#deployment)
- [Monitoring & Observability](#monitoring--observability)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Key Features

- **Comprehensive Threat Detection**: Identifies 14 categories of threats, from phishing and malware instructions to PII exfiltration and prompt injection.
- **Multi-Language Support**: Core detection patterns are optimized for English, Spanish, French, German, and Portuguese.
- **AI-Powered Enrichment**: Uses Google's Gemini model to provide deeper analysis, confidence scoring, and AI-generated text detection.
- **High Performance**: Built with FastAPI and designed for low-latency, high-throughput workloads.
- **Scalable & Resilient**: Features distributed rate limiting, caching, and robust error handling with automatic retries.
- **Production-Ready**: Comes with structured logging, comprehensive monitoring, and a flexible alerting system.
- **Easy Integration**: Provides official Python and Node.js SDKs with a clean, modern API.

## Threat Detection Categories

Guardian detects the following 14 threat categories. For a detailed explanation of each, please see the [Threat Detection Guide](./docs/threat-detection-guide.md).

1.  `phishing_attempt`
2.  `social_engineering`
3.  `credential_harvesting`
4.  `financial_fraud`
5.  `malware_instruction`
6.  `code_injection`
7.  `prompt_injection`
8.  `pii_exfiltration`
9.  `privacy_violation`
10. `toxic_content`
11. `hate_speech`
12. `misinformation`
13. `self_harm_risk`
14. `jailbreak_prompting`

## System Architecture

The API is built around a high-performance, asynchronous core using FastAPI. Key components include:

- **Classifier**: A multi-layered detection engine combining optimized regex patterns and AI.
- **Redis**: Used for distributed rate limiting and caching of analysis results.
- **Supabase**: A PostgreSQL database used for persistent logging and API key management.
- **Gemini**: Google's LLM used for AI enrichment and advanced analysis.

## Getting Started

### Requirements

- Python 3.11+
- Docker & Docker Compose
- A Supabase project (or a standard PostgreSQL database)
- A Redis instance
- A Google AI (Gemini) API key

### Development Setup

To get started with development and testing, you need to install the Python SDK in "editable" mode. This allows you to test changes to the SDK without having to reinstall it every time.

1.  **Automated Setup**:

    Run the development setup script to install all dependencies and the SDK in one go:

    ```bash
    python setup_dev.py
    ```

2.  **Manual Setup**:

    If you prefer to set up the environment manually, follow these steps:

    ```bash
    # Install the Python SDK in development mode
    pip install -e ./sdk/python

    # Install development and testing dependencies
    pip install -r api/requirements-dev.txt
    ```

3.  **Verify Installation**:

    After installation, you should be able to import the `guardian_sdk` in your Python environment:

    ```python
    try:
        from guardian_sdk import Guardian
        print("SDK installed successfully!")
    except ImportError:
        print("SDK not found. Please ensure it was installed correctly.")
    ```

### Environment Variables

Create a `.env` file in the root of the project. A comprehensive list of all variables can be found in `api/app/config.py`. The most important ones are:

```env
# General
ENV=development

# Auth & Security
GUARDIAN_API_KEYS=your_fallback_api_key_1,your_fallback_api_key_2

# Dependencies
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_key
REDIS_URL=redis://localhost:6379/0
GEMINI_API_KEY=your_gemini_api_key

# Logging & Alerting
LOG_LEVEL=INFO
ALERTING_ENABLED=True
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...
```

### Running the API Locally

1.  **Set up Environment**: Create a virtual environment and install dependencies:

    ```bash
    python -m venv .venv
    source .venv/bin/activate # On Windows, use .\.venv\Scripts\Activate.ps1
    pip install -r api/requirements.txt
    ```

2.  **Start Services**: If you don't have Redis running, you can use Docker:

    ```bash
    docker run -d -p 6379:6379 redis:alpine
    ```

3.  **Run the API**:

    ```bash
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --app-dir ./api
    ```

4.  **Test the API**:

    ```bash
    curl -X POST http://localhost:8000/v1/analyze \
      -H "Content-Type: application/json" \
      -H "X-API-Key: your_fallback_api_key_1" \
      -d '{"text": "Click here to reset your password: http://fake-login.com"}'
    ```

## Documentation

- **[API Reference](./docs/api-reference.md)**: Detailed documentation for all API endpoints, including request/response formats and error codes.
- **[Threat Detection Guide](./docs/threat-detection-guide.md)**: A comprehensive guide to the 14 threat categories Guardian detects.
- **[Deployment Guide](./docs/deployment-guide.md)**: Instructions for deploying the Guardian API to production environments.

## SDKs

We provide official SDKs for Python and Node.js to simplify integration.

- **[Python SDK](./sdk/python/README.md)**: A production-ready Python client with async support, connection pooling, and robust error handling.
- **[Node.js SDK](./sdk/node/guardian-sdk/README.md)**: A modern Node.js client with async/await, connection pooling, and detailed error handling.

## Monitoring & Observability

- **Health**: `GET /healthz` provides a detailed health status of the API and its dependencies.
- **Metrics**: `GET /metrics` exposes performance metrics in JSON format or Prometheus format if enabled.
- **Logging**: The API uses `structlog` for structured, context-aware logging, including correlation IDs for tracing requests.

## Testing

The project has a comprehensive test suite using `pytest`.

```bash
# Set the PYTHONPATH to include the app directory
export PYTHONPATH=$(pwd)/api

# Run tests
pytest
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.