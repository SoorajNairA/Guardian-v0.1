# Guardian API

**Guardian** is a high-performance, AI-powered API for real-time threat detection in text content. It provides a robust, scalable, and easy-to-integrate solution for identifying a wide range of security risks before they can harm your users or your platform.

## Table of Contents

- [Key Features](#key-features)
- [Threat Detection Categories](#threat-detection-categories)
- [System Architecture](#system-architecture)
- [Quick Start](#quick-start)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Basic Usage](#basic-usage)
- [Detailed Documentation](#detailed-documentation)
- [SDKs](#sdks)
- [Deployment](#deployment)
- [Development](#development)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Key Features

- **Real-time Threat Analysis**: Millisecond-level response times for immediate threat detection
- **Advanced AI Integration**: Powered by Google's Gemini model for sophisticated content analysis
- **Multi-Layer Detection**:
  - Pattern-based analysis for known threats
  - ML-based classification for emerging threats
  - AI-powered contextual understanding
  - Graph-based entity correlation
- **Comprehensive Coverage**: Identifies 14+ categories of threats and security risks
- **Privacy-First Design**: 
  - Optional PII redaction
  - Configurable privacy modes
  - Data minimization principles
- **Enterprise Features**:
  - Distributed rate limiting
  - Result caching
  - Automatic retries
  - Load balancing
  - Health monitoring
  - Prometheus metrics

## Threat Detection Categories

Guardian's multi-layered detection system covers:

1. **Security Threats**
   - 🎣 Phishing attempts
   - 🔐 Credential harvesting
   - 🦠 Malware distribution
   - 💉 Code injection
   - 🎭 Social engineering

2. **Privacy Risks**
   - 🔒 PII exposure
   - 📄 Data leakage
   - 🕵️ Privacy violations
   - 🎯 Targeting attempts

3. **AI-Specific Threats**
   - 🤖 Prompt injection
   - 🔓 Jailbreak attempts
   - 🎯 Model manipulation
   - ⚠️ Unsafe instructions

4. **Content Risks**
   - 🚫 Toxic content
   - 💢 Hate speech
   - ❌ Misinformation
   - ⚠️ Self-harm risks

## Quick Start

### Requirements

- Python 3.11+
- Docker & Docker Compose
- Supabase account or PostgreSQL database
- Redis (optional, for rate limiting)
- Google AI (Gemini) API key

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/SoorajNairA/Guardian-v0.1.git
   cd Guardian-v0.1
   ```

2. **Setup Options**

   **Option A: Using Docker (Recommended)**
   ```bash
   # Copy and edit environment variables
   cp .env.example .env

   # Start all services
   docker compose up -d
   ```

   **Option B: Manual Setup**
   ```bash
   # Create and activate virtual environment
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   # or
   .venv\Scripts\activate     # Windows

   # Install dependencies
   pip install -r api/requirements.txt
   pip install -r api/requirements-dev.txt  # if developing

   # Install SDK in development mode (if developing)
   pip install -e sdk/python

   # Copy and edit environment variables
   cp .env.example .env
   ```

### Basic Usage

```python
from guardian_sdk import Guardian

# Initialize client
guardian = Guardian(api_key="your-api-key")

# Analyze text
result = guardian.analyze("Text to analyze")

# Check results
if result.risk_score > 70:
    print(f"High risk content detected! Score: {result.risk_score}")
    for threat in result.threats_detected:
        print(f"- {threat.category}: {threat.details}")
```

## Development

### Local Development Setup

1. **Install dependencies**
   ```bash
   pip install -r api/requirements-dev.txt
   pip install -e sdk/python
   ```

2. **Start development server**
   ```bash
   uvicorn api.app.main:app --reload
   ```

3. **Run tests**
   ```bash
   pytest tests/
   ```

### Architecture Overview

The system consists of several key components:

- **FastAPI Backend**: High-performance async API
- **Classifier Engine**: Multi-layered threat detection
- **Gemini Integration**: AI-powered analysis
- **Redis Cache**: Rate limiting and result caching
- **Supabase**: API key management and logging

## Testing

Guardian includes comprehensive test suites:

- Unit tests
- Integration tests
- Performance tests
- Load tests
- Security tests

Run tests with:
```bash
pytest tests/  # All tests
pytest tests/test_classifier_comprehensive.py  # Specific module
```

## Metrics & Monitoring

Guardian exposes metrics at `/metrics` in Prometheus format:
- Request rates and latencies
- Cache hit/miss ratios
- Error rates and types
- Threat detection statistics
- System health indicators

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
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