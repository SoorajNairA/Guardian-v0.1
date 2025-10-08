# Guardian Security Platform - Complete Setup Guide

## Overview
This guide provides detailed instructions for setting up the Guardian Security Platform. It covers both Docker-based deployment and manual setup options, making it suitable for both production and development environments.

## Prerequisites

### Required
- Python 3.11+ installed
- Docker & Docker Compose (recommended)
- Git installed
- A Supabase account
- A Google AI Studio (Gemini) API key

### Optional
- Node.js 18+ (for frontend development)
- Redis (for distributed deployments)
- VS Code with Python extension (recommended for development)

## Quick Start (Docker)
For those who want to get started quickly:

```bash
# Clone repository
git clone https://github.com/SoorajNairA/Guardian-v0.1.git
cd Guardian-v0.1

# Copy and edit environment variables
cp .env.example .env

# Start all services
docker compose up -d

# Verify the API
curl -X POST "http://localhost:8000/v1/analyze" \
     -H "Content-Type: application/json" \
     -H "X-API-Key: your-api-key" \
     -d '{"text": "Hello, world!"}'
```

For detailed setup instructions, continue reading below.

## Detailed Setup Instructions

## 1. Core Services Setup

### 1.1 Supabase Database Setup

1. **Create Supabase Project**
   - Visit [supabase.com](https://supabase.com)
   - Create a new project
   - Note down your project URL and keys

2. **Initialize Database**
   ```bash
   # Run schema migrations
   psql -h your-db-host -U postgres -d postgres -f supabase/schema.sql
   
   # Or use Supabase Dashboard:
   # 1. Go to SQL Editor
   # 2. Copy contents of supabase/schema.sql
   # 3. Execute
   ```

3. **Generate API Keys**
   ```bash
   # Use the provided script
   python scripts/generate_api_keys.py --email your@email.com
   
   # Or use the web interface at /admin/keys
   ```

### 1.2 Google Gemini API Setup

1. **Get API Key**
   - Go to [Google AI Studio](https://aistudio.google.com)
   - Create API key
   - Add key to `.env` file

2. **Configure Model Settings** (Optional)
   ```env
   GEMINI_MODEL=models/gemini-pro-latest
   GEMINI_ENRICHMENT_ENABLED=True
   GEMINI_INCLUDE_ERROR_IN_RESPONSE=True
   ```

### 1.3 Redis Setup (Optional)

Choose one option:

**A. Docker (Recommended)**
```bash
# Included in docker-compose.yml
docker compose up -d redis
```

**B. Local Installation**
```bash
# Windows (PowerShell Admin)
choco install redis-64
redis-server

# macOS
brew install redis
brew services start redis

# Linux
sudo apt install redis-server
sudo systemctl start redis
```

**C. Redis Cloud**
- Visit [redis.com](https://redis.com)
- Create free account
- Get connection URL

## 2. Environment Configuration

### 2.1 Basic Configuration
Copy and edit the environment template:
```bash
cp .env.example .env
```

### 2.2 Required Variables
```env
# Core Settings
ENV=development
PORT=8000

# API Security
GUARDIAN_API_KEYS=your-generated-keys
API_KEY_HASH_TYPE=argon2

# Database
SUPABASE_URL=your-project-url
SUPABASE_SERVICE_ROLE_KEY=your-service-key

# AI Integration
GEMINI_API_KEY=your-gemini-key
GEMINI_MODEL=models/gemini-pro-latest

# Optional Redis
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=
REDIS_SSL=False
```

### 2.3 Optional Settings
```env
# Performance Tuning
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# Caching
CACHE_ENABLED=True
CACHE_TTL=300

# Logging
LOG_LEVEL=INFO
STRUCTURED_LOGGING=True

# Privacy
PRIVACY_MODE=standard  # minimal, standard, or strict
```

## 3. Running the Services

### 3.1 Development Setup

**A. Docker Compose (Recommended)**
```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f api

# Stop services
docker compose down
```

**B. Local Development**
```bash
# Install dependencies
cd api
pip install -r requirements.txt

# Start API server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Start frontend (separate terminal)
cd Frontend
npm install
npm run dev
```

### 3.2 Production Deployment

**A. Docker Deployment**
```bash
# Build optimized image
docker build -t guardian-api:latest ./api

# Run with production settings
docker run -d \
  --name guardian-api \
  -p 8000:8000 \
  -v /path/to/logs:/app/logs \
  --env-file .env.prod \
  guardian-api:latest
```

**B. Kubernetes Deployment**
```bash
# Apply configurations
kubectl apply -f k8s/

# Check status
kubectl get pods -l app=guardian-api

# View logs
kubectl logs -f deployment/guardian-api
```

## 4. Testing & Validation

### 4.1 Verify Installation

1. Check API Health:
```bash
curl http://localhost:8000/healthz
```

2. Verify Services:
```bash
# Check Supabase connection
curl http://localhost:8000/healthz/supabase

# Check Redis if enabled
curl http://localhost:8000/healthz/redis

# Check Gemini integration
curl http://localhost:8000/healthz/gemini
```

3. Verify Frontend:
```bash
# Check if frontend is running
curl http://localhost:5173
```

## 5. Monitoring & Troubleshooting

### 5.1 Health Checks
```bash
# Basic health
curl http://localhost:8000/healthz

# Component status
curl http://localhost:8000/healthz/detail
```

### 5.2 Metrics
- Prometheus: http://localhost:8000/metrics 
- Dashboard: http://localhost:8000/dashboard

### 5.3 Common Issues

1. **Redis Connection Errors**
   - Check Redis is running: `redis-cli ping`
   - Verify URL in .env matches Redis host/port
   - Check network connectivity & SSL settings

2. **Supabase Issues**
   - Verify credentials in .env
   - Check database schema is applied
   - Test connection: `curl $SUPABASE_URL/rest/v1/`

3. **Gemini API Issues** 
   - Validate API key is active
   - Check quota/rate limits
   - Verify model name is correct

4. **Rate Limiting**
   - Check Redis rate limit keys
   - Adjust limits in configuration
   - Monitor usage patterns

### 5.4 Logs
```bash
# View API logs
tail -f logs/guardian-api.log

# Structured logging 
jq '.' logs/guardian-api.jsonl

# Docker container logs
docker compose logs -f api
```

## 6. SDKs & API Usage

### Python SDK
```python
from guardian_sdk import GuardianClient

client = GuardianClient(
    api_key="YOUR_API_KEY",
    base_url="http://localhost:8000"
)

# Basic analysis
result = client.analyze_text("Test message")
print(result.risk_score)

# With configuration
result = client.analyze_text(
    text="Test message",
    config={
        "model": "v2",
        "privacy_level": "high"
    }
)
```

### Node.js SDK
```javascript
const { GuardianClient } = require('@guardian/sdk');

const client = new GuardianClient({
  apiKey: 'YOUR_API_KEY',
  baseUrl: 'http://localhost:8000'
});

// Basic analysis
const result = await client.analyzeText('Test message');
console.log(result.riskScore);

// With configuration
const result = await client.analyzeText('Test message', {
  model: 'v2',
  privacyLevel: 'high'
});
```

### Direct API Calls
```bash
# Basic analysis
curl -X POST "http://localhost:8000/v1/analyze" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text": "Test message"}'

# With configuration
curl -X POST "http://localhost:8000/v1/analyze" \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Test message",
    "config": {
      "model": "v2",
      "privacy_level": "high"
    }
  }'
```

## 7. Next Steps

### 7.1 Production Readiness
1. Set up SSL/TLS
2. Configure proper secrets management
3. Implement automated backups
4. Set up monitoring & alerting
5. Document incident response

### 7.2 Feature Development
1. Customize threat detection rules
2. Add new AI model integrations
3. Implement advanced analytics
4. Create admin dashboard
5. Add batch processing support

### 7.3 Scaling
1. Deploy multiple API instances
2. Set up load balancing
3. Implement caching
4. Optimize database queries
5. Monitor performance metrics

## Support

Need help? 

1. Check documentation: `/docs/` directory
2. Run health checks: `/healthz/detail`
3. Review logs: `logs/guardian-api.log`
4. Open issues on GitHub
5. Contact maintainers
