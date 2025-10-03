# Guardian Security Platform - Complete Setup Guide

## Overview
This guide will help you set up the complete Guardian Security Platform with all services connected: Backend API, Frontend, Supabase Database, Redis, and Google Gemini AI.

## Prerequisites
- Python 3.8+ installed
- Node.js 16+ installed
- Git installed
- A Supabase account
- A Google AI Studio account
- Redis (local or cloud)

## Step 1: Set Up Supabase Database

### 1.1 Create Supabase Project
1. Go to [supabase.com](https://supabase.com)
2. Sign up/login and create a new project
3. Choose a region close to you
4. Wait for the project to be ready (2-3 minutes)

### 1.2 Set Up Database Schema
1. In Supabase dashboard, go to **SQL Editor**
2. Copy and paste the contents of `supabase/schema.sql`:
3. Click **Run** to execute the schema

### 1.3 Get Supabase Credentials
1. Go to **Settings** > **API**
2. Copy your:
   - Project URL
   - Anon public key
   - Service role key (keep this secret!)

### 1.4 Add API Keys to Database
1. Go to **SQL Editor** again
2. Run the generated SQL from the key generator:
```sql
INSERT INTO public.api_keys (key_hash, hash_type, owner_email, status) VALUES
('$argon2id$v=19$m=65536,t=3,p=4$8792Rg9XlApZR7rAxhN7dw$BsgpQ8nJJ3PE1quzNLzYGERBkmH1mTyshsgXNogNLn0', 'argon2', 'your-email@example.com', 'active'),
('$argon2id$v=19$m=65536,t=3,p=4$4f9ktzj13k3++YONAbOVlQ$9+fifzSVingf8U6zv6/S0X0nNqrgEtVElngtj+rUCpk', 'argon2', 'your-email@example.com', 'active');
```

## Step 2: Set Up Redis

### Option A: Local Redis (Development)
**Windows:**
```bash
# Using Chocolatey
choco install redis-64

# Or download from: https://github.com/microsoftarchive/redis/releases
# Start Redis
redis-server
```

**macOS:**
```bash
brew install redis
brew services start redis
```

**Linux:**
```bash
sudo apt-get install redis-server
sudo systemctl start redis
```

### Option B: Redis Cloud (Production)
1. Go to [redis.com](https://redis.com)
2. Create free account and instance
3. Note down connection URL

## Step 3: Set Up Google Gemini API

1. Go to [Google AI Studio](https://aistudio.google.com)
2. Sign in with Google account
3. Click **Get API Key** > **Create API Key**
4. Copy the generated API key

## Step 4: Configure Environment Variables

Update the `.env` file in `api/` directory with your actual credentials:

```env
# Environment
ENV=development

# API Keys (already generated)
GUARDIAN_API_KEYS=WgJOVvPJPe1E7RIy1FvIMbbWFyvEixeE,NN4vXI5yALPdGi5H3vqeBjGhbcVxd04K

# Supabase Configuration (replace with your actual values)
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# Redis Configuration
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=
REDIS_SSL=False

# Gemini Configuration (replace with your actual key)
GEMINI_API_KEY=your-gemini-api-key
GEMINI_MODEL=gemini-1.5-flash

# Rate Limiting
RATE_LIMIT_ENABLED=True
RATE_LIMIT_FALLBACK_TO_MEMORY=True
DEFAULT_RATE_LIMIT_PER_KEY=100
DEFAULT_RATE_LIMIT_PER_IP=1000
RATE_LIMIT_WINDOW_SECONDS=60

# Health Checks
HEALTH_CHECK_TIMEOUT_SECONDS=5
HEALTH_CHECK_SUPABASE_ENABLED=True
HEALTH_CHECK_REDIS_ENABLED=True
HEALTH_CHECK_GEMINI_ENABLED=True

# Logging
LOG_LEVEL=INFO
LOG_TO_FILE=False

# Metrics
METRICS_ENABLED=True
PROMETHEUS_METRICS_ENABLED=True
PROMETHEUS_METRICS_PORT=8001

# Alerting (optional)
ALERTING_ENABLED=False
ALERT_WEBHOOK_URL=
```

## Step 5: Install and Run Backend

```bash
# Navigate to API directory
cd api

# Install dependencies
pip install -r requirements.txt

# Run the API server
uvicorn app.main:app --reload --port 8000
```

The API will be available at:
- **API**: http://localhost:8000
- **Docs**: http://localhost:8000/docs
- **Health**: http://localhost:8000/health
- **Metrics**: http://localhost:8001/metrics

## Step 6: Install and Run Frontend

```bash
# Navigate to Frontend directory
cd Frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will be available at: http://localhost:5173

## Step 7: Test the Complete Setup

### 7.1 Test API Health
```bash
curl http://localhost:8000/health
```

### 7.2 Test Analysis Endpoint
```bash
curl -X POST "http://localhost:8000/v1/analyze" \
  -H "X-API-Key: WgJOVvPJPe1E7RIy1FvIMbbWFyvEixeE" \
  -H "Content-Type: application/json" \
  -d '{"text": "This is a test message for threat detection"}'
```

### 7.3 Test Frontend
1. Open http://localhost:5173
2. Enter an API key: `WgJOVvPJPe1E7RIy1FvIMbbWFyvEixeE`
3. Enter some text to analyze
4. Click "Analyze Text"

## Step 8: Run Tests

```bash
# From project root
cd "C:\SIH Project\Guardian-v0.1"

# Run all tests
pytest -vv tests

# Run specific test categories
pytest -vv tests/test_api_endpoints.py
pytest -vv tests/test_auth.py
pytest -vv tests/test_analyze.py
```

## Troubleshooting

### Common Issues

1. **Redis Connection Error**
   - Make sure Redis is running: `redis-server`
   - Check Redis URL in .env file

2. **Supabase Connection Error**
   - Verify SUPABASE_URL and keys are correct
   - Check if database schema was applied

3. **Gemini API Error**
   - Verify GEMINI_API_KEY is correct
   - Check API quota limits

4. **Rate Limiting Issues**
   - Check Redis connection
   - Verify rate limit settings in .env

5. **Frontend Not Loading**
   - Check if backend is running on port 8000
   - Verify API key is correct

### Health Check Endpoints

- **Overall Health**: http://localhost:8000/health
- **Supabase**: http://localhost:8000/health/supabase
- **Redis**: http://localhost:8000/health/redis
- **Gemini**: http://localhost:8000/health/gemini

## Production Deployment

For production deployment:

1. **Environment Variables**: Use proper secrets management
2. **Database**: Use production Supabase instance
3. **Redis**: Use Redis Cloud or managed Redis
4. **API Keys**: Rotate regularly and use strong keys
5. **Monitoring**: Enable Prometheus metrics and alerting
6. **SSL**: Use HTTPS for all endpoints
7. **Rate Limiting**: Adjust limits based on usage

## API Usage Examples

### Python SDK
```python
from guardian_sdk import GuardianClient

client = GuardianClient(
    api_key="WgJOVvPJPe1E7RIy1FvIMbbWFyvEixeE",
    base_url="http://localhost:8000"
)

result = client.analyze("Suspicious text here")
print(f"Risk Score: {result.risk_score}")
print(f"Threats: {result.threats_detected}")
```

### Node.js SDK
```javascript
const GuardianClient = require('guardian-sdk');

const client = new GuardianClient({
    apiKey: 'WgJOVvPJPe1E7RIy1FvIMbbWFyvEixeE',
    baseUrl: 'http://localhost:8000'
});

const result = await client.analyze('Suspicious text here');
console.log('Risk Score:', result.risk_score);
console.log('Threats:', result.threats_detected);
```

### Direct API Calls
```bash
curl -X POST "http://localhost:8000/v1/analyze" \
  -H "X-API-Key: WgJOVvPJPe1E7RIy1FvIMbbWFyvEixeE" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Click here to reset your password immediately!",
    "config": {
      "model_version": "v1",
      "compliance_mode": "strict"
    }
  }'
```

## Next Steps

1. **Customize Threat Patterns**: Edit `api/app/classifier.py`
2. **Add New Integrations**: Extend the API endpoints
3. **Set Up Monitoring**: Configure Prometheus and Grafana
4. **Deploy to Cloud**: Use Docker, Kubernetes, or cloud services
5. **Scale**: Add load balancers and multiple instances

## Support

If you encounter issues:
1. Check the logs in the terminal
2. Verify all services are running
3. Test individual components using health endpoints
4. Review the troubleshooting section above
