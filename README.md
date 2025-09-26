# Guardian v0.1

Argus Guardian is a FastAPI-based moderation service that detects malicious or policy-violating text using heuristics with optional Gemini enrichment, logs to Supabase, and provides Python/Node SDKs. A localhost-only dev panel shows live metrics.

## Features

- FastAPI `/v1/analyze` with risk score and threat categories
- Heuristic classifier + optional Gemini enrichment (fallback safe)
- API key auth (hashed lookup in Supabase, env fallback)
- Supabase logging (RLS-ready schema included)
- SDKs: Python (`guardian-sdk`), Node (`guardian-sdk`)
- Localhost-only dev panel at `/dev`

## Requirements

- Python 3.11+
- Node.js 18+ (for Node SDK usage/build)
- Optional: Supabase project (URL + Service Role key)
- Optional: Gemini API key

## Environment Variables

- GUARDIAN_API_KEY or GUARDIAN_API_KEYS (comma-separated) – fallback auth
- SUPABASE_URL – e.g. `https://<project>.supabase.co`
- SUPABASE_SERVICE_ROLE_KEY – for server-side inserts and key lookup
- GEMINI_API_KEY – optional LLM enrichment
- GEMINI_MODEL – default `gemini-1.5-flash`

Create a `.env` locally or export in your shell before running.

## Run the API (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r .\Guardian-v0.1\api\requirements.txt -r .\Guardian-v0.1\api\requirements-dev.txt

$env:GUARDIAN_API_KEY="ag_123"
# Optional:
# $env:SUPABASE_URL="https://YOUR.supabase.co"
# $env:SUPABASE_SERVICE_ROLE_KEY="srk_..."
# $env:GEMINI_API_KEY="AIza..."

uvicorn app.main:app --host 0.0.0.0 --port 8000 --app-dir .\Guardian-v0.1\api
```

Smoke test:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/healthz
$headers = @{ "Content-Type" = "application/json"; "X-API-Key" = "ag_123" }
$body = @{ text = "Click here to reset your password" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/analyze" -Method POST -Headers $headers -Body $body | ConvertTo-Json -Depth 6
```

Dev panel (localhost only): `http://127.0.0.1:8000/dev`

## Supabase Setup

Apply schema:

```sql
-- Guardian-v0.1/supabase/schema.sql
```

- Insert API keys as SHA-256 hashes in `api_keys.key_hash` (see example script below).
- The API will verify keys by hash when `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` are set; otherwise uses env fallback.

Create a production key (one-off):

```powershell
python - << 'PY'
import os, base64, secrets, hashlib
from supabase import create_client
url, key = os.environ['SUPABASE_URL'], os.environ['SUPABASE_SERVICE_ROLE_KEY']
supabase = create_client(url, key)
raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
api_key = f"ag_live_{raw}"
key_hash = hashlib.sha256(api_key.encode()).hexdigest()
supabase.table('api_keys').insert({
  'key_hash': key_hash,
  'owner_email': 'owner@example.com',
  'status': 'active',
}).execute()
print('YOUR NEW API KEY (save now):', api_key)
PY
```

## SDKs

Python usage:

```python
from guardian_sdk import Guardian

client = Guardian(api_key="ag_live_...", base_url="http://127.0.0.1:8000")
res = client.analyze("Click here to reset your password")
print(res["risk_score"], res["threats_detected"])
```

Node usage:

```javascript
import { Guardian } from "guardian-sdk";

const guardian = new Guardian({ apiKey: "ag_live_...", baseUrl: "http://127.0.0.1:8000" });
const result = await guardian.analyze("Click here to reset your password");
console.log(result.risk_score, result.threats_detected);
```

Publish SDKs:

- PyPI (token required)
  - Set: `TWINE_USERNAME=__token__`, `TWINE_PASSWORD=pypi-...`
  - `cd Guardian-v0.1/sd k/python && python -m build && twine upload dist/*`
- npm
  - `cd Guardian-v0.1/sdk/node/guardian-sdk && npm install && npm run build && npm publish --access public`

## Tests

```powershell
$env:GUARDIAN_API_KEY="ag_123"
$env:PYTHONPATH="Guardian-v0.1/api"
pytest -q
```

## Load Test (hey)

```powershell
# Requires hey (https://github.com/rakyll/hey)
cd .\Guardian-v0.1\loadtest
./hey.ps1 -Url "http://127.0.0.1:8000/v1/analyze" -ApiKey "ag_123" -DurationSeconds 30 -Rate 200
```

## Deployment (Docker + Railway)

- Build locally:
  - `docker build -t guardian-api -f Guardian-v0.1/api/Dockerfile .`
  - `docker run -p 8000:8000 -e GUARDIAN_API_KEY=ag_123 guardian-api`
- Railway: point to repo root, ensure Dockerfile path `Guardian-v0.1/api/Dockerfile`, set envs.

## Troubleshooting

- Editor says "Import fastapi could not be resolved": select your venv interpreter and `pip install -r requirements.txt`.
- 401 on `/v1/analyze`: set `X-API-Key` and ensure it matches env or Supabase-stored key.
- PyPI upload 403: use API token (`TWINE_USERNAME=__token__`) and bump version.
- NPM build on Windows: ensure `shx` installed (`npm install`) before `npm run build`.

