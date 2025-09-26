# guardian-sdk (Python)

Argus Guardian SDK for Python. Minimal client for `/v1/analyze`.

## Install

```bash
pip install guardian-sdk
```

## Usage

```python
from guardian_sdk import Guardian

client = Guardian(api_key="ag_live_...", base_url="https://your.api")
res = client.analyze("Click here to reset your password")
print(res["risk_score"], res["threats_detected"])
```


