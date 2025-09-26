from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional
import httpx


class Guardian:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout_seconds: float = 10.0,
        max_retries: int = 3,
    ) -> None:
        self.api_key = api_key or os.getenv("GUARDIAN_API_KEY") or ""
        self.base_url = (base_url or os.getenv("GUARDIAN_BASE_URL") or "http://localhost:8000").rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._client = httpx.Client(timeout=timeout_seconds)

    def analyze(self, text: str, *, model_version: Optional[str] = None, compliance_mode: Optional[str] = None) -> Dict[str, Any]:
        if not self.api_key:
            raise ValueError("Missing API key. Provide api_key or set GUARDIAN_API_KEY.")

        payload: Dict[str, Any] = {"text": text}
        config: Dict[str, Any] = {}
        if model_version:
            config["model_version"] = model_version
        if compliance_mode:
            config["compliance_mode"] = compliance_mode
        if config:
            payload["config"] = config

        url = f"{self.base_url}/v1/analyze"
        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}

        attempt = 0
        backoff = 0.5
        while True:
            try:
                resp = self._client.post(url, json=payload, headers=headers)
                if resp.status_code >= 500 and attempt < self.max_retries:
                    raise httpx.HTTPError(f"Server error: {resp.status_code}")
                resp.raise_for_status()
                return resp.json()
            except (httpx.TimeoutException, httpx.HTTPError):
                attempt += 1
                if attempt > self.max_retries:
                    raise
                time.sleep(backoff)
                backoff = min(4.0, backoff * 2)



