from typing import Any, Dict, List
import os
import asyncio
from supabase import create_client, Client


class LoggingClient:
    def __init__(self) -> None:
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_ANON_KEY")
        self._client: Client | None = None
        if url and key:
            try:
                self._client = create_client(url, key)
            except Exception:
                self._client = None

    async def log_event(
        self,
        *,
        request_id: str,
        api_key_id: str,
        text_length: int,
        threats: List[Dict[str, Any]],
        risk_score: int,
        request_meta: Dict[str, Any] | None = None,
    ) -> None:
        if not self._client:
            return

        payload = {
            "request_id": request_id,
            "api_key_id": None,  # defer foreign key until api_keys sync; store meta only
            "risk_score": risk_score,
            "threats": threats,
            "text_length": text_length,
            "request_meta": {"api_key_id_hint": api_key_id, **(request_meta or {})},
        }

        loop = asyncio.get_running_loop()
        # supabase-py is sync; run in thread to avoid blocking
        def _insert():
            try:
                self._client.table("logs").insert(payload).execute()
            except Exception:
                pass

        await loop.run_in_executor(None, _insert)


