from fastapi import Header, HTTPException
from .config import settings
from .crypto_utils import hash_api_key
from supabase import create_client


_supabase_client = None
if settings.supabase_url and (settings.supabase_anon_key or settings.supabase_service_role_key):
    try:
        _supabase_client = create_client(
            settings.supabase_url,
            settings.supabase_service_role_key or settings.supabase_anon_key,
        )
    except Exception:
        _supabase_client = None


async def verify_api_key(x_api_key: str | None = Header(default=None)) -> str:
    # In production, look up hashed key in Supabase. For now, use env var list.
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    # 1) Supabase lookup by hash when configured
    if _supabase_client:
        try:
            key_hash = hash_api_key(x_api_key)
            res = _supabase_client.table("api_keys").select("id,status").eq("key_hash", key_hash).limit(1).execute()
            data = getattr(res, "data", []) or []
            if data:
                row = data[0]
                if row.get("status") != "active":
                    raise HTTPException(status_code=403, detail="API key disabled")
                return str(row.get("id"))
        except HTTPException:
            raise
        except Exception:
            # fall through to env-based validation
            pass

    # 2) Env-based allowlist fallback
    allowed_keys = {k.strip() for k in settings.guardian_api_keys if k.strip()}
    if settings.guardian_api_keys and x_api_key in allowed_keys:
        return "env_allowlist"

    if settings.guardian_api_key and x_api_key == settings.guardian_api_key:
        return "env_default"

    raise HTTPException(status_code=403, detail="Invalid API key")


