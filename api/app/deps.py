import asyncio
import logging
from fastapi import Header, HTTPException
from supabase import create_client
from .config import settings
from .crypto_utils import (
    hash_api_key, 
    verify_api_key as crypto_verify_api_key, 
    legacy_hash_api_key,
    validate_api_key_format,
    secure_compare_keys
)



logger = logging.getLogger(__name__)

_supabase_client = None
if settings.supabase_url and (settings.supabase_anon_key or settings.supabase_service_role_key):
    try:
        _supabase_client = create_client(
            settings.supabase_url,
            settings.supabase_service_role_key or settings.supabase_anon_key,
        )
    except Exception as e:
        logger.warning(f"Failed to initialize Supabase client: {e}")
        _supabase_client = None


async def verify_api_key(x_api_key: str | None = Header(default=None)) -> str:
    """Verify API key with enhanced security and deterministic lookups."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    
    if not validate_api_key_format(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid API key format")

    # 1) Supabase lookup by hash when configured
    if _supabase_client:
        try:
            # Attempt deterministic lookup for legacy SHA-256 keys first
            computed_sha_hash = legacy_hash_api_key(x_api_key)
            
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # 1. Deterministic lookup for SHA-256 keys
                    res_sha = (
                        _supabase_client.table("api_keys")
                        .select("id, status, key_hash, hash_type")
                        .eq("key_hash", computed_sha_hash)
                        .eq("hash_type", "legacy")
                        .execute()
                    )
                    
                    if getattr(res_sha, "data", None):
                        row = res_sha.data[0]
                        if row.get("status") == "active":
                            return str(row.get("id"))

                    # 2. Fallback for Argon2 keys (non-deterministic)
                    # This is a temporary, less scalable solution.
                    # A better approach is a deterministic lookup column.
                    res_argon = (
                        _supabase_client.table("api_keys")
                        .select("id, status, key_hash, hash_type")
                        .eq("hash_type", "argon2")
                        .eq("status", "active")
                        .execute()
                    )

                    if getattr(res_argon, "data", None):
                        for row in res_argon.data:
                            if crypto_verify_api_key(x_api_key, row.get("key_hash")):
                                return str(row.get("id"))
                    
                    # If we are here, no key was found
                    logger.debug("API key not found in Supabase. Falling back to env vars.")
                    break # Exit retry loop, proceed to env var fallback

                except Exception as e:
                    logger.warning(f"Supabase API error (attempt {attempt + 1}): {e}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(0.1 * (2 ** attempt))
                    else:
                        logger.error(f"Supabase connection failed after {max_retries} attempts: {e}")
                        break # Exit retry loop
        except Exception as e:
            logger.error(f"Supabase lookup failed unexpectedly: {e}")
    # 2) Env-based allowlist fallback
    allowed_keys = {k.strip() for k in settings.guardian_api_keys if k.strip()}
    if settings.guardian_api_keys:
        for allowed_key in allowed_keys:
            if secure_compare_keys(x_api_key, allowed_key):
                return "env_allowlist"

    if settings.guardian_api_key and secure_compare_keys(x_api_key, settings.guardian_api_key):
        return "env_default"

    raise HTTPException(status_code=401, detail="Invalid API key")


