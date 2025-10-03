import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx
import psutil
import redis.asyncio as redis
from supabase import Client, create_client

from .config import settings
from .structured_logging import get_logger, log_health_check

logger = get_logger("guardian.health_monitor")


@dataclass
class HealthStatus:
    """Represents the health status of a single dependency."""

    dependency: str
    is_healthy: bool
    status: str
    response_time_ms: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, any] = field(default_factory=dict)


class HealthMonitor:
    """Monitors the health of critical dependencies and system resources."""

    def __init__(self):
        self._redis_client: Optional[redis.Redis] = None
        self._supabase_client: Optional[Client] = None
        self._http_client = httpx.AsyncClient(
            timeout=settings.health_check_timeout_seconds
        )

    async def _init_clients(self):
        """Initializes dependency clients on first use."""
        if settings.health_check_redis_enabled and not self._redis_client:
            try:
                # Use a lightweight ping client only when needed in check_redis
                self._redis_client = redis.from_url(settings.redis_url, decode_responses=True)
            except Exception as e:
                logger.error("Failed to create Redis client for health check", error=str(e))

        if settings.health_check_supabase_enabled and not self._supabase_client:
            try:
                self._supabase_client = create_client(
                    settings.supabase_url, settings.supabase_service_role_key
                )
            except Exception as e:
                logger.error("Failed to create Supabase client for health check", error=str(e))

    async def check_all(self) -> List[HealthStatus]:
        """Runs all enabled health checks concurrently."""
        await self._init_clients()
        checks = []
        if settings.health_check_redis_enabled:
            checks.append(self.check_redis())
        if settings.health_check_supabase_enabled:
            checks.append(self.check_supabase())
        if settings.health_check_gemini_enabled:
            checks.append(self.check_gemini())
        
        checks.append(self.check_system())

        results = await asyncio.gather(*checks, return_exceptions=True)
        
        processed_results = []
        for res in results:
            if isinstance(res, Exception):
                processed_results.append(HealthStatus(dependency="unknown", is_healthy=False, status="unhealthy", error_message=str(res)))
            else:
                processed_results.append(res)
                log_health_check(logger, res.dependency, res.is_healthy, response_time=res.response_time_ms, error=res.error_message)

        return processed_results

    async def check_redis(self) -> HealthStatus:
        """Checks the health of the Redis connection."""
        if not self._redis_client:
            return HealthStatus("Redis", False, "unhealthy", error_message="Client not initialized")
        
        start_time = time.monotonic()
        try:
            await self._redis_client.ping()
            response_time = (time.monotonic() - start_time) * 1000
            return HealthStatus("Redis", True, "healthy", response_time_ms=response_time)
        except Exception as e:
            response_time = (time.monotonic() - start_time) * 1000
            return HealthStatus("Redis", False, "unhealthy", response_time_ms=response_time, error_message=str(e))

    async def check_supabase(self) -> HealthStatus:
        """Checks the health of the Supabase connection."""
        if not self._supabase_client:
            return HealthStatus("Supabase", False, "unhealthy", error_message="Client not initialized")

        start_time = time.monotonic()
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, lambda: self._supabase_client.table("logs").select("id").limit(1).execute())
            response_time = (time.monotonic() - start_time) * 1000
            return HealthStatus("Supabase", True, "healthy", response_time_ms=response_time)
        except Exception as e:
            response_time = (time.monotonic() - start_time) * 1000
            return HealthStatus("Supabase", False, "unhealthy", response_time_ms=response_time, error_message=str(e))

    async def check_gemini(self) -> HealthStatus:
        """Checks the health of the Gemini API by making a simple request."""
        if not settings.gemini_api_key:
            return HealthStatus("Gemini", False, "unhealthy", error_message="API key not configured")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.gemini_model}?key={settings.gemini_api_key}"
        start_time = time.monotonic()
        try:
            response = await self._http_client.get(url)
            response.raise_for_status()
            response_time = (time.monotonic() - start_time) * 1000
            return HealthStatus("Gemini", True, "healthy", response_time_ms=response_time)
        except httpx.HTTPStatusError as e:
            response_time = (time.monotonic() - start_time) * 1000
            return HealthStatus("Gemini", False, "degraded", response_time_ms=response_time, error_message=f"HTTP {e.response.status_code}")
        except Exception as e:
            response_time = (time.monotonic() - start_time) * 1000
            return HealthStatus("Gemini", False, "unhealthy", response_time_ms=response_time, error_message=str(e))

    async def check_system(self) -> HealthStatus:
        """Checks the health of the local system (CPU, memory)."""
        start_time = time.monotonic()
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory_info = psutil.virtual_memory()
            response_time = (time.monotonic() - start_time) * 1000
            
            is_healthy = cpu_percent < 90 and memory_info.percent < 90
            status = "healthy" if is_healthy else "degraded"
            
            return HealthStatus(
                "System",
                is_healthy=is_healthy,
                status=status,
                response_time_ms=response_time,
                metadata={
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_info.percent,
                },
            )
        except Exception as e:
            response_time = (time.monotonic() - start_time) * 1000
            return HealthStatus("System", False, "unhealthy", response_time_ms=response_time, error_message=str(e))

    async def close(self):
        """Closes client connections."""
        await self._http_client.aclose()
        if self._redis_client:
            await self._redis_client.close()
