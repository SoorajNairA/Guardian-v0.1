import asyncio
import time
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Coroutine, Dict, Optional

import os
import redis.asyncio as redis
from .logging_client import logger
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from .config import settings

# Globals for Redis client and in-memory fallback
redis_client: Optional[redis.Redis] = None
memory_store: Dict[str, list] = {}


@dataclass
class RateLimitResult:
    """Encapsulates the result of a rate limit check."""

    allowed: bool
    limit: int
    remaining: int
    reset: int
    window: int
    retry_after: Optional[int] = None
    key: str = ""


class RedisRateLimiter:
    """A Redis-based rate limiter using a sliding window algorithm."""

    def __init__(self, client: redis.Redis):
        self.client = client

    async def is_allowed(
        self, key: str, limit: int, window: int
    ) -> RateLimitResult:
        """
        Checks if a request is allowed under the rate limit.
        Uses a sliding window algorithm with Redis sorted sets.
        """
        now = int(time.time())
        window_start = now - window

        async with self.client.pipeline(transaction=True) as pipe:
            pipe.zremrangebyscore(key, -1, window_start)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, window)
            results = await pipe.execute()

        current_count = results[2]
        remaining = max(0, limit - current_count)
        reset_time = now + window
        allowed = current_count <= limit

        retry_after = None
        if not allowed:
            oldest_timestamps = await self.client.zrange(key, 0, 0, withscores=True)
            if oldest_timestamps:
                oldest_ts = int(oldest_timestamps[0][1])
                retry_after = max(1, oldest_ts - window_start)

        return RateLimitResult(
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            reset=reset_time,
            window=window,
            retry_after=retry_after,
            key=key,
        )


class MemoryRateLimiter:
    """An in-memory rate limiter for fallback purposes."""
    
    def __init__(self, cleanup_interval: int = 300):  # 5 minutes default
        self.cleanup_interval = cleanup_interval
        self.last_cleanup = time.time()
        
    def _cleanup_expired(self, now: int, max_age: int = 3600) -> None:
        """Remove expired entries and clean up old keys"""
        if now - self.last_cleanup < self.cleanup_interval:
            return
            
        try:
            # Remove expired timestamps from existing keys
            for key in list(memory_store.keys()):
                memory_store[key] = [t for t in memory_store[key] if now - t < max_age]
                # Remove empty keys
                if not memory_store[key]:
                    del memory_store[key]
            
            self.last_cleanup = now
        except Exception as e:
            logger.error(f"Error during memory store cleanup: {str(e)}")

    def is_allowed(
        self, key: str, limit: int, window: int
    ) -> RateLimitResult:
        """Checks if a request is allowed using an in-memory store."""
        now = int(time.time())
        
        # Initialize empty list for new keys
        if key not in memory_store:
            memory_store[key] = []
            
        # Clean up expired entries periodically
        self._cleanup_expired(now)
        
        # Remove expired timestamps for this key
        memory_store[key] = [t for t in memory_store[key] if now - t < window]

        current_count = len(memory_store[key])
        allowed = current_count < limit

        if allowed:
            memory_store[key].append(now)

        remaining = max(0, limit - (current_count + 1))
        reset_time = now + window
        retry_after = None
        if not allowed and memory_store[key]:
            retry_after = max(1, (memory_store[key][0] + window) - now)

        return RateLimitResult(
            allowed=allowed,
            limit=limit,
            remaining=remaining,
            reset=reset_time,
            window=window,
            retry_after=retry_after,
            key=key,
        )


async def get_redis_client() -> Optional[redis.Redis]:
    """
    Initializes and returns the Redis client.
    Handles connection errors and returns None if Redis is unavailable.
    """
    global redis_client
    if redis_client:
        return redis_client

    if not settings.rate_limit_enabled:
        return None

    try:
        pool = redis.ConnectionPool.from_url(
            settings.redis_url,
            password=settings.redis_password,
            max_connections=settings.redis_max_connections,
            socket_connect_timeout=settings.redis_socket_timeout,
            decode_responses=True,
        )
        redis_client = redis.Redis(connection_pool=pool)
        await redis_client.ping()
        print("Successfully connected to Redis.")
        return redis_client
    except Exception as e:
        print(f"Redis connection failed: {e}. Rate limiting may fall back to memory.")
        redis_client = None
        return None


def get_api_key_identifier(request: Request) -> Optional[str]:
    """Returns the identifier for API key-based rate limiting."""
    api_key = request.headers.get("X-API-Key")
    return f"api_key:{api_key}" if api_key else None


def get_ip_identifier(request: Request) -> str:
    """Returns the identifier for IP-based rate limiting."""
    ip = request.client.host if request.client else "127.0.0.1"
    return f"ip:{ip}"


class CombinedRateLimiter:
    """
    Manages both API key and IP-based rate limiting, with a fallback to memory.
    """

    def __init__(
        self,
        api_key_limit: int,
        ip_limit: int,
        window: int,
    ):
        self.api_key_limit = api_key_limit
        self.ip_limit = ip_limit
        self.window = window
        self.redis_limiter: Optional[RedisRateLimiter] = None
        self.memory_limiter = MemoryRateLimiter()

    async def _init_redis_limiter(self):
        if not self.redis_limiter:
            client = await get_redis_client()
            if client:
                self.redis_limiter = RedisRateLimiter(client)

    async def check_rate_limit(self, request: Request) -> RateLimitResult:
        """
        Checks rate limits for both API key and IP address.
        API key limit takes precedence.
        """
        await self._init_redis_limiter()

        # Prefer Redis if initialized; do not ping on every request to avoid latency.
        limiter = self.redis_limiter or self.memory_limiter

        # If Redis is unavailable and memory fallback is disabled, allow traffic.
        if limiter is self.memory_limiter and not settings.rate_limit_fallback_to_memory:
            return RateLimitResult(allowed=True, limit=0, remaining=0, reset=0, window=0)

        if settings.environment == "development" and request.client and request.client.host == "127.0.0.1":
            return RateLimitResult(allowed=True, limit=0, remaining=0, reset=0, window=0)

        # Namespace keys per app instance to avoid cross-TestClient bleeding
        ns = getattr(request.app.state, "rate_limit_namespace", "")
        api_key_id = get_api_key_identifier(request)
        if api_key_id:
            try:
                result = await limiter.is_allowed(f"{ns}:{api_key_id}", self.api_key_limit, self.window)
            except Exception:
                # On Redis error, fall back to memory limiter for this request.
                result = self.memory_limiter.is_allowed(f"{ns}:{api_key_id}", self.api_key_limit, self.window)
            # If API key is rate-limited or allowed, return; do not also count IP.
            return result

        ip_id = get_ip_identifier(request)
        try:
            return await limiter.is_allowed(f"{ns}:{ip_id}", self.ip_limit, self.window)
        except Exception:
            return self.memory_limiter.is_allowed(f"{ns}:{ip_id}", self.ip_limit, self.window)


def add_rate_limit_headers(response: Response, result: RateLimitResult):
    """Adds standard rate limit headers to the response."""
    response.headers["X-RateLimit-Limit"] = str(result.limit)
    response.headers["X-RateLimit-Remaining"] = str(result.remaining)
    response.headers["X-RateLimit-Reset"] = str(result.reset)
    response.headers["X-RateLimit-Window"] = str(result.window)
    if result.retry_after is not None:
        response.headers["Retry-After"] = str(result.retry_after)


def rate_limit_combined(
    api_key_limit: int = settings.default_rate_limit_per_key,
    ip_limit: int = settings.default_rate_limit_per_ip,
    window: int = settings.rate_limit_window_seconds,
):
    """
    Decorator to apply combined API key and IP rate limiting.
    """
    limiter = CombinedRateLimiter(api_key_limit, ip_limit, window)

    def decorator(
        func: Callable[..., Coroutine[Any, Any, Any]]
    ) -> Callable[..., Coroutine[Any, Any, Any]]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Re-read enabled flag from env to support test overrides at runtime
            enabled_env = os.getenv("RATE_LIMIT_ENABLED")
            enabled = settings.rate_limit_enabled if enabled_env is None else enabled_env.lower() in ("true","1","t")
            if not enabled:
                return await func(*args, **kwargs)

            request = kwargs.get("request")
            if not isinstance(request, Request):
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
                if not request:
                    raise ValueError("Request object not found for rate limiting.")

            if request.url.path in ["/healthz", "/metrics", "/dev"]:
                return await func(*args, **kwargs)

            # Read limits from current environment for test overrides
            try:
                current_api_key_limit = int(os.getenv("DEFAULT_RATE_LIMIT_PER_KEY", str(limiter.api_key_limit)))
                current_ip_limit = int(os.getenv("DEFAULT_RATE_LIMIT_PER_IP", str(limiter.ip_limit)))
                current_window = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", str(limiter.window)))
                limiter.api_key_limit = current_api_key_limit
                limiter.ip_limit = current_ip_limit
                limiter.window = current_window
            except Exception:
                pass

            result = await limiter.check_rate_limit(request)
            request.state.rate_limit_result = result

            if not result.allowed:
                response = JSONResponse(
                    status_code=429,
                    content={"detail": f"Rate limit exceeded for {result.key}."},
                )
                add_rate_limit_headers(response, result)
                return response

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def rate_limit_per_key(
    requests: int = settings.default_rate_limit_per_key,
    window: int = settings.rate_limit_window_seconds,
):
    """
    Maintained for backward compatibility.
    Delegates to the new combined rate limiter with a high IP limit.
    """
    return rate_limit_combined(api_key_limit=requests, ip_limit=999999, window=window)
