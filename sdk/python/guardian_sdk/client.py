from __future__ import annotations

import logging
import os
import random
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import httpx
import structlog
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
from typing_extensions import Self

# --- Custom Exceptions ---


class GuardianError(Exception):
    """Base exception for all Guardian SDK errors."""


class GuardianAPIError(GuardianError):
    """Raised for API errors from the Guardian service."""

    def __init__(self, message: str, status_code: int, response_data: Any):
        super().__init__(f"{message} (Status: {status_code})")
        self.status_code = status_code
        self.response_data = response_data


class GuardianTimeoutError(GuardianError):
    """Raised for network timeouts."""


class GuardianRateLimitError(GuardianAPIError):
    """Raised for 429 Rate Limit errors."""

    def __init__(self, message: str, status_code: int, response_data: Any, retry_after: int):
        super().__init__(message, status_code, response_data)
        self.retry_after = retry_after


class GuardianValidationError(GuardianError):
    """Raised for input validation errors."""


# --- Configuration ---


@dataclass
class GuardianConfig:
    """Configuration for the Guardian client."""

    api_key: Optional[str] = None
    base_url: Optional[str] = None
    timeout_seconds: float = 15.0
    max_retries: int = 3
    debug: bool = False
    # Connection pooling settings
    http2: bool = False
    limits: httpx.Limits = field(
        default_factory=lambda: httpx.Limits(
            max_connections=100, max_keepalive_connections=20
        )
    )


# --- Logging Setup ---

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

_logger = structlog.get_logger("guardian.sdk")


# --- Client ---


class Guardian:
    def __init__(
        self, config: Optional[GuardianConfig] = None, **kwargs: Any
    ) -> None:
        if config is None:
            config = GuardianConfig(**kwargs)

        self.api_key = config.api_key or os.getenv("GUARDIAN_API_KEY")
        if not self.api_key:
            raise GuardianValidationError(
                "Missing API key. Provide `api_key` in config or set GUARDIAN_API_KEY."
            )

        self.base_url = (
            config.base_url or os.getenv("GUARDIAN_BASE_URL") or "http://localhost:8000"
        ).rstrip("/")
        self.max_retries = config.max_retries

        self._client = httpx.Client(
            base_url=self.base_url,
            timeout=config.timeout_seconds,
            http2=config.http2,
            limits=config.limits,
            event_hooks={
                "request": [self._log_request],
                "response": [self._log_response],
            },
        )

        if config.debug:
            self.enable_debug_logging()

    def _log_request(self, request: httpx.Request):
        _logger.debug(
            "Sending request",
            method=request.method,
            url=str(request.url),
            headers={k: v for k, v in request.headers.items() if k.lower() != "x-api-key"},
        )

    def _log_response(self, response: httpx.Response):
        response.read()  # Ensure response body is available for logging
        _logger.debug(
            "Received response",
            status_code=response.status_code,
            url=str(response.url),
            json=response.json() if "application/json" in response.headers.get("content-type", "") else None,
        )

    def analyze(self, text: str, **kwargs: Any) -> Dict[str, Any]:
        """Analyzes the given text for security risks."""
        if not isinstance(text, str) or not text.strip():
            raise GuardianValidationError("Input `text` must be a non-empty string.")

        payload = {"text": text}
        if "config" in kwargs:
            payload["config"] = kwargs["config"]

        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}

        try:
            retry_decorator = self._create_retry_decorator()
            response = retry_decorator(self._client.post)(
                "/v1/analyze", json=payload, headers=headers
            )
            response.raise_for_status()
            return response.json()
        except RetryError as e:
            _logger.error("Request failed after multiple retries", exc_info=e)
            raise GuardianTimeoutError(
                f"Request failed after {self.max_retries} attempts."
            ) from e
        except httpx.HTTPStatusError as e:
            self._handle_http_status_error(e)

    def _create_retry_decorator(self):
        """Creates a tenacity retry decorator with exponential backoff and jitter."""
        return retry(
            stop=stop_after_attempt(self.max_retries),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            retry=retry_if_exception_type((httpx.TimeoutException, httpx.RequestError, GuardianRateLimitError)),
            before_sleep=lambda s: _logger.warning(
                "Retrying request", attempt=s.attempt_number, wait_time=s.next_action.sleep
            ),
        )

    def _handle_http_status_error(self, exc: httpx.HTTPStatusError) -> None:
        """Translates HTTP errors into specific Guardian exceptions."""
        status = exc.response.status_code
        data = exc.response.json()

        if status == 429:
            retry_after = int(exc.response.headers.get("Retry-After", "0"))
            _logger.warning("Rate limit exceeded", retry_after=retry_after)
            raise GuardianRateLimitError(
                "Rate limit exceeded", status, data, retry_after
            )
        elif 400 <= status < 500:
            _logger.error("API client error", status_code=status, response=data)
            raise GuardianAPIError(f"Client error: {data.get('detail', 'Unknown')}", status, data)
        elif 500 <= status < 600:
            _logger.error("API server error", status_code=status, response=data)
            # This will be retried by tenacity
            raise GuardianAPIError(f"Server error: {data.get('detail', 'Unknown')}", status, data)

    def enable_debug_logging(self):
        """Enables verbose debug logging for the SDK."""
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")
        _logger.info("Debug logging enabled.")

    def close(self):
        """Closes the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()