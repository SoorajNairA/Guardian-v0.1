import logging
import sys
import uuid
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Dict, Optional

import structlog
from structlog.types import Processor

from .config import settings

# Context variables for async-safe context propagation
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")
trace_id_var: ContextVar[str] = ContextVar("trace_id", default="")


# --- Correlation ID Management ---

def generate_correlation_id() -> str:
    """Generates a unique correlation ID for a request."""
    return f"corr-{uuid.uuid4().hex[:12]}"


def generate_trace_id() -> str:
    """Generates a unique trace ID for a request flow."""
    return f"trace-{uuid.uuid4().hex[:12]}"


@dataclass
class CorrelationContext:
    """Manages correlation context for a request."""

    correlation_id: str
    trace_id: str

    def as_dict(self) -> Dict[str, str]:
        return {"correlation_id": self.correlation_id, "trace_id": self.trace_id}


def get_current_context() -> CorrelationContext:
    """Retrieves the current correlation context from context variables."""
    return CorrelationContext(
        correlation_id=correlation_id_var.get(), trace_id=trace_id_var.get()
    )


# --- Structlog Configuration ---


def _add_correlation_info(logger: Any, method_name: str, event_dict: Dict) -> Dict:
    """A structlog processor to add correlation IDs to all log entries."""
    context = get_current_context()
    if context.correlation_id:
        event_dict["correlation_id"] = context.correlation_id
    if context.trace_id:
        event_dict["trace_id"] = context.trace_id
    return event_dict


def configure_logging():
    """Configures structured logging for the application."""
    log_level = settings.log_level
    is_dev = settings.environment == "development"

    processors: list[Processor] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        _add_correlation_info,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if is_dev:
        processors.append(structlog.dev.ConsoleRenderer())
    else:
        processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    handler = logging.StreamHandler(sys.stdout)
    root_logger.addHandler(handler)


def get_logger(name: Optional[str] = None) -> Any:
    """Returns a configured structlog logger."""
    return structlog.get_logger(name)


# --- Enhanced Logging Functions ---


def log_request(logger: Any, request: Any, **extra: Any):
    logger.info(
        "request_started",
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host,
        **extra,
    )


def log_response(logger: Any, response: Any, latency_ms: float, **extra: Any):
    logger.info(
        "request_finished",
        status_code=response.status_code,
        latency_ms=latency_ms,
        **extra,
    )


def log_analysis(logger: Any, **extra: Any):
    logger.info("analysis_completed", **extra)


def log_error(logger: Any, error: Exception, **extra: Any):
    logger.error(
        "error_occurred",
        error_type=type(error).__name__,
        error_message=str(error),
        exc_info=True,
        **extra,
    )


def log_health_check(logger: Any, dependency: str, is_healthy: bool, **extra: Any):
    level = "info" if is_healthy else "warning"
    getattr(logger, level)(
        "health_check", dependency=dependency, is_healthy=is_healthy, **extra
    )


def log_alert(logger: Any, alert_name: str, reason: str, **extra: Any):
    logger.critical("alert_triggered", alert_name=alert_name, reason=reason, **extra)


def log_system_event(logger: Any, event: str, **extra: Any):
    logger.info(f"system_{event}", **extra)