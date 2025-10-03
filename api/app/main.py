import asyncio
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.security import APIKeyHeader
from prometheus_client import make_asgi_app
from pydantic import ValidationError
from fastapi.exceptions import RequestValidationError

from .alerting_system import alerting_system
from .classifier import analyze_text
from .config import settings
from .deps import verify_api_key
from .health_monitor import HealthMonitor
from .logging_client import LogEntry, logging_client
from .metrics_collector import metrics_collector
from .models import AnalyzeRequest, AnalyzeResponse, Threat
from .rate_limiter import add_rate_limit_headers, rate_limit_combined, memory_store
from .stats import stats
from .structured_logging import (
    configure_logging,
    correlation_id_var,
    generate_correlation_id,
    generate_trace_id,
    get_logger,
    log_analysis,
    log_error,
    log_response,
    trace_id_var,
)

# --- App Initialization and Metadata ---

API_DESCRIPTION = """
Guardian is a high-performance, AI-powered API for real-time threat detection in text content. 
It identifies 14 categories of risks, including phishing, malware instructions, PII, and hate speech, with multi-language support.

**Key Features:**
- Comprehensive threat detection
- AI enrichment with Google's Gemini
- High performance with Redis-based rate limiting
- Production-ready monitoring, logging, and alerting
"""

configure_logging()
logger = get_logger("guardian.api")
health_monitor = HealthMonitor()
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Guardian API starting up...")
    logging_client.start_worker()
    app.state.health_monitor = health_monitor
    app.state.metrics_collector = metrics_collector
    app.state.alerting_system = alerting_system
    # Provide a per-app instance namespace for in-memory rate limiter isolation in tests
    app.state.rate_limit_namespace = str(time.time())
    # Reset in-memory rate limiter store per app lifecycle (test isolation)
    try:
        memory_store.clear()
    except Exception:
        pass
    logger.info("Background services started.")
    yield
    logger.info("Guardian API shutting down...")
    logging_client.shutdown()
    await health_monitor.close()
    logger.info("Guardian API shutdown complete.")


app = FastAPI(
    title="Guardian API",
    description=API_DESCRIPTION,
    version="2.0.0",
    contact={
        "name": "Guardian Support",
        "url": "https://github.com/your-org/guardian/issues",
        "email": "support@example.com",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
    lifespan=lifespan,
)

if settings.prometheus_metrics_enabled:
    # Mount the Prometheus ASGI app directly to ensure text/plain responses
    app.mount("/metrics", make_asgi_app())

# --- Middleware ---

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

@app.middleware("http")
async def correlation_and_logging_middleware(request: Request, call_next) -> Response:
    start_time = time.monotonic()
    correlation_id = request.headers.get("X-Correlation-ID", generate_correlation_id())
    trace_id = request.headers.get("X-Trace-ID", generate_trace_id())
    correlation_id_var.set(correlation_id)
    trace_id_var.set(trace_id)

    logger.info("request_started", method=request.method, path=request.url.path, client_ip=request.client.host)

    try:
        response = await call_next(request)
    except Exception as exc:
        log_error(logger, exc)
        stats.record_error(500, (time.monotonic() - start_time) * 1000)
        response = JSONResponse(status_code=500, content={"detail": "Internal Server Error"})
    
    latency_ms = (time.monotonic() - start_time) * 1000
    response.headers["X-Correlation-ID"] = correlation_id
    log_response(logger, response, latency_ms)
    if 200 <= response.status_code < 300:
        try:
            analyzed = getattr(request.state, "analysis_result", None)
            if analyzed:
                stats.add(
                    request_id=correlation_id,
                    risk_score=analyzed.get("risk_score", 0),
                    threats=analyzed.get("threats", []),
                    latency_ms=latency_ms,
                )
            else:
                stats.add(request_id=correlation_id, risk_score=0, threats=[], latency_ms=latency_ms)
        except Exception:
            stats.add(request_id=correlation_id, risk_score=0, threats=[], latency_ms=latency_ms)
    else:
        stats.record_error(response.status_code, latency_ms)

    if hasattr(request.state, "rate_limit_result"):
        add_rate_limit_headers(response, request.state.rate_limit_result)

    return response

# --- API Endpoints ---

@app.post(
    "/v1/analyze",
    response_model=AnalyzeResponse,
    tags=["Analysis"],
    summary="Analyze text for threats",
    description="Processes input text to detect a wide range of security threats, returning a risk score and detailed findings.",
    responses={
        422: {"description": "Validation error for invalid input."},
        429: {"description": "Rate limit exceeded."},
        500: {"description": "Internal server error."},
    },
)
@rate_limit_combined()
async def analyze(
    req: AnalyzeRequest,
    request: Request,
    api_key: str = Security(verify_api_key),
) -> AnalyzeResponse:
    """
    Analyzes a given text for 14 different threat categories.

    - **text**: The input text to analyze (up to 100,000 characters).
    - **config**: Optional configuration for model version and compliance mode.
    """
    start_time = time.monotonic()
    result = await analyze_text(
        text=req.text,
        model_version=req.config.model_version if req.config else None,
        compliance_mode=req.config.compliance_mode if req.config else None,
    )
    latency_ms = (time.monotonic() - start_time) * 1000

    response = AnalyzeResponse(
        request_id=correlation_id_var.get(),
        risk_score=result.risk_score,
        threats_detected=result.threats_detected,
        metadata=result.metadata,
    )

    log_analysis(logger, risk_score=response.risk_score, threats_count=len(response.threats_detected), api_key_id=api_key)

    # Expose analysis summary to middleware for accurate metrics
    try:
        request.state.analysis_result = {
            "risk_score": response.risk_score,
            "threats": [t.model_dump() for t in response.threats_detected],
        }
    except Exception:
        pass

    await logging_client.log_event(LogEntry(
        request_id=correlation_id_var.get(),
        correlation_id=correlation_id_var.get(),
        trace_id=trace_id_var.get(),
        api_key_id=api_key,
        risk_score=response.risk_score,
        text_length=len(req.sanitized_text or ""), # Use sanitized text length
        threats=[t.model_dump() for t in response.threats_detected],
        request_meta={
            "client_ip": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "latency_ms": latency_ms,
        },
    ))

    return response

@app.get("/healthz", tags=["Monitoring"], summary="Get System Health")
async def healthz(request: Request):
    health_statuses = await request.app.state.health_monitor.check_all()
    overall_healthy = all(status.is_healthy for status in health_statuses)
    return JSONResponse(
        status_code=200 if overall_healthy else 503,
        content={
            "status": "ok" if overall_healthy else "unhealthy",
            "dependencies": [status.__dict__ for status in health_statuses],
        },
    )

@app.get("/metrics", tags=["Monitoring"], summary="Get Application Metrics", include_in_schema=False)
async def metrics_disabled(request: Request):
    # When Prometheus mount is enabled, this route is hidden. If disabled, return 404 to match expectations.
    return JSONResponse(status_code=404, content={"detail": "Metrics endpoint disabled"})

@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    log_error(logger, exc, validation_errors=exc.errors())
    return JSONResponse(
        status_code=422,
        content={"detail": "Input validation failed", "errors": exc.errors()},
    )

@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    log_error(logger, exc, validation_errors=exc.errors())
    return JSONResponse(
        status_code=422,
        content={"detail": "Input validation failed", "errors": exc.errors()},
    )