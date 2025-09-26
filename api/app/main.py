from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse
from .models import AnalyzeRequest, AnalyzeResponse
from .deps import verify_api_key
from .classifier import analyze_text
from .logging_client import LoggingClient
from .config import settings
from .stats import stats
import uuid
import time
 


app = FastAPI(title="Argus Guardian API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


logging_client = LoggingClient()


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/v1/analyze", response_model=AnalyzeResponse)
async def analyze(
    req: AnalyzeRequest,
    request: Request,
    api_key_id: str = Depends(verify_api_key),
):
    start_time = time.time()
    request_id = f"req_{uuid.uuid4().hex[:12]}"

    try:
        result = await analyze_text(
            text=req.text,
            model_version=req.config.model_version if req.config else None,
            compliance_mode=req.config.compliance_mode if req.config else None,
        )

        response = AnalyzeResponse(
            request_id=request_id,
            risk_score=result.risk_score,
            threats_detected=result.threats_detected,
            metadata=result.metadata,
        )

        await logging_client.log_event(
            request_id=request_id,
            api_key_id=api_key_id,
            text_length=len(req.text or ""),
            threats=[t.dict() for t in response.threats_detected],
            risk_score=response.risk_score,
            request_meta={
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "latency_ms": int((time.time() - start_time) * 1000),
            },
        )

        # update in-memory dev stats
        try:
            stats.add(
                request_id=request_id,
                risk_score=response.risk_score,
                threats=[t.dict() for t in response.threats_detected],
            )
        except Exception:
            pass

        return response

    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Do not leak internals; log and return generic error
        await logging_client.log_event(
            request_id=request_id,
            api_key_id=api_key_id,
            text_length=len(req.text or ""),
            threats=[],
            risk_score=0,
            request_meta={"error": str(exc)},
        )
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/dev")
def dev_dashboard(request: Request):
    # restrict to localhost only
    host = request.client.host if request.client else None
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise HTTPException(status_code=403, detail="Forbidden")

    total = stats.total_requests
    risky = stats.total_with_risk
    pct = f"{(risky/total*100):.1f}%" if total else "0.0%"

    rows = "".join(
        f"<tr><td>{i+1}</td><td>{item['request_id']}</td><td>{item['risk_score']}</td><td>{', '.join(t.get('category') for t in item['threats'])}</td></tr>"
        for i, item in enumerate(stats.recent)
    )

    html = f"""
<!DOCTYPE html>
<html>
  <head>
    <meta charset='utf-8' />
    <title>Guardian Dev Panel</title>
    <style>
      body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }}
      .kpi {{ display: inline-block; margin-right: 24px; padding: 12px 16px; background: #f5f5f5; border-radius: 8px; }}
      table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
      th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
      th {{ background: #fafafa; }}
    </style>
  </head>
  <body>
    <h1>Guardian Dev Panel</h1>
    <div class='kpi'><b>Total Prompts</b><div>{total}</div></div>
    <div class='kpi'><b>With Risk</b><div>{risky} ({pct})</div></div>
    <div class='kpi'><b>Recent (max 50)</b><div>{len(stats.recent)}</div></div>
    <table>
      <thead><tr><th>#</th><th>Request ID</th><th>Risk Score</th><th>Threats</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </body>
</html>
"""
    return HTMLResponse(content=html, status_code=200)


