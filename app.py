"""
app.py — CyberSentinel v2
FastAPI main application. Replaces Flask with async-native, production-ready server.

Key upgrades vs v1:
  - FastAPI (async) instead of Flask (threaded)
  - Proper REST API with OpenAPI docs at /docs
  - API key authentication
  - Rate limiting
  - Job queue — analyses run in background, polled or streamed
  - Health & metrics endpoints
  - CORS for frontend separation
  - Structured JSON logging

Run:  uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4
"""

import json
import os
import uuid
import time
import logging
import asyncio
from datetime import datetime
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks, Request
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from core.agents.orchestrator import OrchestratorAgent
from core.memory.case_store import CaseStore
from core.memory.threat_cache import ThreatCache
from api.models import AnalyseRequest, CaseSummary, CaseDetail, HealthResponse

load_dotenv()

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'
)
logger = logging.getLogger("cybersentinel")

# ── App init ─────────────────────────────────────────────────
app = FastAPI(
    title="CyberSentinel v2",
    description="Multi-agent AI cybersecurity analysis engine",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

case_store = CaseStore()
threat_cache = ThreatCache()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory rate limiting (upgrade: use Redis for multi-instance)
_rate_limits: dict = {}
MAX_REQUESTS_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", 20))


# ── Auth ─────────────────────────────────────────────────────

VALID_API_KEYS = set(filter(None, os.getenv("API_KEYS", "").split(",")))

def require_api_key(x_api_key: Optional[str] = Header(None)):
    if not VALID_API_KEYS:
        return "anonymous"  # No keys configured — open access
    if not x_api_key or x_api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return x_api_key


def rate_limit(request: Request, api_key: str = Depends(require_api_key)):
    key = api_key or request.client.host
    now = time.time()
    window_start = now - 60

    calls = [t for t in _rate_limits.get(key, []) if t > window_start]
    if len(calls) >= MAX_REQUESTS_PER_MIN:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded: {MAX_REQUESTS_PER_MIN} requests/minute")
    calls.append(now)
    _rate_limits[key] = calls
    return key


# ── Routes ───────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """Health check endpoint. Returns service status and cache stats."""
    cache_stats = await threat_cache.get_stats()
    return HealthResponse(
        status="healthy",
        version="2.0.0",
        timestamp=datetime.utcnow().isoformat(),
        cache=cache_stats
    )


@app.post("/api/v2/analyse/stream", tags=["Analysis"])
async def analyse_stream(
    req: AnalyseRequest,
    api_key: str = Depends(rate_limit)
):
    """
    Start a streaming analysis. Returns Server-Sent Events.
    The client receives real-time events as each agent works.
    """
    case_id = str(uuid.uuid4())[:12]
    logger.info(f"Analysis started case_id={case_id} api_key={api_key[:8]}...")

    async def event_generator():
        try:
            orchestrator = OrchestratorAgent()
            async for event in orchestrator.run(req.input, case_id):
                yield f"event: {event['event']}\ndata: {json.dumps(event['data'])}\n\n"
        except Exception as e:
            logger.error(f"Analysis error case_id={case_id}: {e}")
            yield f"event: error\ndata: {json.dumps({'message': str(e), 'case_id': case_id})}\n\n"
            yield f"event: end\ndata: {json.dumps({'case_id': case_id})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"X-Case-ID": case_id, "Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.post("/api/v2/analyse/async", tags=["Analysis"])
async def analyse_async(
    req: AnalyseRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(rate_limit)
):
    """
    Start analysis as a background job. Returns a case_id immediately.
    Poll GET /api/v2/cases/{case_id} for results.
    Good for integrations / webhooks.
    """
    case_id = await case_store.create_case(req.input)
    logger.info(f"Async analysis queued case_id={case_id}")

    async def run_bg():
        orchestrator = OrchestratorAgent()
        events = []
        async for event in orchestrator.run(req.input, case_id):
            events.append(event)
        if req.webhook_url:
            await _send_webhook(req.webhook_url, case_id, events)

    background_tasks.add_task(run_bg)
    return {"case_id": case_id, "status": "queued", "poll_url": f"/api/v2/cases/{case_id}"}


@app.get("/api/v2/cases", response_model=List[CaseSummary], tags=["Cases"])
async def list_cases(
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    api_key: str = Depends(require_api_key)
):
    """List all investigation cases. Supports filtering by severity and status."""
    return await case_store.list_cases(limit=limit, severity=severity, status=status)


@app.get("/api/v2/cases/{case_id}", response_model=CaseDetail, tags=["Cases"])
async def get_case(case_id: str, api_key: str = Depends(require_api_key)):
    """Get full details of a specific case."""
    case = await case_store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case


@app.get("/api/v2/hunt/{ioc_value}", tags=["Threat Hunting"])
async def hunt_ioc(ioc_value: str, api_key: str = Depends(require_api_key)):
    """
    Threat hunting: find all past cases that contain a given IOC.
    Search by URL, IP, email address, or domain.
    """
    results = await case_store.search_by_ioc(ioc_value)
    return {"ioc": ioc_value, "cases_found": len(results), "cases": results}


@app.get("/api/v2/cache/stats", tags=["System"])
async def cache_stats(api_key: str = Depends(require_api_key)):
    return await threat_cache.get_stats()


@app.delete("/api/v2/cache/{target}", tags=["System"])
async def invalidate_cache(target: str, api_key: str = Depends(require_api_key)):
    """Invalidate cached threat intel for a specific URL/domain."""
    await threat_cache.delete(target)
    return {"status": "invalidated", "target": target}


# ── Webhook helper ────────────────────────────────────────────

async def _send_webhook(url: str, case_id: str, events: list):
    """POST final results to a webhook URL."""
    try:
        import httpx
        report_events = [e for e in events if e.get("event") == "report"]
        payload = {"case_id": case_id, "timestamp": datetime.utcnow().isoformat(), "events": report_events}
        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload, timeout=10)
            logger.info(f"Webhook sent case_id={case_id} url={url}")
    except Exception as e:
        logger.error(f"Webhook failed case_id={case_id}: {e}")


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True, workers=1)
