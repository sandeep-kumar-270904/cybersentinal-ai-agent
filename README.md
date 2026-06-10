# CyberSentinel v2 — Multi-Agent AI Cybersecurity Engine

A production-grade, multi-agent AI system for autonomous threat analysis.
Built with Claude, FastAPI, and a layered agent architecture.

---

## What's New in v2 vs v1

| Feature | v1 (Basic) | v2 (This version) |
|---|---|---|
| Architecture | Single agent | Multi-agent (Orchestrator + 3 specialists) |
| Web framework | Flask (threaded) | FastAPI (async, 4 workers) |
| Tools | 4 tools | 9 tools (+ WHOIS, IP rep, cert, SPF/DKIM, IOC extraction) |
| Persistence | None (stateless) | SQLite case store (PostgreSQL-ready) |
| Caching | None | In-memory + Redis upgrade path |
| URL scanning | Sequential | Parallel (asyncio.gather, semaphore-limited) |
| API | Basic Flask routes | REST API with OpenAPI docs at /docs |
| Auth | None | API key auth |
| Rate limiting | None | Per-key rolling window |
| Deployment | `python app.py` | Docker + Nginx + uvicorn |
| Threat hunting | None | Search all cases by IOC |
| Webhooks | None | POST results to any URL |
| Background jobs | Thread + queue | FastAPI BackgroundTasks |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    FastAPI App                       │
│  /api/v2/analyse/stream  (SSE real-time)            │
│  /api/v2/analyse/async   (background + webhook)     │
│  /api/v2/cases           (case management)          │
│  /api/v2/hunt/{ioc}      (threat hunting)           │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │   OrchestratorAgent     │  ← Claude Opus
          │   (master planner)      │
          └─┬──────────┬───────────┘
            │          │
    ┌───────▼──┐  ┌────▼──────┐
    │  Email   │  │   URL     │  ← Claude Sonnet (faster/cheaper)
    │  Agent   │  │  Agent    │
    └─┬────────┘  └─┬─────────┘
      │             │
  ┌───▼───────┐  ┌──▼──────────────────────┐
  │ 4 email   │  │ 5 URL tools (parallel)  │
  │ tools     │  │ VT + URLScan + WHOIS    │
  └───────────┘  │ + IP rep + cert         │
                 └─────────────────────────┘
                       │
          ┌────────────▼─────────────┐
          │     ReportAgent          │  ← Claude Sonnet
          │  (synthesis + scoring)   │
          └────────────┬─────────────┘
                       │
          ┌────────────▼─────────────┐
          │     CaseStore (SQLite)   │
          │  + ThreatCache (Redis)   │
          └──────────────────────────┘
```

---

## Quick Start

### 1. Clone and configure

```bash
git clone <your-repo>
cd cybersentinel-v2
cp .env.example .env
# Edit .env — add your API keys
```

### 2. .env configuration

```env
ANTHROPIC_API_KEY=sk-ant-...
URLSCAN_API_KEY=your-key        # urlscan.io
VIRUSTOTAL_API_KEY=your-key     # virustotal.com (free tier OK)
ABUSEIPDB_API_KEY=your-key      # abuseipdb.com (NEW in v2)

# Optional
REDIS_URL=redis://localhost:6379/0
API_KEYS=your-api-key-1,your-api-key-2
RATE_LIMIT_PER_MIN=20
ALLOWED_ORIGINS=https://yourapp.com
```

### 3. Run locally

```bash
pip install -r requirements.txt
uvicorn app:app --reload --port 8000
```

Open `http://localhost:8000` for the UI, `http://localhost:8000/docs` for the API.

### 4. Run with Docker

```bash
docker-compose up -d
```

---

## API Usage

### Stream analysis (real-time SSE)

```bash
curl -N -X POST http://localhost:8000/api/v2/analyse/stream \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{"input": "From: security@paypa1.com\nClick: https://paypa1-verify.xyz/login", "deep_scan": true}'
```

### Async analysis with webhook

```bash
curl -X POST http://localhost:8000/api/v2/analyse/async \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{"input": "...", "webhook_url": "https://your-app.com/webhook"}'

# Returns: {"case_id": "abc123", "status": "queued", "poll_url": "/api/v2/cases/abc123"}
```

### Threat hunting (search past cases by IOC)

```bash
curl http://localhost:8000/api/v2/hunt/paypa1-verify.xyz \
  -H "X-API-Key: your-key"
```

---

## Upgrade Roadmap

### v3.0 — Production Scale

- [ ] Swap SQLite for PostgreSQL (change 1 connection string)
- [ ] Celery + Redis for proper job queue (replace BackgroundTasks)
- [ ] Slack/Teams notifications for CRITICAL findings
- [ ] MITRE ATT&CK technique mapping in reports
- [ ] Batch analysis endpoint (analyse 100 emails at once)
- [ ] File attachment scanning (PDF/Office macros via sandbox API)

### v4.0 — Enterprise

- [ ] Multi-tenant with user management (JWT + OAuth)
- [ ] SIEM integration (Splunk/Elastic webhook push)
- [ ] Custom threat intelligence feeds (MISP, OpenCTI)
- [ ] Fine-tuned Claude model on your historical cases
- [ ] Automated escalation workflows
- [ ] Compliance reports (ISO 27001, SOC2)

---

## Project Structure

```
cybersentinel-v2/
├── app.py                        # FastAPI app, routes, auth, rate limiting
├── core/
│   ├── agents/
│   │   ├── orchestrator.py       # Master multi-agent coordinator
│   │   ├── email_agent.py        # Email/phishing specialist
│   │   ├── url_agent.py          # URL/domain specialist (parallel scans)
│   │   └── report_agent.py       # Report synthesis
│   ├── tools/
│   │   ├── email_tools.py        # 4 email tools (headers, SPF, lookalike, IOC)
│   │   └── url_tools.py          # 5 URL tools (VT, URLScan, WHOIS, IP, cert)
│   ├── memory/
│   │   ├── case_store.py         # SQLite case persistence + IOC index
│   │   └── threat_cache.py       # In-memory/Redis cache
│   └── notifications/            # (v3: Slack, email, webhook)
├── api/
│   └── models.py                 # Pydantic request/response schemas
├── templates/                    # Jinja2 HTML templates
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```
