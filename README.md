<div align="center">

# 🛡️ CyberSentinel AI Agent

### Autonomous Multi-Agent Cybersecurity Threat Analysis — Powered by Claude AI

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Claude Opus](https://img.shields.io/badge/Claude-opus--4--6-D97706?style=flat-square)](https://anthropic.com)
[![Claude Sonnet](https://img.shields.io/badge/Claude-sonnet--4--6-D97706?style=flat-square)](https://anthropic.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=flat-square)](https://virustotal.com)
[![URLScan](https://img.shields.io/badge/URLScan.io-API-FF6B35?style=flat-square)](https://urlscan.io)
[![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-API-CC0000?style=flat-square)](https://abuseipdb.com)
[![License](https://img.shields.io/badge/License-MIT-00cc6e?style=flat-square)](LICENSE)

**CyberSentinel** is a fully autonomous multi-agent AI system that investigates suspicious emails and URLs using real cybersecurity APIs. A master Orchestrator agent plans and delegates to three specialist sub-agents — Email, URL, and Report — each running their own independent Claude-powered reasoning loop with their own tools, in parallel.

[Features](#features) · [Architecture](#architecture) · [Setup](#setup) · [Web UI](#web-ui) · [How It Works](#how-the-agentic-loop-works) · [The 9 Tools](#the-9-tools) · [API Reference](#api-endpoints) · [Concepts](#agentic-ai-concepts-demonstrated)

</div>

---

## Overview

Most threat analysis tools follow a fixed pipeline: step 1, step 2, step 3. CyberSentinel doesn't. It uses **Claude AI's tool_use API** to implement a genuine multi-agent system where an Orchestrator LLM controls the investigation by delegating to specialist agents, each of which runs their own independent reasoning loop.

Given a suspicious email or URL, the system figures out on its own what to investigate, which APIs to call, in what order, and when it has enough evidence to conclude. No hardcoded sequences. No fixed pipelines. The output — a scored threat verdict with a full evidence trail — is derived entirely from live external data, not from Claude's training knowledge.

---

## Features

- **Truly multi-agent** — Orchestrator delegates to three specialist agents (Email, URL, Report), each with their own Claude loop and tools
- **9 integrated tools** — email headers, SPF/DKIM/DMARC, brand impersonation, IOC extraction, URLScan.io, VirusTotal (70+ engines), WHOIS, IP reputation, TLS certificate inspection
- **Parallel URL scanning** — all URLs in an email are scanned simultaneously, not one by one
- **Composite threat score** — 0–100 score derived from signals across all tools with a CRITICAL / HIGH / MEDIUM / LOW verdict
- **Case persistence** — every investigation is stored in SQLite with a full IOC index
- **Threat hunting** — search all past cases by any URL, IP, domain, or email address
- **Result caching** — VirusTotal and URLScan results cached to avoid redundant API calls
- **Slack alerts** — automatic notifications for CRITICAL and HIGH findings
- **REST API** — 8 endpoints with full Swagger/OpenAPI docs auto-generated at `/docs`
- **Real-time streaming UI** — watch each agent reason and call tools live via Server-Sent Events
- **Production-ready** — API key auth, rate limiting, Docker + Nginx deployment
- **No agent framework** — built directly on the Claude API. No LangChain, no LlamaIndex

---

## Demo Output

```
══════════════════════════════════════════════════
      CYBERSENTINEL THREAT REPORT
══════════════════════════════════════════════════

Threat Level     : CRITICAL 🔴
Composite Score  : 95 / 100

── Email Analysis ──
  Sender Domain    : paypa1.com
  Domain Mismatch  : YES ⚠️  (reply-to: harvest-cred.ru)
  Lookalike domain : 'paypa1' impersonating PayPal
  SPF              : FAIL
  DKIM             : FAIL
  Urgency Keywords : suspended, 24 hours, verify, click here

── URL Scan (URLScan.io) ──
  Domain           : paypa1-login.ru
  Country          : RU
  Malicious Flag   : YES ⚠️
  Risk Score       : 87 / 100

── VirusTotal Analysis ──
  Malicious Flags  : 34 / 87 engines
  Flagged by       : Kaspersky, Fortinet, ESET, BitDefender, Avast

── WHOIS ──
  Domain Age       : 3 days ⚠️  (newly registered)
  Registrar        : Namecheap, Inc.

── IP Reputation (AbuseIPDB) ──
  IP               : 185.220.101.45
  Abuse Score      : 91 / 100 🔴
  Country          : RU
  Reports          : 847

── TLS Certificate ──
  Issuer           : Let's Encrypt
  Issued           : 2 days ago ⚠️
  Self-signed      : No

── Recommended Action ──
  🚨 DO NOT CLICK. Block sender immediately.
     Report to IT Security. Delete this email.
══════════════════════════════════════════════════
```

Full sample run with all agent reasoning steps: [sample_output.txt](./sample_output.txt)

---

## Architecture

```
User Input (email / URL)
        │
        ▼
┌─────────────────────────────────────┐
│         OrchestratorAgent           │
│         claude-opus-4-6             │
│   Plans · Delegates · Aggregates    │
└──────────────┬──────────────────────┘
               │
       ┌───────┴──────────┐
       │   runs in parallel│
       ▼                   ▼
┌──────────────┐    ┌──────────────┐
│  EmailAgent  │    │   URLAgent   │
│ sonnet-4-6   │    │  sonnet-4-6  │
│              │    │              │
│ analyse_     │    │ scan_url_    │
│  headers()   │    │  urlscan()   │
│ check_spf_   │    │ check_virus  │
│  dkim()      │    │  total()     │
│ detect_look  │    │ lookup_      │
│  alikes()    │    │  whois()     │
│ extract_     │    │ check_ip_    │
│  iocs()      │    │  reputation()│
│              │    │ analyse_     │
│              │    │  certificate()
└──────┬───────┘    └──────┬───────┘
       │                   │
       └─────────┬─────────┘
                 ▼
┌────────────────────────────────────┐
│           ReportAgent              │
│           sonnet-4-6               │
│  Scores · Synthesises · Writes     │
└───────────────┬────────────────────┘
                │
       ┌────────┼─────────┐
       ▼        ▼         ▼
  CaseStore  Threat    Slack
  (SQLite)   Cache     Notifier
```

**Why Opus for the Orchestrator, Sonnet for sub-agents?**
The Orchestrator makes high-level planning decisions — it needs to reason about what the input contains, what agents to invoke, and how to aggregate diverse findings. That warrants Opus. Sub-agents do focused, well-defined tasks (analyse this email, scan these URLs) — Sonnet handles these faster and at lower cost without sacrificing quality.

Each agent operates in a **ReAct loop** (Reason → Act → Observe → Repeat). They don't follow a fixed script — each decides which tools to call based on what it finds. If the URL agent's URLScan result reveals a redirect domain that wasn't in the original input, it independently calls VirusTotal on that new domain. The Orchestrator decides when all agents have enough evidence and triggers the final report.

---

## The 9 Tools

### Email Agent — 4 tools

**`analyse_headers(email_text)`**
Local Python parser, no external API needed. Extracts sender domain, reply-to domain, return-path domain. Detects domain mismatches across all three (a classic spoofing signal). Scans body text for 25+ urgency keywords (suspended, verify now, 24 hours, account locked etc.) and computes an urgency score 0–100. Detects shortened/obfuscated URLs (bit.ly, tinyurl, goo.gl etc.). Extracts all embedded URLs and passes them to the URL agent.

**`check_spf_dkim(email_text)`**
Parses SPF, DKIM, and DMARC authentication results from email headers. SPF verifies the sending server is authorised for the domain. DKIM verifies the email was not tampered with in transit. DMARC tells receiving servers what to do when SPF/DKIM fail. A missing `Authentication-Results` header often means the email bypassed normal mail servers entirely — common in direct-injection phishing attacks.

**`detect_lookalikes(email_text)`**
Brand impersonation detection using regex covering homoglyphs (paypa1 vs paypal), character substitutions (arnazon vs amazon), transpositions, and punycode/internationalized domain names (IDN homograph attacks where Cyrillic characters replace Latin ones). Covers 14 major brands: PayPal, Amazon, Google, Microsoft, Apple, Netflix, Facebook, Instagram, LinkedIn, Dropbox, IRS, FedEx, DHL, and generic bank patterns.

**`extract_iocs(email_text)`**
Structured Indicator of Compromise extraction. Pulls out: all URLs, IPv4 addresses, email addresses, MD5/SHA1/SHA256 file hashes, and attachment filenames with dangerous extensions (exe, zip, docx, xls, pdf, js, vbs, bat, ps1, iso, img). Returns a total IOC count for quick triage.

---

### URL Agent — 5 tools

**`scan_url_urlscan(url)`**
Submits the URL to **URLScan.io** for a live headless browser scan. URLScan loads the actual page in a real browser, captures the full redirect chain, screenshots the page, and analyses all network requests. Returns: resolved domain, hosting country, IP address, server software, malicious verdict flag, and risk score 0–100. Handles shortened URLs by following the complete redirect chain — bit.ly redirecting to a credential-harvesting page is fully exposed.

**`check_virustotal(target)`**
Checks a URL or domain against **70+ antivirus and threat intelligence engines** via VirusTotal API v3. Engines include Kaspersky, Fortinet, ESET, BitDefender, Avast, Sophos, Trend Micro, and many more. Returns: malicious count, suspicious count, total engines checked, list of flagging vendors, and a composite verdict (CLEAN / LOW / MEDIUM / HIGH / CRITICAL). Results are cached for 1 hour to avoid burning API quota on repeated checks of the same URL.

**`lookup_whois(domain)`**
Retrieves WHOIS registration data: domain creation date, age in days, registrar, registrant country, and name servers. Domain age is one of the strongest signals in phishing detection — attackers register fresh domains specifically to avoid reputation-based blocklists. Domains under 30 days old are flagged automatically. Falls back to the `python-whois` library if the primary API is unavailable.

**`check_ip_reputation(domain_or_ip)`**
Resolves the domain to its IP address, then queries **AbuseIPDB** for an abuse confidence score 0–100 based on crowd-sourced reports from security researchers worldwide. Also returns: total abuse reports, country, ISP, usage type (hosting, residential, VPN, Tor), and whether the IP is a known Tor exit node. A score above 75 is flagged as MALICIOUS.

**`analyse_certificate(url)`**
Makes a live SSL/TLS connection and inspects the certificate directly using Python's stdlib `ssl` module — no external API needed. Checks: issuer organisation, issue date, expiry date, whether it's self-signed, whether it was issued in the last 7 days (fresh certs on suspicious domains are a red flag), and Subject Alternative Names. A Let's Encrypt cert issued 2 days ago on a newly registered domain is a very common phishing infrastructure pattern.

---

## Threat Scoring

Every investigation produces a composite threat score 0–100 built from signals across all tools:

| Signal | Points |
|---|---|
| VirusTotal: 10+ engines flagged | +60 |
| VirusTotal: 5–9 engines flagged | +40 |
| VirusTotal: 1–4 engines flagged | +20 |
| URLScan malicious verdict | +30 |
| Brand impersonation detected | +35 |
| SPF failure | +20 |
| DKIM failure | +20 |
| DMARC violation | +15 |
| Domain registered < 30 days | +20 |
| IP abuse score > 50 | +15 |
| High urgency language score | +15 |
| Sender domain mismatch | +25 |
| Self-signed certificate | +10 |
| Expired certificate | +15 |

| Score | Level | Recommended Action |
|---|---|---|
| 80–100 | 🔴 CRITICAL | Block and report immediately. Do not interact. |
| 60–79 | 🟠 HIGH | Do not interact. Verify through official channels. |
| 30–59 | 🟡 MEDIUM | Treat with caution. Verify sender identity. |
| 0–29 | 🟢 LOW | No strong indicators. Standard hygiene applies. |

---

## Agentic AI Concepts Demonstrated

| Concept | Implementation |
|---|---|
| **Multi-agent orchestration** | OrchestratorAgent delegates to three independent specialist agents, each with their own Claude loop, tools, and reasoning scope |
| **Autonomous tool selection** | Each agent receives tool definitions and decides call order based on findings — no hardcoded sequences anywhere in the codebase |
| **ReAct loop** | Reason → Act → Observe → Repeat. Claude narrates reasoning before every tool call, observes the result, and decides the next action |
| **Parallel async execution** | URLAgent scans all URLs simultaneously using `asyncio.gather` with a semaphore to respect API rate limits |
| **Tool use / Function calling** | Claude API `tool_use` blocks. All 9 tools defined with JSON schema. Results returned as `tool_result` messages in multi-turn history |
| **Agent memory** | Full message history maintained across all turns per agent loop. Each agent has complete context of everything it has seen and done |
| **Cross-session persistence** | SQLite case store saves every investigation. IOC index enables retroactive threat hunting across all past cases |
| **Dynamic investigation paths** | URLs found in email headers are automatically passed to URLAgent. A redirect domain found by URLScan triggers a new VirusTotal check |
| **Autonomous termination** | Each agent loop exits only on `stop_reason == "end_turn"` with no pending tool calls — not on a fixed step count |
| **Result caching** | ThreatCache prevents duplicate API calls within a session and across sessions. Malicious results cached for 24 hours, clean results for 1 hour |
| **Threat hunting** | Every IOC from every investigation is indexed. Search all past cases by URL, IP, domain, or email address in one API call |
| **Production patterns** | API key authentication, per-key rate limiting, background job queue, webhook callbacks, structured JSON logging, health endpoint |

---

## Why This Is Not a Chatbot

A typical LLM app: user asks → model answers → done.

CyberSentinel: user submits input → Orchestrator reasons about what needs investigating → delegates to specialist agents → each agent calls real external APIs → each agent reasons about live structured data → agents run in parallel → ReportAgent synthesises multi-source evidence → produces a scored threat verdict with full evidence trail → case persisted to database with IOC index for future threat hunting.

No agent is summarising pre-existing text or drawing on training knowledge. Each is directing live API calls against real external systems and making autonomous decisions based on real-time data it has never seen before. The threat verdict is derived from evidence.

---

## Tech Stack

| Layer | Technology |
|---|---|
| **AI / LLM** | Anthropic Claude API — `claude-opus-4-6` (orchestrator), `claude-sonnet-4-6` (sub-agents), `tool_use`, multi-turn |
| **Threat Intel** | URLScan.io, VirusTotal API v3, AbuseIPDB, python-whois, Python stdlib ssl |
| **Backend** | FastAPI 0.115 (async-native), uvicorn (4 workers), Server-Sent Events |
| **Persistence** | SQLite — case store + IOC index. Swap to PostgreSQL via one connection string change |
| **Cache** | In-memory dict by default. Set `REDIS_URL` in `.env` to switch to Redis automatically |
| **Notifications** | Slack Incoming Webhooks — fires on CRITICAL/HIGH findings |
| **Frontend** | Vanilla HTML/CSS/JS — dark terminal aesthetic, no frameworks |
| **Deployment** | Docker, docker-compose, Nginx reverse proxy, HTTPS, security headers |
| **Config** | python-dotenv, environment-based API key management |
| **No** | LangChain, LlamaIndex, or any agent framework |

> The multi-agent orchestration, each sub-agent loop, and all tool dispatching are implemented directly against the Claude API using `tool_use` blocks. This is not framework usage — it demonstrates ground-up understanding of how agentic systems work.

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/cybersentinel-ai-agent.git
cd cybersentinel-ai-agent
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Get API keys — all free, all instant signup

| Key | Where to get it | Used for |
|---|---|---|
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) | All AI agents |
| `URLSCAN_API_KEY` | [urlscan.io/user/signup](https://urlscan.io/user/signup) | Live URL scanning |
| `VIRUSTOTAL_API_KEY` | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | 70+ AV engines |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com/register](https://www.abuseipdb.com/register) | IP reputation |

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in your API keys
```

Optional settings in `.env`:

```env
REDIS_URL=redis://localhost:6379/0   # cache — falls back to in-memory if not set
API_KEYS=your-key-here               # auth — leave empty for open access
RATE_LIMIT_PER_MIN=20                # requests per API key per minute
SLACK_WEBHOOK_URL=https://hooks...   # CRITICAL/HIGH alerts
```

### 5. Run

```bash
# Local development
uvicorn app:app --reload --port 8000

# Production (Docker — runs app + Redis + Nginx)
docker-compose up -d
```

Open **http://localhost:8000** for the UI.
Open **http://localhost:8000/docs** for the full interactive API.

---

## Project Structure

```
cybersentinel/
│
├── app.py                        ← FastAPI app. All routes, API key auth,
│                                   rate limiting, SSE streaming, background
│                                   jobs, webhook callbacks.
│
├── core/
│   ├── agents/
│   │   ├── orchestrator.py       ← Master agent (Claude Opus). Reads input,
│   │   │                           decides which agents to invoke, aggregates
│   │   │                           findings, triggers report.
│   │   ├── email_agent.py        ← Email/phishing specialist (Claude Sonnet).
│   │   │                           Runs its own tool-use loop with 4 email tools.
│   │   ├── url_agent.py          ← URL/domain specialist (Claude Sonnet).
│   │   │                           Scans multiple URLs in parallel. Cache-aware.
│   │   └── report_agent.py       ← Report synthesiser (Claude Sonnet).
│   │                               Deterministic scoring + Claude narrative.
│   │
│   ├── tools/
│   │   ├── email_tools.py        ← analyse_headers, check_spf_dkim,
│   │   │                           detect_lookalikes, extract_iocs
│   │   └── url_tools.py          ← scan_url_urlscan, check_virustotal,
│   │                               lookup_whois, check_ip_reputation,
│   │                               analyse_certificate
│   │
│   ├── memory/
│   │   ├── case_store.py         ← SQLite case persistence. IOC index for
│   │   │                           threat hunting. PostgreSQL-upgradeable.
│   │   └── threat_cache.py       ← Caches VT/URLScan results. In-memory
│   │                               default, Redis via REDIS_URL.
│   └── notifications/
│       └── slack_notifier.py     ← Posts CRITICAL/HIGH alerts to Slack.
│                                   Includes daily digest support.
│
├── api/
│   └── models.py                 ← Pydantic schemas for all request/response types
│
├── templates/
│   └── index.html                ← Single-file dark UI. Multi-agent live tracks,
│                                   cases panel, IOC hunt. SSE-powered, no polling.
│
├── docker-compose.yml            ← App + Redis + Nginx. Production stack.
├── Dockerfile                    ← Non-root user, uvicorn, 4 workers.
├── nginx.conf                    ← Reverse proxy. SSE buffering disabled.
│                                   HTTPS, rate limiting, security headers.
├── requirements.txt
├── .env.example
├── README.md
└── sample_output.txt             ← Full example investigation run with all
                                    agent reasoning steps visible
```

---

## How the Agentic Loop Works

```python
# orchestrator.py — simplified
async def run(self, user_input, case_id):
    while True:
        response = await claude_opus.messages.create(
            tools=ORCHESTRATOR_TOOLS,     # delegate_to_email, delegate_to_url, delegate_to_report
            messages=messages
        )

        for block in response.content:
            if block.type == "tool_use":
                if block.name == "delegate_to_email_agent":
                    result = await email_agent.run(block.input["email_text"])
                elif block.name == "delegate_to_url_agent":
                    result = await url_agent.run(block.input["urls"])   # parallel
                elif block.name == "delegate_to_report_agent":
                    result = await report_agent.run(all_findings)

        if response.stop_reason == "end_turn":
            break   # Orchestrator decided investigation is complete

# url_agent.py — all URLs scanned at the same time
semaphore = asyncio.Semaphore(3)             # cap at 3 concurrent API calls
tasks = [analyse_url(url, semaphore) for url in urls]
results = await asyncio.gather(*tasks)       # parallel execution
```

Claude controls the loop at every level. The Orchestrator is not told "call email agent, then URL agent." It reads the input, reasons about what it contains, and decides. Each sub-agent is not told "call tool 1 then tool 2." It reads the tool definitions and decides based on what it finds. If VirusTotal flags a domain that was not in the original input (discovered via a redirect), the URL agent independently follows that lead. That autonomous follow-through is what makes it genuinely agentic.

---

## API Endpoints

Full interactive docs auto-generated at **http://localhost:8000/docs**.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v2/analyse/stream` | Start analysis, stream results via SSE in real time |
| `POST` | `/api/v2/analyse/async` | Queue analysis as background job, returns `case_id` to poll |
| `GET` | `/api/v2/cases` | List all past cases. Filter by `?severity=CRITICAL&status=closed` |
| `GET` | `/api/v2/cases/{id}` | Get full case with all findings and report |
| `GET` | `/api/v2/hunt/{ioc}` | Search all cases by URL, IP, domain, or email address |
| `GET` | `/api/v2/cache/stats` | Cache backend, key count, memory usage |
| `DELETE` | `/api/v2/cache/{target}` | Invalidate cached result — forces fresh API scan |
| `GET` | `/health` | Service health check + cache stats |

---

## Web UI

```bash
uvicorn app:app --reload --port 8000
# Open http://localhost:8000
```

Three panels in the dark-theme interface:

**Analyse** — paste any suspicious email (with or without headers) or a bare URL and click Analyse. Each agent — Orchestrator, Email, URL, Report — gets its own live track showing its reasoning, every tool call it makes, and every result it gets back, as they happen. When the investigation completes, the view transitions automatically to the full threat report with score, indicators, and recommended action.

**Cases** — every past investigation saved automatically. Each row shows severity colour, case ID, input preview, and time elapsed. Click any case to reload its full report.

**Hunt** — type any URL, IP address, domain, or email address and instantly search all past cases for that IOC. Find every investigation that ever touched a given piece of infrastructure.

The UI uses Server-Sent Events (SSE) — the server pushes events to the browser as each agent works. No polling, no page refreshes, no websocket setup required.

---

## Author

**Edhubillisandeepkumar**
Roll No: A23126511197 · Information Technology · ANITS(A) · 2027 Batch

Built for the **RHYM Technologies recruitment drive** as a demonstration of hands-on knowledge in: Multi-Agent AI Systems, Agentic AI, Claude AI tool_use, Async Python, Production API Development, Cybersecurity-AI Integration.

---

## License

MIT — see [LICENSE](LICENSE) for details.
