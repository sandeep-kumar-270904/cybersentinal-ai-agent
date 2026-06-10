<div align="center">

# 🛡️ CyberSentinel AI Agent

### Autonomous Agentic Cybersecurity Threat Analysis — Powered by Claude AI

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Claude](https://img.shields.io/badge/Claude-claude--opus--4--5-D97706?style=flat-square)](https://anthropic.com)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?style=flat-square)](https://virustotal.com)
[![URLScan](https://img.shields.io/badge/URLScan.io-API-FF6B35?style=flat-square)](https://urlscan.io)
[![License](https://img.shields.io/badge/License-MIT-00cc6e?style=flat-square)](LICENSE)

**CyberSentinel** is a fully autonomous AI agent that investigates suspicious emails and URLs using real cybersecurity APIs. It does not follow a fixed script — Claude reasons about the input, autonomously decides which tools to call, observes results, and iterates until it can produce a confident structured threat report.

[Features](#features) · [Architecture](#architecture) · [Setup](#setup) · [Web UI](#web-ui) · [How It Works](#how-the-agentic-loop-works) · [Concepts](#agentic-ai-concepts-demonstrated)

</div>

---

## Overview

Most threat analysis tools follow a fixed pipeline: step 1, step 2, step 3. CyberSentinel doesn't. It uses **Claude AI's tool_use API** to implement a genuine agentic system where the LLM controls the investigation flow.

Given a suspicious email or URL, the agent:

1. Reads and reasons about the input
2. Decides which tool to call first based on what it finds
3. Observes the result and updates its understanding
4. Calls the next tool — or digs deeper into what the previous tool revealed
5. Concludes only when it has sufficient evidence — not on a fixed schedule

This is the **ReAct pattern** (Reason → Act → Observe → Repeat) applied to real-world cybersecurity threat intelligence.

---

## Features

- **Truly agentic** — Claude controls the tool call sequence. No hardcoded pipeline.
- **Real threat intelligence** — Live URLScan.io and VirusTotal API calls, not mocked data
- **4 integrated tools** — Email header analysis, URL scanning, multi-engine AV check, report synthesis
- **Web UI with live streaming** — Watch Claude reason step-by-step in real time via Server-Sent Events
- **Terminal mode** — Pure Python CLI for scripting and automation
- **70+ AV engines** — VirusTotal cross-checks every domain against Kaspersky, Fortinet, ESET, and more
- **Zero human steps** — Full threat triage from raw email text to final report, end-to-end automated

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User Input                           │
│              (suspicious email or URL)                      │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   Claude (Reasoning Engine)                 │
│                                                             │
│   STEP 1: Read input → identify suspicious elements         │
│   STEP 2: Select tool → call with relevant arguments        │
│   STEP 3: Observe result → update threat model              │
│   STEP 4: Decide next action → deeper scan or conclude      │
│   STEP 5: Generate report when evidence is sufficient       │
└──────┬───────────────┬──────────────────┬───────────────────┘
       │               │                  │
       ▼               ▼                  ▼
┌─────────────┐ ┌────────────────┐ ┌─────────────────┐
│   Email     │ │  URLScan.io    │ │   VirusTotal    │
│  Header     │ │  Live URL      │ │   70+ Engine    │
│  Parser     │ │  Scanner       │ │   AV Check      │
│  (local)    │ │  (REST API)    │ │   (REST API)    │
└──────┬──────┘ └───────┬────────┘ └────────┬────────┘
       │                │                   │
       └────────────────┴───────────────────┘
                        │
                        ▼
          ┌─────────────────────────┐
          │   generate_threat_      │
          │   report()              │
          │   Claude synthesises    │
          │   all findings          │
          └────────────┬────────────┘
                       │
                       ▼
          ┌─────────────────────────┐
          │   THREAT REPORT         │
          │   Level: CRITICAL 🔴    │
          │   Evidence: [...]       │
          │   Action: Block sender  │
          └─────────────────────────┘
```

---

## Project Structure

```
cybersentinel-ai-agent/
│
├── agent.py              ← Core agentic loop. Claude tool_use, ReAct iterations,
│                           tool dispatcher, multi-turn message history management.
│
├── app.py                ← Flask web server. Streams agent reasoning steps to the
│                           browser in real time via Server-Sent Events (SSE).
│
├── tools.py              ← All 4 tool functions with real API calls.
│                           Also contains TOOL_DEFINITIONS — the JSON schema
│                           that tells Claude what tools are available and how to use them.
│
├── prompts.py            ← System prompt. Defines Claude's role as an autonomous
│                           cybersecurity analyst with explicit reasoning instructions.
│
├── templates/
│   └── index.html        ← Single-file web UI. Phosphor-terminal aesthetic.
│                           Live step cards, VirusTotal bar chart, threat badge.
│
├── requirements.txt      ← anthropic, requests, python-dotenv, flask
├── .env.example          ← API key template — copy to .env and fill in
├── sample_output.txt     ← Full terminal run showing real agent investigation
└── README.md             ← This file
```

---

## Setup

### Prerequisites

- Python 3.10 or higher
- pip

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

| Service | Key Name | Signup Link | Notes |
|---|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) | Free credits on signup |
| URLScan.io | `URLSCAN_API_KEY` | [urlscan.io/user/signup](https://urlscan.io/user/signup) | Instant, no credit card |
| VirusTotal | `VIRUSTOTAL_API_KEY` | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | Free tier: 4 req/min |

### 4. Configure environment

```bash
cp .env.example .env
```

Open `.env` and fill in your three API keys:

```env
ANTHROPIC_API_KEY=sk-ant-...
URLSCAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

---

## Usage

### Terminal Mode

```bash
python agent.py
```

Paste a suspicious email (with headers and body) or a bare URL. Press **Enter twice** to submit. The agent begins the investigation immediately.

**Example input:**

```
From: support@paypa1.com
Reply-To: noreply@harvest-cred.ru
Subject: [URGENT] Your account will be suspended in 24 hours

Your PayPal account has been suspended due to unusual activity.
Click here to verify: http://bit.ly/3xK9mQ2
You have 24 hours before permanent deletion.
```

**Example output:**

```
══════════════════════════════════════════════════
      CYBERSENTINEL THREAT REPORT
══════════════════════════════════════════════════

Threat Level     : CRITICAL 🔴

── Email Analysis ──
  Sender Domain    : paypa1.com
  Domain Mismatch  : YES ⚠️  (reply-to: harvest-cred.ru)
  Urgency Keywords : suspended, 24 hours, immediately, click here
  Signals:
    • Lookalike domain 'paypa1' impersonating PayPal
    • Shortened/obfuscated URL detected: http://bit.ly/3xK9mQ2

── URL Scan (URLScan.io) ──
  Resolved Domain  : paypa1-login.ru
  Country          : RU
  Malicious Flag   : YES ⚠️
  Risk Score       : 87 / 100

── VirusTotal Analysis ──
  Engines Checked  : 87
  Malicious Flags  : 34
  Flagged by       : Kaspersky, Fortinet, ESET, BitDefender, Avast

── Recommended Action ──
  🚨 DO NOT CLICK. Block sender immediately.
     Report to IT Security. Delete this email.
══════════════════════════════════════════════════
```

Full sample run with all agent reasoning steps: [sample_output.txt](./sample_output.txt)

---

## Web UI

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

The web interface streams each step of the agent's investigation in real time:

- **Reasoning cards** — Claude's thought process between tool calls
- **Tool call cards** — what tool was called and with what input
- **Result cards** — parsed output from each API, rendered as structured data
- **Live VirusTotal bar** — animated detection rate visualisation
- **Threat report panel** — colour-coded final verdict with evidence summary

A **⚡ Load demo** button pre-fills the phishing email so you can run a full demonstration without typing.

The UI uses Server-Sent Events (SSE) — the Flask backend streams agent events to the browser as they happen, with no polling.

---

## How the Agentic Loop Works

```python
# agent.py — core loop (simplified)

messages = [{"role": "user", "content": user_input}]

while True:
    response = client.messages.create(
        model="claude-opus-4-5",
        system=SYSTEM_PROMPT,       # defines Claude's analyst role
        tools=TOOL_DEFINITIONS,     # 4 tools Claude can choose from
        messages=messages           # full conversation history
    )

    # Claude returns tool_use blocks when it wants to call a tool
    for block in response.content:
        if block.type == "tool_use":
            result = dispatch_tool(block.name, block.input)
            # result fed back into messages as tool_result

    # Claude returns stop_reason="end_turn" when investigation is complete
    if response.stop_reason == "end_turn" and no tool calls:
        break
```

**Key insight:** Claude is not told "call tool 1, then tool 2." It reads the tool definitions, reasons about the input, and decides the sequence autonomously. If `scan_url` reveals a previously unknown redirect domain, Claude will independently call `check_virustotal` on that new domain — a decision that was not in the original user input. That's what makes it agentic.

---

## The 4 Tools

### `analyse_email_headers(email_text)`
Local Python parser — no external API needed. Extracts sender domain, reply-to domain, detects domain mismatches, scans for urgency keywords, extracts all embedded URLs, and runs lookalike brand detection (paypa1 vs paypal, arnazon vs amazon etc.). Always called first when email text is present.

### `scan_url(url)`
Calls the **URLScan.io REST API**. Submits the URL for live scanning and returns: resolved domain, hosting country, IP address, redirect chain, malicious verdict flag, and risk score. Used by real security professionals for threat intelligence. Handles shortened URLs (bit.ly etc.) by following the full redirect chain.

### `check_virustotal(target)`
Calls the **VirusTotal API**. Checks a URL or domain against **70+ antivirus engines** simultaneously. Returns malicious count, suspicious count, clean count, flagging vendors, and a threat verdict (CLEAN / LOW / MEDIUM / HIGH / CRITICAL). Called after scan_url to cross-verify any domain that looks suspicious.

### `generate_threat_report(email_analysis, url_scan, virustotal)`
Claude's synthesis step. Takes all collected findings from the other three tools, computes an overall threat level, and produces a structured report with evidence list and recommended action. Always the last tool called — Claude only invokes this when it has sufficient evidence to conclude.

---

## Agentic AI Concepts Demonstrated

| Concept | Implementation in this project |
|---|---|
| **ReAct Loop** | Reason → Act → Observe → Repeat. Claude narrates reasoning before each tool call, observes results, and decides whether to continue or conclude. |
| **Autonomous Tool Selection** | Claude receives tool definitions and decides which tools to call and in what order — not hardcoded in the application logic. |
| **Tool Use / Function Calling** | Claude API `tool_use` blocks. Tools defined with JSON schema input definitions. Results returned as `tool_result` messages. |
| **Multi-turn Context** | Full message history (including all tool calls and results) sent with every API request. Claude maintains complete context across the investigation. |
| **Dynamic Investigation Path** | Tool call sequence changes based on findings. A URL found in email headers triggers a URL scan. A domain found in that scan triggers a VirusTotal check. |
| **Autonomous Termination** | Claude decides when to stop. The loop exits only when `stop_reason == "end_turn"` with no pending tool calls — not after a fixed number of steps. |
| **LLM as Reasoning Engine** | Claude is not just generating text — it is making decisions, interpreting structured API data, and synthesising multi-source evidence into a coherent threat assessment. |
| **Cybersecurity-AI Integration** | Real threat intelligence from URLScan.io and VirusTotal processed and contextualised by an LLM — the exact intersection of AI and cybersecurity. |

---

## Why This Is Not a Chatbot

A typical LLM app: user asks → model answers → done.

CyberSentinel: user submits input → Claude reasons → calls real API → reads structured data → decides next action → calls another real API → synthesises everything → produces actionable report.

Claude is not summarising pre-existing text. It is directing a multi-step investigation against live external systems, making autonomous decisions at each step based on real-time data. The output — a threat verdict and recommended action — is derived from evidence, not from Claude's training data.

---

## Tech Stack

| Layer | Technology |
|---|---|
| AI / LLM | Anthropic Claude API (`claude-opus-4-5`), tool_use, multi-turn |
| Threat Intel | URLScan.io REST API, VirusTotal REST API v3 |
| Backend | Python 3.10+, Flask 3.0, Server-Sent Events |
| Frontend | Vanilla HTML/CSS/JS, JetBrains Mono, phosphor-terminal UI |
| Config | python-dotenv, .env-based API key management |
| No | Frameworks, LangChain, LlamaIndex, or any agent library |

> Built without LangChain or any agent framework — the agentic loop is implemented directly against the Claude API using `tool_use` blocks. This demonstrates a ground-up understanding of how agentic systems work, not just framework usage.

---

## Author

**Edhubillisandeepkumar**  
Roll No: A23126511197 · Information Technology · ANITS(A) · 2027 Batch

Built as a demonstration of hands-on knowledge in Agentic AI, Claude AI integration, LLM applications, and Cybersecurity-AI systems for the **RHYM Technologies recruitment drive**.

---

## License

MIT — see [LICENSE](LICENSE) for details.
