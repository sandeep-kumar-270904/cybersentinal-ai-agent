# CyberSentinel AI Agent 🛡️

An autonomous agentic AI system that investigates suspicious emails and URLs using real cybersecurity APIs — powered by Claude AI.

## What It Does

You paste a suspicious email or URL. CyberSentinel autonomously:

1. Analyses email headers for phishing signals
2. Scans embedded URLs via URLScan.io (live threat intelligence)
3. Cross-checks domains against 70+ AV engines via VirusTotal
4. Synthesises all findings into a structured threat report

No manual step selection. Claude decides which tools to call, in what order, based on what it finds — that's the agentic part.

---

## Demo Output

```
══════════════════════════════════════════════════
      CYBERSENTINEL THREAT REPORT
══════════════════════════════════════════════════

Threat Level     : CRITICAL 🔴

── Email Analysis ──
  Sender Domain    : paypa1.com
  Domain Mismatch  : YES ⚠️
  Lookalike domain: 'paypa1' impersonating PayPal

── URL Scan (URLScan.io) ──
  Domain           : paypa1-login.ru
  Country          : RU
  Malicious Flag   : YES ⚠️

── VirusTotal Analysis ──
  Malicious Flags  : 34 / 87 engines
  Flagged by: Kaspersky, Fortinet, ESET, BitDefender, Avast

── Recommended Action ──
  🚨 DO NOT CLICK. Block sender. Report to IT Security.
══════════════════════════════════════════════════
```

Full sample run: [sample_output.txt](./sample_output.txt)

---

## Architecture

```
User Input (email / URL)
        │
        ▼
   Claude (Reasoning Engine)
        │
        ├─► analyse_email_headers()   ← local Python parser
        │         │
        │         ▼ findings
        │
        ├─► scan_url()                ← URLScan.io API
        │         │
        │         ▼ domain, redirects, verdict
        │
        ├─► check_virustotal()        ← VirusTotal API (70+ engines)
        │         │
        │         ▼ malicious count, flagging vendors
        │
        └─► generate_threat_report()  ← Claude synthesis
                  │
                  ▼
           Structured Threat Report
```

Claude operates in a **ReAct loop** (Reason → Act → Observe → Repeat). It doesn't follow a fixed script — it decides which tools to call based on what each tool returns. If scan_url reveals a new domain, Claude checks that domain with VirusTotal too.

---

## Agentic AI Concepts Demonstrated

| Concept | Implementation |
|---|---|
| Autonomous tool selection | Claude decides tool call sequence based on input |
| ReAct loop | Reason → Act → Observe → iterate until report |
| Tool use / Function calling | Claude API `tool_use` blocks |
| Multi-step reasoning | Claude chains 3-4 tool calls with reasoning between |
| Real external API integration | URLScan.io + VirusTotal live data |
| Cybersecurity-AI integration | Threat intelligence + LLM synthesis |

---

## Tech Stack

- **Claude API** (Anthropic) — `claude-opus-4-5` with `tool_use`
- **URLScan.io API** — live URL scanning and domain analysis
- **VirusTotal API** — 70+ antivirus engine verdicts
- **Python 3.10+** — `anthropic`, `requests`, `python-dotenv`
- No framework, no frontend — pure terminal agent

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

### 3. Get API keys (all free)

| Key | Where to get it |
|---|---|
| `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) |
| `URLSCAN_API_KEY` | [urlscan.io/user/signup](https://urlscan.io/user/signup) |
| `VIRUSTOTAL_API_KEY` | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) |

### 4. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in your API keys
```

### 5. Run the agent

```bash
python agent.py
```

Paste a suspicious email or URL, press Enter twice, and watch the agent work.

---

## Project Structure

```
cybersentinel/
├── agent.py          ← main agentic loop (Claude tool_use)
├── tools.py          ← 4 tool functions + Claude tool definitions
├── prompts.py        ← system prompt defining agent behaviour
├── .env.example      ← API key template
├── requirements.txt  ← Python dependencies
├── README.md         ← this file
└── sample_output.txt ← example investigation run
```

---

## How the Agentic Loop Works

```python
# agent.py — simplified view
while not done:
    response = claude.messages.create(
        model="claude-opus-4-5",
        tools=TOOL_DEFINITIONS,   # Claude knows what tools exist
        messages=messages          # full conversation history
    )
    
    if response has tool_use blocks:
        for each tool_call in response:
            result = dispatch_tool(tool_call.name, tool_call.input)
            # result sent back to Claude as tool_result
    
    if response.stop_reason == "end_turn":
        break  # Claude decided investigation is complete
```

Claude controls the loop. It calls `generate_threat_report` only when it has sufficient evidence — not on a fixed schedule.

---

## Author

Built for RHYM Technologies recruitment drive — ANITS(A) 2027 Batch  
Demonstrates hands-on knowledge of: Agentic AI, Claude AI tool_use, LLM Applications, Cybersecurity-AI Integration

---

## License

MIT

---

## Web UI

CyberSentinel ships with a web interface that shows Claude's reasoning in real time.

```bash
python app.py
# Open http://localhost:5000
```

Each step appears as a live card — tool calls, results, and the final report render as Claude works through the investigation. A "Load demo" button lets you run the sample phishing case without typing.

![UI: phosphor-green terminal aesthetic, dark background, step cards for each tool call]
