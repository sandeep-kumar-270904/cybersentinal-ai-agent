"""
orchestrator.py — CyberSentinel v2 Multi-Agent Orchestrator

The master agent that:
  - Receives analysis requests
  - Plans which specialist agents to invoke
  - Aggregates findings from sub-agents
  - Decides when evidence is sufficient
  - Triggers final report synthesis
"""

import json
import os
import asyncio
from typing import Optional
import anthropic
from core.agents.email_agent import EmailAgent
from core.agents.url_agent import URLAgent
from core.agents.report_agent import ReportAgent
from core.memory.case_store import CaseStore
from core.memory.threat_cache import ThreatCache

ORCHESTRATOR_SYSTEM = """You are the CyberSentinel Orchestration Engine — a meta-agent that directs a team of specialist AI agents.

Your job is NOT to analyse threats yourself. Your job is to:
1. Understand the input
2. Decide which specialist agents to invoke and in what order
3. Aggregate their findings
4. Decide if more investigation is needed
5. Trigger the report agent when evidence is sufficient

## Your Specialist Agents (tools)

- delegate_to_email_agent — handles all email/header/phishing analysis
- delegate_to_url_agent   — handles URL scanning, domain checks, VirusTotal, WHOIS, IP reputation
- delegate_to_report_agent — synthesises all findings into a final structured report

## Decision Logic

Input contains email text → always call email_agent first
Input contains URLs → call url_agent for each unique suspicious URL
Input contains only a URL/domain → call url_agent directly
Email agent returns URLs → pass those to url_agent too
All agents done → call report_agent

## Rules
- You are a delegator, not an analyst. Don't do the analysis yourself.
- Run url_agent and email_agent in parallel when both are needed.
- If a sub-agent returns an error, note it and continue with others.
- Always end with report_agent — never skip it.
- Be brief in your narration: one line per decision.
"""

ORCHESTRATOR_TOOLS = [
    {
        "name": "delegate_to_email_agent",
        "description": "Delegates email/phishing analysis to the EmailAgent specialist. Pass the full raw email text. Returns structured phishing indicators, domain analysis, and embedded URLs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "email_text": {"type": "string", "description": "Full raw email text including headers and body"},
                "priority": {"type": "string", "enum": ["high", "medium", "low"], "description": "Triage priority hint"}
            },
            "required": ["email_text"]
        }
    },
    {
        "name": "delegate_to_url_agent",
        "description": "Delegates URL/domain threat analysis to the URLAgent specialist. Handles URLScan.io, VirusTotal, WHOIS, and IP reputation checks. Pass a list of URLs to analyse.",
        "input_schema": {
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of URLs or domains to investigate"
                },
                "deep_scan": {"type": "boolean", "description": "If true, also checks WHOIS and IP reputation. Slower but more thorough."}
            },
            "required": ["urls"]
        }
    },
    {
        "name": "delegate_to_report_agent",
        "description": "Delegates final report synthesis to the ReportAgent. Pass all collected findings. Returns a structured, human-readable threat report with severity rating and recommended actions.",
        "input_schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "object",
                    "description": "Dict containing email_findings, url_findings, and original_input"
                },
                "case_id": {"type": "string", "description": "Case ID for this investigation"}
            },
            "required": ["findings"]
        }
    }
]


class OrchestratorAgent:
    """
    Top-level orchestrator. Spawns and coordinates specialist sub-agents.
    Emits events via async generator for real-time streaming.
    """

    def __init__(self):
        self.client = anthropic.AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.email_agent = EmailAgent()
        self.url_agent = URLAgent()
        self.report_agent = ReportAgent()
        self.case_store = CaseStore()
        self.threat_cache = ThreatCache()

    async def run(self, user_input: str, case_id: str):
        """
        Main async agentic loop. Yields SSE-compatible event dicts.
        """
        messages = [{"role": "user", "content": user_input}]
        all_findings = {"email_findings": None, "url_findings": [], "original_input": user_input}

        yield {"event": "status", "data": {"text": "Orchestrator initialising investigation", "case_id": case_id}}

        iteration = 0
        max_iterations = 15

        while iteration < max_iterations:
            iteration += 1
            yield {"event": "thinking", "data": {"step": iteration, "agent": "orchestrator"}}

            response = await self.client.messages.create(
                model="claude-opus-4-6",
                max_tokens=4096,
                system=ORCHESTRATOR_SYSTEM,
                tools=ORCHESTRATOR_TOOLS,
                messages=messages
            )

            tool_use_blocks = []
            for block in response.content:
                if block.type == "text" and block.text.strip():
                    yield {"event": "reasoning", "data": {"text": block.text.strip(), "agent": "orchestrator"}}
                elif block.type == "tool_use":
                    tool_use_blocks.append(block)

            if response.stop_reason == "end_turn" and not tool_use_blocks:
                yield {"event": "status", "data": {"text": "Orchestration complete", "case_id": case_id}}
                break

            if tool_use_blocks:
                messages.append({"role": "assistant", "content": response.content})
                tool_results = []

                # Run tool calls — parallelise where possible
                tasks = []
                for tb in tool_use_blocks:
                    tasks.append(self._dispatch(tb, all_findings, case_id))

                results = await asyncio.gather(*tasks)

                for tb, (result, events) in zip(tool_use_blocks, results):
                    # Emit events from sub-agent
                    for ev in events:
                        yield ev
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tb.id,
                        "content": json.dumps(result)
                    })

                messages.append({"role": "user", "content": tool_results})

            elif response.stop_reason == "end_turn":
                break

        # Persist case
        await self.case_store.save(case_id, all_findings)
        yield {"event": "end", "data": {"case_id": case_id}}

    async def _dispatch(self, tool_block, all_findings: dict, case_id: str):
        """Dispatch orchestrator tool calls to specialist agents."""
        name = tool_block.name
        inp = tool_block.input
        events = []

        events.append({"event": "agent_delegated", "data": {"to": name, "case_id": case_id}})

        if name == "delegate_to_email_agent":
            result, sub_events = await self.email_agent.run(inp["email_text"])
            all_findings["email_findings"] = result
            events.extend(sub_events)

        elif name == "delegate_to_url_agent":
            result, sub_events = await self.url_agent.run(
                urls=inp["urls"],
                deep_scan=inp.get("deep_scan", False)
            )
            all_findings["url_findings"].extend(result)
            events.extend(sub_events)

        elif name == "delegate_to_report_agent":
            merged_findings = {**all_findings}
            if inp.get("findings"):
                merged_findings.update(inp["findings"])
            result, sub_events = await self.report_agent.run(merged_findings)
            events.extend(sub_events)

        else:
            result = {"error": f"Unknown delegation target: {name}"}

        return result, events
