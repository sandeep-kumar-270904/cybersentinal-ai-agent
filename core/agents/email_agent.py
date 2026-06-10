"""
email_agent.py — CyberSentinel v2
EmailAgent: Specialist agent for email/phishing analysis.
Has its own Claude loop with email-specific tools.
"""

import os
import re
import json
from typing import Tuple
import anthropic
from core.tools.email_tools import (
    analyse_headers,
    check_spf_dkim,
    detect_lookalikes,
    extract_iocs,
    EMAIL_TOOL_DEFINITIONS
)

EMAIL_AGENT_SYSTEM = """You are the CyberSentinel Email Analysis Agent — a specialist in phishing, BEC, and email-borne threats.

Your focus is ONLY email. You have these tools:
1. analyse_headers    — parse headers, detect spoofing, domain mismatch
2. check_spf_dkim     — verify SPF/DKIM/DMARC alignment (simulated check)
3. detect_lookalikes  — detect brand impersonation / lookalike domains
4. extract_iocs       — extract all IOCs: URLs, IPs, domains, hashes

Always run all four tools on any email input. Return a comprehensive findings dict.
"""


class EmailAgent:
    def __init__(self):
        self.client = anthropic.AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    async def run(self, email_text: str) -> Tuple[dict, list]:
        """Run email analysis loop. Returns (findings, events)."""
        messages = [{"role": "user", "content": f"Analyse this email:\n\n{email_text}"}]
        events = []
        findings = {}

        iteration = 0
        while iteration < 8:
            iteration += 1
            events.append({"event": "thinking", "data": {"agent": "email_agent", "step": iteration}})

            response = await self.client.messages.create(
                model="claude-sonnet-4-6",  # Use Sonnet for sub-agents (cheaper, faster)
                max_tokens=2048,
                system=EMAIL_AGENT_SYSTEM,
                tools=EMAIL_TOOL_DEFINITIONS,
                messages=messages
            )

            tool_use_blocks = []
            for block in response.content:
                if block.type == "text" and block.text.strip():
                    events.append({"event": "reasoning", "data": {"text": block.text.strip(), "agent": "email_agent"}})
                elif block.type == "tool_use":
                    tool_use_blocks.append(block)

            if response.stop_reason == "end_turn" and not tool_use_blocks:
                break

            if tool_use_blocks:
                messages.append({"role": "assistant", "content": response.content})
                tool_results = []

                for tb in tool_use_blocks:
                    events.append({"event": "tool_call", "data": {"agent": "email_agent", "tool": tb.name}})
                    result = await self._call_tool(tb.name, tb.input)
                    findings[tb.name] = result
                    events.append({"event": "tool_result", "data": {"agent": "email_agent", "tool": tb.name, "result": result}})
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tb.id,
                        "content": json.dumps(result)
                    })

                messages.append({"role": "user", "content": tool_results})

            elif response.stop_reason == "end_turn":
                break

        return findings, events

    async def _call_tool(self, name: str, inp: dict) -> dict:
        if name == "analyse_headers":
            return analyse_headers(inp["email_text"])
        elif name == "check_spf_dkim":
            return check_spf_dkim(inp["email_text"])
        elif name == "detect_lookalikes":
            return detect_lookalikes(inp["email_text"])
        elif name == "extract_iocs":
            return extract_iocs(inp["email_text"])
        return {"error": f"Unknown tool: {name}"}
