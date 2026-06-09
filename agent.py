"""
agent.py — CyberSentinel AI Agent
Main agentic loop. Claude reasons, calls tools, observes results,
and iterates until the threat report is generated.

Usage:
    python agent.py

Then paste a suspicious email or URL when prompted.
"""

import json
import os
import anthropic
from dotenv import load_dotenv

from tools import (
    scan_url,
    check_virustotal,
    analyse_email_headers,
    generate_threat_report,
    TOOL_DEFINITIONS
)
from prompts import SYSTEM_PROMPT

load_dotenv()


# ─────────────────────────────────────────────
# Tool dispatcher — maps Claude's tool calls to real functions
# ─────────────────────────────────────────────

def dispatch_tool(tool_name: str, tool_input: dict) -> str:
    """
    Receives tool name + input from Claude's tool_use block.
    Calls the real function and returns the result as a JSON string.
    """
    print(f"\n  🔧 [{tool_name}] called with: {json.dumps(tool_input, indent=2)[:200]}")

    if tool_name == "analyse_email_headers":
        result = analyse_email_headers(tool_input["email_text"])

    elif tool_name == "scan_url":
        result = scan_url(tool_input["url"])

    elif tool_name == "check_virustotal":
        result = check_virustotal(tool_input["target"])

    elif tool_name == "generate_threat_report":
        result = generate_threat_report(
            email_analysis=tool_input.get("email_analysis"),
            url_scan=tool_input.get("url_scan"),
            virustotal=tool_input.get("virustotal"),
            original_input=tool_input.get("original_input", "")
        )
        # generate_threat_report returns a string, not dict
        if isinstance(result, str):
            print(result)  # Print report to terminal immediately
            return json.dumps({"report": result})

    else:
        result = {"error": f"Unknown tool: {tool_name}"}

    result_str = json.dumps(result, indent=2)
    print(f"  ✅ Result preview: {result_str[:300]}...")
    return result_str


# ─────────────────────────────────────────────
# Main agentic loop
# ─────────────────────────────────────────────

def run_agent(user_input: str):
    """
    Core agentic loop.
    
    1. Sends user input + system prompt to Claude with tools available
    2. Claude reasons and returns tool_use blocks
    3. We dispatch each tool call to the real function
    4. Results are sent back to Claude as tool_result blocks
    5. Claude continues reasoning until it calls generate_threat_report
    6. Loop ends when Claude returns a final text response
    """

    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    messages = [
        {"role": "user", "content": user_input}
    ]

    print("\n" + "═" * 50)
    print("  CYBERSENTINEL — Investigation Started")
    print("═" * 50)

    iteration = 0
    max_iterations = 10  # safety limit

    while iteration < max_iterations:
        iteration += 1
        print(f"\n  🧠 Claude reasoning... (step {iteration})")

        # Call Claude with tools
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOL_DEFINITIONS,
            messages=messages
        )

        # Check stop reason
        stop_reason = response.stop_reason

        # Collect all content from this response
        tool_use_blocks = []
        text_blocks = []

        for block in response.content:
            if block.type == "text":
                text_blocks.append(block.text)
                if block.text.strip():
                    print(f"\n  💬 {block.text.strip()}")
            elif block.type == "tool_use":
                tool_use_blocks.append(block)

        # If no tool calls and stop_reason is end_turn — Claude is done
        if stop_reason == "end_turn" and not tool_use_blocks:
            print("\n" + "═" * 50)
            print("  Investigation complete.")
            print("═" * 50)
            break

        # Process all tool calls in this response
        if tool_use_blocks:
            # Add Claude's full response (with tool_use blocks) to message history
            messages.append({
                "role": "assistant",
                "content": response.content
            })

            # Execute each tool and collect results
            tool_results = []
            for tool_block in tool_use_blocks:
                tool_result = dispatch_tool(tool_block.name, tool_block.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_block.id,
                    "content": tool_result
                })

            # Send all tool results back to Claude
            messages.append({
                "role": "user",
                "content": tool_results
            })

        # If stop_reason is end_turn with tool calls somehow, break
        elif stop_reason == "end_turn":
            break

    if iteration >= max_iterations:
        print("\n  ⚠️  Max iterations reached. Investigation stopped.")


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main():
    print("\n╔══════════════════════════════════════════════╗")
    print("║        CYBERSENTINEL AI AGENT v1.0           ║")
    print("║   Agentic Cybersecurity Analysis via Claude  ║")
    print("╚══════════════════════════════════════════════╝")
    print("\nPaste a suspicious email or URL below.")
    print("Press Enter twice when done.\n")

    lines = []
    while True:
        try:
            line = input()
            if line == "" and lines and lines[-1] == "":
                break
            lines.append(line)
        except EOFError:
            break

    user_input = "\n".join(lines).strip()

    if not user_input:
        print("No input provided. Exiting.")
        return

    run_agent(user_input)


if __name__ == "__main__":
    main()
