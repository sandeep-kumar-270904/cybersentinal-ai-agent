"""
app.py — CyberSentinel AI Agent
Flask web server. Streams agent reasoning steps to the UI via Server-Sent Events.
Run: python app.py  → open http://localhost:5000
"""

import json
import os
import threading
import queue
import anthropic
from flask import Flask, render_template, request, Response, stream_with_context
from dotenv import load_dotenv

from tools import (
    scan_url, check_virustotal,
    analyse_email_headers, generate_threat_report,
    TOOL_DEFINITIONS
)
from prompts import SYSTEM_PROMPT

load_dotenv()

app = Flask(__name__)

# ── SSE event streaming ────────────────────────────────────────

def stream_event(event_type: str, data: dict):
    """Format a Server-Sent Event."""
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


def run_agent_streaming(user_input: str, event_queue: queue.Queue):
    """
    Full agentic loop — puts SSE events into the queue as it runs.
    The Flask route reads from this queue and streams to the browser.
    """
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    messages = [{"role": "user", "content": user_input}]

    event_queue.put(("status", {"text": "Investigation started", "icon": "🛡️"}))

    iteration = 0
    all_findings = {"email_analysis": None, "url_scan": None, "virustotal": None}

    while iteration < 10:
        iteration += 1
        event_queue.put(("thinking", {"step": iteration}))

        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOL_DEFINITIONS,
            messages=messages
        )

        tool_use_blocks = []
        for block in response.content:
            if block.type == "text" and block.text.strip():
                event_queue.put(("reasoning", {"text": block.text.strip()}))
            elif block.type == "tool_use":
                tool_use_blocks.append(block)

        if response.stop_reason == "end_turn" and not tool_use_blocks:
            event_queue.put(("done", {}))
            break

        if tool_use_blocks:
            messages.append({"role": "assistant", "content": response.content})
            tool_results = []

            for tb in tool_use_blocks:
                event_queue.put(("tool_call", {"name": tb.name, "input": tb.input}))

                # Dispatch
                if tb.name == "analyse_email_headers":
                    result = analyse_email_headers(tb.input["email_text"])
                    all_findings["email_analysis"] = result
                elif tb.name == "scan_url":
                    event_queue.put(("tool_waiting", {"name": "scan_url", "msg": "Waiting for URLScan.io (15s)..."}))
                    result = scan_url(tb.input["url"])
                    all_findings["url_scan"] = result
                elif tb.name == "check_virustotal":
                    result = check_virustotal(tb.input["target"])
                    all_findings["virustotal"] = result
                elif tb.name == "generate_threat_report":
                    result_str = generate_threat_report(
                        email_analysis=all_findings.get("email_analysis"),
                        url_scan=all_findings.get("url_scan"),
                        virustotal=all_findings.get("virustotal"),
                        original_input=user_input
                    )
                    result = {"report": result_str}
                    event_queue.put(("report", {"text": result_str, "findings": all_findings}))
                else:
                    result = {"error": f"Unknown tool: {tb.name}"}

                event_queue.put(("tool_result", {"name": tb.name, "result": result}))

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tb.id,
                    "content": json.dumps(result)
                })

            messages.append({"role": "user", "content": tool_results})

        elif response.stop_reason == "end_turn":
            event_queue.put(("done", {}))
            break

    event_queue.put(("end", {}))


# ── Routes ─────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyse", methods=["POST"])
def analyse():
    data = request.get_json()
    user_input = data.get("input", "").strip()
    if not user_input:
        return {"error": "No input"}, 400

    event_q = queue.Queue()

    def run():
        try:
            run_agent_streaming(user_input, event_q)
        except Exception as e:
            event_q.put(("error", {"message": str(e)}))
            event_q.put(("end", {}))

    threading.Thread(target=run, daemon=True).start()

    def generate():
        while True:
            try:
                event_type, payload = event_q.get(timeout=60)
                yield stream_event(event_type, payload)
                if event_type == "end":
                    break
            except queue.Empty:
                yield stream_event("error", {"message": "Timeout"})
                break

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)
