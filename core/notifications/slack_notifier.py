"""
slack_notifier.py — CyberSentinel v2
Posts alerts to a Slack channel when CRITICAL or HIGH threats are detected.

Setup:
  1. Create a Slack App at https://api.slack.com/apps
  2. Add "Incoming Webhooks" — copy the webhook URL
  3. Set SLACK_WEBHOOK_URL in .env
  4. Optionally set SLACK_ALERT_LEVELS=CRITICAL,HIGH (default)

Usage (call from run_agent_streaming after report is generated):
  from core.notifications.slack_notifier import notify_slack
  await notify_slack(case_id, report)
"""

import os
import json
import asyncio
import httpx
from datetime import datetime

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
SLACK_ALERT_LEVELS = set(os.getenv("SLACK_ALERT_LEVELS", "CRITICAL,HIGH").upper().split(","))


async def notify_slack(case_id: str, report: dict, app_base_url: str = None):
    """
    Posts a threat alert to Slack. Only fires for CRITICAL or HIGH threat levels.
    Silently skips if SLACK_WEBHOOK_URL is not configured.
    """
    if not SLACK_WEBHOOK_URL:
        return

    threat_level = report.get("threat_level", "UNKNOWN")
    if threat_level not in SLACK_ALERT_LEVELS:
        return

    score = report.get("composite_score", 0)
    indicators = report.get("indicators", [])[:5]  # Top 5 indicators
    action = report.get("recommended_action", "")
    case_url = f"{app_base_url}/api/v2/cases/{case_id}" if app_base_url else f"Case ID: {case_id}"

    # Emoji + colour mapping
    level_config = {
        "CRITICAL": {"emoji": "🚨", "color": "#ff0000"},
        "HIGH":     {"emoji": "🟠", "color": "#ff6600"},
        "MEDIUM":   {"emoji": "🟡", "color": "#ffaa00"},
        "LOW":      {"emoji": "🟢", "color": "#00cc44"},
    }
    cfg = level_config.get(threat_level, {"emoji": "⚪", "color": "#888888"})

    # Build Slack Block Kit message
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{cfg['emoji']} CyberSentinel Alert — {threat_level} Threat"
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Case ID:*\n`{case_id}`"},
                {"type": "mrkdwn", "text": f"*Threat Level:*\n{threat_level}"},
                {"type": "mrkdwn", "text": f"*Score:*\n{score}/100"},
                {"type": "mrkdwn", "text": f"*Time:*\n{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"},
            ]
        }
    ]

    if indicators:
        indicator_text = "\n".join(f"• {i}" for i in indicators)
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Top Indicators:*\n{indicator_text}"}
        })

    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": f"*Action:*\n{action}"}
    })

    if app_base_url:
        blocks.append({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "View Full Report"},
                "url": case_url,
                "style": "danger" if threat_level == "CRITICAL" else "primary"
            }]
        })

    payload = {
        "attachments": [{
            "color": cfg["color"],
            "blocks": blocks
        }]
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(SLACK_WEBHOOK_URL, json=payload)
            resp.raise_for_status()
    except Exception as e:
        # Never let notification failure crash the main flow
        print(f"[SlackNotifier] Failed to send alert for case {case_id}: {e}")


async def notify_slack_summary(cases: list):
    """
    Daily digest: post a summary of all cases from the past 24 hours.
    Call this from a cron job or scheduled task.
    """
    if not SLACK_WEBHOOK_URL or not cases:
        return

    critical = [c for c in cases if c.get("severity") == "CRITICAL"]
    high = [c for c in cases if c.get("severity") == "HIGH"]
    medium = [c for c in cases if c.get("severity") == "MEDIUM"]
    low = [c for c in cases if c.get("severity") == "LOW"]

    text = (
        f"*CyberSentinel Daily Digest — {datetime.utcnow().strftime('%Y-%m-%d')}*\n"
        f"🚨 Critical: {len(critical)}  🟠 High: {len(high)}  🟡 Medium: {len(medium)}  🟢 Low: {len(low)}\n"
        f"Total investigations: {len(cases)}"
    )

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(SLACK_WEBHOOK_URL, json={"text": text})
    except Exception as e:
        print(f"[SlackNotifier] Daily digest failed: {e}")
