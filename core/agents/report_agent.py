"""
report_agent.py — CyberSentinel v2
ReportAgent: Synthesises all collected findings into a final structured report.
Uses Claude to generate a natural-language narrative on top of the data.
"""

import os
import json
from datetime import datetime
from typing import Tuple
import anthropic

REPORT_SYSTEM = """You are the CyberSentinel Report Agent. Your job is to synthesise raw threat intelligence findings into a clear, structured, actionable report for a security analyst.

You will receive a JSON object with findings from the email agent, URL agent, and original input.

Your report must:
1. State the overall threat level clearly (CRITICAL / HIGH / MEDIUM / LOW / CLEAN)
2. Summarise what was found in plain English (2–3 sentences)
3. List the specific indicators that drove the threat level
4. State exactly what the analyst should do next
5. Include a confidence level (HIGH / MEDIUM / LOW) based on evidence quality

Keep it tight. No fluff. Analysts are busy.

Output format: Structured text. Use clear section headers. No markdown code blocks.
"""


class ReportAgent:
    def __init__(self):
        self.client = anthropic.AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

    async def run(self, findings: dict) -> Tuple[dict, list]:
        """Generate final threat report. Returns (report_dict, events)."""
        events = []
        events.append({"event": "status", "data": {"text": "Report Agent: Synthesising findings", "agent": "report_agent"}})

        # Build the structured report from raw findings (no LLM needed for this part)
        structured = self._build_structured_report(findings)

        # Ask Claude to write the narrative summary
        try:
            response = await self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1024,
                system=REPORT_SYSTEM,
                messages=[{
                    "role": "user",
                    "content": f"Generate a threat report for these findings:\n\n{json.dumps(findings, indent=2)[:6000]}"
                }]
            )
            narrative = response.content[0].text if response.content else ""
        except Exception as e:
            narrative = f"[Narrative generation failed: {e}]"

        structured["narrative"] = narrative
        structured["generated_at"] = datetime.utcnow().isoformat()

        # Emit the final report event
        events.append({"event": "report", "data": {"report": structured, "findings": findings}})

        return structured, events

    def _build_structured_report(self, findings: dict) -> dict:
        """Build deterministic structured data from findings — no LLM needed."""
        report = {
            "threat_level": "LOW",
            "composite_score": 0,
            "indicators": [],
            "email_summary": {},
            "url_summaries": [],
            "recommended_action": "",
            "confidence": "LOW"
        }

        score = 0
        indicators = []
        evidence_count = 0

        # ── Email findings ──────────────────────────────────────────
        email_f = findings.get("email_findings", {})
        if email_f:
            evidence_count += 1
            headers = email_f.get("analyse_headers", {})
            spf = email_f.get("check_spf_dkim", {})
            lookalikes = email_f.get("detect_lookalikes", {})
            iocs = email_f.get("extract_iocs", {})

            report["email_summary"] = {
                "sender_domain": headers.get("sender_domain"),
                "domain_mismatch": headers.get("domain_mismatch", False),
                "urgency_score": headers.get("urgency_score", 0),
                "embedded_urls": len(headers.get("embedded_urls", [])),
                "auth_passed": spf.get("auth_passed", None),
                "spf": spf.get("spf", "NONE"),
                "dkim": spf.get("dkim", "NONE"),
                "dmarc": spf.get("dmarc", "NONE"),
                "impersonated_brands": lookalikes.get("impersonated_brands", []),
                "ioc_count": iocs.get("total_ioc_count", 0),
            }

            # Score email signals
            if headers.get("domain_mismatch"):
                score += 25
                indicators.append("⚠️  Sender/Reply-To domain mismatch")
            if spf.get("spf") in ("FAIL", "SOFTFAIL"):
                score += 20
                indicators.append(f"🔴 SPF {spf['spf']} — sender not authorised")
            if spf.get("dkim") == "FAIL":
                score += 20
                indicators.append("🔴 DKIM signature failure")
            if spf.get("dmarc") == "FAIL":
                score += 15
                indicators.append("🔴 DMARC policy violation")
            if lookalikes.get("impersonated_brands"):
                score += 35
                brands = ", ".join(lookalikes["impersonated_brands"])
                indicators.append(f"🚨 Brand impersonation detected: {brands}")
            urgency = headers.get("urgency_score", 0)
            if urgency >= 50:
                score += 15
                indicators.append(f"⚠️  High urgency language (score: {urgency}/100)")
            for sig in headers.get("suspicious_signals", []):
                indicators.append(f"⚠️  {sig}")

        # ── URL findings ──────────────────────────────────────────
        url_findings = findings.get("url_findings", [])
        for uf in url_findings:
            evidence_count += 1
            comp = uf.get("composite_score", {})
            url_score = comp.get("score", 0)
            score = max(score, url_score)

            url_summary = {
                "url": uf.get("url", "unknown"),
                "score": url_score,
                "level": comp.get("level", "UNKNOWN"),
                "reasons": comp.get("reasons", []),
                "vt_malicious": uf.get("virustotal", {}).get("malicious_count", 0),
                "urlscan_malicious": uf.get("urlscan", {}).get("malicious", False),
                "domain_age_days": uf.get("whois", {}).get("domain_age_days"),
                "ip_abuse_score": uf.get("ip_reputation", {}).get("abuse_score"),
                "cert_self_signed": uf.get("certificate", {}).get("self_signed"),
            }
            report["url_summaries"].append(url_summary)
            indicators.extend([f"🔗 {r}" for r in comp.get("reasons", [])])

        # ── Compute final threat level ───────────────────────────
        score = min(score, 100)
        report["composite_score"] = score
        report["threat_level"] = (
            "CRITICAL" if score >= 80 else
            "HIGH"     if score >= 60 else
            "MEDIUM"   if score >= 30 else
            "LOW"
        )
        report["indicators"] = indicators

        # ── Recommended action ───────────────────────────────────
        level = report["threat_level"]
        report["recommended_action"] = {
            "CRITICAL": "🚨 DO NOT INTERACT. Block sender immediately. Report to security team. Delete email and do not forward.",
            "HIGH":     "⚠️  HIGH RISK. Do not click any links. Verify sender through official channels before taking any action.",
            "MEDIUM":   "⚠️  MEDIUM RISK. Treat with caution. Verify sender identity. Do not provide credentials.",
            "LOW":      "✅ LOW RISK. No strong indicators detected. Standard email hygiene applies.",
        }.get(level, "Unknown risk level — manual review recommended.")

        # ── Confidence ───────────────────────────────────────────
        report["confidence"] = (
            "HIGH"   if evidence_count >= 3 else
            "MEDIUM" if evidence_count >= 2 else
            "LOW"
        )

        return report
