"""
tools.py — CyberSentinel AI Agent
Real tool functions that hit live cybersecurity APIs.
Each function is exposed to Claude as a tool via tool_use.
"""

import os
import re
import time
import requests
from dotenv import load_dotenv

load_dotenv()

URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


# ─────────────────────────────────────────────
# TOOL 1 — URLScan.io
# ─────────────────────────────────────────────

def scan_url(url: str) -> dict:
    """
    Submits a URL to URLScan.io for live scanning.
    Returns: verdict, domain age, redirect chain, malicious flag.
    """
    if not URLSCAN_API_KEY:
        return {"error": "URLSCAN_API_KEY not set in .env"}

    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {"url": url, "visibility": "public"}

    try:
        # Submit scan
        submit = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=payload,
            timeout=10
        )
        if submit.status_code != 200:
            return {"error": f"URLScan submit failed: {submit.status_code}", "detail": submit.text}

        scan_uuid = submit.json().get("uuid")
        result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"

        # Wait for scan to complete (URLScan takes ~10s)
        print(f"  [URLScan] Scan submitted. Waiting 15s for results...")
        time.sleep(15)

        result = requests.get(result_url, timeout=10)
        if result.status_code != 200:
            return {
                "status": "scan_pending",
                "uuid": scan_uuid,
                "result_link": f"https://urlscan.io/result/{scan_uuid}/",
                "note": "Scan submitted but results not ready yet. Link valid in ~30s."
            }

        data = result.json()
        verdicts = data.get("verdicts", {})
        page = data.get("page", {})
        lists = data.get("lists", {})

        return {
            "url_scanned": url,
            "scan_uuid": scan_uuid,
            "result_link": f"https://urlscan.io/result/{scan_uuid}/",
            "domain": page.get("domain", "unknown"),
            "ip": page.get("ip", "unknown"),
            "country": page.get("country", "unknown"),
            "server": page.get("server", "unknown"),
            "malicious": verdicts.get("overall", {}).get("malicious", False),
            "score": verdicts.get("overall", {}).get("score", 0),
            "categories": verdicts.get("overall", {}).get("categories", []),
            "redirect_chain": lists.get("urls", [])[:5],  # first 5 redirects
            "urlscan_verdict": verdicts.get("urlscan", {}).get("score", "N/A"),
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"URLScan request failed: {str(e)}"}


# ─────────────────────────────────────────────
# TOOL 2 — VirusTotal
# ─────────────────────────────────────────────

def check_virustotal(target: str) -> dict:
    """
    Checks a URL or domain against 70+ AV engines via VirusTotal API.
    Returns: malicious count, total engines, top flagging vendors.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env"}

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        # Determine if it's a URL or domain/hash
        if target.startswith("http://") or target.startswith("https://"):
            import base64
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            # Treat as domain
            endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"

        response = requests.get(endpoint, headers=headers, timeout=10)

        if response.status_code == 404:
            # URL not in VT database — submit it
            if target.startswith("http"):
                submit = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": target},
                    timeout=10
                )
                return {
                    "target": target,
                    "status": "submitted_for_analysis",
                    "note": "URL was not in VirusTotal database. Submitted for analysis.",
                    "malicious_count": 0,
                    "total_engines": 0
                }
            return {"error": "Target not found in VirusTotal", "target": target}

        if response.status_code != 200:
            return {"error": f"VirusTotal API error: {response.status_code}", "detail": response.text}

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total_engines = sum(stats.values()) if stats else 0

        # Get top vendors that flagged it
        flagging_vendors = [
            {"vendor": vendor, "result": info.get("result", "malicious")}
            for vendor, info in results.items()
            if info.get("category") in ("malicious", "suspicious")
        ][:10]  # top 10

        reputation = data.get("data", {}).get("attributes", {}).get("reputation", "N/A")

        return {
            "target": target,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "total_engines": total_engines,
            "clean_count": stats.get("undetected", 0),
            "reputation_score": reputation,
            "flagging_vendors": flagging_vendors,
            "threat_verdict": (
                "CRITICAL" if malicious_count >= 10 else
                "HIGH" if malicious_count >= 5 else
                "MEDIUM" if malicious_count >= 2 else
                "LOW" if malicious_count >= 1 else
                "CLEAN"
            )
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal request failed: {str(e)}"}


# ─────────────────────────────────────────────
# TOOL 3 — Email Header Analyser (local)
# ─────────────────────────────────────────────

def analyse_email_headers(email_text: str) -> dict:
    """
    Parses raw email text locally.
    Extracts: sender domain, reply-to mismatches, urgency keywords,
    embedded URLs, spoofing signals — no external API needed.
    """
    findings = {
        "sender_domain": None,
        "reply_to_domain": None,
        "domain_mismatch": False,
        "urgency_keywords_found": [],
        "embedded_urls": [],
        "suspicious_signals": [],
        "lookalike_domain_detected": False,
        "raw_input_length": len(email_text)
    }

    # Extract sender
    from_match = re.search(r'[Ff]rom[:\s]+.*?@([\w.\-]+)', email_text)
    if from_match:
        findings["sender_domain"] = from_match.group(1).lower()

    # Extract reply-to
    reply_match = re.search(r'[Rr]eply-[Tt]o[:\s]+.*?@([\w.\-]+)', email_text)
    if reply_match:
        findings["reply_to_domain"] = reply_match.group(1).lower()

    # Check domain mismatch
    if findings["sender_domain"] and findings["reply_to_domain"]:
        if findings["sender_domain"] != findings["reply_to_domain"]:
            findings["domain_mismatch"] = True
            findings["suspicious_signals"].append(
                f"Sender domain ({findings['sender_domain']}) ≠ Reply-To domain ({findings['reply_to_domain']})"
            )

    # Urgency keyword detection
    urgency_patterns = [
        "urgent", "immediately", "suspended", "verify now", "action required",
        "24 hours", "48 hours", "expire", "limited time", "click here",
        "confirm your", "your account", "unauthorized", "unusual activity",
        "won", "prize", "congratulations", "free", "risk"
    ]
    text_lower = email_text.lower()
    for kw in urgency_patterns:
        if kw in text_lower:
            findings["urgency_keywords_found"].append(kw)

    if len(findings["urgency_keywords_found"]) >= 3:
        findings["suspicious_signals"].append(
            f"High urgency language detected: {len(findings['urgency_keywords_found'])} trigger words"
        )

    # Extract all URLs
    urls = re.findall(r'https?://[^\s<>"\']+', email_text)
    shortened_domains = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.link", "rb.gy"]
    findings["embedded_urls"] = urls

    for url in urls:
        for short in shortened_domains:
            if short in url:
                findings["suspicious_signals"].append(f"Shortened/obfuscated URL detected: {url}")

    # Lookalike domain detection (e.g. paypa1.com, arnazon.com)
    known_brands = {
        "paypal": ["paypa1", "paypa1", "paypai", "pay-pal"],
        "amazon": ["arnazon", "amaz0n", "amazom"],
        "google": ["g00gle", "googie", "go0gle"],
        "microsoft": ["micros0ft", "micosoft"],
        "apple": ["app1e", "appl3"],
        "bank": ["bankk", "banck"],
    }

    all_text = email_text.lower()
    for brand, lookalikes in known_brands.items():
        for lookalike in lookalikes:
            if lookalike in all_text:
                findings["lookalike_domain_detected"] = True
                findings["suspicious_signals"].append(
                    f"Lookalike brand domain detected: '{lookalike}' (impersonating {brand})"
                )

    # Overall signal count
    findings["total_suspicious_signals"] = len(findings["suspicious_signals"])
    findings["risk_estimate"] = (
        "HIGH" if findings["total_suspicious_signals"] >= 3 else
        "MEDIUM" if findings["total_suspicious_signals"] >= 1 else
        "LOW"
    )

    return findings


# ─────────────────────────────────────────────
# TOOL 4 — Threat Report Generator (Claude synthesis)
# ─────────────────────────────────────────────

def generate_threat_report(
    email_analysis: dict = None,
    url_scan: dict = None,
    virustotal: dict = None,
    original_input: str = ""
) -> str:
    """
    Synthesises findings from all tools into a formatted threat report.
    Called by Claude as the final step after all evidence is gathered.
    """
    lines = []
    lines.append("\n" + "━" * 50)
    lines.append("      CYBERSENTINEL THREAT REPORT")
    lines.append("━" * 50)

    # Determine overall threat level
    threat_scores = []
    if email_analysis and email_analysis.get("risk_estimate"):
        mapping = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        threat_scores.append(mapping.get(email_analysis["risk_estimate"], 1))
    if virustotal and virustotal.get("malicious_count", 0) > 0:
        mc = virustotal["malicious_count"]
        threat_scores.append(4 if mc >= 10 else 3 if mc >= 5 else 2)
    if url_scan and url_scan.get("malicious"):
        threat_scores.append(4)

    max_score = max(threat_scores) if threat_scores else 1
    overall = {4: "CRITICAL 🔴", 3: "HIGH 🟠", 2: "MEDIUM 🟡", 1: "LOW 🟢"}.get(max_score, "UNKNOWN")

    lines.append(f"\nThreat Level     : {overall}")

    # Email findings
    if email_analysis:
        lines.append("\n── Email Analysis ──")
        lines.append(f"  Sender Domain    : {email_analysis.get('sender_domain', 'N/A')}")
        lines.append(f"  Domain Mismatch  : {'YES ⚠️' if email_analysis.get('domain_mismatch') else 'No'}")
        lines.append(f"  Urgency Keywords : {', '.join(email_analysis.get('urgency_keywords_found', [])) or 'None'}")
        lines.append(f"  Embedded URLs    : {len(email_analysis.get('embedded_urls', []))}")
        if email_analysis.get("suspicious_signals"):
            lines.append("  Signals:")
            for sig in email_analysis["suspicious_signals"]:
                lines.append(f"    • {sig}")

    # URLScan findings
    if url_scan and "error" not in url_scan:
        lines.append("\n── URL Scan (URLScan.io) ──")
        lines.append(f"  Domain           : {url_scan.get('domain', 'N/A')}")
        lines.append(f"  Country          : {url_scan.get('country', 'N/A')}")
        lines.append(f"  Malicious Flag   : {'YES ⚠️' if url_scan.get('malicious') else 'No'}")
        lines.append(f"  Risk Score       : {url_scan.get('score', 'N/A')}")
        lines.append(f"  Full Report      : {url_scan.get('result_link', 'N/A')}")

    # VirusTotal findings
    if virustotal and "error" not in virustotal:
        lines.append("\n── VirusTotal Analysis ──")
        lines.append(f"  Target           : {virustotal.get('target', 'N/A')}")
        lines.append(f"  Engines Checked  : {virustotal.get('total_engines', 'N/A')}")
        lines.append(f"  Malicious Flags  : {virustotal.get('malicious_count', 0)}")
        lines.append(f"  Suspicious Flags : {virustotal.get('suspicious_count', 0)}")
        lines.append(f"  VT Verdict       : {virustotal.get('threat_verdict', 'N/A')}")
        if virustotal.get("flagging_vendors"):
            lines.append("  Flagged by:")
            for v in virustotal["flagging_vendors"][:5]:
                lines.append(f"    • {v['vendor']}: {v['result']}")

    # Recommendation
    lines.append("\n── Recommended Action ──")
    if max_score >= 4:
        lines.append("  🚨 DO NOT CLICK any links. Block sender immediately.")
        lines.append("     Report to IT Security / Cybersecurity team.")
        lines.append("     Delete email. Do not forward.")
    elif max_score == 3:
        lines.append("  ⚠️  HIGH RISK. Avoid clicking links.")
        lines.append("     Verify sender through official channels before any action.")
    elif max_score == 2:
        lines.append("  ⚠️  MEDIUM RISK. Treat with caution.")
        lines.append("     Verify sender identity before taking any action.")
    else:
        lines.append("  ✅ LOW RISK. No strong indicators of threat detected.")
        lines.append("     Standard email hygiene applies.")

    lines.append("\n" + "━" * 50 + "\n")

    return "\n".join(lines)


# ─────────────────────────────────────────────
# Tool definitions for Claude tool_use API
# ─────────────────────────────────────────────

TOOL_DEFINITIONS = [
    {
        "name": "scan_url",
        "description": "Submits a URL to URLScan.io for live threat scanning. Returns domain info, redirect chain, malicious verdict, and risk score. Use when a suspicious URL or link is found in the input.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The full URL to scan, including http:// or https://"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "check_virustotal",
        "description": "Checks a URL or domain against 70+ antivirus engines via VirusTotal API. Returns malicious/suspicious engine counts, flagging vendors, and threat verdict. Use for any URL or domain that needs multi-engine verification.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "URL (with http/https) or domain name to check against VirusTotal"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "analyse_email_headers",
        "description": "Analyses raw email text locally for phishing indicators. Detects sender/reply-to mismatches, urgency keywords, shortened URLs, lookalike domains, and suspicious signals. Always call this first when email text is provided.",
        "input_schema": {
            "type": "object",
            "properties": {
                "email_text": {
                    "type": "string",
                    "description": "The full raw email text including headers, body, and any links"
                }
            },
            "required": ["email_text"]
        }
    },
    {
        "name": "generate_threat_report",
        "description": "Synthesises all gathered evidence into a final structured threat report. Call this as the LAST step after all other tools have run and results are collected.",
        "input_schema": {
            "type": "object",
            "properties": {
                "email_analysis": {
                    "type": "object",
                    "description": "Result dict from analyse_email_headers tool"
                },
                "url_scan": {
                    "type": "object",
                    "description": "Result dict from scan_url tool"
                },
                "virustotal": {
                    "type": "object",
                    "description": "Result dict from check_virustotal tool"
                },
                "original_input": {
                    "type": "string",
                    "description": "The original user input text"
                }
            },
            "required": []
        }
    }
]
