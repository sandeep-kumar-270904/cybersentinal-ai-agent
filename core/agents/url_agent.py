"""
url_agent.py — CyberSentinel v2
URLAgent: Specialist agent for URL/domain/IP threat analysis.
Runs multiple threat intel tools in parallel for each URL.
"""

import os
import json
import asyncio
from typing import Tuple, List
import anthropic
from core.tools.url_tools import (
    scan_url_urlscan,
    check_virustotal,
    lookup_whois,
    check_ip_reputation,
    analyse_certificate,
    URL_TOOL_DEFINITIONS
)
from core.memory.threat_cache import ThreatCache

URL_AGENT_SYSTEM = """You are the CyberSentinel URL & Domain Analysis Agent.

For each URL/domain provided, run a comprehensive threat check using all available tools.
Prioritise tools: virustotal first (fastest), then scan_url, then whois/ip_reputation if deep_scan=true.

Tools:
1. check_virustotal   — 70+ AV engines
2. scan_url_urlscan   — live browser scan
3. lookup_whois       — domain age, registrar, registration country
4. check_ip_reputation — AbuseIPDB + geolocation
5. analyse_certificate — TLS cert validity, issuer, age
"""


class URLAgent:
    def __init__(self):
        self.client = anthropic.AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.cache = ThreatCache()

    async def run(self, urls: List[str], deep_scan: bool = False) -> Tuple[list, list]:
        """Analyse multiple URLs, running scans in parallel. Returns (findings_list, events)."""
        events = []
        all_url_findings = []

        # Deduplicate URLs
        unique_urls = list(dict.fromkeys(urls))
        events.append({"event": "status", "data": {"text": f"URL Agent: Analysing {len(unique_urls)} unique URLs", "agent": "url_agent"}})

        # Check cache first
        cache_hits = []
        urls_to_scan = []
        for url in unique_urls:
            cached = await self.cache.get(url)
            if cached:
                cache_hits.append(cached)
                events.append({"event": "cache_hit", "data": {"url": url, "agent": "url_agent"}})
            else:
                urls_to_scan.append(url)

        all_url_findings.extend(cache_hits)

        # Scan uncached URLs in parallel (max 3 concurrent to respect API limits)
        semaphore = asyncio.Semaphore(3)
        tasks = [self._analyse_url(url, deep_scan, semaphore, events) for url in urls_to_scan]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for url, result in zip(urls_to_scan, results):
            if isinstance(result, Exception):
                events.append({"event": "error", "data": {"url": url, "error": str(result)}})
                all_url_findings.append({"url": url, "error": str(result)})
            else:
                await self.cache.set(url, result, ttl=3600)  # Cache for 1 hour
                all_url_findings.append(result)

        return all_url_findings, events

    async def _analyse_url(self, url: str, deep_scan: bool, semaphore: asyncio.Semaphore, events: list) -> dict:
        """Full analysis for a single URL."""
        async with semaphore:
            events.append({"event": "tool_call", "data": {"agent": "url_agent", "tool": "analyse_url", "url": url}})

            findings = {"url": url}

            # Always run VirusTotal (fast, free tier OK)
            vt_result = await asyncio.to_thread(check_virustotal, url)
            findings["virustotal"] = vt_result

            # Run URLScan in parallel with VT
            urlscan_result = await asyncio.to_thread(scan_url_urlscan, url)
            findings["urlscan"] = urlscan_result

            if deep_scan:
                # Extract domain for WHOIS/IP checks
                domain = self._extract_domain(url)
                if domain:
                    whois_result = await asyncio.to_thread(lookup_whois, domain)
                    findings["whois"] = whois_result

                    ip_result = await asyncio.to_thread(check_ip_reputation, domain)
                    findings["ip_reputation"] = ip_result

                cert_result = await asyncio.to_thread(analyse_certificate, url)
                findings["certificate"] = cert_result

            # Compute composite threat score
            findings["composite_score"] = self._compute_score(findings)
            events.append({"event": "tool_result", "data": {"agent": "url_agent", "url": url, "score": findings["composite_score"]}})

            return findings

    def _extract_domain(self, url: str) -> str:
        import re
        match = re.search(r'https?://([^/\?#]+)', url)
        return match.group(1) if match else url

    def _compute_score(self, findings: dict) -> dict:
        """Combine signals from all tools into a composite threat score 0–100."""
        score = 0
        reasons = []

        vt = findings.get("virustotal", {})
        if vt.get("malicious_count", 0) >= 10:
            score += 60
            reasons.append(f"VirusTotal: {vt['malicious_count']} engines flagged")
        elif vt.get("malicious_count", 0) >= 5:
            score += 40
            reasons.append(f"VirusTotal: {vt['malicious_count']} engines flagged")
        elif vt.get("malicious_count", 0) >= 1:
            score += 20
            reasons.append(f"VirusTotal: {vt['malicious_count']} engines flagged")

        us = findings.get("urlscan", {})
        if us.get("malicious"):
            score += 30
            reasons.append("URLScan: Malicious verdict")

        whois = findings.get("whois", {})
        if whois.get("domain_age_days", 999) < 30:
            score += 20
            reasons.append(f"Domain age: {whois.get('domain_age_days')} days (newly registered)")

        ip = findings.get("ip_reputation", {})
        if ip.get("abuse_score", 0) > 50:
            score += 15
            reasons.append(f"IP abuse score: {ip.get('abuse_score')}")

        cert = findings.get("certificate", {})
        if cert.get("self_signed"):
            score += 10
            reasons.append("Self-signed certificate")
        if cert.get("expired"):
            score += 15
            reasons.append("Expired certificate")

        score = min(score, 100)
        level = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"

        return {"score": score, "level": level, "reasons": reasons}
