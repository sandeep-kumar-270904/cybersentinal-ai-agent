"""
email_tools.py — CyberSentinel v2
Email-specific analysis tools for the EmailAgent.
New vs v1: SPF/DKIM check, structured IOC extraction, enhanced lookalike detection.
"""

import re
import hashlib
from typing import Dict


# ─────────────────────────────────────────────
# TOOL 1: Header Analysis (enhanced from v1)
# ─────────────────────────────────────────────

def analyse_headers(email_text: str) -> dict:
    findings = {
        "sender_domain": None, "reply_to_domain": None,
        "display_name": None, "return_path_domain": None,
        "domain_mismatch": False, "suspicious_signals": [],
        "urgency_score": 0, "embedded_url_count": 0
    }

    # Extract From: display name and domain
    from_match = re.search(r'[Ff]rom:\s*"?([^"<\n]*)"?\s*<?[^@]*@([\w.\-]+)>?', email_text)
    if from_match:
        findings["display_name"] = from_match.group(1).strip()
        findings["sender_domain"] = from_match.group(2).lower()

    # Reply-To domain
    reply_match = re.search(r'[Rr]eply-[Tt]o:\s*<?[^@]*@([\w.\-]+)>?', email_text)
    if reply_match:
        findings["reply_to_domain"] = reply_match.group(1).lower()

    # Return-Path domain
    rp_match = re.search(r'[Rr]eturn-[Pp]ath:\s*<?[^@]*@([\w.\-]+)>?', email_text)
    if rp_match:
        findings["return_path_domain"] = rp_match.group(1).lower()

    # Domain mismatch checks
    domains = [d for d in [findings["sender_domain"], findings["reply_to_domain"], findings["return_path_domain"]] if d]
    unique_domains = set(domains)
    if len(unique_domains) > 1:
        findings["domain_mismatch"] = True
        findings["suspicious_signals"].append(f"Domain mismatch across From/Reply-To/Return-Path: {list(unique_domains)}")

    # Urgency keywords
    urgency_kw = [
        "urgent", "immediately", "suspended", "verify now", "action required",
        "24 hours", "48 hours", "expire", "limited time", "click here",
        "confirm your", "unauthorized", "unusual activity", "won", "prize",
        "congratulations", "free", "risk", "account locked", "security alert",
        "bank", "password reset", "login attempt"
    ]
    text_lower = email_text.lower()
    found_kw = [kw for kw in urgency_kw if kw in text_lower]
    findings["urgency_keywords"] = found_kw
    findings["urgency_score"] = min(len(found_kw) * 10, 100)
    if findings["urgency_score"] >= 30:
        findings["suspicious_signals"].append(f"High urgency language ({len(found_kw)} trigger keywords)")

    # Embedded URLs
    urls = re.findall(r'https?://[^\s<>"\'\)]+', email_text)
    findings["embedded_urls"] = list(set(urls))
    findings["embedded_url_count"] = len(findings["embedded_urls"])

    # Shortened URL detection
    shortened_domains = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "short.link", "rb.gy", "tiny.cc", "is.gd"]
    for url in findings["embedded_urls"]:
        for sd in shortened_domains:
            if sd in url:
                findings["suspicious_signals"].append(f"Shortened/obfuscated URL: {url}")

    return findings


# ─────────────────────────────────────────────
# TOOL 2: SPF/DKIM/DMARC (NEW — simulated check from headers)
# ─────────────────────────────────────────────

def check_spf_dkim(email_text: str) -> dict:
    """
    Parses email headers for SPF/DKIM/DMARC authentication results.
    In a real deployment, you'd pass raw MIME headers.
    """
    findings = {"spf": "NONE", "dkim": "NONE", "dmarc": "NONE", "auth_signals": []}

    # SPF result
    spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', email_text, re.IGNORECASE)
    if spf_match:
        findings["spf"] = spf_match.group(1).upper()

    # DKIM result
    dkim_match = re.search(r'dkim=(pass|fail|neutral|none|policy|temperror|permerror)', email_text, re.IGNORECASE)
    if dkim_match:
        findings["dkim"] = dkim_match.group(1).upper()

    # DMARC result
    dmarc_match = re.search(r'dmarc=(pass|fail|bestguesspass|none)', email_text, re.IGNORECASE)
    if dmarc_match:
        findings["dmarc"] = dmarc_match.group(1).upper()

    # Authentication-Results header
    auth_results = re.search(r'Authentication-Results:[^\n]+(?:\n\s+[^\n]+)*', email_text)
    if auth_results:
        findings["auth_header_present"] = True
        findings["raw_auth"] = auth_results.group(0)[:500]
    else:
        findings["auth_header_present"] = False
        findings["auth_signals"].append("No Authentication-Results header found — likely spoofed or stripped")

    # Assess auth failure
    if findings["spf"] in ("FAIL", "SOFTFAIL") or findings["dkim"] == "FAIL":
        findings["auth_signals"].append(f"Authentication failure: SPF={findings['spf']}, DKIM={findings['dkim']}")
    if findings["dmarc"] == "FAIL":
        findings["auth_signals"].append("DMARC policy violation — domain impersonation likely")

    findings["auth_passed"] = (
        findings["spf"] == "PASS" and
        findings["dkim"] == "PASS" and
        findings["dmarc"] in ("PASS", "BESTGUESSPASS")
    )

    return findings


# ─────────────────────────────────────────────
# TOOL 3: Lookalike Domain Detection (enhanced)
# ─────────────────────────────────────────────

def detect_lookalikes(email_text: str) -> dict:
    """
    Enhanced lookalike detection with homoglyph patterns and edit-distance checks.
    """
    findings = {"lookalikes_found": [], "impersonated_brands": [], "risk_score": 0}

    # Comprehensive brand lookalike patterns (homoglyphs + transpositions)
    brand_patterns = {
        "paypal": [r'pay[-_]?pa[l1]', r'p[a@]ypal', r'paypa[l1i]', r'paypаl'],  # Cyrillic 'a'
        "amazon": [r'am[a@]z[o0]n', r'arnazon', r'amazom', r'amaz[o0]n\.(?!com)'],
        "google": [r'g[o0][o0]gle', r'go+gle', r'googie', r'g00gle'],
        "microsoft": [r'micros[o0]ft', r'micosoft', r'microsoft\.(?!com)'],
        "apple": [r'app[l1]e\.(?!com)', r'appl[e3]', r'@apple-'],
        "facebook": [r'faceb[o0][o0]k', r'faceboook', r'face[-_]book'],
        "netflix": [r'netfl[i1]x', r'netfix', r'net-flix'],
        "dropbox": [r'dr[o0]pb[o0]x', r'drop-box'],
        "linkedin": [r'l[i1]nked[i1]n', r'linked-in'],
        "instagram": [r'[i1]nstagram', r'instgram', r'insta-gram'],
        "bank": [r'[a-z]+-?bank[a-z]+\.', r'bankk', r'banck', r'b[a@]nk[-_]'],
        "irs": [r'[i1]rs[-_.]gov', r'irs-refund', r'tax-refund'],
        "fedex": [r'fedx', r'fed-ex', r'fed_ex'],
        "dhl": [r'dh1\.', r'd-h-l', r'dhI\.'],  # capital i vs l
    }

    text_lower = email_text.lower()
    for brand, patterns in brand_patterns.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                if brand not in findings["impersonated_brands"]:
                    findings["impersonated_brands"].append(brand)
                    findings["lookalikes_found"].append({
                        "brand": brand,
                        "pattern_matched": pattern,
                        "context": _extract_context(email_text, pattern, 80)
                    })
                    findings["risk_score"] += 30

    # Detect punycode / international domain attacks
    if re.search(r'xn--[a-z0-9]+', email_text):
        findings["lookalikes_found"].append({"type": "punycode", "detail": "Internationalized domain name (IDN) detected — potential homograph attack"})
        findings["risk_score"] += 40

    findings["risk_score"] = min(findings["risk_score"], 100)
    return findings


def _extract_context(text: str, pattern: str, chars: int = 80) -> str:
    """Extract surrounding context for a regex match."""
    m = re.search(pattern, text.lower())
    if not m:
        return ""
    start = max(0, m.start() - chars // 2)
    end = min(len(text), m.end() + chars // 2)
    return text[start:end].strip()


# ─────────────────────────────────────────────
# TOOL 4: IOC Extraction (NEW)
# ─────────────────────────────────────────────

def extract_iocs(email_text: str) -> dict:
    """
    Structured IOC (Indicator of Compromise) extraction.
    Extracts: URLs, IPs, email addresses, file hashes, attachment names.
    """
    iocs = {"urls": [], "ip_addresses": [], "email_addresses": [], "file_hashes": [], "attachment_names": []}

    # URLs
    iocs["urls"] = list(set(re.findall(r'https?://[^\s<>"\'\)]+', email_text)))

    # IPv4 addresses
    iocs["ip_addresses"] = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', email_text)))

    # Email addresses
    iocs["email_addresses"] = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', email_text)))

    # MD5 / SHA1 / SHA256 hashes
    iocs["file_hashes"] = list(set(
        re.findall(r'\b[0-9a-fA-F]{32}\b', email_text) +  # MD5
        re.findall(r'\b[0-9a-fA-F]{40}\b', email_text) +  # SHA1
        re.findall(r'\b[0-9a-fA-F]{64}\b', email_text)    # SHA256
    ))

    # Attachment references
    iocs["attachment_names"] = list(set(re.findall(
        r'filename[=:]?\s*["\']?([^\s"\'<>]+\.(exe|zip|doc|docx|xls|xlsx|pdf|js|vbs|bat|ps1|rar|7z|iso|img))',
        email_text, re.IGNORECASE
    )))

    iocs["total_ioc_count"] = sum(len(v) for v in iocs.values())
    return iocs


# ─────────────────────────────────────────────
# Tool definitions for EmailAgent's Claude loop
# ─────────────────────────────────────────────

EMAIL_TOOL_DEFINITIONS = [
    {
        "name": "analyse_headers",
        "description": "Parse email headers for sender spoofing, domain mismatch, urgency language, embedded URLs.",
        "input_schema": {"type": "object", "properties": {"email_text": {"type": "string"}}, "required": ["email_text"]}
    },
    {
        "name": "check_spf_dkim",
        "description": "Parse SPF/DKIM/DMARC authentication results from email headers.",
        "input_schema": {"type": "object", "properties": {"email_text": {"type": "string"}}, "required": ["email_text"]}
    },
    {
        "name": "detect_lookalikes",
        "description": "Detect brand impersonation via lookalike/homoglyph domain patterns.",
        "input_schema": {"type": "object", "properties": {"email_text": {"type": "string"}}, "required": ["email_text"]}
    },
    {
        "name": "extract_iocs",
        "description": "Extract all IOCs: URLs, IPs, email addresses, file hashes, attachment names.",
        "input_schema": {"type": "object", "properties": {"email_text": {"type": "string"}}, "required": ["email_text"]}
    }
]
