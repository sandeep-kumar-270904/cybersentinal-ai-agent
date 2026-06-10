"""
url_tools.py — CyberSentinel v2
Extended URL/domain threat intelligence tools.
New tools added vs v1: WHOIS, IP reputation (AbuseIPDB), TLS cert analysis.
"""

import os
import re
import time
import socket
import ssl
import datetime
import requests
from dotenv import load_dotenv

load_dotenv()

URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


# ─────────────────────────────────────────────
# URLScan.io (same as v1, refactored for clarity)
# ─────────────────────────────────────────────

def scan_url_urlscan(url: str) -> dict:
    if not URLSCAN_API_KEY:
        return {"error": "URLSCAN_API_KEY not set"}
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    try:
        submit = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json={"url": url, "visibility": "public"}, timeout=10)
        if submit.status_code != 200:
            return {"error": f"Submit failed: {submit.status_code}"}
        scan_uuid = submit.json().get("uuid")
        time.sleep(15)
        result = requests.get(f"https://urlscan.io/api/v1/result/{scan_uuid}/", timeout=10)
        if result.status_code != 200:
            return {"uuid": scan_uuid, "link": f"https://urlscan.io/result/{scan_uuid}/", "status": "pending"}
        data = result.json()
        verdicts = data.get("verdicts", {})
        page = data.get("page", {})
        return {
            "url": url, "uuid": scan_uuid,
            "link": f"https://urlscan.io/result/{scan_uuid}/",
            "domain": page.get("domain"), "ip": page.get("ip"),
            "country": page.get("country"), "server": page.get("server"),
            "malicious": verdicts.get("overall", {}).get("malicious", False),
            "score": verdicts.get("overall", {}).get("score", 0),
            "categories": verdicts.get("overall", {}).get("categories", []),
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# VirusTotal (enhanced from v1)
# ─────────────────────────────────────────────

def check_virustotal(target: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set"}
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        if target.startswith("http"):
            import base64
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"

        resp = requests.get(endpoint, headers=headers, timeout=10)
        if resp.status_code == 404 and target.startswith("http"):
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": target}, timeout=10)
            return {"target": target, "status": "submitted", "malicious_count": 0}

        if resp.status_code != 200:
            return {"error": f"VT API {resp.status_code}"}

        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})
        mc = stats.get("malicious", 0)
        flagging = [{"vendor": v, "result": i.get("result")} for v, i in results.items() if i.get("category") in ("malicious", "suspicious")][:10]

        return {
            "target": target, "malicious_count": mc,
            "suspicious_count": stats.get("suspicious", 0),
            "total_engines": sum(stats.values()),
            "clean_count": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", "N/A"),
            "flagging_vendors": flagging,
            "verdict": "CRITICAL" if mc >= 10 else "HIGH" if mc >= 5 else "MEDIUM" if mc >= 2 else "LOW" if mc >= 1 else "CLEAN"
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
# NEW: WHOIS / Domain Age
# ─────────────────────────────────────────────

def lookup_whois(domain: str) -> dict:
    """
    Gets domain age, registrar, country via WHOIS.
    Uses whoisjson.com free API (no key required for basic lookups).
    Falls back to python-whois library if available.
    """
    try:
        # Try free WHOIS API
        resp = requests.get(f"https://whoisjson.com/api/v1/whois?domain={domain}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            created_str = data.get("created", "") or data.get("creation_date", "")

            domain_age_days = None
            if created_str:
                try:
                    # Parse various date formats
                    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"):
                        try:
                            created_dt = datetime.datetime.strptime(created_str[:19], fmt[:len(created_str[:19])])
                            domain_age_days = (datetime.datetime.utcnow() - created_dt).days
                            break
                        except ValueError:
                            continue
                except Exception:
                    pass

            return {
                "domain": domain,
                "registrar": data.get("registrar"),
                "creation_date": created_str,
                "expiry_date": data.get("expires"),
                "domain_age_days": domain_age_days,
                "registrant_country": data.get("registrant_country"),
                "name_servers": data.get("name_servers", [])[:3],
                "newly_registered": domain_age_days is not None and domain_age_days < 30
            }
    except Exception:
        pass

    # Fallback: python-whois
    try:
        import whois
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        age_days = (datetime.datetime.utcnow() - cd).days if cd else None
        return {
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": str(cd),
            "domain_age_days": age_days,
            "registrant_country": getattr(w, "country", None),
            "newly_registered": age_days is not None and age_days < 30
        }
    except Exception as e:
        return {"domain": domain, "error": f"WHOIS lookup failed: {str(e)}"}


# ─────────────────────────────────────────────
# NEW: IP Reputation (AbuseIPDB)
# ─────────────────────────────────────────────

def check_ip_reputation(domain_or_ip: str) -> dict:
    """
    Checks IP reputation via AbuseIPDB.
    Resolves domain to IP first if needed.
    """
    # Resolve domain to IP
    ip = domain_or_ip
    try:
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_or_ip):
            ip = socket.gethostbyname(domain_or_ip)
    except socket.gaierror:
        return {"target": domain_or_ip, "error": "Could not resolve domain to IP"}

    if not ABUSEIPDB_API_KEY:
        # Graceful degradation — return what we know
        return {"ip": ip, "note": "ABUSEIPDB_API_KEY not set — skipping reputation check"}

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10
        )
        if resp.status_code != 200:
            return {"ip": ip, "error": f"AbuseIPDB API {resp.status_code}"}

        data = resp.json().get("data", {})
        return {
            "ip": ip,
            "domain": domain_or_ip if domain_or_ip != ip else None,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor", False),
            "verdict": "MALICIOUS" if data.get("abuseConfidenceScore", 0) > 75 else
                       "SUSPICIOUS" if data.get("abuseConfidenceScore", 0) > 25 else "CLEAN"
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}


# ─────────────────────────────────────────────
# NEW: TLS Certificate Analysis
# ─────────────────────────────────────────────

def analyse_certificate(url: str) -> dict:
    """
    Checks TLS certificate validity, issuer, and age.
    Red flags: self-signed, recently issued (<7 days), Let's Encrypt on suspicious domain.
    """
    domain = re.sub(r'https?://', '', url).split('/')[0].split('?')[0]
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=5), server_hostname=domain) as s:
            cert = s.getpeercert()

        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.datetime.utcnow()
        days_valid = (not_after - now).days
        cert_age_days = (now - not_before).days

        issuer = dict(x[0] for x in cert.get('issuer', []))
        org = issuer.get('organizationName', 'Unknown')

        return {
            "domain": domain,
            "issuer": org,
            "issued_days_ago": cert_age_days,
            "expires_in_days": days_valid,
            "expired": days_valid < 0,
            "self_signed": "issuer" not in cert or org == domain,
            "lets_encrypt": "Let's Encrypt" in org,
            "recently_issued": cert_age_days < 7,
            "san": [v for _, v in cert.get('subjectAltName', [])],
        }
    except ssl.SSLError as e:
        return {"domain": domain, "error": f"SSL error: {str(e)}", "self_signed": True}
    except (socket.timeout, ConnectionRefusedError):
        return {"domain": domain, "error": "Could not connect for cert check"}
    except Exception as e:
        return {"domain": domain, "error": str(e)}


# ─────────────────────────────────────────────
# Tool definitions for URLAgent's Claude loop
# ─────────────────────────────────────────────

URL_TOOL_DEFINITIONS = [
    {
        "name": "check_virustotal",
        "description": "Check URL/domain against 70+ AV engines via VirusTotal.",
        "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}
    },
    {
        "name": "scan_url_urlscan",
        "description": "Submit URL to URLScan.io for live browser-based analysis.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}
    },
    {
        "name": "lookup_whois",
        "description": "Get WHOIS registration data: domain age, registrar, country.",
        "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}
    },
    {
        "name": "check_ip_reputation",
        "description": "Check IP abuse score and geolocation via AbuseIPDB.",
        "input_schema": {"type": "object", "properties": {"domain_or_ip": {"type": "string"}}, "required": ["domain_or_ip"]}
    },
    {
        "name": "analyse_certificate",
        "description": "Inspect TLS certificate: issuer, age, expiry, self-signed flag.",
        "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}
    }
]
