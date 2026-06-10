"""
case_store.py — CyberSentinel v2
SQLite-backed case management. Stores all investigations with their findings.
Upgrade path: swap SQLite for PostgreSQL by changing the connection string.
"""

import json
import os
import uuid
import asyncio
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional


DB_PATH = os.getenv("CYBERSENTINEL_DB", "data/cybersentinel.db")


def _get_conn():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                severity TEXT,
                original_input TEXT,
                findings TEXT,   -- JSON blob
                report TEXT,
                tags TEXT        -- JSON array
            );

            CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at);
            CREATE INDEX IF NOT EXISTS idx_cases_severity ON cases(severity);
            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);

            CREATE TABLE IF NOT EXISTS ioc_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,  -- url, ip, domain, hash
                ioc_value TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(id)
            );

            CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_index(ioc_value);
        """)


_init_db()


class CaseStore:
    """
    Manages investigation cases. Each analysis run creates/updates a case.
    Supports searching by IOC, date range, and severity.
    """

    async def create_case(self, original_input: str) -> str:
        """Create a new case, return its ID."""
        case_id = str(uuid.uuid4())[:12]
        now = datetime.utcnow().isoformat()
        await asyncio.to_thread(self._insert_case, case_id, now, original_input)
        return case_id

    def _insert_case(self, case_id, now, original_input):
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO cases (id, created_at, updated_at, original_input, status) VALUES (?,?,?,?,'open')",
                (case_id, now, now, original_input[:2000])
            )

    async def save(self, case_id: str, findings: dict):
        """Update case with final findings and computed severity."""
        severity = self._compute_severity(findings)
        now = datetime.utcnow().isoformat()
        findings_json = json.dumps(findings)
        await asyncio.to_thread(self._update_case, case_id, findings_json, severity, now)
        await self._index_iocs(case_id, findings)

    def _update_case(self, case_id, findings_json, severity, now):
        with _get_conn() as conn:
            conn.execute(
                "UPDATE cases SET findings=?, severity=?, updated_at=?, status='closed' WHERE id=?",
                (findings_json, severity, now, case_id)
            )

    async def _index_iocs(self, case_id: str, findings: dict):
        """Index all IOCs from findings for fast future lookups."""
        iocs_to_index = []
        now = datetime.utcnow().isoformat()

        email_f = findings.get("email_findings", {})
        ioc_f = email_f.get("extract_iocs", {}) if email_f else {}

        for url in ioc_f.get("urls", []):
            iocs_to_index.append((case_id, "url", url, now))
        for ip in ioc_f.get("ip_addresses", []):
            iocs_to_index.append((case_id, "ip", ip, now))
        for em in ioc_f.get("email_addresses", []):
            iocs_to_index.append((case_id, "email", em, now))

        for url_finding in findings.get("url_findings", []):
            if url := url_finding.get("url"):
                iocs_to_index.append((case_id, "url", url, now))

        if iocs_to_index:
            await asyncio.to_thread(self._bulk_insert_iocs, iocs_to_index)

    def _bulk_insert_iocs(self, iocs):
        with _get_conn() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO ioc_index (case_id, ioc_type, ioc_value, first_seen) VALUES (?,?,?,?)",
                iocs
            )

    async def get_case(self, case_id: str) -> Optional[dict]:
        row = await asyncio.to_thread(self._fetch_case, case_id)
        if not row:
            return None
        d = dict(row)
        d["findings"] = json.loads(d["findings"]) if d.get("findings") else {}
        return d

    def _fetch_case(self, case_id):
        with _get_conn() as conn:
            return conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()

    async def search_by_ioc(self, ioc_value: str) -> list:
        """Find all cases that contain a given IOC. Threat hunting feature."""
        return await asyncio.to_thread(self._search_ioc, ioc_value)

    def _search_ioc(self, ioc_value):
        with _get_conn() as conn:
            rows = conn.execute(
                "SELECT c.id, c.created_at, c.severity, i.ioc_type FROM cases c "
                "JOIN ioc_index i ON c.id=i.case_id WHERE i.ioc_value=? ORDER BY c.created_at DESC",
                (ioc_value,)
            ).fetchall()
            return [dict(r) for r in rows]

    async def list_cases(self, limit: int = 50, severity: str = None, status: str = None) -> list:
        return await asyncio.to_thread(self._list_cases, limit, severity, status)

    def _list_cases(self, limit, severity, status):
        where_clauses = []
        params = []
        if severity:
            where_clauses.append("severity=?")
            params.append(severity)
        if status:
            where_clauses.append("status=?")
            params.append(status)
        where = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        params.append(limit)
        with _get_conn() as conn:
            rows = conn.execute(
                f"SELECT id, created_at, severity, status, original_input FROM cases {where} ORDER BY created_at DESC LIMIT ?",
                params
            ).fetchall()
            return [dict(r) for r in rows]

    def _compute_severity(self, findings: dict) -> str:
        max_score = 0
        for url_f in findings.get("url_findings", []):
            score = url_f.get("composite_score", {}).get("score", 0)
            max_score = max(max_score, score)
        email_f = findings.get("email_findings", {})
        if email_f:
            urgency = email_f.get("analyse_headers", {}).get("urgency_score", 0)
            max_score = max(max_score, urgency * 0.5)
        return "CRITICAL" if max_score >= 80 else "HIGH" if max_score >= 60 else "MEDIUM" if max_score >= 30 else "LOW"
