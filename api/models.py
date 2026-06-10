"""
models.py — CyberSentinel v2
Pydantic request/response models for the FastAPI layer.
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime


class AnalyseRequest(BaseModel):
    """Request body for /api/v2/analyse endpoints."""
    input: str = Field(..., min_length=10, max_length=50000, description="Raw email text, URL, or domain to analyse")
    deep_scan: bool = Field(False, description="If true, also run WHOIS and IP reputation checks (slower)")
    webhook_url: Optional[str] = Field(None, description="POST final results here when analysis completes (async mode only)")
    tags: List[str] = Field([], description="Optional tags for case categorisation")

    class Config:
        json_schema_extra = {
            "example": {
                "input": "From: security@paypa1.com\nSubject: URGENT: Your account has been suspended\n\nClick here to verify: https://paypa1-verify.xyz/login",
                "deep_scan": True
            }
        }


class CaseSummary(BaseModel):
    """Lightweight case summary for list endpoints."""
    id: str
    created_at: str
    severity: Optional[str]
    status: str
    original_input: str

    class Config:
        from_attributes = True


class CaseDetail(BaseModel):
    """Full case with all findings."""
    id: str
    created_at: str
    updated_at: str
    status: str
    severity: Optional[str]
    original_input: str
    findings: Optional[Dict[str, Any]]
    report: Optional[str]

    class Config:
        from_attributes = True


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    cache: Dict[str, Any]
