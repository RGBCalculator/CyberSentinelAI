"""
Scan Record Document Model for MongoDB using Beanie ODM.

Stores historical scan records, execution metrics, threat intelligence outcomes,
and security findings for auditing and SOC analytics.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from beanie import Document
from pydantic import Field


class ScanRecord(Document):
    scan_id: str = Field(...)
    target: str = Field(...)
    scan_type: str = Field(default="url")
    status: str = Field(default="completed")
    risk_level: str = Field(default="safe")
    risk_score: float = Field(default=0.0)
    overall_confidence: float = Field(default=1.0)
    execution_duration: float = Field(default=0.0)
    
    findings_count: int = Field(default=0)
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)

    findings: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intel: Dict[str, Any] = Field(default_factory=dict)
    ai_analysis: Dict[str, Any] = Field(default_factory=dict)
    statistics: Dict[str, Any] = Field(default_factory=dict)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: Optional[str] = Field(default=None)

    class Settings:
        name = "scans"
        indexes = [
            "scan_id",
            "target",
            "scan_type",
            "risk_level",
            "created_at",
            "user_id"
        ]
