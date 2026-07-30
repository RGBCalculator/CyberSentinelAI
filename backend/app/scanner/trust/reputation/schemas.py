"""
Shared Schemas for the Reputation Intelligence Subsystem.

This module defines the core data models and enumerations used by all
reputation providers and the Reputation Engine to ensure a unified
contract and standardized threat reporting across the platform.
"""

from enum import Enum
from datetime import datetime
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """
    Enumeration of threat severity levels.
    """
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    """
    Enumeration of known threat categories for categorization.
    """
    UNKNOWN = "UNKNOWN"
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    SPAM = "SPAM"
    BOTNET = "BOTNET"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    SUSPICIOUS = "SUSPICIOUS"


class ProviderMetadata(BaseModel):
    """
    Metadata describing a specific reputation provider.
    """
    name: str
    version: str = "1.0"
    enabled: bool = True
    reliability: float = 1.0


class ReputationFinding(BaseModel):
    """
    Represents a specific finding from a reputation provider.
    """
    provider: str
    malicious: bool = False
    confidence: float = 0.0
    severity: Severity = Severity.INFO
    category: ThreatCategory = ThreatCategory.UNKNOWN
    reference: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)


class ReputationResult(BaseModel):
    """
    The aggregated result from the Reputation Engine, summarizing findings
    across all queried providers.
    """
    findings: List[ReputationFinding] = Field(default_factory=list)
    malicious: bool = False
    confidence: float = 0.0
    provider_count: int = 0
    malicious_count: int = 0
