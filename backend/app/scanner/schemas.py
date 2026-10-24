from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
from datetime import datetime, timezone
import uuid


class ScanType(str, Enum):
    """Supported types of scans in the system."""
    URL = "url"
    FILE = "file"
    EMAIL = "email"
    IP = "ip"
    DOMAIN = "domain"


class ScanStatus(str, Enum):
    """Lifecycle states of a scan."""
    PENDING = "pending"
    VALIDATING = "validating"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(str, Enum):
    """Risk categorization for scan results and findings."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    """Categories classifying the type of vulnerability or anomaly."""
    MALWARE = "malware"
    PHISHING = "phishing"
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    ANOMALY = "anomaly"
    INFO = "info"


class EvidenceType(str, Enum):
    """Types of evidence that can be collected."""
    NETWORK_PACKET = "network_packet"
    FILE_HASH = "file_hash"
    CODE_SNIPPET = "code_snippet"
    API_RESPONSE = "api_response"
    SIGNATURE_MATCH = "signature_match"
    LOG_ENTRY = "log_entry"
    OTHER = "other"


class ScanRequest(BaseModel):
    """
    Unified input payload for initiating a scan.
    
    Attributes:
        target: The primary target to scan (URL string, IP address, file hash, etc.).
        scan_type: The type of scan to perform.
        metadata: Optional dictionary for additional context (e.g., source IP, user agent).
    """
    target: str = Field(default="", description="The asset to be scanned (e.g., URL, IP, domain)")
    scan_type: ScanType = Field(default=ScanType.URL, description="The category of the scan")
    url: Optional[str] = Field(default=None, description="Optional alias for target when scanning URLs")
    metadata: Optional[Dict[str, Any]] = Field(
        default_factory=dict, description="Additional contextual information"
    )

    @model_validator(mode="before")
    @classmethod
    def populate_target_and_type(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("target") and data.get("url"):
                data["target"] = data["url"]
            if not data.get("scan_type"):
                data["scan_type"] = ScanType.URL
        return data


class Evidence(BaseModel):
    """
    Represents raw proof supporting a Finding.
    Independent and reusable across multiple findings and scanners.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique identifier for the evidence")
    source: str = Field(..., description="The tool or source that provided this evidence (e.g., 'VirusTotal', 'Yara')")
    evidence_type: EvidenceType = Field(..., description="The category of the evidence")
    raw_value: str = Field(..., description="The raw, unparsed value of the evidence")
    normalized_value: Optional[str] = Field(None, description="A parsed or structured version of the raw evidence")
    confidence: float = Field(default=1.0, description="Confidence in this specific piece of evidence (0.0 to 1.0)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context for the evidence")


class Recommendation(BaseModel):
    """
    Represents standalone remediation guidance.
    Decoupled from Findings to allow centralized knowledgebase reuse.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique identifier for the recommendation")
    title: str = Field(..., description="Short, actionable title for the remediation")
    description: str = Field(..., description="Detailed explanation of how to fix the issue")
    priority: RiskLevel = Field(default=RiskLevel.MEDIUM, description="The priority of implementing this recommendation")
    estimated_effort: str = Field(default="unknown", description="Estimated effort to implement (e.g., 'Low', 'Medium', 'High')")
    references: List[str] = Field(default_factory=list, description="Links to external documentation (e.g., OWASP, CVE)")
    commands: List[str] = Field(default_factory=list, description="Specific CLI commands to execute for remediation if applicable")
    external_links: List[str] = Field(default_factory=list, description="Helpful URLs for further reading")


class Finding(BaseModel):
    """
    Represents a single security issue or anomaly discovered during a scan.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique identifier for the finding")
    title: str = Field(..., description="A short, descriptive title of the issue")
    description: str = Field(..., description="Detailed explanation of the finding")
    severity: RiskLevel = Field(..., description="The severity or risk level of this specific issue")
    category: FindingCategory = Field(..., description="The broad category classifying this issue")
    confidence: float = Field(default=1.0, description="The scanner's confidence in this finding (0.0 to 1.0)")
    
    recommendations: List[Recommendation] = Field(default_factory=list, description="List of actionable recommendations to remediate this finding")
    evidence: List[Evidence] = Field(default_factory=list, description="List of evidence supporting this finding")
    
    tags: List[str] = Field(default_factory=list, description="Keywords for filtering and searching (e.g., ['sql-injection', 'cve-2023-1234'])")
    references: List[str] = Field(default_factory=list, description="Links to external vulnerability databases or threat intelligence")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="When this finding was identified")


class ScanResult(BaseModel):
    """
    Standardized orchestration Report for a completed scan.
    Aggregates all findings, execution metadata, and computed overall risk.
    """
    scan_id: str = Field(..., description="Unique identifier for this scan instance")
    status: ScanStatus = Field(default=ScanStatus.PENDING, description="Current status of the scan")
    
    # Aggregated metrics
    risk_level: RiskLevel = Field(default=RiskLevel.SAFE, description="Overall risk classification computed from findings")
    risk_score: float = Field(default=0.0, description="Numerical risk score (0.0 to 100.0)")
    overall_confidence: float = Field(default=1.0, description="Aggregated confidence across all findings (0.0 to 1.0)")
    
    # Intelligence payloads
    threat_intel: Dict[str, Any] = Field(default_factory=dict, description="Threat intelligence findings")
    ai_analysis: Dict[str, Any] = Field(default_factory=dict, description="AI engine predictions and confidence scores")
    
    # The enterprise findings array
    findings: List[Finding] = Field(default_factory=list, description="All individual issues discovered during the scan")
    
    # Execution metrics
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Aggregated statistics (e.g., total findings, total criticals)")
    execution_duration: float = Field(default=0.0, description="Total execution time in seconds")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of result generation")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
