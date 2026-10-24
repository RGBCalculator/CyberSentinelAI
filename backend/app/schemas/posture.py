from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
import uuid

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class InvestigationStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class Repository(BaseModel):
    name: str = Field(..., description="Name of the repository (e.g., 'owner/repo')")
    url: Optional[str] = Field(None, description="URL of the repository")
    commit_hash: Optional[str] = Field(None, description="Analyzed commit hash")
    branch: Optional[str] = Field(None, description="Analyzed branch")
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)

class CodeLocation(BaseModel):
    file_path: str = Field(..., description="Relative path to the file")
    start_line: int = Field(..., description="Starting line number")
    end_line: int = Field(..., description="Ending line number")
    snippet: Optional[str] = Field(None, description="Raw source code snippet")

class DependencyPath(BaseModel):
    source: str = Field(..., description="The vulnerable component/function")
    target: str = Field(..., description="The component/function that is affected")
    relationship: str = Field("imports", description="Nature of the dependency (e.g., 'imports', 'calls')")

class BlastRadius(BaseModel):
    affected_files: List[str] = Field(default_factory=list, description="List of files indirectly affected")
    affected_endpoints: List[str] = Field(default_factory=list, description="List of API endpoints exposed to this vulnerability")
    dependency_paths: List[DependencyPath] = Field(default_factory=list, description="Trace of how this vulnerability reaches other parts of the application")

class InvestigationTask(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str = Field(..., description="Actionable title for the investigation step")
    description: str = Field(..., description="Detailed instructions for the security engineer")
    status: InvestigationStatus = Field(default=InvestigationStatus.PENDING)
    evidence_collected: Optional[str] = Field(None, description="Data collected during this investigation step")

class CodeFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = Field(..., description="Scanner rule ID (e.g., 'semgrep-sqli')")
    title: str = Field(..., description="Human readable title")
    description: str = Field(..., description="Detailed explanation of the vulnerability")
    severity: Severity = Field(..., description="Deterministic severity from the scanner")
    risk_score: int = Field(..., description="Computed risk score (0-100) taking blast radius into account")

    # Evidence & Impact
    location: CodeLocation = Field(..., description="Where the vulnerability physically exists")
    blast_radius: BlastRadius = Field(default_factory=BlastRadius, description="Calculated impact across the repository")

    # Actionability
    investigation_plan: List[InvestigationTask] = Field(default_factory=list, description="Deterministic tasks required to verify and remediate")

    # Reasoning (To be populated by CyberSentinel LLM)
    reasoning: Optional[str] = Field(None, description="AI-generated explanation of why this matters and likely consequences")
    security_verdict: Optional[str] = Field(None, description="AI-generated final verdict on exploitability")
    remediation_recommendation: Optional[str] = Field(None, description="AI-generated fix instructions")

class SecurityPosture(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repository: Repository = Field(...)

    # Aggregations
    overall_risk_score: int = Field(default=0, description="Highest risk score among findings or an aggregate (0-100)")
    total_findings: int = Field(default=0)
    critical_findings: int = Field(default=0)
    high_findings: int = Field(default=0)

    # Details
    findings: List[CodeFinding] = Field(default_factory=list, description="All discovered code vulnerabilities")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
