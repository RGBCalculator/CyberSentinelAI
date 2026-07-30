from typing import Optional
from pydantic import BaseModel
from app.scanner.schemas import Finding

class RuleResult(BaseModel):
    """
    Standardized result emitted by a rule evaluation.
    """
    rule_id: str
    success: bool
    finding: Optional[Finding] = None
    error_message: Optional[str] = None
