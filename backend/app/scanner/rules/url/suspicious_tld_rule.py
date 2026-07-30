from typing import Optional
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, Evidence, EvidenceType
from ..base import BaseRule
from ..registry import RuleRegistry
from ..common.metadata import ScanMetadata
from ..common.categories import FindingCategory
from ..common.severity import RuleSeverity


class SuspiciousTLDConfig(BaseModel):
    severity: RuleSeverity = RuleSeverity.MEDIUM


@RuleRegistry.register("url_suspicious_tld")
class SuspiciousTLDRule(BaseRule[SuspiciousTLDConfig]):
    
    @classmethod
    def get_default_config(cls) -> SuspiciousTLDConfig:
        return SuspiciousTLDConfig()

    @property
    def rule_id(self) -> str:
        return "url_suspicious_tld"

    @property
    def name(self) -> str:
        return "Suspicious Top-Level Domain"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects domains utilizing TLDs with high historical abuse rates (e.g., .zip, .tk, .pw)."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.INFO

    @property
    def default_severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        if feature_vector.domain.is_suspicious_tld:
            return Finding(
                title=self.name,
                description=f"{self.description} Detected TLD: {feature_vector.domain.tld}",
                severity=self.config.severity,
                category=self.category,
                confidence=0.8,
                evidence=[
                    Evidence(
                        source=self.rule_id,
                        evidence_type=EvidenceType.OTHER,
                        raw_value=feature_vector.domain.tld
                    )
                ],
                tags=["tld", "suspicious-tld", self.rule_id]
            )
        return None
