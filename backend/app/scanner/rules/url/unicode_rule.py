from typing import Optional
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, Evidence, EvidenceType
from ..base import BaseRule
from ..registry import RuleRegistry
from ..common.metadata import ScanMetadata
from ..common.categories import FindingCategory
from ..common.severity import RuleSeverity


class UnicodeConfig(BaseModel):
    severity: RuleSeverity = RuleSeverity.MEDIUM


@RuleRegistry.register("url_unicode_domain")
class UnicodeRule(BaseRule[UnicodeConfig]):
    
    @classmethod
    def get_default_config(cls) -> UnicodeConfig:
        return UnicodeConfig()

    @property
    def rule_id(self) -> str:
        return "url_unicode_domain"

    @property
    def name(self) -> str:
        return "Unicode / Punycode Domain"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects domains using international characters (IDN) or Punycode, which are often used in homograph phishing attacks."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.PHISHING

    @property
    def default_severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        if feature_vector.domain.is_idn or feature_vector.domain.is_punycode:
            return Finding(
                title=self.name,
                description=self.description,
                severity=self.config.severity,
                category=self.category,
                confidence=0.8,
                evidence=[
                    Evidence(
                        source=self.rule_id,
                        evidence_type=EvidenceType.OTHER,
                        raw_value="IDN/Punycode Detected"
                    )
                ],
                tags=["idn", "homograph", "punycode", self.rule_id]
            )
        return None
