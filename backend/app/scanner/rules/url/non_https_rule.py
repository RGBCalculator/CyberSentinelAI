from typing import Optional
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, Evidence, EvidenceType
from ..base import BaseRule
from ..registry import RuleRegistry
from ..common.metadata import ScanMetadata
from ..common.categories import FindingCategory
from ..common.severity import RuleSeverity


class NonHTTPSConfig(BaseModel):
    severity: RuleSeverity = RuleSeverity.LOW


@RuleRegistry.register("url_non_https")
class NonHTTPSRule(BaseRule[NonHTTPSConfig]):
    
    @classmethod
    def get_default_config(cls) -> NonHTTPSConfig:
        return NonHTTPSConfig()

    @property
    def rule_id(self) -> str:
        return "url_non_https"

    @property
    def name(self) -> str:
        return "Unencrypted Protocol (HTTP)"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "The URL uses unencrypted HTTP instead of HTTPS. This leaves traffic vulnerable to interception."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.ANOMALY

    @property
    def default_severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        if not feature_vector.structural.is_https:
            return Finding(
                title=self.name,
                description=self.description,
                severity=self.config.severity,
                category=self.category,
                confidence=1.0,
                tags=["http", "unencrypted", self.rule_id]
            )
        return None
