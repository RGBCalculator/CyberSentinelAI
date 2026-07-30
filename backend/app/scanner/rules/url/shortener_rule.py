from typing import Optional
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, Evidence, EvidenceType
from ..base import BaseRule
from ..registry import RuleRegistry
from ..common.metadata import ScanMetadata
from ..common.categories import FindingCategory
from ..common.severity import RuleSeverity


class ShortenerConfig(BaseModel):
    severity: RuleSeverity = RuleSeverity.LOW


@RuleRegistry.register("url_shortener")
class ShortenerRule(BaseRule[ShortenerConfig]):
    
    @classmethod
    def get_default_config(cls) -> ShortenerConfig:
        return ShortenerConfig()

    @property
    def rule_id(self) -> str:
        return "url_shortener"

    @property
    def name(self) -> str:
        return "URL Shortener Service Detected"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects known URL shortener services which obfuscate the true destination."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.INFO

    @property
    def default_severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        if feature_vector.domain.is_shortener:
            return Finding(
                title=self.name,
                description=self.description,
                severity=self.config.severity,
                category=self.category,
                confidence=1.0,
                tags=["url-shortener", self.rule_id]
            )
        return None
