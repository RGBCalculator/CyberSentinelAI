from typing import Optional
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, Evidence, EvidenceType
from ..base import BaseRule
from ..registry import RuleRegistry
from ..common.metadata import ScanMetadata
from ..common.categories import FindingCategory
from ..common.severity import RuleSeverity


class EncodedCharConfig(BaseModel):
    severity: RuleSeverity = RuleSeverity.LOW


@RuleRegistry.register("url_encoded_chars")
class EncodedCharacterRule(BaseRule[EncodedCharConfig]):
    
    @classmethod
    def get_default_config(cls) -> EncodedCharConfig:
        return EncodedCharConfig()

    @property
    def rule_id(self) -> str:
        return "url_encoded_chars"

    @property
    def name(self) -> str:
        return "URL Encoded Characters Detected"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects URL encoded characters (%XX). High volumes of encoding are sometimes used to bypass filters."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.ANOMALY

    @property
    def default_severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        if feature_vector.structural.has_encoded_chars:
            return Finding(
                title=self.name,
                description=self.description,
                severity=self.config.severity,
                category=self.category,
                confidence=0.8,
                tags=["encoding", "obfuscation", self.rule_id]
            )
        return None
