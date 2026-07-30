from typing import Optional
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, Evidence, EvidenceType
from ..base import BaseRule
from ..registry import RuleRegistry
from ..common.metadata import ScanMetadata
from ..common.categories import FindingCategory
from ..common.severity import RuleSeverity


class EntropyConfig(BaseModel):
    threshold: float = 4.5
    severity: RuleSeverity = RuleSeverity.MEDIUM


@RuleRegistry.register("url_high_entropy")
class EntropyRule(BaseRule[EntropyConfig]):
    
    @classmethod
    def get_default_config(cls) -> EntropyConfig:
        return EntropyConfig()

    @property
    def rule_id(self) -> str:
        return "url_high_entropy"

    @property
    def name(self) -> str:
        return "High Hostname Entropy"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects randomly generated hostnames (DGA) by evaluating Shannon entropy."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.MALWARE

    @property
    def default_severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        # Ignore IP addresses as their entropy might artificially flag
        if feature_vector.structural.uses_ip:
            return None
            
        entropy = feature_vector.lexical.shannon_entropy
        if entropy > self.config.threshold:
            return Finding(
                title=self.name,
                description=f"{self.description} Detected entropy: {entropy:.2f} (Threshold: {self.config.threshold}).",
                severity=self.config.severity,
                category=self.category,
                confidence=0.7,
                evidence=[
                    Evidence(
                        source=self.rule_id,
                        evidence_type=EvidenceType.OTHER,
                        raw_value=str(entropy),
                        normalized_value=f"Entropy > {self.config.threshold}"
                    )
                ],
                tags=["dga", "high-entropy", self.rule_id]
            )
        return None
