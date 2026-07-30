from typing import Optional
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, Evidence, EvidenceType
from ..base import BaseRule
from ..registry import RuleRegistry
from ..common.metadata import ScanMetadata
from ..common.categories import FindingCategory
from ..common.severity import RuleSeverity


class PathDepthConfig(BaseModel):
    max_depth: int = 5
    severity: RuleSeverity = RuleSeverity.LOW


@RuleRegistry.register("url_deep_path")
class PathDepthRule(BaseRule[PathDepthConfig]):
    
    @classmethod
    def get_default_config(cls) -> PathDepthConfig:
        return PathDepthConfig()

    @property
    def rule_id(self) -> str:
        return "url_deep_path"

    @property
    def name(self) -> str:
        return "Excessive URL Path Depth"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects URLs with unusually deep directory structures, sometimes used to evade basic filters."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.ANOMALY

    @property
    def default_severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        depth = feature_vector.structural.path_depth
        if depth > self.config.max_depth:
            return Finding(
                title=self.name,
                description=f"{self.description} Detected depth: {depth} (Threshold: {self.config.max_depth}).",
                severity=self.config.severity,
                category=self.category,
                confidence=1.0,
                evidence=[
                    Evidence(
                        source=self.rule_id,
                        evidence_type=EvidenceType.OTHER,
                        raw_value=str(depth)
                    )
                ],
                tags=["deep-path", self.rule_id]
            )
        return None
