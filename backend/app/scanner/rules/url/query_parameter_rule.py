from typing import Optional
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, Evidence, EvidenceType
from ..base import BaseRule
from ..registry import RuleRegistry
from ..common.metadata import ScanMetadata
from ..common.categories import FindingCategory
from ..common.severity import RuleSeverity


class QueryParameterConfig(BaseModel):
    max_params: int = 5
    severity: RuleSeverity = RuleSeverity.LOW


@RuleRegistry.register("url_excessive_query_params")
class QueryParameterRule(BaseRule[QueryParameterConfig]):
    
    @classmethod
    def get_default_config(cls) -> QueryParameterConfig:
        return QueryParameterConfig()

    @property
    def rule_id(self) -> str:
        return "url_excessive_query_params"

    @property
    def name(self) -> str:
        return "Excessive Query Parameters"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects URLs with an unusually high number of query parameters, sometimes indicative of tracking or injection attempts."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.ANOMALY

    @property
    def default_severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        param_count = feature_vector.structural.query_param_count
        if param_count > self.config.max_params:
            return Finding(
                title=self.name,
                description=f"{self.description} Detected count: {param_count} (Threshold: {self.config.max_params}).",
                severity=self.config.severity,
                category=self.category,
                confidence=1.0,
                evidence=[
                    Evidence(
                        source=self.rule_id,
                        evidence_type=EvidenceType.OTHER,
                        raw_value=str(param_count)
                    )
                ],
                tags=["query-params", self.rule_id]
            )
        return None
