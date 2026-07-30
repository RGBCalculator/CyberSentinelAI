from typing import Optional
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, Evidence, EvidenceType
from ..base import BaseRule
from ..registry import RuleRegistry
from ..common.metadata import ScanMetadata
from ..common.categories import FindingCategory
from ..common.severity import RuleSeverity


class IPConfig(BaseModel):
    severity: RuleSeverity = RuleSeverity.MEDIUM


@RuleRegistry.register("url_ip_usage")
class IPRule(BaseRule[IPConfig]):
    
    @classmethod
    def get_default_config(cls) -> IPConfig:
        return IPConfig()

    @property
    def rule_id(self) -> str:
        return "url_ip_usage"

    @property
    def name(self) -> str:
        return "URL Uses IP Address"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects if the URL host is a raw IP address, which is commonly used to obfuscate phishing links."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.ANOMALY

    @property
    def default_severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        if feature_vector.structural.uses_ip:
            # We fetch the original host string from lexical length logic (or we can just use metadata.target_url)
            # To extract the exact IP, we can use the target_url but the MLVector abstracted it to a bool.
            # We can still emit a finding.
            return Finding(
                title=self.name,
                description=self.description,
                severity=self.config.severity,
                category=self.category,
                confidence=1.0,
                evidence=[
                    Evidence(
                        source=self.rule_id,
                        evidence_type=EvidenceType.OTHER,
                        raw_value=metadata.target_url,
                        normalized_value="IP_HOST"
                    )
                ],
                tags=["ip-host", "obfuscation", self.rule_id]
            )
        return None
