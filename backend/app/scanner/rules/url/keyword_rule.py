from typing import Optional
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, Evidence, EvidenceType
from ..base import BaseRule
from ..registry import RuleRegistry
from ..common.metadata import ScanMetadata
from ..common.categories import FindingCategory
from ..common.severity import RuleSeverity


class KeywordConfig(BaseModel):
    severity: RuleSeverity = RuleSeverity.MEDIUM


@RuleRegistry.register("url_suspicious_keywords")
class KeywordRule(BaseRule[KeywordConfig]):
    
    @classmethod
    def get_default_config(cls) -> KeywordConfig:
        return KeywordConfig()

    @property
    def rule_id(self) -> str:
        return "url_suspicious_keywords"

    @property
    def name(self) -> str:
        return "Suspicious Keywords in URL"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects keywords commonly associated with phishing or sensitive actions."

    @property
    def category(self) -> FindingCategory:
        return FindingCategory.PHISHING

    @property
    def default_severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        sus_kws = (
            feature_vector.suspicious.phishing_keywords +
            feature_vector.suspicious.banking_keywords +
            feature_vector.suspicious.crypto_keywords +
            feature_vector.suspicious.invoice_keywords + 
            feature_vector.suspicious.login_keywords
        )
        
        if sus_kws:
            sus_kws = list(set(sus_kws)) # Deduplicate
            matches_str = ", ".join(sus_kws)
            return Finding(
                title=self.name,
                description=f"{self.description} Detected: {matches_str}.",
                severity=self.config.severity,
                category=self.category,
                confidence=0.8,
                evidence=[
                    Evidence(
                        source=self.rule_id,
                        evidence_type=EvidenceType.OTHER,
                        raw_value=matches_str
                    )
                ],
                tags=["phishing-keywords", self.rule_id]
            )
        return None
