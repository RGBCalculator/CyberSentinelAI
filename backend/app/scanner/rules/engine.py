import logging
from typing import List, Type

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding, FindingCategory, RiskLevel
from .base import BaseRule
from .registry import RuleRegistry
from .common.metadata import ScanMetadata

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Orchestrates the execution of all registered deterministic rules.
    """

    def __init__(self):
        self._rules: List[BaseRule] = []
        self._initialize_rules()

    def _initialize_rules(self):
        """Instantiates all registered rules with default configurations."""
        registry = RuleRegistry.get_all_rules()
        for rule_id, rule_class in registry.items():
            try:
                self._rules.append(rule_class())
                logger.debug(f"Instantiated rule: {rule_id}")
            except Exception as e:
                logger.error(f"Failed to instantiate rule {rule_id}: {e}")

    async def evaluate_all(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> List[Finding]:
        """
        Executes all instantiated rules against the provided features and metadata.
        
        Args:
            feature_vector: Standardized MLFeatureVector.
            metadata: Contextual data about the scan.
            
        Returns:
            List[Finding]: Collected enterprise findings from all triggered rules.
        """
        findings: List[Finding] = []
        
        for rule in self._rules:
            result = await rule.execute(feature_vector, metadata)
            if not result.success:
                logger.error(f"Rule {result.rule_id} failed during execution: {result.error_message}")
                # We can generate an internal error finding or silently continue.
                # Since we want graceful failure, we log it and continue.
                continue
                
            if result.finding:
                findings.append(result.finding)
                
        return findings
