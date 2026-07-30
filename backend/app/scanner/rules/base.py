from abc import ABC, abstractmethod
from typing import Optional, Generic, TypeVar
from pydantic import BaseModel

from app.scanner.features import MLFeatureVector
from app.scanner.schemas import Finding
from .common.metadata import ScanMetadata
from .common.categories import FindingCategory
from .common.severity import RuleSeverity
from .rule_result import RuleResult


ConfigType = TypeVar("ConfigType", bound=BaseModel)

class BaseRule(ABC, Generic[ConfigType]):
    """
    Abstract interface for all deterministic rules.
    Enforces a strict evaluation contract.
    """
    
    def __init__(self, config: Optional[ConfigType] = None):
        """
        Initializes the rule with a configuration. 
        If None is provided, it must instantiate its own default configuration.
        """
        self.config = config or self.get_default_config()
        
    @classmethod
    @abstractmethod
    def get_default_config(cls) -> ConfigType:
        """Returns the default configuration model for this rule."""
        pass

    @property
    @abstractmethod
    def rule_id(self) -> str:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @property
    @abstractmethod
    def category(self) -> FindingCategory:
        pass

    @property
    @abstractmethod
    def default_severity(self) -> RuleSeverity:
        pass

    @abstractmethod
    async def evaluate(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> Optional[Finding]:
        """
        Evaluates the features against the rule's configuration.
        
        Args:
            feature_vector: The standardized MLFeatureVector extracted from the target.
            metadata: Contextual data about the scan.
            
        Returns:
            An enterprise Finding if the rule triggers, else None.
        """
        pass

    async def execute(self, feature_vector: MLFeatureVector, metadata: ScanMetadata) -> RuleResult:
        """
        Safe execution wrapper that handles exceptions and returns a RuleResult.
        """
        try:
            finding = await self.evaluate(feature_vector, metadata)
            return RuleResult(
                rule_id=self.rule_id,
                success=True,
                finding=finding
            )
        except Exception as e:
            return RuleResult(
                rule_id=self.rule_id,
                success=False,
                error_message=str(e)
            )
