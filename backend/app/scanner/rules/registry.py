from typing import Dict, Type
import logging

logger = logging.getLogger(__name__)


class RuleRegistry:
    """
    Central registry for all deterministic rules.
    Follows the Registry pattern for dynamic plugin loading.
    """
    _registry: Dict[str, Type] = {}

    @classmethod
    def register(cls, rule_id: str):
        """
        Decorator to register a Rule class.
        
        Args:
            rule_id: The unique string identifier of the rule.
        """
        def decorator(rule_class: Type):
            if rule_id in cls._registry:
                logger.warning(f"Rule {rule_id} is already registered. Overwriting.")
            cls._registry[rule_id] = rule_class
            logger.debug(f"Registered rule: {rule_id}")
            return rule_class
        return decorator

    @classmethod
    def get_all_rules(cls) -> Dict[str, Type]:
        """Returns all registered rules."""
        return cls._registry

    @classmethod
    def clear(cls) -> None:
        """Clears the registry (mainly for testing)."""
        cls._registry.clear()
