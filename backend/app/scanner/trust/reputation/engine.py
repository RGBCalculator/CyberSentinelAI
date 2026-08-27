"""
Reputation Engine for the Reputation Intelligence Subsystem.

This module provides the ReputationEngine, which orchestrates multiple
reputation providers concurrently to evaluate the threat level of an
indicator (e.g., domain, IP, URL). It aggregates the findings into a
unified ReputationResult.
"""

import asyncio
import logging
from typing import Optional, List

from app.scanner.trust.reputation.schemas import ReputationFinding, ReputationResult
from app.scanner.trust.reputation.base import BaseReputationProvider
from app.scanner.trust.reputation.registry import ReputationProviderRegistry

logger = logging.getLogger(__name__)


class ReputationEngine:
    """
    Orchestrates reputation providers to analyze indicators.

    The engine relies on a registry to discover and manage providers. It
    executes all enabled providers concurrently, gracefully handles failures,
    and aggregates their findings into a unified result.
    """

    def __init__(self):
        """
        Initializes the ReputationEngine.

        Instantiates a ReputationProviderRegistry to manage all
        reputation intelligence sources.
        """
        self.registry = ReputationProviderRegistry()

    async def initialize(self) -> None:
        """
        Initializes all registered reputation providers.

        This delegates initialization to the underlying registry.
        """
        await self.registry.initialize_all()

    async def shutdown(self) -> None:
        """
        Shuts down all registered reputation providers.

        This delegates shutdown to the underlying registry.
        """
        await self.registry.shutdown_all()

    async def _safe_lookup(
        self, provider: BaseReputationProvider, indicator: str
    ) -> Optional[ReputationFinding]:
        """
        Safely executes a reputation lookup using the specified provider.

        Catches any unexpected exceptions to ensure one failing provider
        does not crash the entire orchestration process. Logs the outcome.

        Args:
            provider (BaseReputationProvider): The provider to use for the lookup.
            indicator (str): The indicator to analyze (e.g., IP, domain, URL).

        Returns:
            Optional[ReputationFinding]: The finding from the provider, or None
                                         if an error occurred or no data was found.
        """
        provider_name = provider.metadata.name
        try:
            finding = await provider.lookup(indicator)
            if finding:
                logger.debug(
                    "Provider '%s' returned a finding for indicator '%s'.",
                    provider_name,
                    indicator,
                )
            return finding
        except Exception as e:
            logger.error(
                "Provider '%s' encountered an unexpected exception while analyzing indicator '%s': %s",
                provider_name,
                indicator,
                e,
                exc_info=True,
            )
            return None

    async def analyze(self, indicator: str) -> ReputationResult:
        """
        Analyzes an indicator concurrently using all enabled reputation providers.

        Workflow:
        1. Retrieves all enabled providers from the registry.
        2. If no providers are enabled, returns an empty ReputationResult.
        3. Concurrently queries all enabled providers.
        4. Collects successful findings (ignoring failures or empty results).
        5. Aggregates findings to calculate confidence, malicious counts, and overall status.

        Args:
            indicator (str): The indicator to analyze (e.g., IP, domain, URL).

        Returns:
            ReputationResult: The aggregated reputation result across all providers.
        """
        providers = self.registry.get_enabled()

        if not providers:
            logger.warning("No enabled reputation providers found in registry.")
            return ReputationResult()

        provider_count = len(providers)

        # Run lookups concurrently
        tasks = [self._safe_lookup(provider, indicator) for provider in providers]
        raw_results = await asyncio.gather(*tasks)

        # Filter out None results
        findings: List[ReputationFinding] = [
            result for result in raw_results if result is not None
        ]

        malicious_count = sum(1 for finding in findings if finding.malicious)
        is_malicious = malicious_count > 0

        # Calculate confidence
        confidence = 0.0
        if findings:
            total_confidence = sum(finding.confidence for finding in findings)
            confidence = total_confidence / len(findings)

        return ReputationResult(
            findings=findings,
            malicious=is_malicious,
            confidence=confidence,
            provider_count=provider_count,
            malicious_count=malicious_count,
        )
