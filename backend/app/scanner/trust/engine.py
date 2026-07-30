"""
Trust Engine module for CyberSentinel AI.

This module provides the TrustEngine which orchestrates various analyzers
to collect trust intelligence signals (Certificate, Domain, DNS, Reputation)
and computes a final Trust Score.
"""

import logging
from typing import Any, Callable, Coroutine

from app.scanner.trust.schemas import TrustResult
from app.scanner.trust.score import TrustScoreCalculator
from app.scanner.trust.analyzers import (
    CertificateAnalyzer,
    DomainAnalyzer,
    DNSAnalyzer,
    ReputationAnalyzer
)


logger = logging.getLogger(__name__)


class TrustEngine:
    """
    Coordinates the trust intelligence analysis process.
    
    It instantiates specific analyzers and delegates the task of collecting
    signals to them. Finally, it uses the TrustScoreCalculator to determine
    the overall trust score and trust level.
    """

    def __init__(self):
        """
        Initializes the TrustEngine and instantiates all required analyzers
        along with the score calculator.
        """
        self.certificate_analyzer = CertificateAnalyzer()
        self.domain_analyzer = DomainAnalyzer()
        self.dns_analyzer = DNSAnalyzer()
        self.reputation_analyzer = ReputationAnalyzer()
        self.score_calculator = TrustScoreCalculator()

    async def analyze(self, target: str) -> TrustResult:
        """
        Executes all trust analyzers, aggregates the results into a TrustResult,
        and calculates the final score.

        Args:
            target (str): The target to analyze (e.g., domain name).

        Returns:
            TrustResult: The aggregated trust intelligence results.
        """
        result = TrustResult()

        # Define analyzers and their corresponding attributes in TrustResult
        analyzers = [
            ("CertificateAnalyzer", self.certificate_analyzer.analyze, "certificate"),
            ("DomainAnalyzer", self.domain_analyzer.analyze, "domain"),
            ("DNSAnalyzer", self.dns_analyzer.analyze, "dns"),
            ("ReputationAnalyzer", self.reputation_analyzer.analyze, "reputation"),
        ]

        for name, analyzer_func, attr in analyzers:
            await self._execute_analyzer(name, analyzer_func, target, result, attr)

        # Calculate final score based on collected intelligence
        try:
            self.score_calculator.calculate(result)
        except Exception as e:
            logger.error(
                "TrustScoreCalculator failed for target '%s': %s", 
                target, 
                e, 
                exc_info=True
            )

        return result

    async def _execute_analyzer(
        self,
        name: str,
        analyzer_func: Callable[[str], Coroutine[Any, Any, Any]],
        target: str,
        result: TrustResult,
        attr: str
    ) -> None:
        """
        Safely executes an individual analyzer and updates the TrustResult.
        Any exception raised is caught, logged, and execution continues.

        Args:
            name (str): The name of the analyzer (used for logging).
            analyzer_func (Callable): The async function to execute.
            target (str): The analysis target.
            result (TrustResult): The result object to update.
            attr (str): The attribute on the TrustResult to update.
        """
        try:
            info = await analyzer_func(target)
            if info:
                setattr(result, attr, info)
        except Exception as e:
            logger.error(
                "%s failed for target '%s': %s", 
                name, 
                target, 
                e, 
                exc_info=True
            )
