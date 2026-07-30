"""
Abstract Base Class for the Reputation Intelligence Subsystem.

This module defines the abstract interface that all reputation providers
must implement. It establishes the contract for integrating new threat
intelligence feeds into the Reputation Engine.
"""

from abc import ABC, abstractmethod
from typing import Optional

from app.scanner.trust.reputation.schemas import ProviderMetadata, ReputationFinding


class BaseReputationProvider(ABC):
    """
    Abstract Base Class for Reputation Providers.
    
    All reputation providers must inherit from this class and implement
    the required abstract methods and properties to ensure compatibility
    with the Reputation Engine.
    """

    @property
    @abstractmethod
    def metadata(self) -> ProviderMetadata:
        """
        Retrieves the metadata associated with the provider.
        
        Returns:
            ProviderMetadata: Configuration and details about the provider.
        """
        pass

    @abstractmethod
    async def lookup(self, indicator: str) -> Optional[ReputationFinding]:
        """
        Queries the provider for reputation intelligence on a given indicator.
        
        This method must NOT raise exceptions. Any internal errors, rate limits, 
        or network failures must be handled gracefully, returning None.

        Args:
            indicator (str): The domain, IP, or URL to lookup.

        Returns:
            Optional[ReputationFinding]: The finding details if the provider 
                                         has information on the indicator, 
                                         or None otherwise.
        """
        pass

    async def health_check(self) -> bool:
        """
        Checks the health and availability of the reputation provider.
        
        This can be overridden by providers to verify API keys, connectivity,
        or rate limits.
        
        Returns:
            bool: True if the provider is healthy, False otherwise.
        """
        return True

    async def initialize(self) -> None:
        """
        Initializes the reputation provider.
        
        This can be overridden by providers to establish connections,
        load local databases, or perform asynchronous setup tasks.
        
        Default implementation is a no-op.
        """
        pass

    async def shutdown(self) -> None:
        """
        Shuts down the reputation provider.
        
        This can be overridden by providers to close connections,
        save state, or perform cleanup tasks.
        
        Default implementation is a no-op.
        """
        pass
