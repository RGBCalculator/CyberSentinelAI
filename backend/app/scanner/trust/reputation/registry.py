"""
Provider Registry for the Reputation Intelligence Subsystem.

This module provides the ReputationProviderRegistry, which manages
the lifecycle, discovery, and coordination of all reputation providers.
"""

import asyncio
import logging
from threading import Lock
from typing import List, Dict, Optional, Tuple

from app.scanner.trust.reputation.base import BaseReputationProvider

logger = logging.getLogger(__name__)


class ReputationProviderRegistry:
    """
    Registry for managing all reputation providers.
    
    Provides thread-safe registration, discovery, initialization, 
    and shutdown capabilities for the Reputation Engine.
    """

    def __init__(self):
        """
        Initializes the ReputationProviderRegistry.
        """
        self._providers: Dict[str, BaseReputationProvider] = {}
        self._lock = Lock()

    def register(self, provider: BaseReputationProvider) -> None:
        """
        Registers a new reputation provider in a thread-safe manner.
        
        Args:
            provider (BaseReputationProvider): The provider instance to register.
        """
        with self._lock:
            name = provider.metadata.name
            if name in self._providers:
                logger.error("Attempted to register duplicate provider: %s. Ignoring.", name)
                return
            self._providers[name] = provider
            logger.info("Successfully registered reputation provider: %s v%s", 
                        name, provider.metadata.version)

    def unregister(self, provider_name: str) -> None:
        """
        Unregisters a provider by its name in a thread-safe manner.
        
        Args:
            provider_name (str): The name of the provider to unregister.
        """
        with self._lock:
            if provider_name in self._providers:
                del self._providers[provider_name]
                logger.info("Unregistered reputation provider: %s", provider_name)
            else:
                logger.debug("Provider not found for unregistration: %s", provider_name)

    def get_provider(self, provider_name: str) -> Optional[BaseReputationProvider]:
        """
        Retrieves a provider by its name.
        
        Args:
            provider_name (str): The name of the provider.
            
        Returns:
            Optional[BaseReputationProvider]: The provider instance, or None if not found.
        """
        with self._lock:
            return self._providers.get(provider_name)

    def get_all(self) -> List[BaseReputationProvider]:
        """
        Retrieves a list of all registered providers.
        
        Returns:
            List[BaseReputationProvider]: A list of all provider instances.
        """
        with self._lock:
            return list(self._providers.values())

    def get_enabled(self) -> List[BaseReputationProvider]:
        """
        Retrieves a list of enabled providers, sorted by reliability (highest first).
        
        Returns:
            List[BaseReputationProvider]: Sorted list of enabled provider instances.
        """
        with self._lock:
            enabled_providers = [p for p in self._providers.values() if p.metadata.enabled]
            
        # Sort by reliability descending
        return sorted(enabled_providers, key=lambda p: p.metadata.reliability, reverse=True)

    async def initialize_all(self) -> None:
        """
        Initializes all registered providers concurrently using asyncio.gather().
        
        Catches and logs any exceptions that occur during initialization,
        preventing failures in one provider from affecting others.
        """
        providers = self.get_all()
        if not providers:
            return

        async def _safe_init(provider: BaseReputationProvider) -> None:
            try:
                await provider.initialize()
                logger.debug("Initialized provider: %s", provider.metadata.name)
            except Exception as e:
                logger.error("Failed to initialize provider %s: %s", 
                             provider.metadata.name, e, exc_info=True)

        await asyncio.gather(*[_safe_init(p) for p in providers], return_exceptions=True)
        logger.info("Completed initialization for %d reputation providers.", len(providers))

    async def shutdown_all(self) -> None:
        """
        Shuts down all registered providers concurrently using asyncio.gather().
        
        Catches and logs any exceptions that occur during shutdown.
        """
        providers = self.get_all()
        if not providers:
            return

        async def _safe_shutdown(provider: BaseReputationProvider) -> None:
            try:
                await provider.shutdown()
                logger.debug("Shut down provider: %s", provider.metadata.name)
            except Exception as e:
                logger.error("Failed to shut down provider %s: %s", 
                             provider.metadata.name, e, exc_info=True)

        await asyncio.gather(*[_safe_shutdown(p) for p in providers], return_exceptions=True)
        logger.info("Completed shutdown for %d reputation providers.", len(providers))

    async def health_check_all(self) -> Dict[str, bool]:
        """
        Performs a health check on all registered providers concurrently.
        
        Returns:
            Dict[str, bool]: A dictionary mapping provider names to their health status.
        """
        providers = self.get_all()
        results: Dict[str, bool] = {}
        
        if not providers:
            return results

        async def _safe_health_check(provider: BaseReputationProvider) -> Tuple[str, bool]:
            name = provider.metadata.name
            try:
                is_healthy = await provider.health_check()
                if not is_healthy:
                    logger.warning("Health check failed for provider: %s", name)
                return name, bool(is_healthy)
            except Exception as e:
                logger.error("Exception during health check for provider %s: %s", 
                             name, e, exc_info=True)
                return name, False

        tasks = [_safe_health_check(p) for p in providers]
        check_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in check_results:
            if isinstance(result, Exception):
                logger.error("Unexpected exception in health_check_all gather: %s", result)
                continue
            name, status = result
            results[name] = status
            
        return results
