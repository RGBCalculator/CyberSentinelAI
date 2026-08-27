import asyncio
import logging
from typing import Optional
from ai_platform.core.interfaces import ModelProvider
from ai_platform.engine.registry import ModelRegistry

logger = logging.getLogger(__name__)

class ModelManager:
    """
    Orchestrates loading, unloading, lazy loading, and background loading of models.
    """
    def __init__(self, registry: ModelRegistry):
        self.registry = registry

    async def load_model_async(self, provider: ModelProvider) -> bool:
        """
        Loads a model asynchronously and atomically registers it upon success (Hot Swap).
        """
        metadata = provider.metadata()
        logger.info(f"Initiating background load for {metadata.name} v{metadata.version}")

        try:
            # The load() method of the provider must be non-blocking
            await provider.load()

            # Atomically swap into the registry
            self.registry.register(provider)
            logger.info(f"Successfully loaded and registered {metadata.name} v{metadata.version}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model {metadata.name} v{metadata.version}: {e}", exc_info=True)
            return False

    async def unload_model(self, name: str, version: str) -> bool:
        """
        Removes a model from the registry and unloads it from memory.
        """
        provider = self.registry.unregister(name, version)
        if provider:
            try:
                await provider.unload()
                logger.info(f"Successfully unloaded model {name} v{version}")
                return True
            except Exception as e:
                logger.error(f"Error while unloading model {name} v{version}: {e}", exc_info=True)
                return False
        return False
