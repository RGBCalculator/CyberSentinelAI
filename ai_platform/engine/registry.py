import logging
from threading import Lock
from typing import Dict, Optional, List
from ai_platform.core.interfaces import ModelProvider

logger = logging.getLogger(__name__)

class ModelRegistry:
    """
    Thread-safe, in-memory storage mapping model IDs to loaded ModelProvider instances.
    Supports versioning and hot-swapping without locking the main thread during reads.
    """
    def __init__(self):
        self._providers: Dict[str, Dict[str, ModelProvider]] = {}
        self._lock = Lock()

    def register(self, provider: ModelProvider) -> None:
        """
        Registers a loaded ModelProvider into the registry.
        """
        metadata = provider.metadata()
        with self._lock:
            if metadata.name not in self._providers:
                self._providers[metadata.name] = {}
            self._providers[metadata.name][metadata.version] = provider
            logger.info(f"Registered model {metadata.name} v{metadata.version} ({metadata.framework})")

    def unregister(self, name: str, version: str) -> Optional[ModelProvider]:
        """
        Removes a model from the registry.
        """
        with self._lock:
            if name in self._providers and version in self._providers[name]:
                provider = self._providers[name].pop(version)
                if not self._providers[name]:
                    del self._providers[name]
                logger.info(f"Unregistered model {name} v{version}")
                return provider
            return None

    def get_provider(self, name: str, version: Optional[str] = None) -> Optional[ModelProvider]:
        """
        Retrieves a ModelProvider by name and optional version.
        If version is None, retrieves the latest version (lexicographically).
        """
        with self._lock: # Quick lock for dict lookup
            if name not in self._providers or not self._providers[name]:
                return None

            if version:
                return self._providers[name].get(version)
            else:
                # Default to the "latest" version by simple string sorting
                latest_version = sorted(self._providers[name].keys(), reverse=True)[0]
                return self._providers[name][latest_version]

    def list_models(self) -> List[dict]:
        """Returns metadata for all registered models."""
        with self._lock:
            return [
                p.metadata().model_dump()
                for versions in self._providers.values()
                for p in versions.values()
            ]
