from abc import ABC, abstractmethod
from typing import Any, Dict
from urllib.parse import ParseResult

from .ml_vector import MLFeatureVector


class BaseFeatureExtractor(ABC):
    """
    Abstract interface for all specific feature extractors.
    
    Each extractor is responsible for computing a specific subset of features
    (e.g., Lexical, Domain, Suspicious) from the parsed URL.
    """

    @abstractmethod
    async def extract(
        self, 
        target_url: str, 
        parsed_url: ParseResult, 
        vector: MLFeatureVector, 
        context: Dict[str, Any]
    ) -> None:
        """
        Extracts features and updates the provided MLFeatureVector in-place.
        
        Args:
            target_url: The normalized raw string URL.
            parsed_url: The parsed url object (urllib.parse).
            vector: The MLFeatureVector to update with extracted features.
            context: Shared dictionary for caching intermediate data between extractors.
        """
        pass
