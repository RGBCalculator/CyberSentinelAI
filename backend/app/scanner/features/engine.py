from typing import Any, Dict
from urllib.parse import urlparse

from .base import BaseFeatureExtractor
from .ml_vector import MLFeatureVector
from .lexical import LexicalExtractor
from .structural import StructuralExtractor
from .domain import DomainExtractor
from .suspicious import SuspiciousPatternExtractor
from .statistical import StatisticalExtractor


class FeatureEngine:
    """
    Orchestrates the execution of a suite of BaseFeatureExtractors.
    Produces a standardized MLFeatureVector.
    """

    def __init__(self):
        # The order matters slightly since StatisticalExtractor relies on the others being populated
        self.extractors: list[BaseFeatureExtractor] = [
            LexicalExtractor(),
            StructuralExtractor(),
            DomainExtractor(),
            SuspiciousPatternExtractor(),
            StatisticalExtractor()
        ]

    async def extract_features(self, target_url: str) -> MLFeatureVector:
        """
        Runs the full extraction pipeline for a given URL.
        
        Args:
            target_url: The normalized URL string.
            
        Returns:
            MLFeatureVector: The deeply nested, strongly typed feature object.
        """
        parsed = urlparse(target_url)
        vector = MLFeatureVector()
        context: Dict[str, Any] = {}
        
        for extractor in self.extractors:
            await extractor.extract(target_url, parsed, vector, context)
            
        return vector
