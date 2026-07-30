import math
from typing import Any, Dict
from urllib.parse import ParseResult

from .base import BaseFeatureExtractor
from .ml_vector import MLFeatureVector


class LexicalExtractor(BaseFeatureExtractor):
    """
    Extracts lexical features such as lengths, ratios, and entropy.
    """

    def _calculate_entropy(self, s: str) -> float:
        """Calculates Shannon entropy of a string."""
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob)

    async def extract(
        self, 
        target_url: str, 
        parsed_url: ParseResult, 
        vector: MLFeatureVector, 
        context: Dict[str, Any]
    ) -> None:
        
        url_len = len(target_url)
        host = parsed_url.hostname or ""
        
        vector.lexical.url_length = url_len
        vector.lexical.host_length = len(host)
        
        # Domain length heuristic (stripping subdomains if possible, simplified here to host length 
        # or left for domain extractor to refine. We'll refine it in domain extractor context if needed,
        # but for now host length is an approximation).
        vector.lexical.domain_length = len(host)
        
        vector.lexical.path_length = len(parsed_url.path)
        vector.lexical.query_length = len(parsed_url.query)
        vector.lexical.fragment_length = len(parsed_url.fragment)
        
        # Character distributions
        if url_len > 0:
            digits = sum(1 for c in target_url if c.isdigit())
            letters = sum(1 for c in target_url if c.isalpha())
            uppers = sum(1 for c in target_url if c.isupper())
            lowers = sum(1 for c in target_url if c.islower())
            
            vector.lexical.character_count = url_len
            vector.lexical.digit_ratio = digits / url_len
            vector.lexical.letter_ratio = letters / url_len
            vector.lexical.uppercase_ratio = uppers / url_len
            vector.lexical.lowercase_ratio = lowers / url_len
        else:
            vector.lexical.character_count = 0
            vector.lexical.digit_ratio = 0.0
            vector.lexical.letter_ratio = 0.0
            vector.lexical.uppercase_ratio = 0.0
            vector.lexical.lowercase_ratio = 0.0
            
        vector.lexical.shannon_entropy = self._calculate_entropy(host)
