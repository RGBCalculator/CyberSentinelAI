from typing import Any, Dict
from urllib.parse import ParseResult

from .base import BaseFeatureExtractor
from .ml_vector import MLFeatureVector


class StatisticalExtractor(BaseFeatureExtractor):
    """
    Compiles the final numerical vector suitable for ML ingestion.
    Runs strictly last in the sequence.
    """

    async def extract(
        self, 
        target_url: str, 
        parsed_url: ParseResult, 
        vector: MLFeatureVector, 
        context: Dict[str, Any]
    ) -> None:
        
        # Flatten all relevant structured features into a list of floats
        numeric_list = []
        
        # Lexical
        numeric_list.extend([
            float(vector.lexical.url_length),
            float(vector.lexical.host_length),
            float(vector.lexical.domain_length),
            float(vector.lexical.path_length),
            float(vector.lexical.query_length),
            float(vector.lexical.fragment_length),
            float(vector.lexical.character_count),
            float(vector.lexical.digit_ratio),
            float(vector.lexical.letter_ratio),
            float(vector.lexical.uppercase_ratio),
            float(vector.lexical.lowercase_ratio),
            float(vector.lexical.shannon_entropy)
        ])
        
        # Structural
        numeric_list.extend([
            float(vector.structural.is_https),
            float(vector.structural.uses_ip),
            float(vector.structural.is_ipv6),
            float(vector.structural.has_auth_section),
            float(vector.structural.port or 0),
            float(vector.structural.is_non_standard_port),
            float(vector.structural.query_param_count),
            float(vector.structural.has_fragment),
            float(vector.structural.path_depth),
            float(vector.structural.has_trailing_slash),
            float(vector.structural.repeated_separators),
            float(vector.structural.has_encoded_chars)
        ])
        
        # Domain
        numeric_list.extend([
            float(vector.domain.is_idn),
            float(vector.domain.is_punycode),
            float(vector.domain.is_reserved),
            float(vector.domain.is_localhost),
            float(vector.domain.is_private_ip),
            float(vector.domain.is_multicast_ip),
            float(vector.domain.is_loopback),
            float(vector.domain.is_shortener),
            float(vector.domain.is_suspicious_tld)
        ])
        
        # Suspicious (Convert lists to counts)
        numeric_list.extend([
            float(len(vector.suspicious.phishing_keywords)),
            float(len(vector.suspicious.banking_keywords)),
            float(len(vector.suspicious.crypto_keywords)),
            float(len(vector.suspicious.invoice_keywords)),
            float(len(vector.suspicious.login_keywords)),
            float(vector.suspicious.has_random_strings),
            float(vector.suspicious.has_base64_tokens),
            float(vector.suspicious.has_uuids),
            float(vector.suspicious.has_long_hashes),
            float(vector.suspicious.has_repeated_chars)
        ])
        
        vector.statistical.numeric_vector = numeric_list
