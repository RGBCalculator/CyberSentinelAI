import urllib.parse
from typing import Any, Dict
from urllib.parse import ParseResult
import ipaddress

from .base import BaseFeatureExtractor
from .ml_vector import MLFeatureVector


class StructuralExtractor(BaseFeatureExtractor):
    """
    Extracts structural elements like ports, parameters, path depths, and protocol properties.
    """

    async def extract(
        self, 
        target_url: str, 
        parsed_url: ParseResult, 
        vector: MLFeatureVector, 
        context: Dict[str, Any]
    ) -> None:
        
        host = parsed_url.hostname or ""
        
        # Scheme checks
        vector.structural.is_https = parsed_url.scheme.lower() == "https"
        
        # IP checks
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            vector.structural.uses_ip = True
            vector.structural.is_ipv6 = ip.version == 6
        except ValueError:
            pass

        # Auth section
        vector.structural.has_auth_section = bool(parsed_url.username or parsed_url.password)
        
        # Ports
        port = parsed_url.port
        vector.structural.port = port
        if port is not None:
            if (parsed_url.scheme == "http" and port != 80) or \
               (parsed_url.scheme == "https" and port != 443):
                vector.structural.is_non_standard_port = True
                
        # Parameters
        query_params = urllib.parse.parse_qs(parsed_url.query)
        vector.structural.query_param_count = len(query_params)
        
        # Fragments
        vector.structural.has_fragment = bool(parsed_url.fragment)
        
        # Path Depth
        if parsed_url.path:
            # e.g., /a/b/c -> ['a', 'b', 'c']
            depth = len([p for p in parsed_url.path.split("/") if p])
            vector.structural.path_depth = depth
            vector.structural.has_trailing_slash = parsed_url.path.endswith("/") and parsed_url.path != "/"
        
        # Repeated separators in path (e.g., http://example.com/a//b)
        vector.structural.repeated_separators = "//" in parsed_url.path
        
        # Encoded characters in URL (basic check for %XX)
        vector.structural.has_encoded_chars = "%" in target_url
