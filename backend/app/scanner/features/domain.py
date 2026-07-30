import ipaddress
from typing import Any, Dict
from urllib.parse import ParseResult

from .base import BaseFeatureExtractor
from .ml_vector import MLFeatureVector

SHORTENER_DOMAINS = [
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "is.gd", "cli.gs",
    "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac",
    "su.pr", "twurl.nl", "snipurl.com", "short.to", "budurl.com", "ping.fm"
]

SUSPICIOUS_TLDS = [
    ".zip", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".pw", ".cc", ".club"
]


class DomainExtractor(BaseFeatureExtractor):
    """
    Analyzes the hostname/domain properties.
    """

    def _split_tld(self, host: str) -> str:
        """Basic heuristic to extract the TLD offline."""
        parts = host.split(".")
        if len(parts) >= 2:
            # Simple check for ccTLDs (e.g., co.uk)
            if len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
                return f".{parts[-2]}.{parts[-1]}"
            return f".{parts[-1]}"
        return ""

    async def extract(
        self, 
        target_url: str, 
        parsed_url: ParseResult, 
        vector: MLFeatureVector, 
        context: Dict[str, Any]
    ) -> None:
        
        host = parsed_url.hostname or ""
        host_clean = host.strip("[]").lower()
        
        # IP vs Domain checks
        try:
            ip = ipaddress.ip_address(host_clean)
            vector.domain.is_private_ip = ip.is_private
            vector.domain.is_multicast_ip = ip.is_multicast
            vector.domain.is_loopback = ip.is_loopback
            vector.domain.is_localhost = host_clean == "127.0.0.1" or host_clean == "::1"
            vector.domain.is_reserved = ip.is_reserved
        except ValueError:
            # It's a domain
            vector.domain.is_localhost = host_clean == "localhost"
            
            # Check IDN / Punycode
            if host_clean.startswith("xn--") or "xn--" in host_clean:
                vector.domain.is_punycode = True
            
            try:
                # If encoding to idna results in a different string, it contains international chars
                if host_clean.encode("ascii") != host_clean.encode("idna"):
                    pass # Not purely ascii, but we already handled punycode check above. Wait, if it's raw unicode:
            except UnicodeEncodeError:
                vector.domain.is_idn = True
                
            # Shorteners
            for short in SHORTENER_DOMAINS:
                if short in host_clean:
                    vector.domain.is_shortener = True
                    break
                    
            # TLD parsing
            tld = self._split_tld(host_clean)
            vector.domain.tld = tld
            
            if tld in SUSPICIOUS_TLDS:
                vector.domain.is_suspicious_tld = True
