import re
from typing import Any, Dict
from urllib.parse import ParseResult

from .base import BaseFeatureExtractor
from .ml_vector import MLFeatureVector


class SuspiciousPatternExtractor(BaseFeatureExtractor):
    """
    Detects obfuscation techniques, random strings, and specific keyword categories.
    """
    
    # Pre-compiled regexes
    UUID_REGEX = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
    B64_REGEX = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
    HASH_REGEX = re.compile(r'\b[0-9a-fA-F]{32,128}\b') # Matches MD5 up to SHA-512 hashes
    REPEATED_CHARS_REGEX = re.compile(r'(.)\1{4,}') # 5 or more repeated chars

    PHISHING_KWS = ["login", "signin", "auth", "credential", "verify", "update", "account", "security"]
    BANKING_KWS = ["bank", "paypal", "chase", "wells", "boa", "citi", "capitalone", "stripe"]
    CRYPTO_KWS = ["wallet", "crypto", "bitcoin", "ethereum", "btc", "eth", "exchange", "binance", "coinbase"]
    INVOICE_KWS = ["invoice", "billing", "receipt", "payment", "order", "tracking", "fedex", "dhl", "ups"]

    async def extract(
        self, 
        target_url: str, 
        parsed_url: ParseResult, 
        vector: MLFeatureVector, 
        context: Dict[str, Any]
    ) -> None:
        
        # Truncate string for regex evaluation if excessively long to prevent ReDoS
        eval_str = target_url.lower()
        if len(eval_str) > 2000:
            eval_str = eval_str[:2000]
            
        # Keyword mapping
        vector.suspicious.phishing_keywords = [kw for kw in self.PHISHING_KWS if kw in eval_str]
        vector.suspicious.banking_keywords = [kw for kw in self.BANKING_KWS if kw in eval_str]
        vector.suspicious.crypto_keywords = [kw for kw in self.CRYPTO_KWS if kw in eval_str]
        vector.suspicious.invoice_keywords = [kw for kw in self.INVOICE_KWS if kw in eval_str]
        
        # The prompt asked for "login_keywords" as well, which overlaps with phishing, but we can populate it:
        vector.suspicious.login_keywords = [kw for kw in ["login", "signin", "logon"] if kw in eval_str]
        
        # Regex scans
        vector.suspicious.has_uuids = bool(self.UUID_REGEX.search(target_url))
        vector.suspicious.has_base64_tokens = bool(self.B64_REGEX.search(target_url))
        vector.suspicious.has_long_hashes = bool(self.HASH_REGEX.search(target_url))
        vector.suspicious.has_repeated_chars = bool(self.REPEATED_CHARS_REGEX.search(target_url))
        
        # Random string heuristic (combining hash & base64 & high entropy from lexical context if we wanted)
        # For this standalone extractor, if it has long hashes or b64, we flag it as having random strings.
        vector.suspicious.has_random_strings = vector.suspicious.has_base64_tokens or vector.suspicious.has_long_hashes
