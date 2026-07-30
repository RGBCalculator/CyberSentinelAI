from pydantic import BaseModel, Field
from typing import List, Optional


class LexicalFeatures(BaseModel):
    url_length: int = 0
    host_length: int = 0
    domain_length: int = 0
    path_length: int = 0
    query_length: int = 0
    fragment_length: int = 0
    character_count: int = 0
    digit_ratio: float = 0.0
    letter_ratio: float = 0.0
    uppercase_ratio: float = 0.0
    lowercase_ratio: float = 0.0
    shannon_entropy: float = 0.0


class StructuralFeatures(BaseModel):
    is_https: bool = False
    uses_ip: bool = False
    is_ipv6: bool = False
    has_auth_section: bool = False
    port: Optional[int] = None
    is_non_standard_port: bool = False
    query_param_count: int = 0
    has_fragment: bool = False
    path_depth: int = 0
    has_trailing_slash: bool = False
    repeated_separators: bool = False
    has_encoded_chars: bool = False


class DomainFeatures(BaseModel):
    is_idn: bool = False
    is_punycode: bool = False
    tld: str = ""
    is_reserved: bool = False
    is_localhost: bool = False
    is_private_ip: bool = False
    is_multicast_ip: bool = False
    is_loopback: bool = False
    is_shortener: bool = False
    is_suspicious_tld: bool = False


class SuspiciousFeatures(BaseModel):
    phishing_keywords: List[str] = Field(default_factory=list)
    banking_keywords: List[str] = Field(default_factory=list)
    crypto_keywords: List[str] = Field(default_factory=list)
    invoice_keywords: List[str] = Field(default_factory=list)
    login_keywords: List[str] = Field(default_factory=list)
    has_random_strings: bool = False
    has_base64_tokens: bool = False
    has_uuids: bool = False
    has_long_hashes: bool = False
    has_repeated_chars: bool = False


class StatisticalFeatures(BaseModel):
    # This acts as a purely numerical mapping of all relevant features for direct ML inference
    numeric_vector: List[float] = Field(default_factory=list)


class MLFeatureVector(BaseModel):
    """
    Standardized payload aggregating all static analysis features.
    Designed to be directly consumed by downstream AI models and rule engines.
    """
    lexical: LexicalFeatures = Field(default_factory=LexicalFeatures)
    structural: StructuralFeatures = Field(default_factory=StructuralFeatures)
    domain: DomainFeatures = Field(default_factory=DomainFeatures)
    suspicious: SuspiciousFeatures = Field(default_factory=SuspiciousFeatures)
    statistical: StatisticalFeatures = Field(default_factory=StatisticalFeatures)
