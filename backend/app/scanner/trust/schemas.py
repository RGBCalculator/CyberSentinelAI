"""
Data models for the Trust Intelligence Engine.

This module contains Pydantic schemas representing the structured data
used for trust evaluation, including certificate, domain, DNS, and reputation information.
"""

from enum import Enum
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class TrustLevel(str, Enum):
    """
    Enumeration representing the calculated trust level of an entity.
    """
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"


class CertificateInfo(BaseModel):
    """
    Schema containing details about an SSL/TLS certificate.
    """
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    expired: bool = False
    self_signed: bool = False
    trusted_ca: bool = False
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    key_size: Optional[int] = None


class DomainInfo(BaseModel):
    """
    Schema representing WHOIS and related domain registration details.
    """
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    privacy_protected: bool = False
    country: Optional[str] = None


class DNSInfo(BaseModel):
    """
    Schema representing DNS record details for a domain.
    """
    a_records: List[str] = Field(default_factory=list)
    aaaa_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    cname: Optional[str] = None
    dnssec_enabled: bool = False


class ReputationInfo(BaseModel):
    """
    Schema representing third-party reputation data for an entity.
    """
    score: float = 50.0
    blacklisted: bool = False
    provider: Optional[str] = None
    reason: Optional[str] = None


class TrustResult(BaseModel):
    """
    Aggregate schema containing the final trust evaluation results.
    Combines all trust signals (certificate, domain, DNS, reputation) 
    along with the final calculated scores and reasons.
    """
    certificate: CertificateInfo = Field(default_factory=CertificateInfo)
    domain: DomainInfo = Field(default_factory=DomainInfo)
    dns: DNSInfo = Field(default_factory=DNSInfo)
    reputation: ReputationInfo = Field(default_factory=ReputationInfo)
    trust_score: float = 50.0
    trust_level: TrustLevel = TrustLevel.MEDIUM
    reasons: List[str] = Field(default_factory=list)
