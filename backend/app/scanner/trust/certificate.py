"""
Certificate Analyzer for the Trust Intelligence Engine.

This module provides the CertificateAnalyzer, which retrieves raw SSL/TLS 
certificate information from an external provider and parses it into a 
structured CertificateInfo object using the cryptography library.
"""

import logging
from urllib.parse import urlparse
from datetime import datetime
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from app.scanner.trust.schemas import CertificateInfo
from app.scanner.trust.providers.ssl_provider import SSLProvider

logger = logging.getLogger(__name__)


class CertificateAnalyzer:
    """
    Analyzer responsible for parsing raw SSL/TLS certificate data into structured
    CertificateInfo objects. Delegates networking to SSLProvider.
    """

    def __init__(self, provider: Optional[SSLProvider] = None):
        """
        Initializes the CertificateAnalyzer.

        Args:
            provider (SSLProvider, optional): Provider for fetching SSL certificates.
                                              Defaults to a new SSLProvider instance.
        """
        self.provider = provider or SSLProvider()

    async def analyze(self, target: str) -> CertificateInfo:
        """
        Analyzes the SSL/TLS certificate for a given target URL or domain.

        Args:
            target (str): The target URL or domain to analyze.

        Returns:
            CertificateInfo: An object populated with the certificate details, or an
                             empty CertificateInfo on failure.
        """
        cert_info = CertificateInfo()

        try:
            hostname = self._extract_hostname(target)
            if not hostname:
                logger.warning("Could not extract a valid hostname from target: %s", target)
                return cert_info

            # Retrieve raw certificate data
            raw_cert = await self.provider.fetch_certificate(hostname)
            if not raw_cert:
                logger.warning("No certificate data returned for hostname: %s", hostname)
                return cert_info

            # Ensure we have bytes to parse with cryptography
            if not isinstance(raw_cert, bytes):
                logger.error("Expected raw certificate bytes, got %s", type(raw_cert))
                return cert_info

            # Parse the certificate using cryptography
            cert = self._parse_certificate(raw_cert)
            if not cert:
                return cert_info

            # Populate CertificateInfo
            self._populate_from_x509(cert_info, cert)

        except Exception as e:
            logger.error(
                "CertificateAnalyzer encountered an error while analyzing target '%s': %s",
                target,
                e,
                exc_info=True
            )

        return cert_info

    def _extract_hostname(self, target: str) -> Optional[str]:
        """
        Extracts the hostname from a given URL or domain string.
        """
        if "://" not in target:
            target = "https://" + target

        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            if hostname:
                return hostname.rstrip('.')
            return None
        except ValueError as e:
            logger.debug("Failed to parse hostname from target '%s': %s", target, e)
            return None

    def _parse_certificate(self, raw_cert: bytes) -> Optional[x509.Certificate]:
        """
        Parses raw certificate bytes using the cryptography library.
        """
        try:
            # Try parsing as DER
            return x509.load_der_x509_certificate(raw_cert, default_backend())
        except ValueError:
            try:
                # Try parsing as PEM
                return x509.load_pem_x509_certificate(raw_cert, default_backend())
            except ValueError as e:
                logger.error("Failed to parse certificate bytes as DER or PEM: %s", e)
                return None
        except Exception as e:
            logger.error("Unexpected error parsing certificate: %s", e)
            return None

    def _populate_from_x509(self, cert_info: CertificateInfo, cert: x509.Certificate) -> None:
        """
        Populates CertificateInfo using a parsed cryptography x509 Certificate.
        """
        try:
            # Issuer and Subject
            issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            cert_info.issuer = issuer_attrs[0].value if issuer_attrs else str(cert.issuer)
                
            subject_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cert_info.subject = subject_attrs[0].value if subject_attrs else str(cert.subject)

            # Dates (handling naive and aware datetimes based on cryptography version)
            cert_info.valid_from = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
            cert_info.valid_to = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
            
            # Status flags
            now = datetime.utcnow()
            if cert_info.valid_to and cert_info.valid_to.tzinfo:
                now = datetime.now(cert_info.valid_to.tzinfo)
                
            if cert_info.valid_to and cert_info.valid_from:
                cert_info.expired = now > cert_info.valid_to or now < cert_info.valid_from
                
            cert_info.self_signed = cert.issuer == cert.subject
            
            # Trusted CA defaults to False as it requires a local trust store validation
            cert_info.trusted_ca = False

            # Other attributes
            cert_info.serial_number = str(cert.serial_number)
            
            if hasattr(cert, "signature_algorithm_oid"):
                cert_info.signature_algorithm = cert.signature_algorithm_oid._name
            
            # Key size
            public_key = cert.public_key()
            if hasattr(public_key, "key_size"):
                cert_info.key_size = public_key.key_size

        except Exception as e:
            logger.error("Error extracting attributes from x509 certificate: %s", e)
