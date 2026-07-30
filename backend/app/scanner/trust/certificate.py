"""
Certificate Analyzer for the Trust Intelligence Engine.

This module provides the CertificateAnalyzer, which retrieves and parses
SSL/TLS certificate information for a given target using an external provider.
"""

import logging
from urllib.parse import urlparse
from typing import Optional

from app.scanner.trust.schemas import CertificateInfo

# Attempt to import the SSLProvider. If it does not exist, we will define a
# stub interface to be implemented later.
try:
    from app.scanner.trust.providers.ssl_provider import SSLProvider
except ImportError:
    class SSLProvider:
        """
        TODO: Implement SSLProvider in app.scanner.trust.providers.ssl_provider.
        
        This is a temporary interface/stub. The actual implementation should handle 
        socket connections and SSL/TLS certificate retrieval.
        """
        def __init__(self):
            pass

        async def fetch_certificate(self, hostname: str) -> dict:
            """
            TODO: Fetch certificate details over the network.
            
            Args:
                hostname (str): The domain name to query.
                
            Returns:
                dict: A dictionary containing certificate properties such as
                      issuer, subject, valid_from, valid_to, expired, self_signed,
                      trusted_ca, serial_number, signature_algorithm, and key_size.
            """
            # Raise NotImplementedError to simulate failure if used before implementation
            raise NotImplementedError("SSLProvider is not yet implemented.")


logger = logging.getLogger(__name__)


class CertificateAnalyzer:
    """
    Analyzer responsible for SSL/TLS certificate inspection.
    Delegates network communication to an injected or instantiated SSLProvider.
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

            # Delegate networking to the SSL provider
            cert_data = await self.provider.fetch_certificate(hostname)
            if not cert_data:
                logger.warning("No certificate data returned for hostname: %s", hostname)
                return cert_info

            # Map the provider data to the CertificateInfo schema
            cert_info.issuer = cert_data.get("issuer")
            cert_info.subject = cert_data.get("subject")
            cert_info.valid_from = cert_data.get("valid_from")
            cert_info.valid_to = cert_data.get("valid_to")
            cert_info.expired = bool(cert_data.get("expired", False))
            cert_info.self_signed = bool(cert_data.get("self_signed", False))
            cert_info.trusted_ca = bool(cert_data.get("trusted_ca", False))
            cert_info.serial_number = cert_data.get("serial_number")
            cert_info.signature_algorithm = cert_data.get("signature_algorithm")
            
            # Key size can sometimes be parsed as a string, ensure it is int if present
            key_size = cert_data.get("key_size")
            if key_size is not None:
                try:
                    cert_info.key_size = int(key_size)
                except ValueError:
                    logger.warning("Invalid key_size value retrieved: %s", key_size)

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

        Args:
            target (str): The URL or domain name.

        Returns:
            Optional[str]: The extracted hostname, or None if extraction fails.
        """
        # If the target doesn't have a scheme, urlparse might parse it incorrectly
        # We prepend a dummy scheme to ensure correct parsing if missing.
        if "://" not in target:
            target = "https://" + target

        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            if hostname:
                # Remove any trailing dot from the hostname (FQDN edge case)
                return hostname.rstrip('.')
            return None
        except ValueError as e:
            logger.debug("Failed to parse hostname from target '%s': %s", target, e)
            return None
