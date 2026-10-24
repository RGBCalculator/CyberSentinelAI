"""
SSL Provider for the Trust Intelligence Engine.

Responsible for network communication to retrieve raw SSL/TLS certificate
information, negotiated cipher suites, protocol versions, and verification
telemetry from target hosts.

Handles intentionally misconfigured certificates (expired, self-signed,
hostname mismatch, untrusted root) by capturing the exact verification failure,
then securely falling back to unverified peer-cert retrieval so the actual
x509 parameters can still be inspected.
"""

import asyncio
import logging
import ssl
import socket
from typing import Optional, Dict, Any, Tuple

logger = logging.getLogger(__name__)


class SSLProvider:
    """
    Provider class to fetch SSL/TLS certificate details over the network.
    Designed to be robust, inspectable, and safely handle certificate verification errors.
    """

    def __init__(self, timeout: float = 6.0):
        """
        Initializes the SSLProvider.

        Args:
            timeout (float): Connection timeout in seconds.
        """
        self.timeout = timeout

    async def fetch_certificate(self, hostname: str, port: int = 443) -> Optional[bytes]:
        """
        Retrieves raw peer certificate DER bytes. Backwards-compatible interface.
        """
        telemetry = await self.fetch_telemetry(hostname, port)
        return telemetry.get("raw_cert")

    async def fetch_telemetry(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Establishes a secure connection to the specified host and retrieves
        its SSL/TLS peer certificate, TLS version, cipher suite, and verification status.

        Returns:
            Dict[str, Any] with keys:
            - raw_cert: Optional[bytes]
            - connection_success: bool
            - verified: bool
            - verification_error: Optional[str]
            - tls_version: Optional[str]
            - cipher_suite: Optional[str]
            - hostname_matched: Optional[bool]
        """
        clean_host = hostname.strip().rstrip('.')
        result: Dict[str, Any] = {
            "raw_cert": None,
            "connection_success": False,
            "verified": False,
            "verification_error": None,
            "tls_version": None,
            "cipher_suite": None,
            "hostname_matched": None
        }

        # Step 1: Attempt standard verified handshake
        verified_context = ssl.create_default_context()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    clean_host,
                    port,
                    ssl=verified_context,
                    server_hostname=clean_host
                ),
                timeout=self.timeout
            )
            try:
                ssl_object = writer.get_extra_info('ssl_object')
                if ssl_object:
                    result["raw_cert"] = ssl_object.getpeercert(binary_form=True)
                    result["connection_success"] = True
                    result["verified"] = True
                    result["hostname_matched"] = True
                    result["tls_version"] = ssl_object.version()
                    cipher_info = ssl_object.cipher()
                    result["cipher_suite"] = cipher_info[0] if cipher_info else None
                    return result
            finally:
                writer.close()
                await writer.wait_closed()

        except ssl.SSLCertVerificationError as e:
            # Verification failed (e.g., expired.badssl.com, self-signed.badssl.com, wrong.host.badssl.com)
            verify_msg = getattr(e, "verify_message", str(e))
            result["verified"] = False
            result["hostname_matched"] = False if "hostname" in str(e).lower() else True
            result["verification_error"] = f"TLS Verification Failed: {verify_msg}"
            logger.info("SSL verification failed for %s:%d: %s. Falling back to unverified peer-cert retrieval.", clean_host, port, verify_msg)

        except (ssl.SSLError, OSError, asyncio.TimeoutError) as e:
            # Could be SSL protocol error, connection refused, or timeout
            logger.debug("Initial verified connection failed for %s:%d: %s", clean_host, port, e)
            result["verification_error"] = str(e)

        # Step 2: Fallback to unverified context to extract the peer certificate
        unverified_context = ssl._create_unverified_context()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    clean_host,
                    port,
                    ssl=unverified_context,
                    server_hostname=clean_host
                ),
                timeout=self.timeout
            )
            try:
                ssl_object = writer.get_extra_info('ssl_object')
                if ssl_object:
                    result["raw_cert"] = ssl_object.getpeercert(binary_form=True)
                    result["connection_success"] = True
                    result["tls_version"] = ssl_object.version()
                    cipher_info = ssl_object.cipher()
                    result["cipher_suite"] = cipher_info[0] if cipher_info else None
                    if not result["verification_error"]:
                        result["verification_error"] = "Certificate verification failed (untrusted chain or self-signed)."
                    return result
            finally:
                writer.close()
                await writer.wait_closed()

        except asyncio.TimeoutError:
            result["connection_success"] = False
            result["verification_error"] = f"Connection to {clean_host}:{port} timed out after {self.timeout}s."
        except OSError as e:
            result["connection_success"] = False
            result["verification_error"] = f"Connection refused on port {port} (host may be HTTP-only or offline)."
        except Exception as e:
            result["connection_success"] = False
            result["verification_error"] = f"TLS handshake error: {str(e)}"

        return result
