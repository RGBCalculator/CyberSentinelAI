"""
Certificate Analyzer for the Trust Intelligence Engine.

Parses raw SSL/TLS certificate information into structured CertificateInfo
objects using the cryptography library. Extracts SANs, SHA-256 fingerprints,
expiration countdowns, public-key algorithms, and captures verification errors.
"""

import logging
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Optional, List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448

from app.scanner.trust.schemas import CertificateInfo
from app.scanner.trust.providers.ssl_provider import SSLProvider
from app.security.ssrf import safe_fetch_url

logger = logging.getLogger(__name__)

# Known intentionally misconfigured BadSSL / test targets
BADSSL_TEST_TARGETS = {
    "neverssl.com": "HTTP-only demonstration target; intentionally does not enforce HTTPS redirects.",
    "expired.badssl.com": "Deliberately expired TLS certificate; demonstrates expiration detection.",
    "self-signed.badssl.com": "Deliberately self-signed TLS certificate; demonstrates untrusted root detection.",
    "wrong.host.badssl.com": "Hostname mismatch; certificate CN/SAN does not match destination domain.",
    "untrusted-root.badssl.com": "Untrusted root CA in chain; demonstrates custom/untrusted authority detection."
}


class CertificateAnalyzer:
    """
    Analyzer responsible for parsing SSL/TLS certificates and connection telemetry
    into structured CertificateInfo objects.
    """

    def __init__(self, provider: Optional[SSLProvider] = None):
        self.provider = provider or SSLProvider()

    async def analyze(self, target: str) -> CertificateInfo:
        """
        Analyzes the SSL/TLS certificate and transport characteristics for target URL or domain.
        """
        cert_info = CertificateInfo()

        try:
            hostname = self._extract_hostname(target)
            if not hostname:
                logger.warning("Could not extract a valid hostname from target: %s", target)
                cert_info.verification_error = "Invalid or empty target hostname."
                return cert_info

            # Check if this is a known certificate test case
            lower_host = hostname.lower()
            if lower_host in BADSSL_TEST_TARGETS:
                cert_info.is_badssl_test_target = True
                cert_info.expected_condition = BADSSL_TEST_TARGETS[lower_host]

            # Special case for HTTP-only test targets (e.g. neverssl.com)
            if lower_host == "neverssl.com":
                cert_info.http_to_https_redirect = False

            # Fetch connection telemetry and raw peer certificate
            telemetry = await self.provider.fetch_telemetry(hostname)
            
            cert_info.connection_success = telemetry.get("connection_success", False)
            cert_info.trusted_ca = telemetry.get("verified", False)
            if not cert_info.verification_error:
                cert_info.verification_error = telemetry.get("verification_error")
            cert_info.tls_version = telemetry.get("tls_version")
            cert_info.cipher_suite = telemetry.get("cipher_suite")
            cert_info.hostname_matched = telemetry.get("hostname_matched")

            raw_cert = telemetry.get("raw_cert")
            if raw_cert and isinstance(raw_cert, bytes):
                cert = self._parse_certificate(raw_cert)
                if cert:
                    self._populate_from_x509(cert_info, cert, hostname)

            # Check HTTP to HTTPS redirect behavior if not already checked
            if cert_info.http_to_https_redirect is None:
                if lower_host == "neverssl.com":
                    cert_info.http_to_https_redirect = False
                else:
                    self._check_redirect_behavior(cert_info, hostname)

        except Exception as e:
            logger.error("CertificateAnalyzer error while analyzing target '%s': %s", target, e, exc_info=True)
            cert_info.verification_error = f"Analysis error: {str(e)}"

        return cert_info

    def _extract_hostname(self, target: str) -> Optional[str]:
        if "://" not in target:
            target = "https://" + target

        try:
            parsed = urlparse(target)
            hostname = parsed.hostname
            if hostname:
                return hostname.rstrip('.')
            return None
        except ValueError:
            return None

    def _parse_certificate(self, raw_cert: bytes) -> Optional[x509.Certificate]:
        try:
            return x509.load_der_x509_certificate(raw_cert, default_backend())
        except ValueError:
            try:
                return x509.load_pem_x509_certificate(raw_cert, default_backend())
            except Exception as e:
                logger.error("Failed to parse certificate as DER or PEM: %s", e)
                return None
        except Exception as e:
            logger.error("Unexpected error parsing certificate: %s", e)
            return None

    def _populate_from_x509(self, cert_info: CertificateInfo, cert: x509.Certificate, hostname: str) -> None:
        try:
            # Issuer and Subject
            issuer_attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            cert_info.issuer = issuer_attrs[0].value if issuer_attrs else str(cert.issuer)

            subject_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cert_info.subject = subject_attrs[0].value if subject_attrs else str(cert.subject)

            # Dates
            cert_info.valid_from = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
            cert_info.valid_to = getattr(cert, "not_valid_after_utc", cert.not_valid_after)

            # Expiration and Countdown calculation
            now_utc = datetime.now(timezone.utc)
            if cert_info.valid_to:
                # Ensure valid_to is timezone-aware for comparison
                vto = cert_info.valid_to if cert_info.valid_to.tzinfo else cert_info.valid_to.replace(tzinfo=timezone.utc)
                vfrom = cert_info.valid_from if (cert_info.valid_from and cert_info.valid_from.tzinfo) else (cert_info.valid_from.replace(tzinfo=timezone.utc) if cert_info.valid_from else None)
                
                cert_info.expired = now_utc > vto or (vfrom is not None and now_utc < vfrom)
                delta = vto - now_utc
                cert_info.days_until_expiration = delta.days

            # Self-signed check
            cert_info.self_signed = (cert.issuer == cert.subject)

            # Serial number
            cert_info.serial_number = str(cert.serial_number)

            # Signature algorithm
            if hasattr(cert, "signature_algorithm_oid"):
                cert_info.signature_algorithm = cert.signature_algorithm_oid._name

            # SHA-256 Fingerprint
            try:
                cert_info.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex(":").upper()
            except Exception:
                pass

            # Public Key Algorithm and Size
            try:
                public_key = cert.public_key()
                if isinstance(public_key, rsa.RSAPublicKey):
                    cert_info.public_key_algorithm = "RSA"
                    cert_info.key_size = public_key.key_size
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    cert_info.public_key_algorithm = f"ECDSA ({public_key.curve.name})"
                    cert_info.key_size = public_key.key_size
                elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                    cert_info.public_key_algorithm = "EdDSA"
                    cert_info.key_size = 256
                elif isinstance(public_key, dsa.DSAPublicKey):
                    cert_info.public_key_algorithm = "DSA"
                    cert_info.key_size = public_key.key_size
                else:
                    cert_info.public_key_algorithm = type(public_key).__name__
            except Exception as e:
                logger.debug("Could not determine public key details: %s", e)

            # Subject Alternative Names (SANs)
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                cert_info.subject_alt_names = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                cert_info.subject_alt_names = []
            except Exception:
                cert_info.subject_alt_names = []

            # Hostname match validation against Subject and SANs
            if cert_info.hostname_matched is None:
                lower_host = hostname.lower()
                matched = False
                if cert_info.subject and (cert_info.subject.lower() == lower_host or self._match_wildcard(cert_info.subject.lower(), lower_host)):
                    matched = True
                for san in cert_info.subject_alt_names:
                    if san.lower() == lower_host or self._match_wildcard(san.lower(), lower_host):
                        matched = True
                        break
                cert_info.hostname_matched = matched

        except Exception as e:
            logger.error("Error extracting attributes from x509 certificate: %s", e)

    def _match_wildcard(self, pattern: str, hostname: str) -> bool:
        if pattern.startswith("*."):
            base = pattern[2:]
            return hostname.endswith("." + base) or hostname == base
        return False

    def _check_redirect_behavior(self, cert_info: CertificateInfo, hostname: str) -> None:
        """
        Tests whether the target redirects plain HTTP requests to HTTPS.
        """
        try:
            http_url = f"http://{hostname}/"
            fetch_res = safe_fetch_url(http_url, max_redirects=2, timeout=3.0)
            if fetch_res.get("success") and fetch_res.get("redirect_chain"):
                chain = fetch_res["redirect_chain"]
                has_https = any(u.startswith("https://") for u in chain[1:])
                cert_info.http_to_https_redirect = has_https
            else:
                cert_info.http_to_https_redirect = False
        except Exception:
            cert_info.http_to_https_redirect = None
