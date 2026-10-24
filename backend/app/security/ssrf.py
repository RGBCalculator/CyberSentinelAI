"""
SSRF Protection Utilities for CyberSentinel AI.

Prevents Server-Side Request Forgery by validating target hosts and IP addresses
against loopback, private, link-local, multicast, and cloud metadata addresses (169.254.169.254).
"""

import ipaddress
import socket
import logging
from typing import Tuple, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

CLOUD_METADATA_IPS = {
    "169.254.169.254",    # AWS, GCP, Azure, OpenStack instance metadata
    "fd00:ec2::254",       # AWS IPv6 metadata
    "metadata.google.internal"
}


def is_safe_target_for_network(target: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if a target host/IP is safe for outbound network calls.
    Returns (True, None) if safe, or (False, reason) if dangerous.
    """
    if "://" in target:
        try:
            parsed = urlparse(target)
            hostname = parsed.hostname or ""
        except Exception as e:
            return False, f"Invalid URL target: {e}"
    else:
        hostname = target.split(":")[0].strip()

    if not hostname:
        return False, "Target hostname is empty."

    cleaned_host = hostname.strip("[]").lower()

    if cleaned_host in CLOUD_METADATA_IPS:
        return False, f"Access to cloud metadata endpoint '{cleaned_host}' is blocked for security."

    # Direct IP validation
    try:
        ip = ipaddress.ip_address(cleaned_host)
        if ip.is_loopback:
            return False, f"Loopback address '{ip}' is blocked for outbound security scans."
        if ip.is_private:
            return False, f"Private network address '{ip}' is blocked for outbound security scans."
        if ip.is_link_local:
            return False, f"Link-local address '{ip}' is blocked for outbound security scans."
        if ip.is_multicast or ip.is_reserved:
            return False, f"Reserved/multicast address '{ip}' is blocked."
        return True, None
    except ValueError:
        pass

    # Hostname DNS resolution check
    try:
        resolved_ips = socket.getaddrinfo(cleaned_host, None)
        for item in resolved_ips:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or str(ip) in CLOUD_METADATA_IPS:
                    return False, f"Hostname '{cleaned_host}' resolves to restricted internal IP '{ip_str}'."
            except ValueError:
                continue
    except socket.gaierror:
        # If hostname cannot be resolved, safe to let DNS provider handle NXDOMAIN
        pass
    except Exception as e:
        logger.debug("DNS resolution check failed for %s: %s", cleaned_host, e)

    return True, None
