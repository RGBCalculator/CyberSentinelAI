"""
SSRF Protection & Safe Egress Utilities for CyberSentinel AI.

Treats all user-supplied URLs and domains as hostile input. Protects against:
- IPv4 and IPv6 loopback (127.0.0.0/8, ::1)
- Private and unique-local networks (RFC 1918, RFC 4193 fc00::/7)
- Link-local and cloud metadata endpoints (169.254.0.0/16, 169.254.169.254, fd00:ec2::254)
- IPv4-mapped IPv6 addresses (::ffff:127.0.0.1, ::ffff:169.254.169.254)
- Alternate IP representations (hex, octal, dword)
- Localhost aliases and internal suffixes (.local, .internal, .lan, .corp)
- Forbidden database/container/cloud ports (27017, 6379, 5432, 3306, etc.)
- Open redirect chains into private/prohibited destinations (re-validates every redirect)
- Oversized response attacks and decompression bombs (streamed limit)
"""

import ipaddress
import socket
import logging
import re
from typing import Tuple, Optional, List, Dict, Any
from urllib.parse import urlparse, urljoin
import requests

logger = logging.getLogger(__name__)

# Cloud provider instance metadata addresses & internal endpoints
CLOUD_METADATA_HOSTS = {
    "169.254.169.254",          # AWS, GCP, Azure, OpenStack IPv4 metadata
    "fd00:ec2::254",             # AWS IPv6 metadata
    "169.254.169.250",          # Tencent Cloud metadata
    "100.100.100.200",          # Alibaba Cloud metadata
    "metadata.google.internal",  # Google Cloud metadata DNS
    "instance-data",            # AWS legacy metadata alias
    "metadata.internal",        # Generic internal metadata
}

# Localhost and internal host aliases
LOCAL_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "0.0.0.0",
    "::1",
    "[::1]"
}

# Internal TLDs / suffixes that should not be queried externally
INTERNAL_TLDS = (
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".intranet",
    ".onion"
)

# Standard allowed protocols
ALLOWED_SCHEMES = {"http", "https"}

# High-risk internal ports that should never be scanned externally
BLOCKED_PORTS = {
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    53,     # DNS
    69,     # TFTP
    111,    # RPCBIND
    135,    # MSRPC
    139,    # NetBIOS
    445,    # SMB
    1433,   # MS SQL
    1521,   # Oracle
    2375,   # Docker unencrypted
    2376,   # Docker TLS
    3306,   # MySQL
    5000,   # Flask/Docker Registry
    5432,   # PostgreSQL
    6379,   # Redis
    8000,   # Internal backend API
    8086,   # InfluxDB
    9000,   # Portainer/MinIO
    9200,   # Elasticsearch HTTP
    9300,   # Elasticsearch transport
    11211,  # Memcached
    27017,  # MongoDB default
    27018,  # MongoDB shard
    28017   # MongoDB web status
}


def parse_numeric_ip(host: str) -> Optional[ipaddress.IPv4Address]:
    """
    Attempts to decode alternative representations of IPv4 addresses:
    - Decimal integer (Dword): e.g. 2130706433 -> 127.0.0.1
    - Hexadecimal: e.g. 0x7f000001 -> 127.0.0.1
    - Octal: e.g. 0177.0.0.1 -> 127.0.0.1
    """
    host_clean = host.strip().lower()
    
    # 1. Hex representation (e.g., 0x7f000001)
    if host_clean.startswith("0x") and len(host_clean) <= 10:
        try:
            val = int(host_clean, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # 2. Pure integer / Dword representation (e.g., 2130706433)
    if host_clean.isdigit():
        try:
            val = int(host_clean)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # 3. Octal dot components (e.g., 0177.0.0.1)
    if "." in host_clean:
        parts = host_clean.split(".")
        if len(parts) == 4:
            try:
                octets = []
                for p in parts:
                    if p.startswith("0x"):
                        octets.append(int(p, 16))
                    elif p.startswith("0") and len(p) > 1 and all(c in "01234567" for c in p):
                        octets.append(int(p, 8))
                    else:
                        octets.append(int(p, 10))
                if all(0 <= o <= 255 for o in octets):
                    return ipaddress.IPv4Address(".".join(str(o) for o in octets))
            except Exception:
                pass

    return None


def is_safe_target_for_network(target: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if a target host/IP/URL is safe for outbound network calls.
    Returns (True, None) if safe, or (False, reason) if prohibited.
    """
    if not target or not isinstance(target, str):
        return False, "Target is empty or invalid."

    target_clean = target.strip()

    # URL Scheme and Credentials check
    if "://" in target_clean:
        try:
            parsed = urlparse(target_clean)
        except Exception as e:
            return False, f"Malformed URL: {e}"

        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            return False, f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

        if parsed.username or parsed.password:
            return False, "URLs containing embedded user credentials are not permitted."

        # Port validation
        if parsed.port:
            if parsed.port in BLOCKED_PORTS:
                return False, f"Destination port '{parsed.port}' is an internal/restricted service port."
            if not (1 <= parsed.port <= 65535):
                return False, f"Port '{parsed.port}' is out of valid range."

        hostname = parsed.hostname or ""
    else:
        # Host:port or raw host
        host_part = target_clean.split("/")[0].strip()
        if ":" in host_part and not host_part.startswith("[") and host_part.count(":") == 1:
            h, p = host_part.split(":")
            try:
                port = int(p)
                if port in BLOCKED_PORTS:
                    return False, f"Destination port '{port}' is an internal/restricted service port."
            except ValueError:
                return False, "Malformed port in target."
            hostname = h
        else:
            hostname = host_part

    if not hostname:
        return False, "Target hostname is empty."

    cleaned_host = hostname.strip("[]").lower()

    # 1. Localhost names and aliases
    if cleaned_host in LOCAL_HOSTNAMES:
        return False, f"Localhost identifier '{cleaned_host}' is blocked for outbound security scans."

    # 2. Cloud metadata hosts
    if cleaned_host in CLOUD_METADATA_HOSTS:
        return False, f"Access to cloud metadata endpoint '{cleaned_host}' is blocked for security."

    # 3. Internal TLDs
    if any(cleaned_host.endswith(tld) for tld in INTERNAL_TLDS):
        return False, f"Internal/Private domain suffix in '{cleaned_host}' is blocked."

    # 4. Alternative numeric representations (Dword, Hex, Octal)
    numeric_ip = parse_numeric_ip(cleaned_host)
    if numeric_ip is not None:
        if (numeric_ip.is_loopback or numeric_ip.is_private or 
            numeric_ip.is_link_local or numeric_ip.is_reserved or 
            numeric_ip.is_unspecified or str(numeric_ip) in CLOUD_METADATA_HOSTS):
            return False, f"Numeric IP representation resolves to restricted address '{numeric_ip}'."

    # 5. Direct IP Address Validation
    try:
        ip = ipaddress.ip_address(cleaned_host)

        # Handle IPv4-mapped IPv6 (::ffff:127.0.0.1, etc.)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            mapped_ipv4 = ip.ipv4_mapped
            if (mapped_ipv4.is_loopback or mapped_ipv4.is_private or 
                mapped_ipv4.is_link_local or str(mapped_ipv4) in CLOUD_METADATA_HOSTS):
                return False, f"IPv4-mapped IPv6 address maps to restricted IP '{mapped_ipv4}'."

        if ip.is_loopback:
            return False, f"Loopback address '{ip}' is blocked for outbound security scans."
        if ip.is_private:
            return False, f"Private network address '{ip}' is blocked for outbound security scans."
        if ip.is_link_local:
            return False, f"Link-local address '{ip}' is blocked for outbound security scans."
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False, f"Reserved/unspecified address '{ip}' is blocked."
        if str(ip) in CLOUD_METADATA_HOSTS:
            return False, f"Cloud metadata IP '{ip}' is blocked."
        return True, None
    except ValueError:
        pass

    # 6. Hostname DNS Pre-Resolution Validation
    try:
        resolved_ips = socket.getaddrinfo(cleaned_host, None)
        for item in resolved_ips:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)

                # Check IPv4-mapped IPv6 in resolved addresses
                if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                    mapped_ipv4 = ip.ipv4_mapped
                    if (mapped_ipv4.is_loopback or mapped_ipv4.is_private or 
                        mapped_ipv4.is_link_local or str(mapped_ipv4) in CLOUD_METADATA_HOSTS):
                        return False, f"Hostname '{cleaned_host}' resolves to restricted mapped IP '{mapped_ipv4}'."

                if (ip.is_loopback or ip.is_private or ip.is_link_local or 
                    ip.is_reserved or ip.is_unspecified or str(ip) in CLOUD_METADATA_HOSTS):
                    return False, f"Hostname '{cleaned_host}' resolves to restricted internal IP '{ip_str}'."
            except ValueError:
                continue
    except socket.gaierror:
        # Non-resolving hostnames will be handled by application/DNS resolver
        pass
    except Exception as e:
        logger.debug("DNS resolution check failed for %s: %s", cleaned_host, e)

    return True, None


def safe_fetch_url(
    url: str,
    method: str = "GET",
    max_redirects: int = 3,
    max_bytes: int = 5_242_880,  # 5 MB max response size
    timeout: float = 8.0,
    headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Safely executes an outbound HTTP request with SSRF protection, strict redirect
    re-validation, max byte streaming, and error sanitization.

    Returns:
        Dict[str, Any] containing:
        - success (bool)
        - status_code (int or None)
        - content (bytes or None)
        - text (str or None)
        - headers (dict)
        - final_url (str)
        - redirect_count (int)
        - error (str or None)
    """
    current_url = url
    redirect_count = 0
    redirect_chain: List[str] = [url]
    custom_headers = {
        "User-Agent": "CyberSentinelAI-SecurityAudit/2.0 (+https://cybersentinel.local/bot)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    if headers:
        custom_headers.update(headers)

    while True:
        # 1. SSRF validation of current URL
        safe, reason = is_safe_target_for_network(current_url)
        if not safe:
            return {
                "success": False,
                "status_code": None,
                "content": None,
                "text": None,
                "headers": {},
                "final_url": current_url,
                "redirect_count": redirect_count,
                "redirect_chain": redirect_chain,
                "error": f"SSRF Protection blocked destination: {reason}"
            }

        try:
            # 2. Make outbound request without auto-following redirects
            resp = requests.request(
                method=method,
                url=current_url,
                headers=custom_headers,
                allow_redirects=False,
                timeout=timeout,
                stream=True
            )

            # 3. Handle Redirects safely
            if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                if redirect_count >= max_redirects:
                    resp.close()
                    return {
                        "success": False,
                        "status_code": resp.status_code,
                        "content": None,
                        "text": None,
                        "headers": dict(resp.headers),
                        "final_url": current_url,
                        "redirect_count": redirect_count,
                        "redirect_chain": redirect_chain,
                        "error": f"Exceeded maximum allowed redirects ({max_redirects})."
                    }

                location = resp.headers["Location"]
                resp.close()
                next_url = urljoin(current_url, location)
                redirect_count += 1
                redirect_chain.append(next_url)
                current_url = next_url
                continue

            # 4. Stream response body safely with size cap
            chunks = []
            total_bytes = 0
            for chunk in resp.iter_content(chunk_size=65536):
                chunks.append(chunk)
                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    resp.close()
                    return {
                        "success": False,
                        "status_code": resp.status_code,
                        "content": None,
                        "text": None,
                        "headers": dict(resp.headers),
                        "final_url": current_url,
                        "redirect_count": redirect_count,
                        "redirect_chain": redirect_chain,
                        "error": f"Response exceeded maximum allowed size of {max_bytes} bytes."
                    }

            resp.close()
            full_content = b"".join(chunks)
            try:
                encoding = resp.encoding or "utf-8"
                text_content = full_content.decode(encoding, errors="replace")
            except Exception:
                text_content = full_content.decode("utf-8", errors="replace")

            return {
                "success": True,
                "status_code": resp.status_code,
                "content": full_content,
                "text": text_content,
                "headers": dict(resp.headers),
                "final_url": current_url,
                "redirect_count": redirect_count,
                "redirect_chain": redirect_chain,
                "error": None
            }

        except requests.exceptions.Timeout:
            return {
                "success": False,
                "status_code": None,
                "content": None,
                "text": None,
                "headers": {},
                "final_url": current_url,
                "redirect_count": redirect_count,
                "redirect_chain": redirect_chain,
                "error": "Connection timed out during security check."
            }
        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "status_code": None,
                "content": None,
                "text": None,
                "headers": {},
                "final_url": current_url,
                "redirect_count": redirect_count,
                "redirect_chain": redirect_chain,
                "error": "Failed to connect to target host (connection refused or network unreachable)."
            }
        except Exception as e:
            logger.error("Unexpected error in safe_fetch_url: %s", e)
            return {
                "success": False,
                "status_code": None,
                "content": None,
                "text": None,
                "headers": {},
                "final_url": current_url,
                "redirect_count": redirect_count,
                "redirect_chain": redirect_chain,
                "error": "An internal error occurred during request inspection."
            }
