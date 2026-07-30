"""
DNS Analyzer for the Trust Intelligence Engine.

This module provides the DNSAnalyzer, which parses raw DNS data 
from the DNSProvider into a structured DNSInfo object.
"""

import logging
from urllib.parse import urlparse
from typing import Optional, Dict, List, Any

from app.scanner.trust.schemas import DNSInfo
from app.scanner.trust.providers.dns_provider import DNSProvider

logger = logging.getLogger(__name__)


class DNSAnalyzer:
    """
    Analyzer responsible for transforming raw DNS data into a structured
    DNSInfo object, and performing logic to extract trust signals like SPF/DMARC.
    """

    def __init__(self, provider: Optional[DNSProvider] = None):
        """
        Initializes the DNSAnalyzer.

        Args:
            provider (DNSProvider, optional): Provider for fetching DNS data.
                                              Defaults to a new DNSProvider instance.
        """
        self.provider = provider or DNSProvider()

    async def analyze(self, target: str) -> DNSInfo:
        """
        Analyzes DNS information for a given target URL or domain.

        Args:
            target (str): The target URL or domain to analyze.

        Returns:
            DNSInfo: An object populated with the DNS details and computed signals, 
                     or an empty DNSInfo on failure.
        """
        dns_info = DNSInfo()

        try:
            hostname = self._extract_hostname(target)
            if not hostname:
                logger.warning("Could not extract a valid hostname from target: %s", target)
                return dns_info

            # Retrieve raw DNS data
            raw_dns = await self.provider.fetch_dns(hostname)
            if not raw_dns:
                logger.warning("No DNS data returned for hostname: %s", hostname)
                return dns_info

            self._populate_dns_info(dns_info, raw_dns)
            self._compute_signals(dns_info)

        except Exception as e:
            logger.error(
                "DNSAnalyzer encountered an error while analyzing target '%s': %s",
                target,
                e,
                exc_info=True
            )

        return dns_info

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

    def _strip_quotes(self, record: str) -> str:
        """
        Strips surrounding quotes from a DNS record string.
        """
        record = record.strip()
        if record.startswith('"') and record.endswith('"'):
            return record[1:-1]
        if record.startswith("'") and record.endswith("'"):
            return record[1:-1]
        return record

    def _populate_dns_info(self, dns_info: DNSInfo, raw_dns: Dict[str, List[str]]) -> None:
        """
        Populates the base DNSInfo lists from the raw DNS results.
        """
        dns_info.a_records = raw_dns.get("A", [])
        dns_info.aaaa_records = raw_dns.get("AAAA", [])
        dns_info.mx_records = raw_dns.get("MX", [])
        dns_info.ns_records = raw_dns.get("NS", [])
        
        # Process TXT records to strip quotes
        raw_txt = raw_dns.get("TXT", [])
        dns_info.txt_records = [self._strip_quotes(txt) for txt in raw_txt]

    def _compute_signals(self, dns_info: DNSInfo) -> None:
        """
        Computes business logic trust signals and sets them dynamically.
        """
        # Determine boolean flags
        has_mx = len(dns_info.mx_records) > 0
        
        has_spf = False
        has_dmarc = False
        has_dkim = False
        
        for txt in dns_info.txt_records:
            txt_lower = txt.lower().strip()
            if txt_lower.startswith("v=spf1"):
                has_spf = True
            if txt_lower.startswith("v=dmarc1"):
                has_dmarc = True
            if txt_lower.startswith("v=dkim1"):
                has_dkim = True
                
        self._safe_set(dns_info, "has_mx", has_mx)
        self._safe_set(dns_info, "has_spf", has_spf)
        self._safe_set(dns_info, "has_dmarc", has_dmarc)
        self._safe_set(dns_info, "has_dkim", has_dkim)
        
        # Compute record counts
        self._safe_set(dns_info, "a_record_count", len(dns_info.a_records))
        self._safe_set(dns_info, "aaaa_record_count", len(dns_info.aaaa_records))
        self._safe_set(dns_info, "mx_record_count", len(dns_info.mx_records))
        self._safe_set(dns_info, "ns_record_count", len(dns_info.ns_records))
        self._safe_set(dns_info, "txt_record_count", len(dns_info.txt_records))

    def _safe_set(self, model: DNSInfo, field: str, value: Any) -> None:
        """
        Safely sets an attribute on a Pydantic model.
        Catches ValueError which is raised by Pydantic v2 when attempting 
        to set a field that is not defined in the schema.
        """
        if value is None:
            return
            
        try:
            setattr(model, field, value)
        except ValueError:
            logger.debug("Field '%s' is not defined in DNSInfo schema, skipping.", field)
        except Exception as e:
            logger.warning("Failed to set field '%s' on DNSInfo: %s", field, e)
