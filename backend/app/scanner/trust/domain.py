"""
Domain Analyzer for the Trust Intelligence Engine.

This module provides the DomainAnalyzer, which parses raw WHOIS data 
from the WHOISProvider into a structured DomainInfo object.
"""

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional, Any

from app.scanner.trust.schemas import DomainInfo
from app.scanner.trust.providers.whois_provider import WHOISProvider

logger = logging.getLogger(__name__)


class DomainAnalyzer:
    """
    Analyzer responsible for transforming raw WHOIS data into a structured
    DomainInfo object.
    """

    def __init__(self, provider: Optional[WHOISProvider] = None):
        """
        Initializes the DomainAnalyzer.

        Args:
            provider (WHOISProvider, optional): Provider for fetching WHOIS data.
                                                Defaults to a new WHOISProvider instance.
        """
        self.provider = provider or WHOISProvider()

    async def analyze(self, target: str) -> DomainInfo:
        """
        Analyzes WHOIS information for a given target URL or domain.

        Args:
            target (str): The target URL or domain to analyze.

        Returns:
            DomainInfo: An object populated with the domain details, or an
                        empty DomainInfo on failure.
        """
        domain_info = DomainInfo()

        try:
            hostname = self._extract_hostname(target)
            if not hostname:
                logger.warning("Could not extract a valid hostname from target: %s", target)
                return domain_info

            # Retrieve raw WHOIS data
            raw_whois = await self.provider.fetch_whois(hostname)
            if not raw_whois:
                logger.warning("No WHOIS data returned for hostname: %s", hostname)
                return domain_info

            self._populate_domain_info(domain_info, raw_whois)

        except Exception as e:
            logger.error(
                "DomainAnalyzer encountered an error while analyzing target '%s': %s",
                target,
                e,
                exc_info=True
            )

        return domain_info

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

    def _get_first_valid(self, value: Any) -> Any:
        """
        Helper to handle WHOIS fields that may be returned as lists.
        Returns the first non-None valid value.
        """
        if isinstance(value, list):
            for item in value:
                if item:
                    return item
            return None
        return value

    def _populate_domain_info(self, domain_info: DomainInfo, raw_whois: Any) -> None:
        """
        Parses raw WHOIS data and populates the DomainInfo object.
        """
        try:
            registrar = self._get_first_valid(raw_whois.get("registrar"))
            creation_date = self._get_first_valid(raw_whois.get("creation_date"))
            updated_date = self._get_first_valid(raw_whois.get("updated_date"))
            expiration_date = self._get_first_valid(raw_whois.get("expiration_date"))
            country = self._get_first_valid(raw_whois.get("country"))
            
            # Organization might be in different fields depending on the TLD
            organization = self._get_first_valid(raw_whois.get("org")) or self._get_first_valid(raw_whois.get("organization"))

            self._safe_set(domain_info, "registrar", registrar)
            self._safe_set(domain_info, "creation_date", creation_date)
            self._safe_set(domain_info, "updated_date", updated_date)
            self._safe_set(domain_info, "expiration_date", expiration_date)
            self._safe_set(domain_info, "country", country)
            self._safe_set(domain_info, "organization", organization)

            # Determine if privacy protected (basic heuristic)
            privacy_keywords = ["privacy", "proxy", "protected", "redacted", "hidden"]
            org_lower = str(organization).lower() if organization else ""
            reg_lower = str(registrar).lower() if registrar else ""
            
            is_private = any(kw in org_lower or kw in reg_lower for kw in privacy_keywords)
            self._safe_set(domain_info, "privacy_protected", is_private)

            # Calculate age and expiration metrics
            now = datetime.now(timezone.utc)
            
            if isinstance(creation_date, datetime):
                # Ensure timezone awareness for calculation
                cd = creation_date if creation_date.tzinfo else creation_date.replace(tzinfo=timezone.utc)
                age_delta = now - cd
                self._safe_set(domain_info, "domain_age_days", age_delta.days)

            if isinstance(expiration_date, datetime):
                ed = expiration_date if expiration_date.tzinfo else expiration_date.replace(tzinfo=timezone.utc)
                exp_delta = ed - now
                self._safe_set(domain_info, "days_until_expiration", exp_delta.days)

        except Exception as e:
            logger.error("Error populating DomainInfo from WHOIS data: %s", e)

    def _safe_set(self, model: DomainInfo, field: str, value: Any) -> None:
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
            logger.debug("Field '%s' is not defined in DomainInfo schema, skipping.", field)
        except Exception as e:
            logger.warning("Failed to set field '%s' on DomainInfo: %s", field, e)
