"""
OpenPhish Reputation Provider.

This module implements the OpenPhish provider for the Reputation Intelligence Subsystem,
allowing the engine to query OpenPhish for known phishing indicators.
"""

import logging
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import httpx
from app.scanner.trust.reputation.base import BaseReputationProvider
from app.scanner.trust.reputation.schemas import (
    ProviderMetadata,
    ReputationFinding,
    Severity,
    ThreatCategory,
)

logger = logging.getLogger(__name__)


class OpenPhishProvider(BaseReputationProvider):
    """
    Reputation provider for OpenPhish.

    Queries the OpenPhish API to determine if a given indicator (URL or domain)
    is associated with phishing campaigns.
    """

    def __init__(self, api_url: str = "https://api.openphish.com/v1/check"):
        """
        Initializes the OpenPhish provider.

        Args:
            api_url (str): The base URL for the OpenPhish API.
        """
        self._api_url = api_url
        self._timeout = 10.0
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def metadata(self) -> ProviderMetadata:
        """
        Retrieves the provider metadata.

        Returns:
            ProviderMetadata: Configuration and details for OpenPhish.
        """
        return ProviderMetadata(
            name="OpenPhish",
            version="1.0",
            enabled=True,
            reliability=0.90,
        )

    async def initialize(self) -> None:
        """
        Initializes the asynchronous HTTP client.
        """
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)

    async def shutdown(self) -> None:
        """
        Closes the asynchronous HTTP client and cleans up resources.
        """
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _normalize_indicator(self, indicator: str) -> str:
        """
        Normalizes the indicator to ensure it is suitable for querying.
        If it lacks a scheme, it is considered a domain and prefixed to form a URL.

        Args:
            indicator (str): The raw indicator (e.g., domain, IP, or URL).

        Returns:
            str: The normalized URL indicator.
        """
        indicator = indicator.strip()
        parsed = urlparse(indicator)
        if not parsed.scheme:
            # Treated as a domain/IP, prefixing to ensure a valid URL format
            return f"http://{indicator}"
        return indicator

    async def _perform_request(self, target_url: str) -> Optional[Dict[str, Any]]:
        """
        Performs the asynchronous HTTP request to the OpenPhish API.

        Args:
            target_url (str): The normalized URL to query.

        Returns:
            Optional[Dict[str, Any]]: The parsed JSON response, or None on failure.
        """
        # Ensure the client exists in case lookup is called before initialize
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)

        request_params = {"url": target_url}

        try:
            response = await self._client.get(self._api_url, params=request_params)
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException as e:
            logger.error("OpenPhish API request timed out for '%s': %s", target_url, e)
        except httpx.HTTPStatusError as e:
            logger.error(
                "OpenPhish API returned HTTP error %s for '%s'",
                e.response.status_code,
                target_url,
            )
        except httpx.RequestError as e:
            logger.error("OpenPhish API connection failed for '%s': %s", target_url, e)
        except ValueError as e:
            logger.error("OpenPhish API returned invalid JSON for '%s': %s", target_url, e)
        except Exception as e:
            logger.error(
                "Unexpected exception during OpenPhish API request for '%s': %s",
                target_url,
                e,
                exc_info=True,
            )

        return None

    def _parse_response(self, data: Dict[str, Any], indicator: str) -> ReputationFinding:
        """
        Parses the OpenPhish JSON response into a ReputationFinding.

        Args:
            data (Dict[str, Any]): The raw JSON response.
            indicator (str): The originally queried indicator.

        Returns:
            ReputationFinding: The structured finding object.
        """
        # We assume the API returns a boolean indicating phishing presence, e.g. "phishing": true
        is_phishing = bool(data.get("phishing", False))

        confidence = 0.95 if is_phishing else 0.0

        return ReputationFinding(
            provider=self.metadata.name,
            malicious=is_phishing,
            confidence=confidence,
            severity=Severity.HIGH,
            category=ThreatCategory.PHISHING,
            reference=data.get("reference") or f"OpenPhish lookup for {indicator}",
            description=(
                "Identified as a phishing indicator by OpenPhish."
                if is_phishing
                else "No phishing activity detected."
            ),
            raw_data=data,
        )

    async def lookup(self, indicator: str) -> Optional[ReputationFinding]:
        """
        Queries OpenPhish for reputation intelligence on a given indicator.

        This method normalizes the indicator, performs an asynchronous request,
        and parses the response safely without raising any exceptions.

        Args:
            indicator (str): The domain, IP, or URL to lookup.

        Returns:
            Optional[ReputationFinding]: The finding details, or None on failure.
        """
        normalized_indicator = self._normalize_indicator(indicator)

        data = await self._perform_request(normalized_indicator)

        if data is None:
            return None

        return self._parse_response(data, indicator)
