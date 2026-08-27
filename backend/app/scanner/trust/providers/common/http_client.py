"""
Shared HTTP Client for Threat Intelligence Providers.

This module provides the EnterpriseHTTPClient, a centralized, asynchronous
HTTP client designed for all external API communications within the
CyberSentinel AI platform. It wraps httpx.AsyncClient to standardize
timeouts, connection pooling, HTTP/2 support, and error handling.

Every threat intelligence provider must use this client instead of
directly instantiating httpx.AsyncClient.
"""

import logging
from typing import Optional, Dict

import httpx

logger = logging.getLogger(__name__)

_USER_AGENT = "CyberSentinelAI/1.0"


class EnterpriseHTTPClient:
    """
    Enterprise-grade asynchronous HTTP client for external API requests.

    This class maintains a single underlying httpx.AsyncClient instance
    with HTTP/2 support, connection pooling, redirect following, and a
    configurable timeout. It exposes high-level GET and POST methods that
    centralize error handling and logging, returning None on any failure
    instead of raising networking exceptions.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        """
        Initializes the EnterpriseHTTPClient.

        Args:
            timeout: Request timeout in seconds applied to all operations.
            client: An optional pre-configured httpx.AsyncClient instance
                for dependency injection (e.g., testing). If not provided,
                a default client is created with HTTP/2, connection pooling,
                redirect following, and the specified timeout.
        """
        if client is not None:
            self._client = client
        else:
            limits = httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
            )
            self._client = httpx.AsyncClient(
                http2=True,
                limits=limits,
                timeout=httpx.Timeout(timeout),
                follow_redirects=True,
                headers={"User-Agent": _USER_AGENT},
            )

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: object,
    ) -> Optional[httpx.Response]:
        """Executes an HTTP request, centralizing error handling and logging.

        Both ``get`` and ``post`` delegate to this method so that
        networking logic is never duplicated.

        Args:
            method: The HTTP method (e.g., ``GET``, ``POST``).
            url: The target URL.
            **kwargs: Additional arguments forwarded to
                ``httpx.AsyncClient.request`` (e.g., params, headers, json).

        Returns:
            The HTTP response on success, or ``None`` if the request failed.
        """
        try:
            response = await self._client.request(method, url, **kwargs)
            response.raise_for_status()
            logger.debug(
                "HTTP %s %s completed with status %s",
                method,
                url,
                response.status_code,
            )
            return response
        except httpx.TimeoutException as exc:
            logger.error(
                "HTTP %s request to '%s' timed out: %s", method, url, exc
            )
        except httpx.HTTPStatusError as exc:
            logger.error(
                "HTTP %s request to '%s' returned status %s: %s",
                method,
                url,
                exc.response.status_code,
                exc,
            )
        except httpx.RequestError as exc:
            logger.error(
                "HTTP %s request to '%s' failed (connection error): %s",
                method,
                url,
                exc,
            )
        except ValueError as exc:
            logger.error(
                "HTTP %s request to '%s' encountered a value error: %s",
                method,
                url,
                exc,
            )
        except Exception as exc:
            logger.error(
                "Unexpected exception during HTTP %s request to '%s': %s",
                method,
                url,
                exc,
                exc_info=True,
            )

        return None

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[httpx.Response]:
        """Executes an asynchronous HTTP GET request safely.

        Args:
            url: The target URL.
            params: Optional query parameters.
            headers: Optional HTTP headers merged with the client defaults.

        Returns:
            The HTTP response on success, or ``None`` on failure.
        """
        return await self._request(
            "GET", url, params=params, headers=headers
        )

    async def post(
        self,
        url: str,
        json: Optional[object] = None,
        data: Optional[object] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[httpx.Response]:
        """Executes an asynchronous HTTP POST request safely.

        Args:
            url: The target URL.
            json: Optional JSON-serializable payload.
            data: Optional form-encoded or bytes payload.
            headers: Optional HTTP headers merged with the client defaults.

        Returns:
            The HTTP response on success, or ``None`` on failure.
        """
        return await self._request(
            "POST", url, json=json, data=data, headers=headers
        )

    async def close(self) -> None:
        """Gracefully closes the underlying asynchronous HTTP client."""
        await self._client.aclose()
