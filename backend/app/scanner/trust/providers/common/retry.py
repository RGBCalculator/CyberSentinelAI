"""
Asynchronous Retry Framework for External API Providers.

This module provides the RetryPolicy class, a generic and reusable retry
mechanism with exponential backoff designed for all external API
communications within the CyberSentinel AI platform. It centralizes
retry logic so that individual providers never need to implement their
own retry loops.
"""

import asyncio
import logging
from typing import Awaitable, Callable, Optional, TypeVar

import httpx

logger = logging.getLogger(__name__)

T = TypeVar("T")

_RETRYABLE_EXCEPTIONS = (
    httpx.TimeoutException,
    httpx.ConnectError,
    httpx.NetworkError,
    httpx.RemoteProtocolError,
)

_NON_RETRYABLE_STATUS_CODES = frozenset({400, 401, 403, 404})


class RetryPolicy:
    """Configurable asynchronous retry policy with exponential backoff.

    Wraps an arbitrary async callable and transparently retries it on
    transient network failures (timeouts, connection resets, protocol
    errors) while immediately failing on non-retryable HTTP status codes.

    Attributes:
        max_attempts: Maximum number of execution attempts (including the
            initial attempt).
        base_delay: Initial delay in seconds before the first retry.
        max_delay: Upper bound on the computed delay in seconds.
        backoff_factor: Multiplier applied to the delay after each
            successive retry.
    """

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 10.0,
        backoff_factor: float = 2.0,
    ) -> None:
        """Initializes the RetryPolicy.

        Args:
            max_attempts: Maximum number of execution attempts.
            base_delay: Initial delay in seconds before the first retry.
            max_delay: Upper bound on the computed backoff delay.
            backoff_factor: Multiplier applied to the delay on each retry.
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor

    def _compute_delay(self, attempt: int) -> float:
        """Computes the backoff delay for a given attempt number.

        Args:
            attempt: The zero-based attempt index (0 for the first retry).

        Returns:
            The delay in seconds, capped at ``max_delay``.
        """
        return min(self.base_delay * (self.backoff_factor ** attempt), self.max_delay)

    @staticmethod
    def _is_non_retryable(exc: httpx.HTTPStatusError) -> bool:
        """Determines whether an HTTP status error should not be retried.

        Args:
            exc: The HTTP status error to evaluate.

        Returns:
            ``True`` if the response status code is in the non-retryable
            set, ``False`` otherwise.
        """
        return exc.response.status_code in _NON_RETRYABLE_STATUS_CODES

    async def execute(
        self,
        operation: Callable[..., Awaitable[T]],
        *args: object,
        **kwargs: object,
    ) -> Optional[T]:
        """Executes an async operation with retry and exponential backoff.

        The operation is invoked up to ``max_attempts`` times. Retryable
        network exceptions trigger a sleep-then-retry cycle with
        exponentially increasing delays. Non-retryable HTTP status codes
        (400, 401, 403, 404) cause an immediate failure. If all attempts
        are exhausted, ``None`` is returned and no exception is raised.

        Args:
            operation: The async callable to execute.
            *args: Positional arguments forwarded to ``operation``.
            **kwargs: Keyword arguments forwarded to ``operation``.

        Returns:
            The result of ``operation`` on success, or ``None`` if all
            attempts failed.
        """
        last_exception: Optional[Exception] = None

        for attempt in range(self.max_attempts):
            try:
                result = await operation(*args, **kwargs)

                if attempt > 0:
                    logger.info(
                        "Operation succeeded on attempt %d/%d after prior failures.",
                        attempt + 1,
                        self.max_attempts,
                    )

                return result

            except httpx.HTTPStatusError as exc:
                if self._is_non_retryable(exc):
                    logger.error(
                        "Non-retryable HTTP %s on attempt %d/%d — aborting retries.",
                        exc.response.status_code,
                        attempt + 1,
                        self.max_attempts,
                    )
                    return None

                last_exception = exc

            except _RETRYABLE_EXCEPTIONS as exc:
                last_exception = exc

            except Exception as exc:
                logger.error(
                    "Unexpected non-retryable exception on attempt %d/%d: %s",
                    attempt + 1,
                    self.max_attempts,
                    exc,
                    exc_info=True,
                )
                return None

            # If we reach here, the attempt failed with a retryable error.
            is_last_attempt = attempt + 1 >= self.max_attempts
            if is_last_attempt:
                break

            delay = self._compute_delay(attempt)
            logger.warning(
                "Attempt %d/%d failed (%s). Retrying in %.1fs…",
                attempt + 1,
                self.max_attempts,
                last_exception,
                delay,
            )
            await asyncio.sleep(delay)

        logger.error(
            "All %d attempts exhausted. Last exception: %s",
            self.max_attempts,
            last_exception,
        )
        return None
