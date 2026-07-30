"""
WHOIS Provider for the Trust Intelligence Engine.

This module is responsible solely for retrieving raw WHOIS information
for a given domain. It performs networking only and does not interpret
or map the data into any internal schemas.
"""

import asyncio
import logging
import socket
from typing import Optional, Any

try:
    import whois
    from whois.parser import PywhoisError
except ImportError:
    # Handle cases where python-whois is not installed
    whois = None
    PywhoisError = Exception

logger = logging.getLogger(__name__)


class WHOISProvider:
    """
    Provider class to fetch raw WHOIS information for a domain.
    Designed to be easily replaceable or mocked for testing.
    """

    async def fetch_whois(self, domain: str) -> Optional[Any]:
        """
        Executes a WHOIS lookup for the given domain.
        
        Since python-whois is synchronous, this method delegates the blocking
        call to a background thread using asyncio.to_thread().

        Args:
            domain (str): The domain name to query.

        Returns:
            Optional[Any]: The raw WHOIS response object if successful,
                           or None if the lookup fails.
        """
        if whois is None:
            logger.error("The python-whois library is not installed.")
            return None

        try:
            # Delegate the synchronous whois lookup to a thread pool
            # to avoid blocking the asyncio event loop.
            raw_whois = await asyncio.to_thread(whois.whois, domain)
            
            # whois.whois() can sometimes return a dictionary with None values 
            # for domains that don't exist instead of raising an error.
            if not raw_whois or not raw_whois.get("domain_name"):
                logger.warning("WHOIS lookup returned empty or invalid data for domain '%s'.", domain)
                return None
                
            return raw_whois

        except PywhoisError as e:
            logger.warning("WHOIS parser error or invalid domain '%s': %s", domain, e)
            return None
        except socket.timeout as e:
            logger.warning("WHOIS lookup timed out for domain '%s': %s", domain, e)
            return None
        except socket.error as e:
            logger.error("Network error during WHOIS lookup for domain '%s': %s", domain, e)
            return None
        except Exception as e:
            logger.error("Unexpected error during WHOIS lookup for domain '%s': %s", domain, e, exc_info=True)
            return None
