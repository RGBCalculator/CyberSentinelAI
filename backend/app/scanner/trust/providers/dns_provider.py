"""
DNS Provider for the Trust Intelligence Engine.

This module is responsible solely for retrieving raw DNS information
for a given domain. It performs networking only and does not interpret
or map the data into any internal schemas.
"""

import asyncio
import logging
from typing import Optional, Dict, List

try:
    import dns.resolver
    from dns.exception import DNSException
except ImportError:
    # Handle cases where dnspython is not installed
    dns = None
    DNSException = Exception

logger = logging.getLogger(__name__)


class DNSProvider:
    """
    Provider class to fetch raw DNS information for a domain.
    Designed to be easily replaceable or mocked for testing.
    """

    def __init__(self, timeout: float = 5.0, lifetime: float = 10.0):
        """
        Initializes the DNSProvider.

        Args:
            timeout (float): Timeout for individual queries in seconds.
            lifetime (float): Total time to wait for a response in seconds.
        """
        self.timeout = timeout
        self.lifetime = lifetime

    async def fetch_dns(self, domain: str) -> Optional[Dict[str, List[str]]]:
        """
        Executes DNS lookups for various record types (A, AAAA, MX, NS, TXT).
        
        Since instructed to treat dnspython as synchronous, this method delegates
        blocking calls to a background thread using asyncio.to_thread().

        Args:
            domain (str): The domain name to query.

        Returns:
            Optional[Dict[str, List[str]]]: A dictionary containing the raw DNS results
                                            if successful, or None if an unrecoverable 
                                            failure occurs (e.g. NXDOMAIN).
        """
        if dns is None:
            logger.error("The dnspython library is not installed.")
            return None

        # Create a fresh resolver to ensure thread safety
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.lifetime

        record_types = ["A", "AAAA", "MX", "NS", "TXT"]
        results: Dict[str, List[str]] = {rt: [] for rt in record_types}
        
        for rtype in record_types:
            try:
                # Delegate the blocking lookup to a thread pool
                answers = await asyncio.to_thread(resolver.resolve, domain, rtype)
                
                # Extract string representations of the records
                for rdata in answers:
                    results[rtype].append(rdata.to_text())

            except dns.resolver.NXDOMAIN:
                # If NXDOMAIN is raised, the domain itself does not exist.
                # This is an unrecoverable failure for the entire lookup.
                logger.warning("NXDOMAIN: Domain '%s' does not exist.", domain)
                return None
            except dns.resolver.NoAnswer:
                # The domain exists, but has no records of this specific type.
                logger.debug("No %s records found for domain '%s'.", rtype, domain)
            except dns.resolver.Timeout:
                logger.warning("DNS lookup timed out for domain '%s' querying %s record.", domain, rtype)
            except dns.resolver.NoNameservers:
                logger.warning("No nameservers found for domain '%s' querying %s record.", domain, rtype)
            except DNSException as e:
                # Catch-all for other dnspython specific exceptions
                logger.warning("DNS error for domain '%s' querying %s record: %s", domain, rtype, e)
            except Exception as e:
                # Catch-all for unexpected exceptions to ensure the process continues
                logger.error(
                    "Unexpected error for domain '%s' querying %s record: %s", 
                    domain, 
                    rtype, 
                    e, 
                    exc_info=True
                )

        return results
