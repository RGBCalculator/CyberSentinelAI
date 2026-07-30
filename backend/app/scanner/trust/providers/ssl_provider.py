"""
SSL Provider for the Trust Intelligence Engine.

This module is responsible solely for network communication to retrieve
raw SSL/TLS certificate information from target hosts. It does not perform
any trust scoring or certificate interpretation.
"""

import asyncio
import logging
import ssl
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class SSLProvider:
    """
    Provider class to fetch SSL/TLS certificate details over the network.
    Designed to be easily replaceable or mocked for testing.
    """

    def __init__(self, timeout: float = 10.0):
        """
        Initializes the SSLProvider.

        Args:
            timeout (float): Connection timeout in seconds.
        """
        self.timeout = timeout
        # Create a default SSL context. This will verify the certificate by default.
        self.ssl_context = ssl.create_default_context()

    async def fetch_certificate(self, hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """
        Establishes a secure connection to the specified host and retrieves
        its SSL/TLS peer certificate.

        Args:
            hostname (str): The target hostname.
            port (int): The target port (default is 443).

        Returns:
            Optional[Dict[str, Any]]: A dictionary containing the raw certificate information 
                                      if successful, or None if the connection fails.
        """
        try:
            # Using asyncio.open_connection to establish an async socket connection
            # with the configured SSL context.
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    hostname, 
                    port, 
                    ssl=self.ssl_context, 
                    server_hostname=hostname
                ),
                timeout=self.timeout
            )
            
            try:
                # Retrieve the raw peer certificate.
                # binary_form=False returns it as a parsed dictionary.
                ssl_object = writer.get_extra_info('ssl_object')
                if ssl_object:
                    cert = ssl_object.getpeercert(binary_form=False)
                    return cert
                else:
                    logger.error("No SSL object found on connection to %s:%d", hostname, port)
                    return None
            finally:
                writer.close()
                await writer.wait_closed()

        except asyncio.TimeoutError:
            logger.warning("Connection to %s:%d timed out after %s seconds.", hostname, port, self.timeout)
            return None
        except ssl.SSLCertVerificationError as e:
            # Certificate verification failed (e.g., expired, self-signed).
            logger.warning("Certificate verification failed for %s:%d: %s", hostname, port, e)
            return None
        except ssl.SSLError as e:
            logger.warning("SSL handshake failed for %s:%d: %s", hostname, port, e)
            return None
        except OSError as e:
            logger.error("Network or socket error connecting to %s:%d: %s", hostname, port, e)
            return None
        except Exception as e:
            logger.error("Unexpected error fetching certificate from %s:%d: %s", hostname, port, e, exc_info=True)
            return None
