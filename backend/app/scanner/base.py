from abc import ABC, abstractmethod
from typing import Any, Dict, List

from .schemas import ScanRequest, ScanResult, Finding


class BaseScanner(ABC):
    """
    Abstract Base Class representing the contract for all specific asset scanners.
    
    Every scanner plugin (e.g., URLScanner, FileScanner) must inherit from this
    class and implement the core execution lifecycle methods. This enforces a
    standardized scanning pipeline that the ScanOrchestrator can reliably execute.
    """

    @abstractmethod
    async def validate(self, request: ScanRequest) -> bool:
        """
        Validate the specific target format (e.g., check if URL is structurally valid).
        
        Args:
            request: The scan request containing the target.
            
        Returns:
            bool: True if valid, False otherwise.
            
        Raises:
            ValueError: If validation fails critically.
        """
        pass

    @abstractmethod
    async def normalize(self, request: ScanRequest) -> ScanRequest:
        """
        Normalize the input target to a standard format for processing.
        (e.g., strip 'http://' from URLs, lowercase domains).
        
        Args:
            request: The original scan request.
            
        Returns:
            ScanRequest: The mutated or new request with a normalized target.
        """
        pass

    @abstractmethod
    async def pre_process(self, request: ScanRequest) -> Dict[str, Any]:
        """
        Extract initial features or perform prerequisite steps needed for the main execution.
        
        Args:
            request: The normalized scan request.
            
        Returns:
            Dict[str, Any]: Context or features extracted during pre-processing.
        """
        pass

    @abstractmethod
    async def execute(self, request: ScanRequest, context: Dict[str, Any]) -> List[Finding]:
        """
        The core scanning logic specific to the asset type.
        
        Args:
            request: The normalized scan request.
            context: The dictionary returned from `pre_process`.
            
        Returns:
            List[Finding]: A list of enterprise Finding models discovered during execution.
        """
        pass
