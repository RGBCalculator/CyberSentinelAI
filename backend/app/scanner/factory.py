from typing import Dict, Type

from .base import BaseScanner
from .schemas import ScanType


class ScannerFactory:
    """
    Registry and Factory for scanners.
    
    Implements the Factory and Registry patterns to allow dynamic instantiation 
    of the correct scanner implementation based on the requested ScanType.
    This adheres to the Open-Closed Principle, allowing new scanners to be added 
    without modifying this module.
    """

    _registry: Dict[ScanType, Type[BaseScanner]] = {}

    @classmethod
    def register(cls, scan_type: ScanType):
        """
        Decorator to register a scanner class for a specific scan type.
        
        Args:
            scan_type: The ScanType enum value this scanner handles.
            
        Returns:
            A decorator function that registers the class.
        """
        def wrapper(scanner_class: Type[BaseScanner]) -> Type[BaseScanner]:
            if not issubclass(scanner_class, BaseScanner):
                raise ValueError(f"Class {scanner_class.__name__} must inherit from BaseScanner")
            
            cls._registry[scan_type] = scanner_class
            return scanner_class
            
        return wrapper

    @classmethod
    def create(cls, scan_type: ScanType) -> BaseScanner:
        """
        Instantiate and return the appropriate scanner for the given type.
        
        Args:
            scan_type: The requested ScanType.
            
        Returns:
            An instance of the registered BaseScanner implementation.
            
        Raises:
            ValueError: If no scanner is registered for the provided type.
        """
        scanner_class = cls._registry.get(scan_type)
        if not scanner_class:
            raise ValueError(f"No scanner registered for scan type: {scan_type.value}")
        
        return scanner_class()
