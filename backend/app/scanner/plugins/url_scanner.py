import urllib.parse
from typing import Any, Dict, List
import ipaddress

from app.scanner.base import BaseScanner
from app.scanner.factory import ScannerFactory
from app.scanner.schemas import ScanRequest, ScanType, Finding
from app.scanner.features import FeatureEngine, MLFeatureVector
from app.scanner.rules import RuleEngine, ScanMetadata


@ScannerFactory.register(ScanType.URL)
class URLScanner(BaseScanner):
    """
    Enterprise scanner plugin for URL analysis.
    Uses the FeatureEngine for decoupled static extraction, 
    and the RuleEngine for generating deterministic findings.
    """

    def __init__(self):
        super().__init__()
        self.feature_engine = FeatureEngine()
        self.rule_engine = RuleEngine()

    async def validate(self, request: ScanRequest) -> bool:
        """
        Validates that the target is a well-formed HTTP/HTTPS URL.
        """
        target = request.target
        if not target.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")

        try:
            parsed = urllib.parse.urlparse(target)
            if not parsed.hostname:
                raise ValueError("URL must contain a valid hostname.")
                
            host = parsed.hostname
            # Check for IP address
            try:
                ip = ipaddress.ip_address(host.strip("[]"))
                # Allow localhost/loopback if needed, but it's fundamentally a valid IP
            except ValueError:
                # Not an IP, so it should be a hostname. Check Punycode support
                try:
                    host.encode("idna").decode("ascii")
                except Exception:
                    raise ValueError(f"Invalid hostname format or Punycode encoding: {host}")
        except Exception as e:
            raise ValueError(f"Malformed URL provided: {str(e)}")

        return True

    async def normalize(self, request: ScanRequest) -> ScanRequest:
        """
        Normalizes the URL to a standard format.
        """
        parsed = urllib.parse.urlparse(request.target)
        
        # Lowercase scheme and host
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower() if parsed.hostname else ""
        
        # IDN to Punycode
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            pass # Keep original if idna fails

        port = parsed.port
        # Remove default ports
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None
            
        netloc = host
        if port:
            netloc = f"{host}:{port}"
            
        # Add userinfo if present
        if parsed.username or parsed.password:
            userinfo = ""
            if parsed.username:
                userinfo += parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            netloc = f"{userinfo}@{netloc}"

        path = parsed.path
        if path == "" or path == "/":
            path = "" # Strip trailing slash for root
            
        normalized_url = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalized_url += f"?{parsed.query}"
        if parsed.fragment:
            normalized_url += f"#{parsed.fragment}"
            
        return ScanRequest(target=normalized_url, scan_type=request.scan_type, metadata=request.metadata)

    async def pre_process(self, request: ScanRequest) -> Dict[str, Any]:
        """
        Delegates feature extraction to the FeatureEngine.
        """
        vector: MLFeatureVector = await self.feature_engine.extract_features(request.target)
        
        # We can store the MLFeatureVector itself, or model_dump() it.
        # Storing the dumped dict ensures standard serializability across the orchestration bus.
        return {
            "ml_vector": vector.model_dump(),
            "target_url": request.target
        }

    async def execute(self, request: ScanRequest, context: Dict[str, Any]) -> List[Finding]:
        """
        Generates deterministic findings by passing features into the RuleEngine.
        """
        # Re-hydrate the MLFeatureVector
        vector = MLFeatureVector(**context.get("ml_vector", {}))
        
        # Create metadata context for the rules
        metadata = ScanMetadata(
            scan_id=request.metadata.get("scan_id", "unknown") if request.metadata else "unknown",
            target_url=context.get("target_url", request.target),
            scan_type=request.scan_type.value
        )
        
        # Delegate finding generation to the Rule Engine
        findings = await self.rule_engine.evaluate_all(vector, metadata)

        return findings
