import uuid
import logging
import time
from typing import Any, Dict, List

from .schemas import ScanRequest, ScanResult, ScanStatus, RiskLevel, Finding, FindingCategory
from .factory import ScannerFactory
from .base import BaseScanner

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Coordinates the entire scanning lifecycle.
    
    This class is responsible for taking a ScanRequest, instantiating the right
    scanner via the ScannerFactory, and walking it through the standardized
    pipeline: Validation -> Normalization -> Pre-processing -> Execution ->
    Threat Intel (Placeholder) -> AI Analysis (Placeholder) -> Risk Scoring.
    """

    def __init__(self):
        # Dependencies could be injected here later (e.g., ThreatIntelService, AIEngine)
        pass

    async def run_scan(self, request: ScanRequest) -> ScanResult:
        """
        Executes the full scanning pipeline.
        
        Args:
            request: The inbound scan request payload.
            
        Returns:
            ScanResult: The final standardized outcome (Report) of the scan.
        """
        scan_id = str(uuid.uuid4())
        start_time = time.time()
        
        # Initialize result with PENDING status
        result = ScanResult(
            scan_id=scan_id,
            status=ScanStatus.PENDING,
            risk_level=RiskLevel.SAFE,
            risk_score=0.0
        )

        try:
            # 1. Obtain Scanner
            scanner: BaseScanner = ScannerFactory.create(request.scan_type)
            
            # 2. Validation
            result.status = ScanStatus.VALIDATING
            is_valid = await scanner.validate(request)
            if not is_valid:
                raise ValueError("Validation failed for the provided target.")
                
            # 3. Normalization
            normalized_req = await scanner.normalize(request)
            
            # 4. Pre-processing
            result.status = ScanStatus.SCANNING
            context = await scanner.pre_process(normalized_req)
            
            # 5. Scanner Execution
            scanner_findings: List[Finding] = await scanner.execute(normalized_req, context)
            
            # 6. Threat Intelligence (Placeholder)
            result.status = ScanStatus.ANALYZING
            ti_data = await self._fetch_threat_intel(normalized_req.target, request.scan_type.value)
            
            # 7. AI Analysis (Placeholder)
            ai_data = await self._run_ai_analysis(normalized_req.target, scanner_findings)
            
            # 8. Risk Scoring & Finalization
            self._calculate_final_risk(result, scanner_findings, ti_data, ai_data)
            
            result.status = ScanStatus.COMPLETED
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {str(e)}", exc_info=True)
            result.status = ScanStatus.FAILED
            # Create a synthetic Finding for the internal error to adhere to the schema
            error_finding = Finding(
                title="Internal Orchestrator Error",
                description=f"Scan failed with error: {str(e)}",
                severity=RiskLevel.CRITICAL,
                category=FindingCategory.ANOMALY
            )
            result.findings.append(error_finding)
        
        # Finalize execution time
        result.execution_duration = round(time.time() - start_time, 3)

        return result

    async def _fetch_threat_intel(self, target: str, scan_type: str) -> Dict[str, Any]:
        """
        Placeholder for external Threat Intelligence lookups (e.g., VirusTotal, AbuseIPDB).
        """
        # TODO: Inject and call ThreatIntelligenceService
        return {"provider": "placeholder", "malicious": False}

    async def _run_ai_analysis(self, target: str, scanner_findings: List[Finding]) -> Dict[str, Any]:
        """
        Placeholder for passing features into the AI Engine for predictions.
        """
        # TODO: Inject and call AIEngine
        return {"model": "placeholder", "confidence": 0.0, "prediction": "benign"}

    def _calculate_final_risk(self, result: ScanResult, scanner_findings: List[Finding], ti_data: Dict[str, Any], ai_data: Dict[str, Any]) -> None:
        """
        Aggregates data from all sources to compute the final risk score and level.
        """
        result.threat_intel = ti_data
        result.ai_analysis = ai_data
        result.findings = scanner_findings
        
        # Calculate statistics
        total_findings = len(scanner_findings)
        critical_count = sum(1 for f in scanner_findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in scanner_findings if f.severity == RiskLevel.HIGH)
        
        result.statistics = {
            "total_findings": total_findings,
            "critical_issues": critical_count,
            "high_issues": high_count
        }
        
        # Basic scoring logic based on highest severity finding
        if critical_count > 0 or ti_data.get("malicious") or ai_data.get("prediction") == "malicious":
            result.risk_level = RiskLevel.CRITICAL
            result.risk_score = 95.0
        elif high_count > 0:
            result.risk_level = RiskLevel.HIGH
            result.risk_score = 75.0
        elif total_findings > 0:
            result.risk_level = RiskLevel.MEDIUM
            result.risk_score = 40.0
        else:
            result.risk_level = RiskLevel.SAFE
            result.risk_score = 5.0
