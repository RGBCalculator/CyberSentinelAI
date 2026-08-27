import asyncio
import json
import pytest
from app.scanner.schemas import ScanRequest, ScanType
from app.scanner.orchestrator import ScanOrchestrator

@pytest.mark.asyncio
async def test_url_scanner():
    request = ScanRequest(
        target="http://192.168.1.1:8080/secure/login.php?user=admin",
        scan_type=ScanType.URL
    )
    orchestrator = ScanOrchestrator()
    result = await orchestrator.run_scan(request)
    
    print(f"Status: {result.status}")
    print(f"Risk Level: {result.risk_level}")
    print(f"Risk Score: {result.risk_score}")
    print(f"Execution Duration: {result.execution_duration}s")
    print("Findings:")
    for finding in result.findings:
        print(f" - [{finding.severity.value}] {finding.title}: {finding.description}")
        for evidence in finding.evidence:
            print(f"    Evidence: {evidence.raw_value}")
            
if __name__ == "__main__":
    asyncio.run(test_url_scanner())
