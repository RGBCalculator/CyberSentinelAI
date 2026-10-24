import pytest
from unittest.mock import AsyncMock
import httpx
from httpx import ASGITransport

from app.main import app
from app.routers.scan import get_scan_orchestrator
from app.scanner.schemas import (
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanType,
    RiskLevel,
    Finding,
    FindingCategory,
)


@pytest.fixture(autouse=True)
def cleanup_dependency_overrides():
    """Ensure FastAPI dependency overrides are cleared after each test."""
    yield
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_scan_url_success_real_scanner():
    """
    Tests that a real scan of a target URL succeeds through the API endpoint,
    returning a valid ScanResult schema with HTTP 200.
    """
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "target": "http://192.168.1.1:8080/secure/login.php?user=admin",
            "scan_type": "url",
            "metadata": {"test_run": True}
        }
        response = await client.post("/api/v1/scan", json=payload)

        assert response.status_code == 200
        data = response.json()

        assert "scan_id" in data
        assert data["status"] == ScanStatus.COMPLETED.value
        assert data["risk_level"] in [lvl.value for lvl in RiskLevel]
        assert isinstance(data["risk_score"], (int, float))
        assert isinstance(data["findings"], list)
        assert data["execution_duration"] >= 0.0
        assert "statistics" in data
        assert "threat_intel" in data


@pytest.mark.asyncio
async def test_scan_url_mocked_success():
    """
    Tests the scan endpoint with an isolated mock orchestrator, ensuring
    it does not depend on live services and returns structured data accurately.
    """
    mock_orchestrator = AsyncMock()
    mock_result = ScanResult(
        scan_id="test-mock-scan-id",
        status=ScanStatus.COMPLETED,
        risk_level=RiskLevel.HIGH,
        risk_score=75.0,
        overall_confidence=0.9,
        findings=[
            Finding(
                title="Suspicious IP In URL",
                description="The URL uses a raw IP address instead of a domain name.",
                severity=RiskLevel.HIGH,
                category=FindingCategory.ANOMALY,
                confidence=1.0,
            )
        ],
        statistics={"total_findings": 1, "critical_issues": 0, "high_issues": 1},
        execution_duration=0.123,
    )
    mock_orchestrator.run_scan.return_value = mock_result
    app.dependency_overrides[get_scan_orchestrator] = lambda: mock_orchestrator

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "target": "https://secure-login.test",
            "scan_type": "url"
        }
        response = await client.post("/api/v1/scan", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == "test-mock-scan-id"
        assert data["risk_score"] == 75.0
        assert data["risk_level"] == "high"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["title"] == "Suspicious IP In URL"


@pytest.mark.asyncio
async def test_scan_failure_orchestrator_failed_status():
    """
    Tests that when the scanner orchestrator reports a FAILED status,
    the endpoint returns HTTP 500 without leaking sensitive internals.
    """
    mock_orchestrator = AsyncMock()
    failed_result = ScanResult(
        scan_id="failed-scan-123",
        status=ScanStatus.FAILED,
        risk_level=RiskLevel.CRITICAL,
        risk_score=99.0,
        findings=[
            Finding(
                title="Internal Orchestrator Error",
                description="Scan failed with error: internal stack details",
                severity=RiskLevel.CRITICAL,
                category=FindingCategory.ANOMALY,
            )
        ],
    )
    mock_orchestrator.run_scan.return_value = failed_result
    app.dependency_overrides[get_scan_orchestrator] = lambda: mock_orchestrator

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "target": "https://failing-target.example",
            "scan_type": "url"
        }
        response = await client.post("/api/v1/scan", json=payload)

        assert response.status_code == 500
        data = response.json()
        # Verify RFC 7807 problem details or detail error string
        detail_or_title = data.get("detail") or data.get("title") or ""
        assert "internal stack details" not in str(data)
        assert response.status_code == 500


@pytest.mark.asyncio
async def test_scan_failure_orchestrator_unhandled_exception():
    """
    Tests that an unhandled exception inside the scanner pipeline is caught
    and converted to HTTP 500 without leaking stack traces or sensitive strings.
    """
    mock_orchestrator = AsyncMock()
    mock_orchestrator.run_scan.side_effect = RuntimeError("Sensitive DB Connection String Leaked")
    app.dependency_overrides[get_scan_orchestrator] = lambda: mock_orchestrator

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "target": "https://crash-test.example",
            "scan_type": "url"
        }
        response = await client.post("/api/v1/scan", json=payload)

        assert response.status_code == 500
        data = response.json()
        assert "Sensitive DB Connection String Leaked" not in str(data)


@pytest.mark.asyncio
async def test_scan_invalid_input_empty_target():
    """
    Tests that empty or whitespace-only target is rejected with HTTP 400.
    """
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "target": "   ",
            "scan_type": "url"
        }
        response = await client.post("/api/v1/scan", json=payload)
        assert response.status_code == 400


@pytest.mark.asyncio
async def test_scan_invalid_url_protocol():
    """
    Tests that non-HTTP/HTTPS URLs are rejected with HTTP 400.
    """
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "target": "ftp://files.example.com/payload.exe",
            "scan_type": "url"
        }
        response = await client.post("/api/v1/scan", json=payload)
        assert response.status_code == 400


@pytest.mark.asyncio
async def test_scan_invalid_scan_type_schema():
    """
    Tests that an invalid scan_type is rejected by schema validation with HTTP 422.
    """
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "target": "https://example.com",
            "scan_type": "nonexistent_scanner_type"
        }
        response = await client.post("/api/v1/scan", json=payload)
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_scan_trailing_slash_support():
    """
    Verifies that POST /api/v1/scan/ works identically to /api/v1/scan.
    """
    mock_orchestrator = AsyncMock()
    mock_orchestrator.run_scan.return_value = ScanResult(
        scan_id="test-slash-id",
        status=ScanStatus.COMPLETED,
        risk_level=RiskLevel.SAFE,
        risk_score=0.0
    )
    app.dependency_overrides[get_scan_orchestrator] = lambda: mock_orchestrator

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "target": "https://example.com",
            "scan_type": "url"
        }
        response = await client.post("/api/v1/scan/", json=payload)
        assert response.status_code == 200
        assert response.json()["scan_id"] == "test-slash-id"
