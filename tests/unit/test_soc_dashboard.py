import pytest
import httpx
from httpx import ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_soc_overview_endpoint():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/soc/overview")
        assert resp.status_code == 200
        data = resp.json()
        assert "security_posture" in data
        assert "threat_intelligence" in data
        assert "scanner_health" in data
        assert "findings_overview" in data
        assert data["security_posture"]["is_demo"] is True


@pytest.mark.asyncio
async def test_threat_intel_status_endpoint():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/threat-intel/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "virustotal" in data
        assert "phishtank" in data
        assert "openphish" in data
        assert "abuseipdb" in data
        # Ensure credentials are not exposed
        for p in data.values():
            assert "api_key" not in p
            assert "secret" not in p


@pytest.mark.asyncio
async def test_threat_intel_lookup_safe_target():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/v1/threat-intel/lookup", json={
            "indicator": "https://example.com",
            "indicator_type": "url"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "verdict" in data
        assert "providers" in data


@pytest.mark.asyncio
async def test_website_analyze_ssrf_blocked():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Loopback/private target should be blocked
        resp = await client.post("/api/v1/website/analyze", json={
            "target": "http://127.0.0.1:8000"
        })
        assert resp.status_code == 400
        assert "SSRF" in resp.json()["detail"] or "blocked" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_reports_export_endpoint():
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/reports/export")
        assert resp.status_code == 200
        data = resp.json()
        assert "report_id" in data
        assert "executive_summary" in data
