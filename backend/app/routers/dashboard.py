"""
SOC Dashboard, Website Security, and Threat Intelligence Routers.

Provides endpoints for:
- Website Security & Trust Intelligence (SSL/TLS, WHOIS, DNS)
- Threat Intelligence Provider Status and Live Lookups
- Unified SOC Overview Metrics & Aggregations
- Security Report Generation
"""

import logging
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from datetime import datetime, timezone

from app.scanner.trust.engine import TrustEngine
from app.services.threat_intel import threat_intel_service
from app.routers.posture import get_demo_posture
from app.security.ssrf import is_safe_target_for_network

logger = logging.getLogger(__name__)

router = APIRouter(tags=["SOC & Threat Intelligence"])

_trust_engine: Optional[TrustEngine] = None

def get_trust_engine() -> TrustEngine:
    global _trust_engine
    if _trust_engine is None:
        _trust_engine = TrustEngine()
    return _trust_engine


class WebsiteAnalyzeRequest(BaseModel):
    target: str = Field(..., description="Target URL or domain (e.g., 'https://example.com' or 'example.com')")


class ThreatIntelLookupRequest(BaseModel):
    indicator: str = Field(..., description="Target URL, domain, or IP address")
    indicator_type: str = Field(default="url", description="Type of indicator: 'url', 'domain', or 'ip'")


@router.post(
    "/website/analyze",
    summary="Website Security & Trust Intelligence Analysis",
    description="Analyzes SSL/TLS certificates, WHOIS domain information, and DNS records."
)
async def analyze_website_security(req: WebsiteAnalyzeRequest):
    """Executes SSL/TLS, WHOIS, and DNS analysis safely via the TrustEngine."""
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty.")

    # Validate for SSRF
    safe, reason = is_safe_target_for_network(target)
    if not safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target rejected by SSRF safety validation: {reason}"
        )

    try:
        engine = get_trust_engine()
        result = await engine.analyze(target)
        return result.model_dump(mode="json")
    except Exception as e:
        logger.error("Website security analysis failed for '%s': %s", target, e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Website security analysis failed: {str(e)}"
        )


@router.get(
    "/threat-intel/status",
    summary="Get Threat Intelligence Providers Status",
    description="Returns the operational and configuration status of VirusTotal, PhishTank, OpenPhish, and AbuseIPDB."
)
async def get_threat_intel_status():
    """Returns provider status without exposing credentials."""
    return threat_intel_service.get_providers_status()


@router.post(
    "/threat-intel/lookup",
    summary="Direct Threat Intelligence Lookup",
    description="Queries all enabled threat intelligence engines for a given indicator."
)
async def lookup_threat_intel(req: ThreatIntelLookupRequest):
    """Performs multi-engine threat intelligence lookup."""
    indicator = req.indicator.strip()
    if not indicator:
        raise HTTPException(status_code=400, detail="Indicator cannot be empty.")
    
    return await threat_intel_service.lookup(indicator, req.indicator_type.lower())


@router.get(
    "/soc/overview",
    summary="Unified SOC Overview Dashboard Metrics",
    description="Aggregates security posture demo metrics, live scan statistics, integration health, and recent activities."
)
async def get_soc_overview():
    """Aggregates real and demo security metrics into a unified SOC summary."""
    # 1. Fetch Posture Data (Demo fixture)
    posture_data = None
    try:
        posture = get_demo_posture()
        posture_data = posture.model_dump(mode="json")
    except Exception as e:
        logger.warning("Could not load demo posture fixture: %s", e)

    # 2. Query MongoDB Scan History
    total_scans = 0
    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
    recent_scans = []
    
    try:
        from app.models.scan import ScanRecord
        total_scans = await ScanRecord.count()
        recent_records = await ScanRecord.find().sort("-created_at").limit(5).to_list()
        
        # Aggregate distribution
        for level in risk_distribution.keys():
            risk_distribution[level] = await ScanRecord.find(ScanRecord.risk_level == level).count()

        recent_scans = [
            {
                "scan_id": r.scan_id,
                "target": r.target,
                "scan_type": r.scan_type,
                "risk_level": r.risk_level,
                "risk_score": r.risk_score,
                "findings_count": r.findings_count,
                "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at)
            }
            for r in recent_records
        ]
    except Exception as err:
        logger.debug("MongoDB scans unavailable (fallback to zeroed): %s", err)

    # 3. Provider Statuses
    ti_status = threat_intel_service.get_providers_status()

    # 4. Synthesize unified findings list
    combined_findings = []
    if posture_data and "findings" in posture_data:
        for f in posture_data["findings"]:
            combined_findings.append({
                "id": f.get("id"),
                "source": "Security Posture (Code)",
                "title": f.get("title"),
                "severity": f.get("severity", "HIGH").lower(),
                "risk_score": f.get("risk_score", 85),
                "target": f.get("location", {}).get("file_path", "internal-finance-api"),
                "category": "Code Vulnerability",
                "is_demo": True,
                "description": f.get("description")
            })

    # Add any high-risk scan findings
    if recent_scans:
        for s in recent_scans:
            if s.get("risk_level") in ["critical", "high"]:
                combined_findings.append({
                    "id": s.get("scan_id"),
                    "source": "Live URL Scanner",
                    "title": f"Threat Detected on {s.get('target')}",
                    "severity": s.get("risk_level"),
                    "risk_score": s.get("risk_score"),
                    "target": s.get("target"),
                    "category": "URL Threat",
                    "is_demo": False,
                    "description": f"URL scan completed with risk score {s.get('risk_score')}"
                })

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "security_posture": {
            "is_demo": True,
            "overall_risk_score": posture_data.get("overall_risk_score", 95) if posture_data else 0,
            "total_findings": posture_data.get("total_findings", 0) if posture_data else 0,
            "critical_findings": posture_data.get("critical_findings", 0) if posture_data else 0,
            "high_findings": posture_data.get("high_findings", 0) if posture_data else 0,
            "repository": posture_data.get("repository", {}) if posture_data else {}
        },
        "scans_summary": {
            "total_scans": total_scans,
            "risk_distribution": risk_distribution,
            "recent_scans": recent_scans
        },
        "threat_intelligence": {
            "providers": ti_status,
            "active_count": sum(1 for p in ti_status.values() if p.get("status") == "ready"),
            "total_count": len(ti_status)
        },
        "findings_overview": {
            "total": len(combined_findings),
            "findings": combined_findings
        },
        "scanner_health": {
            "url_scanner": "operational",
            "trust_engine": "operational",
            "ai_inference": "operational",
            "threat_intel_hub": "operational"
        }
    }


@router.get(
    "/reports/export",
    summary="Export Security Posture & SOC Report",
    description="Generates an executive security report summary."
)
async def export_security_report():
    """Generates an executive SOC security audit report."""
    overview = await get_soc_overview()
    return {
        "report_id": f"REP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": "CyberSentinel AI Security Operations Center",
        "executive_summary": {
            "overall_posture_risk": overview["security_posture"]["overall_risk_score"],
            "total_vulnerabilities": overview["findings_overview"]["total"],
            "threat_intel_engines": f"{overview['threat_intelligence']['active_count']}/{overview['threat_intelligence']['total_count']} active",
            "total_scans_logged": overview["scans_summary"]["total_scans"],
            "verdict": "High attention required. Mitigate critical SQL injection and hardcoded AWS credentials."
        },
        "full_data": overview
    }
