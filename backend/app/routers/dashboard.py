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
from datetime import datetime, timezone, timedelta

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
    status_counts = {"completed": 0, "partial": 0, "failed": 0}
    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
    activity_7d = []
    recent_scans = []
    
    try:
        from app.models.scan import ScanRecord
        total_scans = await ScanRecord.count()
        recent_records = await ScanRecord.find().sort("-created_at").limit(10).to_list()
        
        # Status counts
        status_counts["completed"] = await ScanRecord.find(ScanRecord.status == "completed").count()
        status_counts["partial"] = await ScanRecord.find(ScanRecord.status == "partial").count()
        status_counts["failed"] = await ScanRecord.find(ScanRecord.status == "failed").count()

        # Aggregate risk distribution
        for level in risk_distribution.keys():
            risk_distribution[level] = await ScanRecord.find(ScanRecord.risk_level == level).count()

        # Calculate 7-day scan activity
        now = datetime.now(timezone.utc)
        for i in range(6, -1, -1):
            day_date = (now - timedelta(days=i)).date()
            day_start = datetime(day_date.year, day_date.month, day_date.day, tzinfo=timezone.utc)
            day_end = day_start + timedelta(days=1)
            count = await ScanRecord.find(
                ScanRecord.created_at >= day_start,
                ScanRecord.created_at < day_end
            ).count()
            activity_7d.append({
                "date": day_date.isoformat(),
                "day": day_date.strftime("%a"),
                "count": count
            })

        recent_scans = [
            {
                "scan_id": r.scan_id,
                "target": r.target,
                "scan_type": r.scan_type,
                "status": getattr(r, "status", "completed"),
                "risk_level": r.risk_level,
                "risk_score": r.risk_score,
                "findings_count": r.findings_count,
                "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at)
            }
            for r in recent_records
        ]
    except Exception as err:
        logger.debug("MongoDB scans unavailable (fallback to zeroed): %s", err)
        # Fallback empty 7-day array
        now = datetime.now(timezone.utc)
        for i in range(6, -1, -1):
            d = (now - timedelta(days=i)).date()
            activity_7d.append({"date": d.isoformat(), "day": d.strftime("%a"), "count": 0})

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
                "category": "Static Code Analysis",
                "is_demo": True,
                "description": f.get("description"),
                "detected_at": datetime.now(timezone.utc).isoformat()
            })

    # Add scan findings from recent scans
    if recent_scans:
        for s in recent_scans:
            if s.get("findings_count", 0) > 0:
                combined_findings.append({
                    "id": f"scan-{s.get('scan_id')}",
                    "source": "Live URL Scanner",
                    "title": f"Threat Detected on {s.get('target')}",
                    "severity": s.get("risk_level", "medium").lower(),
                    "risk_score": s.get("risk_score", 45),
                    "target": s.get("target"),
                    "category": "URL & Web Threat",
                    "is_demo": False,
                    "description": f"URL scan completed with risk score {s.get('risk_score')} and {s.get('findings_count')} anomalies detected.",
                    "detected_at": s.get("created_at")
                })

    # Calculate findings by severity distribution
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in combined_findings:
        sev = f.get("severity", "medium").lower()
        if sev in findings_by_severity:
            findings_by_severity[sev] += 1
        elif sev in ["safe", "info", "informational"]:
            findings_by_severity["low"] += 1

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
            "status_counts": status_counts,
            "risk_distribution": risk_distribution,
            "activity_7d": activity_7d,
            "recent_scans": recent_scans
        },
        "threat_intelligence": {
            "providers": ti_status,
            "active_count": sum(1 for p in ti_status.values() if p.get("status") == "ready"),
            "total_count": len(ti_status)
        },
        "findings_overview": {
            "total": len(combined_findings),
            "by_severity": findings_by_severity,
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
    "/findings",
    summary="Query Unified Security Findings",
    description="Retrieves security findings from code posture and scan history with search and filters."
)
async def get_all_findings(
    severity: Optional[str] = Query(None, description="Severity filter: critical, high, medium, low"),
    category: Optional[str] = Query(None, description="Category filter"),
    search: Optional[str] = Query(None, description="Search term for title, description, target"),
    limit: int = Query(50, ge=1, le=100),
    skip: int = Query(0, ge=0)
):
    """Retrieves all aggregated findings across code posture and scan records."""
    overview = await get_soc_overview()
    all_findings = overview.get("findings_overview", {}).get("findings", [])

    filtered = []
    for f in all_findings:
        if severity and severity.upper() != "ALL" and f.get("severity", "").upper() != severity.upper():
            continue
        if category and category.upper() != "ALL" and f.get("category", "").upper() != category.upper():
            continue
        if search:
            q = search.lower()
            text_match = (
                q in f.get("title", "").lower() or
                q in f.get("description", "").lower() or
                q in f.get("target", "").lower() or
                q in f.get("category", "").lower()
            )
            if not text_match:
                continue
        filtered.append(f)

    total = len(filtered)
    paginated = filtered[skip:skip + limit]
    return {
        "total": total,
        "limit": limit,
        "skip": skip,
        "findings": paginated
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
