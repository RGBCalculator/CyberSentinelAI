import logging
from typing import Optional, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, model_validator

from app.scanner import (
    ScanOrchestrator,
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanType,
)

logger = logging.getLogger(__name__)

# Module-level reusable orchestrator instance (stateless and safe for concurrent requests)
_orchestrator: Optional[ScanOrchestrator] = None


def get_scan_orchestrator() -> ScanOrchestrator:
    """
    Dependency provider that yields a reusable, thread-safe ScanOrchestrator instance.
    Can be overridden in tests via app.dependency_overrides.
    """
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ScanOrchestrator()
    return _orchestrator


router = APIRouter(tags=["Scanner"])


@router.post(
    "/scan",
    response_model=ScanResult,
    status_code=status.HTTP_200_OK,
    summary="Scan target asset",
    description="Executes the standardized security scanning pipeline on the provided target asset (e.g., URL)."
)
@router.post(
    "/scan/",
    response_model=ScanResult,
    status_code=status.HTTP_200_OK,
    include_in_schema=False
)
async def scan_target(
    request: ScanRequest,
    orchestrator: ScanOrchestrator = Depends(get_scan_orchestrator),
) -> ScanResult:
    """
    Receives a ScanRequest, executes the scanning pipeline via ScanOrchestrator,
    and returns the standardized ScanResult report.
    """
    target = request.target.strip() if request.target else ""
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target cannot be empty."
        )

    # Basic protocol validation for URL scans
    if request.scan_type == ScanType.URL:
        if not target.startswith(("http://", "https://")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid URL target. URL must begin with 'http://' or 'https://'."
            )

    try:
        result = await orchestrator.run_scan(request)
    except Exception as exc:
        logger.error(
            "Unexpected error running scan on target '%s': %s",
            request.target,
            exc,
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan execution failed due to an internal error."
        )

    if result.status == ScanStatus.FAILED:
        logger.error("Scan %s failed for target: %s", result.scan_id, request.target)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan processing failed. Please verify the target and try again."
        )

    # Persist scan history to MongoDB (fail-safe for offline/mock environments)
    try:
        from app.models.scan import ScanRecord
        critical_count = sum(1 for f in result.findings if getattr(f.severity, "value", f.severity) == "critical")
        high_count = sum(1 for f in result.findings if getattr(f.severity, "value", f.severity) == "high")
        medium_count = sum(1 for f in result.findings if getattr(f.severity, "value", f.severity) == "medium")
        low_count = sum(1 for f in result.findings if getattr(f.severity, "value", f.severity) == "low")

        record = ScanRecord(
            scan_id=result.scan_id,
            target=request.target,
            scan_type=request.scan_type.value,
            status=result.status.value,
            risk_level=result.risk_level.value,
            risk_score=float(result.risk_score),
            overall_confidence=float(result.overall_confidence),
            execution_duration=float(result.execution_duration),
            findings_count=len(result.findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            findings=[f.model_dump(mode="json") if hasattr(f, "model_dump") else dict(f) for f in result.findings],
            threat_intel=result.threat_intel,
            ai_analysis=result.ai_analysis,
            statistics=result.statistics,
            created_at=result.created_at
        )
        await record.insert()
    except Exception as db_err:
        logger.debug("Could not persist ScanRecord to MongoDB (non-fatal): %s", db_err)

    return result


@router.get(
    "/scans",
    summary="Get recent scans",
    description="Returns a paginated list of historical security scans from MongoDB."
)
async def get_recent_scans(
    limit: int = 20,
    skip: int = 0,
    risk_level: Optional[str] = None
):
    """Retrieves recent scans for the SOC dashboard."""
    try:
        from app.models.scan import ScanRecord
        query = {}
        if risk_level:
            query["risk_level"] = risk_level.lower()
        
        records = await ScanRecord.find(query).sort("-created_at").skip(skip).limit(min(limit, 100)).to_list()
        total = await ScanRecord.find(query).count()
        return {
            "total": total,
            "scans": [
                {
                    "scan_id": r.scan_id,
                    "target": r.target,
                    "scan_type": r.scan_type,
                    "risk_level": r.risk_level,
                    "risk_score": r.risk_score,
                    "findings_count": r.findings_count,
                    "critical_count": r.critical_count,
                    "high_count": r.high_count,
                    "execution_duration": r.execution_duration,
                    "threat_intel_verdict": r.threat_intel.get("verdict", "unknown") if r.threat_intel else "unknown",
                    "ai_prediction": r.ai_analysis.get("prediction", "unknown") if r.ai_analysis else "unknown",
                    "created_at": r.created_at.isoformat() if hasattr(r.created_at, "isoformat") else str(r.created_at)
                }
                for r in records
            ]
        }
    except Exception as err:
        logger.warning("Failed retrieving scans from MongoDB: %s", err)
        return {"total": 0, "scans": []}


@router.get(
    "/scans/{scan_id}",
    summary="Get scan by ID",
    description="Retrieves a specific historical scan record."
)
async def get_scan_by_id(scan_id: str):
    """Retrieves an individual scan report by ID."""
    try:
        from app.models.scan import ScanRecord
        record = await ScanRecord.find_one(ScanRecord.scan_id == scan_id)
        if not record:
            raise HTTPException(status_code=404, detail="Scan record not found.")
        return record.model_dump(mode="json")
    except HTTPException:
        raise
    except Exception as err:
        logger.error("Error retrieving scan %s: %s", scan_id, err)
        raise HTTPException(status_code=500, detail="Database query failed.")


class FakeLoginScanRequest(BaseModel):
    target: Optional[str] = Field(default=None, description="Target website URL to inspect for fake login patterns")
    url: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def populate_target(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("target") and data.get("url"):
                data["target"] = data["url"]
        return data


@router.post(
    "/scan/fake-login",
    summary="Fake Login Page & Phishing Detection",
    description="Inspects target page structure for brand impersonation, cross-origin form submissions, and credential harvesting."
)
async def scan_fake_login_page(req: FakeLoginScanRequest):
    """Safely analyzes target web page for phishing and fake login indicators."""
    target = (req.target or req.url or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")

    try:
        from app.scanner.phishing import fake_login_detector
        result = await fake_login_detector.analyze_url(target)
        if not result.get("analyzed") and result.get("verdict") == "blocked":
            raise HTTPException(status_code=400, detail=result.get("error"))
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Fake login inspection failed for %s: %s", target, e)
        raise HTTPException(status_code=500, detail=f"Fake login inspection failed: {str(e)}")

