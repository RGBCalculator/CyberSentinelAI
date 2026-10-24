import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status

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

    return result
