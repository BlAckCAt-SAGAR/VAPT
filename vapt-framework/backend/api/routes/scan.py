"""
Scan endpoints for the VAPT Framework API.
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from typing import Optional

from api.models.schemas import (
    ScanRequest, ScanResponse, ScanStatusResponse,
    ScanListResponse, ScanStatus, ErrorResponse
)
from api.middleware.auth import api_auth
from tasks.scan_task import run_vapt_scan, get_scan_status, list_scans
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post(
    "",
    response_model=ScanResponse,
    responses={403: {"model": ErrorResponse}, 429: {"model": ErrorResponse}}
)
async def start_scan(
    scan_request: ScanRequest,
    request: Request,
    api_key: str = Depends(api_auth.validate)
):
    """
    Start a new VAPT scan.
    
    Requires API key in X-API-Key header.
    """
    try:
        # Launch Celery task
        task = run_vapt_scan.delay(
            target=scan_request.target,
            scan_type=scan_request.scan_type or "full"
        )
        
        return ScanResponse(
            scan_id=task.id,
            status=ScanStatus.PENDING,
            target=scan_request.target,
            message=f"Scan started for {scan_request.target}. Check status with GET /scans/{task.id}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")


@router.get(
    "/{scan_id}",
    response_model=ScanStatusResponse,
    responses={404: {"model": ErrorResponse}}
)
async def get_scan(
    scan_id: str,
    api_key: str = Depends(api_auth.validate)
):
    """
    Get the current status of a scan.
    """
    status = get_scan_status(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return status


@router.get(
    "/{scan_id}/report",
    responses={404: {"model": ErrorResponse}}
)
async def get_scan_report(
    scan_id: str,
    format: str = "json",
    api_key: str = Depends(api_auth.validate)
):
    """
    Get the scan report (JSON or HTML).
    """
    from tasks.scan_task import get_scan_report as fetch_report
    
    report = fetch_report(scan_id, format)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report for scan {scan_id} not found")
    return report


@router.get(
    "",
    response_model=ScanListResponse
)
async def get_scans(
    limit: int = 10,
    offset: int = 0,
    api_key: str = Depends(api_auth.validate)
):
    """
    List all past scans.
    """
    scans, total = list_scans(limit, offset)
    return ScanListResponse(scans=scans, total=total)