# ─────────────────────────────────────────
# Netrix — scans.py (API v1)
# Purpose: Scan management endpoints (create, list, get, status,
#          results, delete, WebSocket progress).
# Author: Netrix Development Team
# ─────────────────────────────────────────

import asyncio
import logging
import math
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.database.session import get_db
from app.dependencies import get_scan_manager
from app.models.host import Host
from app.models.port import Port
from app.models.vulnerability import Vulnerability
from app.scanner.scan_manager import ScanManager
from app.schemas.scan import ScanCreate, ScanList, ScanResponse, ScanStatus
from app.services.scan_service import ScanService

logger = logging.getLogger("netrix")

router = APIRouter()


@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scan",
)
async def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    scan_manager: ScanManager = Depends(get_scan_manager),
):
    """
    Launch a new network scan against a target.

    The target is validated and a scan record is created in the database.
    The scan is then started asynchronously via the ScanManager thread pool.

    Args:
        scan_data: Scan creation payload with target and scan_type.

    Returns:
        ScanResponse: The newly created scan record.

    Raises:
        InvalidTargetException: If the target is invalid.
        ScanAlreadyRunningException: If a scan is already running for this target.
    """
    service = ScanService(db)
    scan = service.create_scan(
        target=scan_data.target,
        scan_type=scan_data.scan_type,
        user_id=current_user.id,
        custom_args=scan_data.custom_args,
        custom_ports=scan_data.custom_ports,
    )

    # Start the scan asynchronously
    await service.start_scan_async(scan, scan_manager)

    logger.info(
        "[NETRIX] Scan %s created and queued by user '%s'.",
        scan.scan_id, current_user.username,
    )
    return scan


@router.get(
    "/",
    response_model=ScanList,
    status_code=status.HTTP_200_OK,
    summary="List scans",
)
async def list_scans(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    scan_status: Optional[str] = Query(
        None,
        alias="status",
        description="Filter by status (pending, running, completed, failed)",
    ),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    List all scans for the current user with pagination.

    Supports optional status filtering and configurable page size.

    Returns:
        ScanList: Paginated list of scan records.
    """
    service = ScanService(db)
    scans, total = service.list_scans(
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        status=scan_status,
    )

    return ScanList(
        scans=scans,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 0,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Get scan details",
)
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get detailed information about a specific scan.

    Returns:
        ScanResponse: Full scan record including results summary.

    Raises:
        ScanNotFoundException: If the scan does not exist or does not
                               belong to the user.
    """
    service = ScanService(db)
    return service.get_scan(scan_id, current_user.id)


@router.get(
    "/{scan_id}/status",
    response_model=ScanStatus,
    status_code=status.HTTP_200_OK,
    summary="Get scan status",
)
async def get_scan_status(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    scan_manager: ScanManager = Depends(get_scan_manager),
):
    """
    Get lightweight live status of a scan.

    Combines the database record with live progress from the ScanManager
    for active scans.

    Returns:
        ScanStatus: Current scan status and progress percentage.
    """
    service = ScanService(db)
    status_data = await service.get_scan_status(scan_id, current_user.id, scan_manager)
    return ScanStatus(**status_data)


@router.get(
    "/{scan_id}/results",
    status_code=status.HTTP_200_OK,
    summary="Get scan results",
)
async def get_scan_results(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get full scan results including hosts and vulnerabilities.

    Returns the scan record with nested host and vulnerability data.
    Only available for completed scans.

    Returns:
        dict: Scan data with hosts and vulnerability counts.

    Raises:
        ScanNotFoundException: If the scan does not exist.
    """
    service = ScanService(db)
    scan = service.get_scan(scan_id, current_user.id)

    hosts = db.query(Host).filter(Host.scan_id == scan.id).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()

    # Fetch ports for each host
    host_ids = [h.id for h in hosts]
    ports = db.query(Port).filter(Port.host_id.in_(host_ids)).all() if host_ids else []
    ports_by_host = {}
    for p in ports:
        ports_by_host.setdefault(p.host_id, []).append(p)

    return {
        "scan": scan.to_dict(),
        "hosts": [
            {
                "id": h.id,
                "ip_address": h.ip_address,
                "hostname": h.hostname,
                "status": h.status,
                "os_name": h.os_name,
                "risk_score": h.risk_score,
                "risk_level": h.risk_level,
                "ports": [
                    {
                        "port_number": p.port_number,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service_name": p.service_name,
                        "product": p.product or "",
                        "version": p.version or "",
                        "is_critical_port": p.is_critical_port,
                    }
                    for p in sorted(
                        ports_by_host.get(h.id, []),
                        key=lambda x: x.port_number,
                    )
                ],
            }
            for h in hosts
        ],
        "vulnerabilities": [
            {
                "id": v.id,
                "cve_id": v.cve_id,
                "severity": v.severity,
                "title": v.title,
                "cvss_score": v.cvss_score,
            }
            for v in vulns
        ],
        "summary": {
            "total_hosts": len(hosts),
            "total_vulnerabilities": len(vulns),
            "total_open_ports": sum(
                1 for p in ports if p.state == "open"
            ),
        },
    }


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a scan",
)
async def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Delete a completed or failed scan and all associated data.

    Cannot delete scans that are still running or pending.

    Returns:
        dict: Confirmation message.

    Raises:
        ScanNotFoundException: If the scan does not exist.
        ScanAlreadyRunningException: If the scan is still in progress.
    """
    service = ScanService(db)
    service.delete_scan(scan_id, current_user.id)
    return {"message": f"Scan {scan_id} deleted successfully."}


@router.websocket("/{scan_id}/ws")
async def scan_progress_ws(
    websocket: WebSocket,
    scan_id: str,
    scan_manager: ScanManager = Depends(get_scan_manager),
):
    """
    WebSocket endpoint for real-time scan progress updates.

    Clients connect to ``/scans/{scan_id}/ws`` and receive JSON messages
    with the scan's current progress until the scan completes.
    """
    await websocket.accept()
    logger.info("[NETRIX] WebSocket connected for scan %s.", scan_id)

    try:
        while True:
            live_status = scan_manager.get_scan_status(scan_id)

            if live_status:
                await websocket.send_json(live_status)
                if live_status.get("status") in ("completed", "failed"):
                    break
            else:
                await websocket.send_json({
                    "scan_id": scan_id,
                    "status": "completed",
                    "progress": 100,
                    "message": "Scan finished or not found.",
                })
                break

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        logger.info("[NETRIX] WebSocket disconnected for scan %s.", scan_id)
    except Exception as ws_error:
        logger.error(
            "[NETRIX] WebSocket error for scan %s: %s",
            scan_id, str(ws_error),
        )
        await websocket.close()
