# ─────────────────────────────────────────
# Netrix — scans.py (API v1)
# Purpose: Scan management endpoints (create, list, get, status,
#          results, delete, WebSocket progress).
# Author: Netrix Development Team
# ─────────────────────────────────────────

import asyncio
import logging
import math
import traceback
import uuid
from datetime import datetime, timezone

from fastapi import (
    APIRouter, BackgroundTasks, Depends,
    HTTPException, Query, Request, WebSocket,
    WebSocketDisconnect, status,
)
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.security import get_current_user
from app.database.session import get_db
from app.dependencies import get_scan_manager
from app.services.audit_service import log_event
from app.models.host import Host
from app.models.port import Port
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.scanner.scan_manager import ScanManager
from app.schemas.scan import ScanCreate, ScanList, ScanResponse, ScanStatus
from app.services.scan_service import ScanService

logger = logging.getLogger("netrix")

router = APIRouter()


# ─────────────────────────────────────────
# MODULE-LEVEL background task function
# MUST be outside the router / class
# Creates its own DB session via SessionLocal
# ─────────────────────────────────────────
async def run_scan_background(
    scan_id: str,
    target: str,
    scan_type: str,
    user_id: int,
):
    """
    Background task that runs the actual Nmap scan.

    This function is invoked by FastAPI BackgroundTasks *after*
    the HTTP response has already been sent. It creates its OWN
    database session using SessionLocal() so it is completely
    independent of the request lifecycle.
    """
    from app.database.session import SessionLocal

    db = SessionLocal()
    try:
        print(f"[NETRIX] 🔍 Starting background scan: {scan_id}")

        # ── Step 1: Retrieve scan record ─────────────────────────
        scan = db.query(Scan).filter(
            Scan.scan_id == scan_id
        ).first()

        if not scan:
            print(f"[NETRIX] ❌ Scan {scan_id} not found in database!")
            return

        # ── Step 2: Mark as running ──────────────────────────────
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 5
        db.commit()
        print(f"[NETRIX] Scan {scan_id} → running")

        # ── Step 3: Execute the actual Nmap scan ─────────────────
        from app.scanner.nmap_engine import NmapEngine, ScanType

        engine = NmapEngine()

        # Map scan type string to ScanType enum
        scan_type_map = {
            "quick": ScanType.QUICK,
            "stealth": ScanType.STEALTH,
            "full": ScanType.FULL,
            "aggressive": ScanType.AGGRESSIVE,
            "vulnerability": ScanType.VULNERABILITY,
            "custom": ScanType.QUICK,
        }

        nmap_scan_type = scan_type_map.get(
            scan_type.lower(),
            ScanType.QUICK,
        )

        print(f"[NETRIX] Running nmap on {target} (type={scan_type})")

        # run_scan() is BLOCKING — run in thread executor
        loop = asyncio.get_event_loop()
        summary = await loop.run_in_executor(
            None,
            lambda: engine.run_scan(
                target=target,
                scan_type=nmap_scan_type,
                scan_id=scan_id,
            ),
        )

        print(
            f"[NETRIX] Nmap scan completed! "
            f"Hosts found: {len(summary.hosts)}"
        )

        # ── Step 4: Update progress ──────────────────────────────
        scan.progress = 80
        db.commit()

        # ── Step 5: Save hosts to database ───────────────────────
        saved_hosts = 0
        saved_ports = 0

        for host_result in summary.hosts:
            print(f"[NETRIX] Saving host: {host_result.ip}")

            db_host = Host(
                scan_id=scan.id,
                ip_address=host_result.ip,
                hostname=host_result.hostname or "",
                status=host_result.status or "up",
                os_name=getattr(
                    host_result.os_info, "name", ""
                ) or "",
                os_accuracy=int(getattr(
                    host_result.os_info, "accuracy", 0
                ) or 0),
                os_family=getattr(
                    host_result.os_info, "os_family", ""
                ) or "",
                os_generation=getattr(
                    host_result.os_info, "os_generation", ""
                ) or "",
                os_cpe=getattr(
                    host_result.os_info, "cpe", ""
                ) or "",
                mac_address=host_result.mac_address or "",
                mac_vendor=host_result.mac_vendor or "",
                uptime=str(host_result.uptime or ""),
                tcp_sequence=str(
                    getattr(host_result, "tcp_sequence", "")
                    or ""
                ),
                risk_score=host_result.risk_score or 0,
                risk_level=host_result.risk_level or "info",
            )
            db.add(db_host)
            db.flush()  # Get db_host.id for port FK
            saved_hosts += 1

            # ── Step 6: Save ports for this host ─────────────────
            for service in host_result.services:
                db_port = Port(
                    host_id=db_host.id,
                    port_number=int(service.port),
                    protocol=service.protocol or "tcp",
                    state=service.state or "open",
                    service_name=service.service_name or "",
                    product=service.product or "",
                    version=service.version or "",
                    extra_info=service.extra_info or "",
                    cpe=service.cpe or "",
                    nse_output=service.nse_scripts
                    if service.nse_scripts
                    else {},
                    is_critical_port=getattr(
                        service, "is_critical_port", False
                    ),
                )
                db.add(db_port)
                saved_ports += 1

        # ── Step 7: Final scan record update ─────────────────────
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.total_hosts = summary.total_hosts or 0
        scan.hosts_up = summary.hosts_up or 0
        scan.hosts_down = summary.hosts_down or 0
        scan.progress = 100
        db.commit()

        print(f"[NETRIX] ✅ Scan {scan_id} COMPLETE!")
        print(f"[NETRIX]    Hosts saved: {saved_hosts}")
        print(f"[NETRIX]    Ports saved: {saved_ports}")

    except Exception as e:
        print(f"[NETRIX] ❌ Background scan error: {e}")
        traceback.print_exc()

        # Mark scan as failed
        try:
            scan = db.query(Scan).filter(
                Scan.scan_id == scan_id
            ).first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)[:2000]
                scan.progress = 0
                scan.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception as db_error:
            print(f"[NETRIX] ❌ DB error while marking failed: {db_error}")
            db.rollback()
    finally:
        db.close()
        print(f"[NETRIX] DB session closed for scan {scan_id}")


# ─────────────────────────────────────────
# POST /scans/ — Create and launch a scan
# ─────────────────────────────────────────
@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scan",
)
async def create_scan(
    scan_data: ScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    scan_manager: ScanManager = Depends(get_scan_manager),
):
    """
    Launch a new network scan against a target.

    Creates a scan record in the database ('pending' state) and
    launches the Nmap scan via ScanManager so that WebSocket
    events are properly streamed to connected clients.
    """
    service = ScanService(db)
    scan = service.create_scan(
        target=scan_data.target,
        scan_type=scan_data.scan_type,
        user_id=current_user.id,
        custom_args=scan_data.custom_args,
        custom_ports=scan_data.custom_ports,
    )

    # Launch via ScanManager — enables WebSocket event streaming
    await scan_manager.launch_scan(
        target=scan.target,
        scan_type=scan.scan_type,
        scan_id=scan.scan_id,
        user_id=current_user.id,
        custom_args=scan_data.custom_args or "",
        custom_ports=scan_data.custom_ports or "",
    )

    log_event(db, current_user.id, "scan_start", request,
              {"scan_id": scan.scan_id, "target": scan.target, "scan_type": scan.scan_type})
    logger.info(
        "[NETRIX] Scan %s created and launched by user '%s'.",
        scan.scan_id, current_user.username,
    )
    return scan


# ─────────────────────────────────────────
# GET /scans/ — List scans (paginated)
# ─────────────────────────────────────────
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


# ─────────────────────────────────────────
# GET /scans/{scan_id} — Get single scan
# ─────────────────────────────────────────
@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve a scan by scan_id (NETRIX_XXX) or numeric id."""
    # Try string scan_id first (NETRIX_ABC123 format)
    scan = db.query(Scan).filter(
        Scan.scan_id == scan_id
    ).first()

    # If not found, try numeric id
    if not scan and scan_id.isdigit():
        scan = db.query(Scan).filter(
            Scan.id == int(scan_id)
        ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found",
        )

    return scan.to_dict()


# ─────────────────────────────────────────
# GET /scans/{scan_id}/status — Lightweight status
# ─────────────────────────────────────────
@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get lightweight scan status for polling."""
    scan = db.query(Scan).filter(
        Scan.scan_id == scan_id
    ).first()

    if not scan:
        raise HTTPException(404, "Not found")

    # Count real vuln totals from DB (service-matched CVEs are not stored
    # in scan.total_vulnerabilities, so we query Vulnerability directly)
    total_vulns = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan.id
    ).count()
    critical_vulns = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan.id,
        Vulnerability.severity == "critical",
    ).count()
    total_ports = db.query(Port).join(Host).filter(
        Host.scan_id == scan.id
    ).count()

    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "progress": scan.progress or 0,
        "started_at": str(scan.started_at) if scan.started_at else None,
        "completed_at": str(scan.completed_at) if scan.completed_at else None,
        "error_message": scan.error_message,
        "total_hosts": scan.total_hosts or 0,
        "hosts_up": scan.hosts_up or 0,
        "total_vulns": total_vulns,
        "total_ports": total_ports,
        "critical_count": critical_vulns,
    }


# ─────────────────────────────────────────
# GET /scans/{scan_id}/results — Full results
# ─────────────────────────────────────────
@router.get("/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get full scan results with hosts, ports, and vulnerabilities."""
    # Find scan (try string scan_id first)
    scan = db.query(Scan).filter(
        Scan.scan_id == scan_id
    ).first()

    # If not found, try numeric id
    if not scan and scan_id.isdigit():
        scan = db.query(Scan).filter(
            Scan.id == int(scan_id)
        ).first()

    if not scan:
        raise HTTPException(404, "Not found")

    # Get all hosts
    hosts = db.query(Host).filter(
        Host.scan_id == scan.id
    ).all()

    hosts_data = []
    for host in hosts:
        ports = db.query(Port).filter(
            Port.host_id == host.id
        ).all()
        vulns = db.query(Vulnerability).filter(
            Vulnerability.host_id == host.id
        ).all()

        h = host.to_dict()
        h["ports"] = [p.to_dict() for p in ports]
        h["vulnerabilities"] = [
            v.to_dict() for v in vulns
        ]
        hosts_data.append(h)

    return {
        "scan": scan.to_dict(),
        "hosts": hosts_data,
        "total_hosts": len(hosts_data),
        "total_ports": sum(
            len(h["ports"]) for h in hosts_data
        ),
        "total_vulnerabilities": sum(
            len(h["vulnerabilities"])
            for h in hosts_data
        ),
    }


# ─────────────────────────────────────────
# GET /scans/{scan_id}/hosts — Hosts for a scan
# ─────────────────────────────────────────
@router.get("/{scan_id}/hosts")
async def get_scan_hosts(
    scan_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get all hosts discovered in a scan, with their ports."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan and scan_id.isdigit():
        scan = db.query(Scan).filter(Scan.id == int(scan_id)).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    hosts = db.query(Host).filter(Host.scan_id == scan.id).all()
    hosts_data = []
    for host in hosts:
        ports = db.query(Port).filter(Port.host_id == host.id).all()
        h = host.to_dict()
        h["ports"] = [p.to_dict() for p in ports]
        hosts_data.append(h)

    return {
        "scan_id": scan.scan_id,
        "total_hosts": len(hosts_data),
        "hosts": hosts_data,
    }


# ─────────────────────────────────────────
# GET /scans/{scan_id}/vulns — Vulns for a scan
# ─────────────────────────────────────────
@router.get("/{scan_id}/vulns")
async def get_scan_vulns(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get all vulnerabilities discovered in a scan."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan and scan_id.isdigit():
        scan = db.query(Scan).filter(Scan.id == int(scan_id)).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id)
    if severity:
        query = query.filter(Vulnerability.severity == severity.lower())

    vulns = query.order_by(
        Vulnerability.cvss_score.is_(None),
        Vulnerability.cvss_score.desc(),
    ).all()

    return {
        "scan_id": scan.scan_id,
        "total_vulnerabilities": len(vulns),
        "vulnerabilities": [v.to_dict() for v in vulns],
    }


# ─────────────────────────────────────────
# DELETE /scans/{scan_id} — Delete a scan
# ─────────────────────────────────────────
@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a scan",
)
async def delete_scan(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Delete a completed or failed scan and all associated data.
    """
    service = ScanService(db)
    # Capture scan_id string before deletion for audit log
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    scan_id_str = scan.scan_id if scan else str(scan_id)
    service.delete_scan(scan_id, current_user.id)
    log_event(db, current_user.id, "scan_delete", request, {"scan_id": scan_id_str})
    return {"message": f"Scan {scan_id} deleted successfully."}


# ─────────────────────────────────────────
# WebSocket /scans/ws/{scan_id} — Live progress
# ─────────────────────────────────────────
@router.websocket("/ws/{scan_id}")
async def scan_websocket(
    websocket: WebSocket,
    scan_id: str,
):
    """
    WebSocket endpoint for real-time scan event streaming.

    Clients connect to ``/api/v1/scans/ws/{scan_id}?token=<jwt>``
    and receive granular JSON events in real-time.
    """
    # ── Step 1: Authenticate via query param ─────────────────
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008, reason="Missing token")
        return

    from app.core.security import verify_token_websocket
    payload = verify_token_websocket(token)

    if payload is None:
        await websocket.close(code=1008, reason="Invalid token")
        return

    user_id = payload.get("user_id")
    if not user_id:
        await websocket.close(code=1008, reason="Invalid token payload")
        return

    # ── Step 2: Accept connection ────────────────────────────
    await websocket.accept()
    logger.info("[NETRIX] WebSocket connected for scan %s (user=%s).", scan_id, user_id)

    # ── Step 3: Get scan manager ─────────────────────────────
    from app.dependencies import get_scan_manager_instance
    scan_manager = get_scan_manager_instance()

    # ── Step 4: Send connected event ─────────────────────────
    await websocket.send_json({
        "event": "connected",
        "message": "🔗 WebSocket connected — streaming live events...",
        "scan_id": scan_id,
    })

    # ── Step 5: Register event queue ─────────────────────────
    event_queue = scan_manager.register_event_queue(scan_id)

    try:
        no_activity_count = 0
        max_no_activity = 150  # 150 × 2s = 5 minutes timeout

        while True:
            # Read all available events from the queue
            import queue as queue_module
            events_sent = 0

            while True:
                try:
                    event = event_queue.get_nowait()
                    await websocket.send_json(event)
                    events_sent += 1

                    # If terminal event, exit
                    if event.get("event") in ("scan_complete", "error"):
                        await asyncio.sleep(0.5)
                        logger.info(
                            "[NETRIX] Scan %s terminal event sent, closing WS.",
                            scan_id,
                        )
                        return
                except queue_module.Empty:
                    break

            if events_sent > 0:
                no_activity_count = 0
            else:
                no_activity_count += 1

            # Check if scan is still active
            if scan_id not in scan_manager.active_scans:
                # Scan may have finished before WS connected, or this is a
                # different worker process — check the actual DB status.
                live = await scan_manager.get_scan_status(scan_id)
                scan_status_val = live.get("status", "unknown")

                if scan_status_val in ("pending", "running"):
                    # Scan is still in progress per DB — keep waiting
                    pass
                elif scan_status_val == "failed":
                    # Scan already failed — send proper error event
                    err_msg = live.get("message", "Scan failed.")
                    await websocket.send_json({
                        "event": "error",
                        "message": f"❌ {err_msg}",
                        "scan_id": scan_id,
                    })
                    return

                elif scan_status_val == "completed":
                    # Fetch real totals from DB
                    total_hosts = total_ports = total_vulns = 0
                    try:
                        from app.database.session import SessionLocal
                        from app.models.scan import Scan as ScanModel
                        from app.models.host import Host as HostModel
                        from app.models.port import Port as PortModel
                        from app.models.vulnerability import Vulnerability as VulnModel
                        _db = SessionLocal()
                        try:
                            _scan = _db.query(ScanModel).filter(
                                ScanModel.scan_id == scan_id
                            ).first()
                            if _scan:
                                total_hosts = _scan.hosts_up or 0
                                total_ports = (
                                    _db.query(PortModel)
                                    .join(HostModel, PortModel.host_id == HostModel.id)
                                    .filter(HostModel.scan_id == _scan.id)
                                    .count()
                                )
                                total_vulns = (
                                    _db.query(VulnModel)
                                    .filter(VulnModel.scan_id == _scan.id)
                                    .count()
                                )
                        finally:
                            _db.close()
                    except Exception:
                        pass

                    await websocket.send_json({
                        "event": "scan_complete",
                        "progress": 100,
                        "total_hosts": total_hosts,
                        "total_ports": total_ports,
                        "total_vulns": total_vulns,
                        "critical_count": 0,
                        "duration": "N/A",
                        "message": "✅ Scan completed.",
                        "scan_id": scan_id,
                    })
                    return

            # Timeout after extended inactivity
            if no_activity_count >= max_no_activity:
                await websocket.send_json({
                    "event": "error",
                    "message": "❌ Scan timed out — no activity for 5 minutes.",
                    "scan_id": scan_id,
                })
                return

            # Wait before next poll cycle
            await asyncio.sleep(2)

    except WebSocketDisconnect:
        logger.info("[NETRIX] WebSocket disconnected for scan %s.", scan_id)
    except Exception as ws_error:
        logger.error(
            "[NETRIX] WebSocket error for scan %s: %s",
            scan_id, str(ws_error),
        )
        try:
            await websocket.send_json({
                "event": "error",
                "message": f"❌ WebSocket error: {str(ws_error)[:100]}",
                "scan_id": scan_id,
            })
        except Exception:
            pass
    finally:
        scan_manager.unregister_event_queue(scan_id, event_queue)
        try:
            await websocket.close()
        except Exception:
            pass
