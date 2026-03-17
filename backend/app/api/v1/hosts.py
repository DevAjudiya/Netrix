# ─────────────────────────────────────────
# Netrix — hosts.py (API v1)
# Purpose: Host discovery, details, ports, and per-host
#          vulnerability endpoints.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import logging
import math
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.exceptions import ScanNotFoundException
from app.core.security import get_current_user
from app.database.session import get_db
from app.models.host import Host
from app.models.port import Port
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan
from app.schemas.host import HostResponse, HostWithPorts, PortResponse
from app.schemas.vulnerability import VulnerabilityResponse

logger = logging.getLogger("netrix")

router = APIRouter()


@router.get("/")
async def get_hosts(
    scan_id: Optional[int] = Query(None),
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        query = db.query(Host)
        if scan_id:
            query = query.filter(
                Host.scan_id == scan_id
            )
        hosts = query.all()
        
        result = []
        for host in hosts:
            ports = db.query(Port).filter(
                Port.host_id == host.id
            ).all()
            h = host.to_dict()
            h['ports'] = [p.to_dict() for p in ports]
            result.append(h)
        
        return result
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get(
    "/{host_id}",
    response_model=HostWithPorts,
    status_code=status.HTTP_200_OK,
    summary="Get host details",
)
async def get_host(
    host_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get detailed information about a specific host, including all ports.

    Returns:
        HostWithPorts: Host record with nested port data.

    Raises:
        ScanNotFoundException: If the host does not exist or does not
                               belong to a user-owned scan.
    """
    user_scan_ids = db.query(Scan.id).filter(Scan.user_id == current_user.id)
    host = db.query(Host).filter(
        Host.id == host_id,
        Host.scan_id.in_(user_scan_ids),
    ).first()

    if not host:
        raise ScanNotFoundException(
            message="Host not found.",
            details=f"Host ID {host_id} does not exist.",
        )

    # Eagerly load ports
    ports = db.query(Port).filter(Port.host_id == host.id).all()
    host.ports = ports

    return host


@router.get(
    "/{host_id}/ports",
    status_code=status.HTTP_200_OK,
    summary="Get host ports",
)
async def get_host_ports(
    host_id: int,
    state: Optional[str] = Query(None, description="Filter by port state (open, closed, filtered)"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get all discovered ports for a specific host.

    Supports optional state filtering.

    Returns:
        dict: List of port records for the host.

    Raises:
        ScanNotFoundException: If the host does not exist.
    """
    user_scan_ids = db.query(Scan.id).filter(Scan.user_id == current_user.id)
    host = db.query(Host).filter(
        Host.id == host_id,
        Host.scan_id.in_(user_scan_ids),
    ).first()

    if not host:
        raise ScanNotFoundException(
            message="Host not found.",
            details=f"Host ID {host_id} does not exist.",
        )

    query = db.query(Port).filter(Port.host_id == host.id)
    if state:
        query = query.filter(Port.state == state.lower())

    ports = query.order_by(Port.port_number.asc()).all()

    return {
        "host_id": host.id,
        "ip_address": host.ip_address,
        "total_ports": len(ports),
        "ports": [
            {
                "id": p.id,
                "port_number": p.port_number,
                "protocol": p.protocol,
                "state": p.state,
                "service_name": p.service_name,
                "product": p.product,
                "version": p.version,
                "cpe": p.cpe,
                "is_critical_port": p.is_critical_port,
                "is_web_port": p.is_web_port,
                "is_database_port": p.is_database_port,
            }
            for p in ports
        ],
    }


@router.get(
    "/{host_id}/vulnerabilities",
    status_code=status.HTTP_200_OK,
    summary="Get host vulnerabilities",
)
async def get_host_vulnerabilities(
    host_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get all vulnerabilities discovered on a specific host.

    Supports optional severity filtering.

    Returns:
        dict: List of vulnerability records for the host.

    Raises:
        ScanNotFoundException: If the host does not exist.
    """
    user_scan_ids = db.query(Scan.id).filter(Scan.user_id == current_user.id)
    host = db.query(Host).filter(
        Host.id == host_id,
        Host.scan_id.in_(user_scan_ids),
    ).first()

    if not host:
        raise ScanNotFoundException(
            message="Host not found.",
            details=f"Host ID {host_id} does not exist.",
        )

    query = db.query(Vulnerability).filter(Vulnerability.host_id == host.id)
    if severity:
        query = query.filter(Vulnerability.severity == severity.lower())

    vulns = query.order_by(Vulnerability.cvss_score.desc().nullslast()).all()

    return {
        "host_id": host.id,
        "ip_address": host.ip_address,
        "total_vulnerabilities": len(vulns),
        "vulnerabilities": [
            {
                "id": v.id,
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "title": v.title,
                "description": v.description,
                "remediation": v.remediation,
                "source": v.source,
                "is_confirmed": v.is_confirmed,
            }
            for v in vulns
        ],
    }
