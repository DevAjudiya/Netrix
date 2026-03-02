# ─────────────────────────────────────────
# Netrix — vulnerabilities.py (API v1)
# Purpose: Vulnerability lookup, CVE data, and statistics endpoints.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import logging
import math
from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.exceptions import ScanNotFoundException
from app.core.security import get_current_user
from app.database.session import get_db
from app.dependencies import get_cve_engine
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import (
    VulnerabilityList,
    VulnerabilityResponse,
)
from app.services.cve_service import CVEService

logger = logging.getLogger("netrix")

router = APIRouter()


@router.get(
    "/",
    response_model=VulnerabilityList,
    status_code=status.HTTP_200_OK,
    summary="List vulnerabilities",
)
async def list_vulnerabilities(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    source: Optional[str] = Query(None, description="Filter by source"),
    confirmed_only: bool = Query(False, description="Only confirmed vulnerabilities"),
    scan_id: Optional[int] = Query(None, description="Filter by scan ID"),
    min_cvss: Optional[float] = Query(None, ge=0.0, le=10.0, description="Minimum CVSS score"),
    max_cvss: Optional[float] = Query(None, ge=0.0, le=10.0, description="Maximum CVSS score"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    List all discovered vulnerabilities across the user's scans.

    Supports filtering by severity, source, CVSS range and scan ID.

    Returns:
        VulnerabilityList: Paginated list of vulnerability records.
    """
    # Only show vulnerabilities from the user's own scans
    user_scan_ids = db.query(Scan.id).filter(Scan.user_id == current_user.id)
    query = db.query(Vulnerability).filter(Vulnerability.scan_id.in_(user_scan_ids))

    if scan_id:
        query = query.filter(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity.lower())
    if source:
        query = query.filter(Vulnerability.source == source)
    if confirmed_only:
        query = query.filter(Vulnerability.is_confirmed.is_(True))
    if min_cvss is not None:
        query = query.filter(Vulnerability.cvss_score >= min_cvss)
    if max_cvss is not None:
        query = query.filter(Vulnerability.cvss_score <= max_cvss)

    total = query.count()
    vulns = (
        query.order_by(Vulnerability.cvss_score.desc().nullslast())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return VulnerabilityList(
        vulnerabilities=vulns,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 0,
    )


@router.get(
    "/cve/{cve_id}",
    status_code=status.HTTP_200_OK,
    summary="Look up a CVE",
)
async def lookup_cve(
    cve_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Look up a specific CVE by its identifier (e.g. CVE-2023-12345).

    Checks the local database first, then falls back to the NVD API.

    Returns:
        dict: CVE detail information including description, CVSS, and remediation.
    """
    cve_service = CVEService(db)
    cve_detail = cve_service.get_cve_detail(cve_id)

    if not cve_detail:
        return {
            "cve_id": cve_id,
            "found": False,
            "message": f"No data found for {cve_id}.",
        }

    return {
        "cve_id": cve_id,
        "found": True,
        "data": cve_detail,
    }


@router.get(
    "/stats/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Get vulnerability statistics for a scan",
)
async def get_vulnerability_stats(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get vulnerability statistics for a specific scan.

    Returns counts grouped by severity, top CVEs by CVSS score,
    and an overall risk score.

    Returns:
        dict: Vulnerability statistics and risk assessment.

    Raises:
        ScanNotFoundException: If the scan does not exist.
    """
    scan = db.query(Scan).filter(
        Scan.id == scan_id, Scan.user_id == current_user.id,
    ).first()

    if not scan:
        raise ScanNotFoundException(details=f"Scan ID {scan_id} not found.")

    # Severity breakdown
    severity_counts = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .filter(Vulnerability.scan_id == scan_id)
        .group_by(Vulnerability.severity)
        .all()
    )
    severity_map = {sev: count for sev, count in severity_counts}

    # Top CVEs by CVSS score
    top_cves = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.scan_id == scan_id,
            Vulnerability.cve_id.isnot(None),
        )
        .order_by(Vulnerability.cvss_score.desc().nullslast())
        .limit(10)
        .all()
    )

    total_vulns = sum(severity_map.values())

    # Risk score calculation (weighted sum)
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
    risk_score = sum(
        weights.get(sev, 0) * count for sev, count in severity_map.items()
    )
    max_possible = total_vulns * 10 if total_vulns > 0 else 1
    risk_percentage = min(round((risk_score / max_possible) * 100, 1), 100.0)

    return {
        "scan_id": scan.scan_id,
        "total_vulnerabilities": total_vulns,
        "severity_breakdown": {
            "critical": severity_map.get("critical", 0),
            "high": severity_map.get("high", 0),
            "medium": severity_map.get("medium", 0),
            "low": severity_map.get("low", 0),
            "info": severity_map.get("info", 0),
        },
        "top_cves": [
            {
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score,
                "severity": v.severity,
                "title": v.title,
            }
            for v in top_cves
        ],
        "risk_score": risk_score,
        "risk_percentage": risk_percentage,
    }


@router.get(
    "/{vuln_id}",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_200_OK,
    summary="Get vulnerability details",
)
async def get_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get detailed information about a specific vulnerability.

    Returns:
        VulnerabilityResponse: Full vulnerability record.

    Raises:
        ScanNotFoundException: If the vulnerability does not exist or
                               does not belong to a user-owned scan.
    """
    user_scan_ids = db.query(Scan.id).filter(Scan.user_id == current_user.id)
    vuln = db.query(Vulnerability).filter(
        Vulnerability.id == vuln_id,
        Vulnerability.scan_id.in_(user_scan_ids),
    ).first()

    if not vuln:
        raise ScanNotFoundException(
            message="Vulnerability not found.",
            details=f"Vulnerability ID {vuln_id} does not exist.",
        )

    return vuln
