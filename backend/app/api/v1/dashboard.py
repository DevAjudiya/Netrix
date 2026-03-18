# ─────────────────────────────────────────
# Netrix — dashboard.py (API v1)
# Purpose: Dashboard statistics, recent scans, and chart data endpoints.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import logging
from datetime import datetime, timedelta, timezone


from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.database.session import get_db
from app.models.host import Host
from app.models.report import Report
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability

logger = logging.getLogger("netrix")

router = APIRouter()


@router.get("/stats")
async def get_stats(
    current_user = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        uid = current_user.id
        
        total_scans = db.query(Scan).filter(
            Scan.user_id == uid
        ).count()
        
        completed = db.query(Scan).filter(
            Scan.user_id == uid,
            Scan.status == 'completed'
        ).count()
        
        running = db.query(Scan).filter(
            Scan.user_id == uid,
            Scan.status == 'running'
        ).count()
        
        # Hosts from user scans
        user_scan_ids = [
            s.id for s in db.query(Scan).filter(
                Scan.user_id == uid
            ).all()
        ]
        
        total_hosts = db.query(Host).filter(
            Host.scan_id.in_(user_scan_ids)
        ).count() if user_scan_ids else 0
        
        total_vulns = db.query(Vulnerability).filter(
            Vulnerability.scan_id.in_(user_scan_ids)
        ).count() if user_scan_ids else 0
        
        critical = db.query(Vulnerability).filter(
            Vulnerability.scan_id.in_(user_scan_ids),
            Vulnerability.severity == 'critical'
        ).count() if user_scan_ids else 0
        
        total_reports = db.query(Report).filter(
            Report.user_id == uid
        ).count()

        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        scans_this_week = db.query(Scan).filter(
            Scan.user_id == uid,
            Scan.created_at >= week_ago,
        ).count()

        return {
            "total_scans": total_scans,
            "completed_scans": completed,
            "active_scans": running,
            "total_hosts_discovered": total_hosts,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical,
            "total_reports": total_reports,
            "scans_this_week": scans_this_week,
        }
    except Exception as e:
        print(f"[NETRIX] Stats error: {e}")
        return {
            "total_scans": 0,
            "completed_scans": 0,
            "active_scans": 0,
            "total_hosts_discovered": 0,
            "total_vulnerabilities": 0,
            "critical_vulnerabilities": 0,
            "total_reports": 0,
            "scans_this_week": 0
        }


@router.get(
    "/recent-scans",
    status_code=status.HTTP_200_OK,
    summary="Get recent scans",
)
async def get_recent_scans(
    limit: int = Query(5, ge=1, le=20, description="Number of recent scans"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get the most recent scans for the dashboard overview.

    Returns:
        dict: List of recent scan records ordered by creation date.
    """
    scans = (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .all()
    )

    return {
        "recent_scans": [s.to_dict() for s in scans],
        "total": len(scans),
    }


@router.get(
    "/vulnerability-chart",
    status_code=status.HTTP_200_OK,
    summary="Get vulnerability distribution chart data",
)
async def get_vulnerability_chart(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get vulnerability severity distribution for chart rendering.

    Returns a breakdown of vulnerability counts per severity level,
    suitable for pie charts or bar charts on the dashboard.

    Returns:
        dict: Severity distribution with labels, values, and colours.
    """
    user_scan_ids = db.query(Scan.id).filter(Scan.user_id == current_user.id)

    severity_counts = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .filter(Vulnerability.scan_id.in_(user_scan_ids))
        .group_by(Vulnerability.severity)
        .all()
    )

    severity_map = {sev: count for sev, count in severity_counts}

    colours = {
        "critical": "#DC2626",
        "high": "#F97316",
        "medium": "#EAB308",
        "low": "#3B82F6",
        "info": "#6B7280",
    }

    chart_data = []
    for level in ("critical", "high", "medium", "low", "info"):
        chart_data.append({
            "label": level.capitalize(),
            "value": severity_map.get(level, 0),
            "color": colours[level],
        })

    return {
        "chart_type": "vulnerability_distribution",
        "data": chart_data,
        "total": sum(item["value"] for item in chart_data),
    }


@router.get(
    "/scan-history-chart",
    status_code=status.HTTP_200_OK,
    summary="Get scan history chart data",
)
async def get_scan_history_chart(
    days: int = Query(30, ge=7, le=365, description="Number of days to look back"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get scan activity over time for timeline chart rendering.

    Returns daily scan counts for the specified time range,
    suitable for line charts or area charts on the dashboard.

    Returns:
        dict: Daily scan counts with dates and values.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    scans = (
        db.query(Scan)
        .filter(
            Scan.user_id == current_user.id,
            Scan.created_at >= cutoff,
        )
        .all()
    )

    # Build a daily count map
    daily_counts: dict = {}
    for scan in scans:
        day = scan.created_at.strftime("%Y-%m-%d")
        daily_counts[day] = daily_counts.get(day, 0) + 1

    # Fill in zeroes for days with no scans
    chart_data = []
    current_date = cutoff.date()
    end_date = datetime.now(timezone.utc).date()
    while current_date <= end_date:
        date_str = current_date.strftime("%Y-%m-%d")
        chart_data.append({
            "date": date_str,
            "scans": daily_counts.get(date_str, 0),
        })
        current_date += timedelta(days=1)

    return {
        "chart_type": "scan_history",
        "days": days,
        "data": chart_data,
        "total_scans": sum(item["scans"] for item in chart_data),
    }
