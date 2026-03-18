# ─────────────────────────────────────────
# Netrix — reports.py (API v1)
# Purpose: Report generation, listing, download and deletion endpoints.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import logging
import math
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session

from app.core.exceptions import ReportGenerationException, ScanNotFoundException
from app.core.security import get_current_user
from app.database.session import get_db
from app.models.report import Report
from app.models.scan import Scan
from app.schemas.report import ReportCreate, ReportResponse
from app.services.report_service import ReportService

logger = logging.getLogger("netrix")

router = APIRouter()


@router.post(
    "/generate",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a report",
)
async def generate_report(
    report_data: ReportCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Generate a report for a completed scan.

    Supports PDF, JSON, CSV, and HTML formats. The report is saved
    to disk and a database record is created for tracking.

    Args:
        report_data: Report creation payload with scan_id and format.

    Returns:
        ReportResponse: The newly generated report metadata.

    Raises:
        ScanNotFoundException: If the scan does not exist.
        ReportGenerationException: If report generation fails.
    """
    # Verify scan exists and belongs to user
    scan = db.query(Scan).filter(
        Scan.id == report_data.scan_id,
        Scan.user_id == current_user.id,
    ).first()

    if not scan:
        raise ScanNotFoundException(
            details=f"Scan ID {report_data.scan_id} not found.",
        )

    if scan.status != "completed":
        raise ReportGenerationException(
            message="Can only generate reports for completed scans.",
            details=f"Scan {scan.scan_id} is currently '{scan.status}'.",
            status_code=422,
        )

    report_service = ReportService(db)
    report = report_service.generate_report(
        scan_id=scan.id,
        user_id=current_user.id,
        report_format=report_data.format,
    )

    logger.info(
        "[NETRIX] Report generated: %s (format: %s) by user '%s'.",
        report.report_name, report.format, current_user.username,
    )
    return report


@router.get(
    "/",
    status_code=status.HTTP_200_OK,
    summary="List reports",
)
async def list_reports(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    report_format: Optional[str] = Query(
        None,
        alias="format",
        description="Filter by format (pdf, json, csv, html)",
    ),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    List all reports for the current user with pagination.

    Supports optional format filtering and configurable page size.

    Returns:
        dict: Paginated list of report records.
    """
    query = db.query(Report).filter(Report.user_id == current_user.id)

    if report_format:
        query = query.filter(Report.format == report_format.lower())

    total = query.count()
    reports = (
        query.order_by(Report.generated_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "reports": [r.to_dict() for r in reports],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": math.ceil(total / page_size) if total > 0 else 0,
    }


@router.get(
    "/{report_id}",
    response_model=ReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Get report details",
)
async def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Get detailed metadata for a specific report.

    Returns:
        ReportResponse: Full report record.

    Raises:
        ReportGenerationException: If the report does not exist.
    """
    report = db.query(Report).filter(
        Report.id == report_id,
        Report.user_id == current_user.id,
    ).first()

    if not report:
        raise ReportGenerationException(
            message="Report not found.",
            details=f"Report ID {report_id} does not exist.",
            status_code=404,
        )

    return report


@router.get(
    "/{report_id}/download",
    status_code=status.HTTP_200_OK,
    summary="Download a report file",
)
async def download_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Download a generated report file.

    Returns the report file as a streaming response with the
    appropriate Content-Type header.

    Returns:
        FileResponse: The report file download.

    Raises:
        ReportGenerationException: If the report or file does not exist.
    """
    report = db.query(Report).filter(
        Report.id == report_id,
        Report.user_id == current_user.id,
    ).first()

    if not report:
        raise ReportGenerationException(
            message="Report not found.",
            details=f"Report ID {report_id} does not exist.",
            status_code=404,
        )

    if not report.file_path or not os.path.exists(report.file_path):
        raise ReportGenerationException(
            message="Report file not found on disk.",
            details=f"Expected at: {report.file_path}",
        )

    # Update download tracking
    report.download_count += 1
    report.last_downloaded = datetime.now(timezone.utc)
    db.commit()

    # Determine content type
    content_type_map = {
        "pdf": "application/pdf",
        "json": "application/json",
        "csv": "text/csv",
        "html": "text/html",
    }
    media_type = content_type_map.get(report.format, "application/octet-stream")

    logger.info(
        "[NETRIX] Report %s downloaded by user '%s'.",
        report.report_name, current_user.username,
    )

    return FileResponse(
        path=report.file_path,
        media_type=media_type,
        filename=report.report_name,
    )


@router.delete(
    "/{report_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a report",
)
async def delete_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Delete a report and its associated file from disk.

    Returns:
        dict: Confirmation message.

    Raises:
        ReportGenerationException: If the report does not exist.
    """
    report = db.query(Report).filter(
        Report.id == report_id,
        Report.user_id == current_user.id,
    ).first()

    if not report:
        raise ReportGenerationException(
            message="Report not found.",
            details=f"Report ID {report_id} does not exist.",
            status_code=404,
        )

    # Remove the physical file if it exists
    if report.file_path and os.path.exists(report.file_path):
        try:
            os.remove(report.file_path)
            logger.info("[NETRIX] Report file deleted: %s", report.file_path)
        except OSError as file_error:
            logger.warning(
                "[NETRIX] Could not delete report file: %s", str(file_error),
            )

    report_name = report.report_name
    db.delete(report)
    db.commit()

    logger.info(
        "[NETRIX] Report '%s' deleted by user '%s'.",
        report_name, current_user.username,
    )

    return {"message": f"Report '{report_name}' deleted successfully."}
