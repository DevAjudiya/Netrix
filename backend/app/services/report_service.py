# ─────────────────────────────────────────
# Netrix — services/report_service.py
# Purpose: Business logic for report generation, storage,
#          download, and lifecycle management.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import logging
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.exceptions import ReportGenerationException, ScanNotFoundException
from app.models.host import Host
from app.models.port import Port
from app.models.report import Report
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.scanner.report_engine import ReportData, ReportEngine
from app.scanner.vuln_engine import CVEEngine

logger = logging.getLogger("netrix")


class ReportService:
    """
    Service layer for generating, storing and managing scan reports.

    Orchestrates the full report pipeline: data collection from DB →
    ReportData preparation → file generation → DB record creation.
    """

    def __init__(self, db: Session) -> None:
        """
        Initialise the report service.

        Args:
            db: SQLAlchemy database session.
        """
        self.db = db
        self.settings = get_settings()
        self.engine = ReportEngine()
        self._cve_engine = CVEEngine()

    # ─────────────────────────────────────
    # Main pipeline
    # ─────────────────────────────────────
    def generate_report(
        self,
        scan_id: int,
        user_id: int,
        report_format: str = "pdf",
        report_name: Optional[str] = None,
    ) -> Report:
        """
        Complete report generation pipeline.

        1. Validates the scan exists, belongs to user, and is completed.
        2. Collects all host/port/vulnerability data from the DB.
        3. Prepares a ``ReportData`` object.
        4. Generates the report file on disk.
        5. Creates a ``Report`` DB record with metadata.

        Args:
            scan_id:       Database ID of the scan.
            user_id:       User requesting the report.
            report_format: One of ``pdf``, ``json``, ``csv``, ``html``.
            report_name:   Optional custom report name.

        Returns:
            Report: The newly created Report ORM object.

        Raises:
            ScanNotFoundException:     If the scan does not exist.
            ReportGenerationException: If the scan is not completed or
                                       generation fails.
        """
        # 1. Validate scan
        scan = self.db.query(Scan).filter(
            Scan.id == scan_id,
            Scan.user_id == user_id,
        ).first()

        if not scan:
            raise ScanNotFoundException(
                details=f"Scan ID {scan_id} not found.",
            )

        if scan.status != "completed":
            raise ReportGenerationException(
                message="Cannot generate a report for a scan that has not completed.",
                details=f"Scan {scan.scan_id} is currently '{scan.status}'.",
            )

        # 2. Enrich any CVEs that are still missing CVSS/description/remediation
        try:
            from app.services.cve_service import enrich_scan_vulnerabilities
            enrich_result = enrich_scan_vulnerabilities(
                scan_db_id=scan.id,
                db=self.db,
            )
            if enrich_result.get("enriched", 0) > 0:
                logger.info(
                    "[NETRIX] Pre-report enrichment for scan %s: %s",
                    scan.scan_id, enrich_result,
                )
        except Exception as enrich_err:
            logger.warning(
                "[NETRIX] Pre-report enrichment failed (non-fatal): %s",
                str(enrich_err),
            )

        # 3. Collect data
        scan_data = self._collect_scan_data(scan)
        vuln_data = self._collect_vulnerability_data(scan)

        # 4. Prepare ReportData
        report_data = self.engine.prepare_report_data(
            scan_summary=scan_data,
            vulnerability_matches=vuln_data,
            generated_by=f"User {user_id}",
        )

        if report_name:
            report_data.report_name = report_name

        # 4. Generate file
        fmt = report_format.lower().strip()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"netrix_report_{scan.scan_id}_{timestamp}.{fmt}"
        output_path = os.path.join(self.settings.REPORTS_DIR, filename)

        try:
            file_path = self.engine.generate_report(
                report_data=report_data,
                fmt=fmt,
                output_path=output_path,
            )
        except Exception as gen_error:
            logger.error(
                "[NETRIX] Report generation failed for scan %s: %s",
                scan.scan_id, str(gen_error),
            )
            raise ReportGenerationException(
                message="Report generation failed.",
                details=str(gen_error),
            )

        # 5. Save DB record
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

        # Always store report_name with the correct extension
        base_name = report_data.report_name or filename
        ext = f".{fmt}"
        stored_name = base_name if base_name.lower().endswith(ext) else f"{base_name}{ext}"

        report = Report(
            scan_id=scan.id,
            user_id=user_id,
            report_name=stored_name,
            format=fmt,
            file_path=os.path.abspath(file_path),
            file_size=file_size,
            total_hosts=report_data.total_hosts,
            total_vulnerabilities=report_data.total_vulnerabilities,
            critical_count=report_data.critical_count,
            high_count=report_data.high_count,
            medium_count=report_data.medium_count,
            low_count=report_data.low_count,
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        logger.info(
            "[NETRIX] Report %d generated for scan %s: %s (%d bytes)",
            report.id, scan.scan_id, filename, file_size,
        )
        return report

    # ─────────────────────────────────────
    # File path retrieval
    # ─────────────────────────────────────
    def get_report_file_path(
        self,
        report_id: int,
        user_id: int,
    ) -> str:
        """
        Retrieve the physical file path for a report download.

        Args:
            report_id: Database ID of the report.
            user_id:   ID of the requesting user (for ownership check).

        Returns:
            str: Absolute path to the report file.

        Raises:
            ReportGenerationException: If the report or file does not exist.
        """
        report = self.db.query(Report).filter(
            Report.id == report_id,
            Report.user_id == user_id,
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

        return report.file_path

    # ─────────────────────────────────────
    # Deletion
    # ─────────────────────────────────────
    def delete_report(
        self,
        report_id: int,
        user_id: int,
    ) -> bool:
        """
        Delete a report file from disk and its DB record.

        Args:
            report_id: Database ID of the report.
            user_id:   ID of the requesting user.

        Returns:
            bool: ``True`` if deleted successfully.

        Raises:
            ReportGenerationException: If the report does not exist.
        """
        report = self.db.query(Report).filter(
            Report.id == report_id,
            Report.user_id == user_id,
        ).first()

        if not report:
            raise ReportGenerationException(
                message="Report not found.",
                details=f"Report ID {report_id} does not exist.",
                status_code=404,
            )

        # Remove file from disk
        if report.file_path and os.path.exists(report.file_path):
            try:
                os.remove(report.file_path)
                logger.info(
                    "[NETRIX] Report file deleted: %s", report.file_path,
                )
            except OSError as file_err:
                logger.warning(
                    "[NETRIX] Could not delete report file %s: %s",
                    report.file_path, str(file_err),
                )

        report_name = report.report_name
        self.db.delete(report)
        self.db.commit()

        logger.info("[NETRIX] Report '%s' (ID %d) deleted.", report_name, report_id)
        return True

    # ─────────────────────────────────────
    # Listing
    # ─────────────────────────────────────
    def get_user_reports(
        self,
        user_id: int,
        scan_id: Optional[int] = None,
        report_format: Optional[str] = None,
    ) -> List[Dict]:
        """
        List all reports for a user, with optional filters.

        Args:
            user_id:       The user whose reports to list.
            scan_id:       Optional scan ID filter.
            report_format: Optional format filter (pdf/json/csv/html).

        Returns:
            list[dict]: List of report dictionaries sorted by newest first.
        """
        query = self.db.query(Report).filter(Report.user_id == user_id)

        if scan_id is not None:
            query = query.filter(Report.scan_id == scan_id)
        if report_format:
            query = query.filter(Report.format == report_format.lower())

        reports = query.order_by(Report.generated_at.desc()).all()

        return [r.to_dict() for r in reports]

    # ─────────────────────────────────────
    # Private data collectors
    # ─────────────────────────────────────
    def _collect_scan_data(self, scan: Scan) -> Dict:
        """
        Collect all scan-related data into a flat dictionary.

        Args:
            scan: The Scan ORM object.

        Returns:
            dict: Scan summary with nested host/port data.
        """
        hosts = self.db.query(Host).filter(Host.scan_id == scan.id).all()
        host_data = []

        for host in hosts:
            ports = self.db.query(Port).filter(Port.host_id == host.id).all()
            host_data.append({
                "ip_address": host.ip_address,
                "hostname": host.hostname,
                "status": host.status,
                "os_name": host.os_name,
                "os_family": host.os_family,
                "mac_address": host.mac_address,
                "risk_score": host.risk_score,
                "risk_level": host.risk_level,
                "ports": [
                    {
                        "port_number": p.port_number,
                        "protocol": p.protocol,
                        "state": p.state,
                        "service_name": p.service_name,
                        "product": p.product,
                        "version": p.version,
                        "cpe": p.cpe,
                        "is_critical_port": p.is_critical_port,
                    }
                    for p in ports
                ],
            })

        return {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "target_type": scan.target_type,
            "scan_type": scan.scan_type,
            "scan_args": scan.scan_args,
            "status": scan.status,
            "total_hosts": scan.total_hosts,
            "hosts_up": scan.hosts_up,
            "hosts_down": scan.hosts_down,
            "nmap_version": scan.nmap_version,
            "started_at": (
                scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if scan.started_at else None
            ),
            "completed_at": (
                scan.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                if scan.completed_at else None
            ),
            "duration": (
                f"{scan.duration:.1f} seconds"
                if scan.duration else "N/A"
            ),
            "hosts": host_data,
        }

    def _collect_vulnerability_data(self, scan: Scan) -> List[Dict]:
        """
        Collect all vulnerability data for a scan.

        Args:
            scan: The Scan ORM object.

        Returns:
            list[dict]: List of vulnerability dictionaries with
                        host / port context.
        """
        vulns = self.db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan.id,
        ).all()

        vuln_data = []
        for v in vulns:
            # Resolve host IP
            host_ip = "N/A"
            host = self.db.query(Host).filter(Host.id == v.host_id).first()
            if host:
                host_ip = host.ip_address

            # Resolve port and service
            port_num = None
            service_name = "N/A"
            if v.port_id:
                port = self.db.query(Port).filter(Port.id == v.port_id).first()
                if port:
                    port_num = port.port_number
                    service_name = port.service_name or "N/A"

            # Enrich remediation from offline DB when not stored
            remediation = v.remediation
            if not remediation and v.cve_id:
                offline = self._cve_engine._offline_db.get(v.cve_id)
                if offline:
                    remediation = offline.get("remediation", "")
            if not remediation and v.cve_id:
                remediation = self._cve_engine.get_remediation(
                    v.cve_id, service_name
                )

            vuln_data.append({
                "cve_id": v.cve_id,
                "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
                "cvss_vector": v.cvss_vector,
                "severity": v.severity,
                "title": v.title,
                "description": v.description,
                "remediation": remediation,
                "source": v.source,
                "is_confirmed": v.is_confirmed,
                "affected_host": host_ip,
                "host_ip": host_ip,
                "affected_port": port_num,
                "port": port_num,
                "affected_service": service_name,
                "service": service_name,
                "published_date": (
                    v.published_date.isoformat() if v.published_date else None
                ),
            })

        return vuln_data
