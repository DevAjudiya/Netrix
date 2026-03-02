# ─────────────────────────────────────────
# Netrix — CVE Service
# Purpose: Business logic layer for CVE operations
# ─────────────────────────────────────────

import logging
from typing import Any, Dict, List, Optional

from app.models.vulnerability import Vulnerability
from app.scanner.vuln_engine import CVEDetail, CVEEngine, VulnerabilityMatch

logger = logging.getLogger("netrix")


class CVEService:
    """Business logic layer for CVE vulnerability operations."""

    def __init__(self, db_session: Any) -> None:
        """
        Initialize the CVE service.

        Args:
            db_session: SQLAlchemy database session for persistence.
        """
        self.db_session = db_session
        self.engine = CVEEngine()
        logger.info("[NETRIX] CVE Service initialized")

    async def process_scan_vulnerabilities(
        self,
        scan_summary: Any,
        scan_db_id: int,
    ) -> Dict:
        """
        Complete vulnerability processing pipeline.

        1. Match CVEs to all discovered services
        2. Calculate overall risk assessment
        3. Save findings to database
        4. Return summary report

        Args:
            scan_summary: ScanSummary object from NmapEngine.
            scan_db_id:   Database primary key of the Scan record.

        Returns:
            dict: Summary report with matches, risk, and saved count.
        """
        try:
            logger.info("[NETRIX] Starting vulnerability processing for scan %d", scan_db_id)

            # 1. Match CVEs to scan results
            matches = self.engine.match_vulnerabilities(scan_summary)

            # 2. Calculate overall risk
            risk = self.engine.calculate_overall_risk(matches)

            # 3. Save to database
            saved_count = self.engine.save_vulnerabilities_to_db(
                matches, scan_db_id, self.db_session,
            )

            # 4. Build summary report
            report = {
                "scan_id": scan_db_id,
                "total_vulnerabilities": risk.get("total_vulnerabilities", 0),
                "overall_risk_score": risk.get("overall_score", 0),
                "overall_severity": risk.get("overall_severity", "info"),
                "critical_count": risk.get("critical_count", 0),
                "high_count": risk.get("high_count", 0),
                "medium_count": risk.get("medium_count", 0),
                "low_count": risk.get("low_count", 0),
                "most_vulnerable_host": risk.get("most_vulnerable_host", "N/A"),
                "most_dangerous_cve": risk.get("most_dangerous_cve", "N/A"),
                "risk_summary": risk.get("risk_summary", ""),
                "saved_to_database": saved_count,
                "vulnerability_matches": self.engine.to_dict(matches),
            }

            logger.info(
                "[NETRIX] Vulnerability processing complete — %d vulns, risk score %d",
                risk.get("total_vulnerabilities", 0),
                risk.get("overall_score", 0),
            )
            return report

        except Exception as exc:
            logger.error("[NETRIX] Vulnerability processing failed: %s", exc)
            return {
                "scan_id": scan_db_id,
                "total_vulnerabilities": 0,
                "overall_risk_score": 0,
                "overall_severity": "info",
                "error": str(exc),
            }

    async def get_vulnerability_details(
        self,
        cve_id: str,
    ) -> Optional[CVEDetail]:
        """
        Get CVE details — check database first, then offline DB, then NVD API.

        Args:
            cve_id: The CVE identifier (e.g. 'CVE-2021-44228').

        Returns:
            Optional[CVEDetail]: The CVE detail record, or None.
        """
        try:
            # 1. Check database
            db_vuln = (
                self.db_session.query(Vulnerability)
                .filter(Vulnerability.cve_id == cve_id)
                .first()
            )
            if db_vuln:
                return CVEDetail(
                    cve_id=db_vuln.cve_id or cve_id,
                    title=db_vuln.title or cve_id,
                    description=db_vuln.description or "",
                    cvss_score=float(db_vuln.cvss_score) if db_vuln.cvss_score else 0.0,
                    cvss_vector=db_vuln.cvss_vector or "",
                    severity=db_vuln.severity or "info",
                    published_date=db_vuln.published_date.isoformat() if db_vuln.published_date else "",
                    remediation=db_vuln.remediation or "",
                    references=[],
                    source=db_vuln.source or "offline_db",
                    affected_products=[],
                )

            # 2. Check offline database
            if cve_id in self.engine._offline_db:
                data = self.engine._offline_db[cve_id]
                return self.engine._offline_to_cve_detail(cve_id, data)

            # 3. Fetch from NVD API
            return self.engine.fetch_cve_from_nvd(cve_id)

        except Exception as exc:
            logger.error("[NETRIX] Failed to get CVE details for %s: %s", cve_id, exc)
            return None

    async def get_scan_vulnerabilities(
        self,
        scan_id: int,
    ) -> List[Dict]:
        """
        Get all vulnerabilities for a scan from the database.

        Results are grouped by severity and sorted by CVSS score (highest first).

        Args:
            scan_id: Database primary key of the Scan record.

        Returns:
            list[dict]: Vulnerability records sorted by CVSS score.
        """
        try:
            vulns = (
                self.db_session.query(Vulnerability)
                .filter(Vulnerability.scan_id == scan_id)
                .order_by(Vulnerability.cvss_score.desc())
                .all()
            )

            result: List[Dict] = []
            for vuln in vulns:
                result.append(vuln.to_dict())

            logger.info(
                "[NETRIX] Retrieved %d vulnerabilities for scan %d",
                len(result), scan_id,
            )
            return result

        except Exception as exc:
            logger.error("[NETRIX] Failed to get scan vulnerabilities: %s", exc)
            return []

    async def get_vulnerability_stats(
        self,
        scan_id: int,
    ) -> Dict:
        """
        Get vulnerability statistics for the dashboard.

        Returns count by severity, top 5 most critical CVEs,
        most affected host, and overall risk score.

        Args:
            scan_id: Database primary key of the Scan record.

        Returns:
            dict: Dashboard statistics.
        """
        try:
            vulns = (
                self.db_session.query(Vulnerability)
                .filter(Vulnerability.scan_id == scan_id)
                .order_by(Vulnerability.cvss_score.desc())
                .all()
            )

            if not vulns:
                return {
                    "scan_id": scan_id,
                    "total": 0,
                    "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "top_critical": [],
                    "most_affected_host": "N/A",
                    "overall_risk_score": 0,
                }

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            host_counts: Dict[int, int] = {}

            for vuln in vulns:
                sev = vuln.severity.lower() if vuln.severity else "info"
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                host_counts[vuln.host_id] = host_counts.get(vuln.host_id, 0) + 1

            top_5 = [
                {
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "cvss_score": float(v.cvss_score) if v.cvss_score else 0.0,
                    "severity": v.severity,
                }
                for v in vulns[:5]
            ]

            most_affected_id = max(host_counts, key=host_counts.get) if host_counts else None
            most_affected = f"Host ID: {most_affected_id}" if most_affected_id else "N/A"

            total = len(vulns)
            risk_score = min(
                100,
                severity_counts["critical"] * 25
                + severity_counts["high"] * 15
                + severity_counts["medium"] * 8
                + severity_counts["low"] * 3,
            )

            return {
                "scan_id": scan_id,
                "total": total,
                "by_severity": severity_counts,
                "top_critical": top_5,
                "most_affected_host": most_affected,
                "overall_risk_score": risk_score,
            }

        except Exception as exc:
            logger.error("[NETRIX] Failed to get vulnerability stats: %s", exc)
            return {
                "scan_id": scan_id,
                "total": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "top_critical": [],
                "most_affected_host": "N/A",
                "overall_risk_score": 0,
                "error": str(exc),
            }
