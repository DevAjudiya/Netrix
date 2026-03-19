# ─────────────────────────────────────────
# Netrix — CVE Service
# Purpose: Business logic layer for CVE operations
# ─────────────────────────────────────────

import logging
import re as _re
from datetime import datetime
from typing import Any, Dict, List, Optional

_CVE_RE = _re.compile(r'^CVE-\d{4}-\d+$', _re.IGNORECASE)

from sqlalchemy.orm import Session

from app.models.host import Host
from app.models.vulnerability import Vulnerability
from app.scanner.vuln_engine import CVEDetail, CVEEngine, VulnerabilityMatch

logger = logging.getLogger("netrix")


# ─────────────────────────────────────────
# Module-level enrichment pipeline
# ─────────────────────────────────────────
def enrich_scan_vulnerabilities(scan_db_id: int, db: Session) -> Dict:
    """
    Enrich every vulnerability record for a completed scan.

    For each vulnerability that is missing cvss_score, description,
    or remediation:
        1. Try the offline CVE database first (instant, no network).
        2. Fall back to the NVD API (rate-limited by NVDRateLimiter).
    After enriching CVEs, recalculate risk_score / risk_level for
    every host in the scan based on its highest CVSS finding.

    This function is synchronous and safe to call from worker threads
    (scan_manager) as well as from the main FastAPI thread
    (report_service).

    Args:
        scan_db_id: Database primary key of the Scan record.
        db:         SQLAlchemy session to use for queries and updates.

    Returns:
        dict: Summary with counts of enriched / already_complete / failed.
    """
    engine = CVEEngine()
    enriched = already_complete = failed = 0

    try:
        vulns = db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan_db_id
        ).all()

        if not vulns:
            logger.info(
                "[NETRIX] Enrichment: no vulnerabilities for scan %d", scan_db_id
            )
            return {"enriched": 0, "already_complete": 0, "failed": 0}

        logger.info(
            "[NETRIX] Enrichment: starting for scan %d (%d vulns)",
            scan_db_id, len(vulns),
        )

        needs_enrichment = [
            v for v in vulns
            if v.cvss_score is None
            or not v.description
            or not v.remediation
        ]

        logger.info(
            "[NETRIX] Enrichment: %d/%d vulns need enrichment",
            len(needs_enrichment), len(vulns),
        )
        already_complete = len(vulns) - len(needs_enrichment)

        severity_to_score = {
            "critical": 9.5, "high": 7.5,
            "medium": 5.0, "low": 2.0, "info": 0.0,
        }

        for vuln in needs_enrichment:
            # NSE detections with no CVE ID, or NSE-placeholder IDs that aren't real CVEs
            is_real_cve = vuln.cve_id and _CVE_RE.match(vuln.cve_id)
            if not is_real_cve:
                if vuln.cvss_score is None and vuln.severity:
                    vuln.cvss_score = severity_to_score.get(vuln.severity, 5.0)
                if not vuln.remediation:
                    service_hint = (vuln.title or "").lower()
                    vuln.remediation = engine.get_remediation("", service_hint) or \
                        "Investigate the NSE script finding and apply vendor patches. Restrict network exposure."
                enriched += 1
                continue
            try:
                detail: Optional[CVEDetail] = None

                # 1. Offline DB (no network, instant)
                if vuln.cve_id in engine._offline_db:
                    detail = engine._offline_to_cve_detail(
                        vuln.cve_id, engine._offline_db[vuln.cve_id]
                    )

                # 2. NVD API fallback (rate-limited)
                if detail is None:
                    detail = engine.fetch_cve_from_nvd(vuln.cve_id)

                if detail is None:
                    # Severity-based fallback when NVD and offline DB both have no data
                    if vuln.cvss_score is None and vuln.severity:
                        vuln.cvss_score = severity_to_score.get(vuln.severity, 5.0)
                    failed += 1
                    logger.debug(
                        "[NETRIX] Enrichment: no data found for %s, used severity fallback", vuln.cve_id
                    )
                    continue

                # Apply enrichment only for missing fields
                if vuln.cvss_score is None and detail.cvss_score:
                    vuln.cvss_score = detail.cvss_score
                if not vuln.cvss_vector and detail.cvss_vector:
                    vuln.cvss_vector = detail.cvss_vector
                if not vuln.description and detail.description:
                    vuln.description = detail.description
                if not vuln.remediation and detail.remediation:
                    vuln.remediation = detail.remediation
                if not vuln.title or vuln.title == vuln.cve_id:
                    if detail.title:
                        vuln.title = detail.title[:255]
                if detail.published_date and not vuln.published_date:
                    try:
                        vuln.published_date = datetime.strptime(
                            detail.published_date[:10], "%Y-%m-%d"
                        ).date()
                    except (ValueError, TypeError):
                        pass
                # Recalculate severity from CVSS score if it was null
                if vuln.cvss_score is not None:
                    vuln.severity = engine._score_to_severity(float(vuln.cvss_score))
                if detail.source in ("nvd_api", "offline_db", "nse_script"):
                    vuln.source = detail.source

                enriched += 1
                logger.info(
                    "[NETRIX] Enrichment: %s → cvss=%.1f severity=%s",
                    vuln.cve_id,
                    float(vuln.cvss_score) if vuln.cvss_score else 0.0,
                    vuln.severity,
                )

            except Exception as vuln_err:
                failed += 1
                logger.warning(
                    "[NETRIX] Enrichment: failed for %s: %s",
                    vuln.cve_id, str(vuln_err),
                )

        # Commit all CVE enrichments at once
        try:
            db.commit()
        except Exception as commit_err:
            db.rollback()
            logger.error("[NETRIX] Enrichment commit failed: %s", commit_err)
            return {"enriched": 0, "already_complete": already_complete, "failed": failed}

        # ── Update host risk scores ───────────────────────────────
        _update_host_risk_scores(scan_db_id, db, engine)

        logger.info(
            "[NETRIX] Enrichment complete for scan %d: "
            "enriched=%d already_complete=%d failed=%d",
            scan_db_id, enriched, already_complete, failed,
        )

    except Exception as exc:
        logger.error(
            "[NETRIX] Enrichment pipeline error for scan %d: %s",
            scan_db_id, str(exc),
        )

    return {"enriched": enriched, "already_complete": already_complete, "failed": failed}


def _update_host_risk_scores(scan_db_id: int, db: Session, engine: CVEEngine) -> None:
    """
    Recalculate risk_score and risk_level for every host in the scan
    based on the maximum CVSS score across all its vulnerabilities.
    """
    try:
        hosts = db.query(Host).filter(Host.scan_id == scan_db_id).all()
        for host in hosts:
            host_vulns = db.query(Vulnerability).filter(
                Vulnerability.host_id == host.id
            ).all()
            if not host_vulns:
                continue
            scores = [
                float(v.cvss_score)
                for v in host_vulns
                if v.cvss_score is not None
            ]
            if not scores:
                continue
            max_score = max(scores)
            # risk_score: scale CVSS (0–10) to integer (0–100)
            host.risk_score = min(100, int(max_score * 10))
            host.risk_level = engine._score_to_severity(max_score)

        db.commit()
        logger.info(
            "[NETRIX] Risk scores updated for %d hosts in scan %d",
            len(hosts), scan_db_id,
        )
    except Exception as exc:
        db.rollback()
        logger.warning(
            "[NETRIX] Risk score update failed for scan %d: %s",
            scan_db_id, str(exc),
        )


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
            # 1. Check offline database (authoritative, curated data)
            if cve_id in self.engine._offline_db:
                data = self.engine._offline_db[cve_id]
                return self.engine._offline_to_cve_detail(cve_id, data)

            # 2. Fetch from NVD API
            nvd_detail = self.engine.fetch_cve_from_nvd(cve_id)
            if nvd_detail:
                return nvd_detail

            # 3. Fall back to database record (may have sparse NSE data)
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
