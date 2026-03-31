# ─────────────────────────────────────────
# Netrix — CVE Service
# Purpose: Business logic layer for CVE operations
# ─────────────────────────────────────────

import json
import logging
import os
import re as _re
from datetime import datetime, timedelta, timezone
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


# ─────────────────────────────────────────
# NVD API lookup by detected product/version
# ─────────────────────────────────────────

def fetch_nvd_cves_for_scan(
    scan_db_id: int,
    db: Session,
    push_event=None,
) -> Dict:
    """
    Query the NVD API for CVEs based on product/version detected on each port.

    For each port with a known product (or service name):
        1. If a CPE string is available, call search_cves_by_cpe() (most precise).
        2. Otherwise call search_cves_by_keyword("product version") (up to 5 results).
    New CVE records are inserted as Vulnerability rows with source="nvd_api".
    Duplicate CVE IDs within the same scan are skipped.

    Args:
        scan_db_id: Database primary key of the Scan record.
        db:         SQLAlchemy session used for all queries and inserts.
        push_event: Optional callable(event_dict) — called for each new CVE found,
                    forwarded to WebSocket subscribers as a ``cve_found`` event.

    Returns:
        dict: {"ports_processed", "cves_found", "cves_saved"}
    """
    from app.models.port import Port
    from app.models.host import Host

    engine = CVEEngine()
    ports_processed = cves_found = cves_saved = 0

    try:
        # ── Collect all ports for this scan ──────────────────────
        ports = (
            db.query(Port)
            .join(Host, Port.host_id == Host.id)
            .filter(Host.scan_id == scan_db_id)
            .all()
        )

        if not ports:
            logger.info("[NVD LOOKUP] No ports found for scan %d", scan_db_id)
            return {"ports_processed": 0, "cves_found": 0, "cves_saved": 0}

        logger.info(
            "[NVD LOOKUP] Starting NVD lookup for %d ports in scan %d",
            len(ports), scan_db_id,
        )

        # ── Pre-load existing CVE IDs to avoid duplicates ────────
        existing_cve_ids: set = {
            row[0]
            for row in db.query(Vulnerability.cve_id)
            .filter(Vulnerability.scan_id == scan_db_id)
            .all()
            if row[0]
        }

        # ── Deduplicate: only query NVD once per unique product/version ──
        queried_keys: set = set()

        for port in ports:
            product = (port.product or "").strip()
            version = (port.version or "").strip()
            cpe = (port.cpe or "").strip()
            service_name = (port.service_name or "").strip()

            # Prefer product name; fall back to service name only for known
            # security-relevant services.  Generic protocol names like "domain",
            # "msrpc", "bgp", "ldp", "submission" waste API quota and return
            # unrelated CVEs, so skip them when there is no specific product.
            _SKIP_GENERIC = {
                "domain", "msrpc", "netbios-ssn", "netbios-ns", "submission",
                "ldp", "bgp", "sunrpc", "unknown", "tcpwrapped", "rsftp",
                "pptp", "irc", "epmd", "x11",
            }
            if product:
                search_term = product
            elif service_name and service_name.lower() not in _SKIP_GENERIC:
                search_term = service_name
            else:
                continue

            dedup_key = f"{cpe}{search_term.lower()}{version.lower()}"
            if dedup_key in queried_keys:
                continue
            queried_keys.add(dedup_key)
            ports_processed += 1

            # ── NVD query ────────────────────────────────────────
            cve_list: List[CVEDetail] = []

            if cpe:
                cve_list = engine.search_cves_by_cpe(cpe)
                if cve_list:
                    logger.info(
                        "[NVD LOOKUP] CPE '%s' → %d CVEs", cpe, len(cve_list)
                    )

            if not cve_list:
                keyword = f"{search_term} {version}".strip() if version else search_term
                cve_list = engine.search_cves_by_keyword(keyword, max_results=5)
                if cve_list:
                    logger.info(
                        "[NVD LOOKUP] Keyword '%s' → %d CVEs", keyword, len(cve_list)
                    )

            if not cve_list:
                continue

            cves_found += len(cve_list)

            # ── Save new CVEs ─────────────────────────────────────
            for cve in cve_list:
                if not cve.cve_id:
                    continue
                if cve.cve_id in existing_cve_ids:
                    continue

                pub_date = None
                if cve.published_date:
                    try:
                        pub_date = datetime.strptime(
                            cve.published_date[:10], "%Y-%m-%d"
                        ).date()
                    except (ValueError, TypeError):
                        pass

                db.add(Vulnerability(
                    scan_id=scan_db_id,
                    host_id=port.host_id,
                    port_id=port.id,
                    cve_id=cve.cve_id,
                    cvss_score=cve.cvss_score if cve.cvss_score else None,
                    cvss_vector=cve.cvss_vector or None,
                    severity=cve.severity or "info",
                    title=(cve.title or cve.cve_id)[:255],
                    description=cve.description or None,
                    remediation=cve.remediation or None,
                    published_date=pub_date,
                    source="nvd_api",
                ))
                existing_cve_ids.add(cve.cve_id)
                cves_saved += 1

                if push_event:
                    try:
                        push_event({
                            "event": "cve_found",
                            "cve_id": cve.cve_id,
                            "severity": cve.severity,
                            "cvss_score": cve.cvss_score,
                            "title": (cve.title or cve.cve_id)[:100],
                            "service": f"{search_term} {version}".strip(),
                            "port": port.port_number,
                            "source": "nvd_api",
                            "message": (
                                f"🔍 NVD: {cve.cve_id} ({cve.severity.upper()}) "
                                f"on port {port.port_number}"
                            ),
                        })
                    except Exception:
                        pass

        try:
            db.commit()
        except Exception as commit_err:
            db.rollback()
            logger.error("[NVD LOOKUP] Commit failed: %s", commit_err)
            return {
                "ports_processed": ports_processed,
                "cves_found": cves_found,
                "cves_saved": 0,
            }

        logger.info(
            "[NVD LOOKUP] Complete for scan %d: ports=%d cves_found=%d cves_saved=%d",
            scan_db_id, ports_processed, cves_found, cves_saved,
        )

    except Exception as exc:
        logger.error("[NVD LOOKUP] Failed for scan %d: %s", scan_db_id, exc)

    return {
        "ports_processed": ports_processed,
        "cves_found": cves_found,
        "cves_saved": cves_saved,
    }


# ─────────────────────────────────────────
# NVD Sync
# ─────────────────────────────────────────

def sync_nvd_database() -> Dict:
    """
    Synchronise the offline CVE JSON database with the NVD API.

    Fetches CVEs modified since the last sync (stored in Redis) or the
    last 30 days when no prior sync is recorded.  Merges new entries into
    the offline JSON file and updates Redis metadata.

    Always called in a background thread (FastAPI BackgroundTasks) so it
    is safe to block and use synchronous I/O.

    Returns:
        dict: {"added": int, "skipped": int, "total": int}
    """
    from app.config import get_settings

    settings = get_settings()
    db_path = settings.OFFLINE_CVE_DB_PATH
    added = skipped = 0

    # Synchronous Redis client (independent of app.state.redis which is async)
    r = None
    try:
        import redis as _sync_redis
        r = _sync_redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    except Exception as redis_err:
        logger.warning("[CVE SYNC] Could not connect to Redis: %s", redis_err)

    try:
        engine = CVEEngine()

        # ── Determine sync window ──────────────────────────────────────
        last_sync_dt = datetime.now(timezone.utc) - timedelta(days=30)
        if r:
            try:
                stored = r.get("netrix:cve:last_sync")
                if stored:
                    last_sync_dt = datetime.fromisoformat(stored)
            except Exception:
                pass

        start_str = last_sync_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

        logger.info("[CVE SYNC] Fetching CVEs modified %s → %s", start_str, end_str)

        # ── Fetch from NVD ────────────────────────────────────────────
        engine._rate_limit()
        resp = engine.session.get(
            settings.NVD_API_URL,
            params={
                "lastModStartDate": start_str,
                "lastModEndDate": end_str,
                "resultsPerPage": 100,
            },
            timeout=30,
        )

        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("vulnerabilities", []):
                detail = engine._parse_nvd_item(item, source="nvd_api")
                if not (detail and detail.cve_id):
                    continue
                if detail.cve_id in engine._offline_db:
                    skipped += 1
                    continue
                engine._offline_db[detail.cve_id] = {
                    "title": detail.title,
                    "description": detail.description,
                    "cvss_score": detail.cvss_score,
                    "cvss_vector": detail.cvss_vector,
                    "severity": detail.severity,
                    "published_date": detail.published_date[:10] if detail.published_date else "",
                    "affected": detail.affected_products,
                    "remediation": detail.remediation,
                    "references": detail.references,
                }
                added += 1

            # ── Persist updated offline DB ──────────────────────────────
            try:
                os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
                with open(db_path, "w", encoding="utf-8") as fh:
                    json.dump(engine._offline_db, fh, indent=2)
                logger.info("[CVE SYNC] Offline DB saved: added=%d skipped=%d total=%d",
                            added, skipped, len(engine._offline_db))
            except IOError as io_err:
                logger.error("[CVE SYNC] Failed to write offline DB: %s", io_err)
        else:
            logger.warning("[CVE SYNC] NVD API returned HTTP %d", resp.status_code)

        # ── Update Redis metadata ──────────────────────────────────────
        now_iso = datetime.now(timezone.utc).isoformat()
        if r:
            try:
                r.set("netrix:cve:last_sync", now_iso)
                r.set("netrix:cve:last_sync_count", str(added))
                r.set("netrix:cve:last_sync_total", str(len(engine._offline_db)))
            except Exception as redis_err:
                logger.warning("[CVE SYNC] Could not write Redis metadata: %s", redis_err)

        logger.info("[CVE SYNC] Sync complete — added=%d skipped=%d", added, skipped)

    except Exception as exc:
        logger.error("[CVE SYNC] Unexpected error: %s", exc)
    finally:
        if r:
            try:
                r.delete("netrix:cve:sync_in_progress")
            except Exception:
                pass
        if r:
            try:
                r.close()
            except Exception:
                pass

    return {"added": added, "skipped": skipped}


# ─────────────────────────────────────────
# CVE Rematch
# ─────────────────────────────────────────

def rematch_all_scans(db: Session) -> Dict:
    """
    Re-run CVE matching against all existing port data in the database.

    For each port that has a ``service_name``, queries the CVE engine
    (offline DB first, then NVD API) and inserts any newly discovered
    vulnerabilities that are not already recorded for that port.

    Args:
        db: SQLAlchemy session to use for all queries and inserts.

    Returns:
        dict: {"scans_processed", "ports_processed", "vulnerabilities_added"}
    """
    from datetime import date as _date
    from app.models.scan import Scan
    from app.models.host import Host
    from app.models.port import Port

    engine = CVEEngine()
    scans_processed = ports_processed = vulnerabilities_added = 0

    try:
        scans = db.query(Scan).all()
        logger.info("[REMATCH] Starting rematch across %d scans", len(scans))

        for scan in scans:
            scans_processed += 1
            hosts = db.query(Host).filter(Host.scan_id == scan.id).all()

            for host in hosts:
                ports = db.query(Port).filter(Port.host_id == host.id).all()

                for port in ports:
                    if not port.service_name:
                        continue

                    ports_processed += 1
                    svc_name = port.product or port.service_name or ""
                    version = port.version or ""
                    cpe = port.cpe or ""

                    cve_list = engine.match_service_to_cves(svc_name, version, cpe)
                    if not cve_list:
                        continue

                    # Existing CVE IDs for this port — skip duplicates
                    existing_ids = {
                        row[0]
                        for row in db.query(Vulnerability.cve_id)
                        .filter(
                            Vulnerability.scan_id == scan.id,
                            Vulnerability.port_id == port.id,
                        )
                        .all()
                    }

                    for cve in cve_list:
                        if cve.cve_id in existing_ids:
                            continue

                        pub_date = None
                        if cve.published_date:
                            try:
                                pub_date = datetime.strptime(
                                    cve.published_date[:10], "%Y-%m-%d"
                                ).date()
                            except (ValueError, TypeError):
                                pass

                        db.add(Vulnerability(
                            scan_id=scan.id,
                            host_id=host.id,
                            port_id=port.id,
                            cve_id=cve.cve_id,
                            cvss_score=cve.cvss_score,
                            cvss_vector=cve.cvss_vector,
                            severity=cve.severity,
                            title=(cve.title or cve.cve_id)[:255],
                            description=cve.description,
                            remediation=cve.remediation,
                            published_date=pub_date,
                            source=cve.source if cve.source in (
                                "nvd_api", "offline_db", "nse_script"
                            ) else "offline_db",
                        ))
                        existing_ids.add(cve.cve_id)
                        vulnerabilities_added += 1

        try:
            db.commit()
        except Exception as commit_err:
            db.rollback()
            logger.error("[REMATCH] Commit failed: %s", commit_err)

        logger.info(
            "[REMATCH] Complete — scans=%d ports=%d vulns_added=%d",
            scans_processed, ports_processed, vulnerabilities_added,
        )

    except Exception as exc:
        logger.error("[REMATCH] Failed: %s", exc)

    return {
        "scans_processed": scans_processed,
        "ports_processed": ports_processed,
        "vulnerabilities_added": vulnerabilities_added,
    }


def _rematch_background_task() -> None:
    """Wrapper for use with FastAPI BackgroundTasks — creates its own DB session."""
    from app.database.session import SessionLocal
    db = SessionLocal()
    try:
        rematch_all_scans(db)
    finally:
        db.close()
