# ─────────────────────────────────────────
# Netrix — scan_manager.py
# Purpose: Async scan job orchestrator — manages concurrent scans,
#          rate-limits users, and bridges NmapEngine results to the
#          database and WebSocket progress channel.
# ─────────────────────────────────────────

import asyncio
import logging
import queue
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.exceptions import (
    RateLimitExceededException,
    ScanAlreadyRunningException,
)
from app.core.validators import validate_target
from app.scanner.nmap_engine import NmapEngine, ScanType

logger = logging.getLogger("netrix")
settings = get_settings()


class ScanManager:
    """
    Manages the lifecycle of concurrent network scans.

    Scans are offloaded to a ``ThreadPoolExecutor`` because the
    ``python-nmap`` library blocks on I/O.  The manager enforces
    per-user rate limits, tracks active scans, and pushes progress
    updates that can be forwarded over WebSockets.
    """

    def __init__(self, max_workers: int = 5) -> None:
        """
        Initialise the scan manager with a thread pool.

        Args:
            max_workers: Maximum number of concurrent scan threads.
        """
        self.engine = NmapEngine()
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="netrix-scan",
        )
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self._progress_callbacks: Dict[str, Callable] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # Per-scan event queues for WebSocket streaming
        self._event_queues: Dict[str, List[queue.Queue]] = {}

        logger.info(
            "[NETRIX] %s | Scan Manager initialised — max_workers=%d",
            datetime.now(timezone.utc).isoformat(), max_workers,
        )

    # ─────────────────────────────────────
    # Start a new scan
    # ─────────────────────────────────────
    async def start_scan(
        self,
        target: str,
        scan_type: str,
        scan_id: str,
        user_id: int,
        db_session: Session,
        custom_args: str = "",
        custom_ports: str = "",
        is_admin: bool = False,
    ) -> str:
        """
        Validate, register, and launch a scan asynchronously.

        Process:
            1. Validate the target string.
            2. Enforce the per-user hourly rate limit.
            3. Ensure no duplicate scan is running for this target.
            4. Create a ``Scan`` record in the database (status=pending).
            5. Submit the blocking ``NmapEngine.run_scan`` call to the
               thread pool.
            6. Return the ``scan_id`` immediately.

        Args:
            target:       IP, CIDR, or domain.
            scan_type:    One of the ``ScanType`` values.
            scan_id:      Pre-generated unique scan identifier.
            user_id:      ID of the requesting user.
            db_session:   Active SQLAlchemy session.
            custom_args:  Custom nmap arguments (for CUSTOM type).
            custom_ports: Custom port range.

        Returns:
            str: The ``scan_id``.

        Raises:
            RateLimitExceededException: If the user exceeded scan limits.
            ScanAlreadyRunningException: If the target already has an
                active scan.
        """
        from app.models.scan import Scan

        # ── Validate target ──────────────────────────────────────
        try:
            validate_target(target)
        except Exception as val_err:
            logger.warning("[NETRIX] Target validation failed: %s", str(val_err))
            raise

        # ── Rate limit ───────────────────────────────────────────
        if not is_admin:
            user_scan_count = self.get_scan_count_for_user(
                user_id, db_session, hours=1,
            )
            max_scans = settings.MAX_SCANS_PER_USER_PER_HOUR
            if user_scan_count >= max_scans:
                logger.warning(
                    "[NETRIX] User %d exceeded scan limit (%d/%d per hour)",
                    user_id, user_scan_count, max_scans,
                )
                raise RateLimitExceededException(
                    message=f"Scan limit exceeded — maximum {max_scans} scans per hour.",
                    details=f"You have run {user_scan_count} scan(s) in the last hour.",
                )

        # ── Duplicate check ──────────────────────────────────────
        for sid, info in self.active_scans.items():
            if info.get("target") == target and info.get("status") == "running":
                logger.warning(
                    "[NETRIX] Duplicate scan blocked — %s already running as %s",
                    target, sid,
                )
                raise ScanAlreadyRunningException(
                    message="A scan is already running for this target.",
                    details=f"Active scan ID: {sid}",
                )

        # ── Create DB record ─────────────────────────────────────
        scan_type_enum = ScanType(scan_type)
        target_type = NmapEngine._detect_target_type(target)

        scan_record = Scan(
            scan_id=scan_id,
            user_id=user_id,
            target=target,
            target_type=target_type,
            scan_type=scan_type,
            scan_args=custom_args or None,
            status="pending",
            progress=0,
        )
        db_session.add(scan_record)
        db_session.commit()
        db_session.refresh(scan_record)

        logger.info(
            "[NETRIX] %s | Scan %s registered (Scan.id=%d, target=%s)",
            datetime.now(timezone.utc).isoformat(),
            scan_id, scan_record.id, target,
        )

        # ── Track as active ──────────────────────────────────────
        self.active_scans[scan_id] = {
            "scan_id": scan_id,
            "db_id": scan_record.id,
            "target": target,
            "scan_type": scan_type,
            "user_id": user_id,
            "status": "pending",
            "progress": 0,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "message": "Queued for execution",
        }

        # ── Submit to thread pool ────────────────────────────────
        self._loop = asyncio.get_running_loop()
        self._loop.run_in_executor(
            self.executor,
            self._run_scan_thread,
            target,
            scan_type_enum,
            scan_id,
            user_id,
            custom_args,
            custom_ports,
        )

        return scan_id

    # ─────────────────────────────────────
    # Launch a scan (lightweight — DB record already exists)
    # ─────────────────────────────────────
    async def launch_scan(
        self,
        target: str,
        scan_type: str,
        scan_id: str,
        user_id: int,
        custom_args: str = "",
        custom_ports: str = "",
    ) -> str:
        """
        Launch a pre-created scan into the thread pool.

        Unlike ``start_scan``, this method assumes the scan record
        already exists in the database (created by ``ScanService``).
        It only registers the scan as active and submits the Nmap
        work to the executor.

        Args:
            target:       IP, CIDR, or domain.
            scan_type:    One of the ``ScanType`` values.
            scan_id:      Pre-generated unique scan identifier.
            user_id:      ID of the requesting user.
            custom_args:  Custom nmap arguments.
            custom_ports: Custom port range.

        Returns:
            str: The ``scan_id``.
        """
        scan_type_enum = ScanType(scan_type)

        # ── Track as active ──────────────────────────────────────
        self.active_scans[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "user_id": user_id,
            "status": "pending",
            "progress": 0,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "message": "Queued for execution",
        }

        # ── Submit to thread pool ────────────────────────────────
        self._loop = asyncio.get_running_loop()
        self._loop.run_in_executor(
            self.executor,
            self._run_scan_thread,
            target,
            scan_type_enum,
            scan_id,
            user_id,
            custom_args,
            custom_ports,
        )

        logger.info(
            "[NETRIX] %s | Scan %s launched (target=%s)",
            datetime.now(timezone.utc).isoformat(),
            scan_id, target,
        )
        return scan_id

    # ─────────────────────────────────────
    # Status query
    # ─────────────────────────────────────
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Return the current status of a scan.

        Checks the in-memory tracker first, then falls back to the
        database so that server restarts or multi-worker deployments
        don't falsely report a running scan as completed.
        """
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]

        # Fall back to DB — don't assume "completed" for unknown scans
        try:
            from app.database.session import SessionLocal
            from app.models.scan import Scan as ScanModel
            db = SessionLocal()
            try:
                scan = db.query(ScanModel).filter(ScanModel.scan_id == scan_id).first()
                if scan:
                    return {
                        "scan_id": scan_id,
                        "status": scan.status,
                        "progress": scan.progress or 0,
                        "total_hosts": scan.hosts_up or 0,
                        "message": "Status from database",
                    }
            finally:
                db.close()
        except Exception:
            pass

        return {
            "scan_id": scan_id,
            "status": "unknown",
            "progress": 0,
            "message": "Scan not found",
        }

    # ─────────────────────────────────────
    # Cancel
    # ─────────────────────────────────────
    async def cancel_scan(
        self,
        scan_id: str,
        db_session: Session,
    ) -> bool:
        """
        Cancel a running or pending scan.

        Updates the database status to ``failed`` with a cancellation
        message and removes the scan from the active tracker.

        Returns:
            bool: ``True`` if the scan was found and cancelled.
        """
        from app.models.scan import Scan

        if scan_id not in self.active_scans:
            logger.warning("[NETRIX] Cannot cancel — scan %s not active", scan_id)
            return False

        try:
            scan = (
                db_session.query(Scan)
                .filter(Scan.scan_id == scan_id)
                .first()
            )
            if scan:
                scan.status = "failed"
                scan.error_message = "Scan cancelled by user"
                scan.completed_at = datetime.now(timezone.utc)
                db_session.commit()

            self.active_scans.pop(scan_id, None)

            logger.info(
                "[NETRIX] %s | Scan %s cancelled",
                datetime.now(timezone.utc).isoformat(), scan_id,
            )
            return True

        except Exception as cancel_err:
            db_session.rollback()
            logger.error(
                "[NETRIX] Failed to cancel scan %s: %s",
                scan_id, str(cancel_err),
            )
            return False

    # ─────────────────────────────────────
    # Threaded scan execution
    # ─────────────────────────────────────
    # ─────────────────────────────────────
    # Event queue management (for WebSocket streaming)
    # ─────────────────────────────────────
    def register_event_queue(self, scan_id: str) -> queue.Queue:
        """
        Register a new event consumer queue for a scan.

        Multiple WebSocket clients can subscribe to the same scan.
        Returns a thread-safe Queue that will receive events.
        """
        q: queue.Queue = queue.Queue(maxsize=500)
        self._event_queues.setdefault(scan_id, []).append(q)
        logger.debug("[NETRIX] Event queue registered for scan %s", scan_id)
        return q

    def unregister_event_queue(self, scan_id: str, q: queue.Queue) -> None:
        """Remove an event consumer queue."""
        queues = self._event_queues.get(scan_id, [])
        if q in queues:
            queues.remove(q)
        if not queues:
            self._event_queues.pop(scan_id, None)
        logger.debug("[NETRIX] Event queue unregistered for scan %s", scan_id)

    def push_event(self, scan_id: str, event: Dict[str, Any]) -> None:
        """
        Push an event to all registered queues for a scan.

        Thread-safe — called from the scan worker thread.
        """
        event.setdefault("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        event.setdefault("scan_id", scan_id)
        for q in self._event_queues.get(scan_id, []):
            try:
                q.put_nowait(event)
            except queue.Full:
                # Drop oldest event to make room
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    pass

    # ─────────────────────────────────────
    # Threaded scan execution
    # ─────────────────────────────────────
    def _run_scan_thread(
        self,
        target: str,
        scan_type: ScanType,
        scan_id: str,
        user_id: int,
        custom_args: str,
        custom_ports: str,
    ) -> None:
        """
        Execute the blocking Nmap scan inside a worker thread.

        This method:
            1. Runs ``NmapEngine.run_scan()``.
            2. Opens a fresh database session to persist results.
            3. Updates the active-scan tracker throughout.
            4. Pushes granular events for WebSocket consumers.
            5. Cleans up the active entry on completion or failure.
        """
        from app.database.session import SessionLocal

        db = SessionLocal()

        try:
            # Update status → running (in-memory tracker)
            if scan_id in self.active_scans:
                self.active_scans[scan_id]["status"] = "running"
                self.active_scans[scan_id]["progress"] = 5

            # Update status → running (database)
            from app.models.scan import Scan as ScanModel
            try:
                scan_record = db.query(ScanModel).filter(ScanModel.scan_id == scan_id).first()
                if scan_record:
                    scan_record.status = "running"
                    scan_record.started_at = datetime.now(timezone.utc)
                    scan_record.progress = 5
                    db.commit()
            except Exception as db_status_err:
                logger.warning("[NETRIX] Could not update DB status to running: %s", str(db_status_err))
                db.rollback()

            logger.info(
                "[NETRIX] %s | Thread started for scan %s",
                datetime.now(timezone.utc).isoformat(), scan_id,
            )

            # Push scan_started event
            self.push_event(scan_id, {
                "event": "scan_started",
                "target": target,
                "scan_type": scan_type.value,
                "message": f"🔍 Initiating {scan_type.value} scan on {target}...",
            })

            # ── Progress callback ────────────────────────────────
            def progress_callback(
                sid: str,
                progress: int,
                status: str,
                message: str,
            ) -> None:
                if sid in self.active_scans:
                    self.active_scans[sid]["progress"] = progress
                    self.active_scans[sid]["status"] = status
                    self.active_scans[sid]["message"] = message
                # Push progress event
                self.push_event(sid, {
                    "event": "progress",
                    "progress": progress,
                    "current_host": "",
                    "hosts_found": 0,
                    "ports_found": 0,
                    "vulns_found": 0,
                    "message": message or f"Scanning... {progress}%",
                })

            # ── Event callback for granular events ───────────────
            def event_callback(event: Dict[str, Any]) -> None:
                self.push_event(scan_id, event)

            # ── Run the scan ─────────────────────────────────────
            # Create a fresh NmapEngine per thread so self.nm is never
            # shared across concurrent scans (race condition fix).
            local_engine = NmapEngine()
            summary = local_engine.run_scan(
                target=target,
                scan_type=scan_type,
                custom_args=custom_args,
                custom_ports=custom_ports,
                scan_id=scan_id,
                callback=progress_callback,
                event_callback=event_callback,
            )

            # ── Persist to DB ────────────────────────────────────
            scan_db_id = local_engine.save_to_database(
                summary=summary,
                db_session=db,
                user_id=user_id,
            )

            # ── NVD API lookup by detected product/version ────────
            if scan_db_id:
                try:
                    from app.services.cve_service import fetch_nvd_cves_for_scan
                    nvd_result = fetch_nvd_cves_for_scan(
                        scan_db_id=scan_db_id,
                        db=db,
                        push_event=lambda e: self.push_event(scan_id, e),
                    )
                    logger.info(
                        "[NETRIX] NVD lookup for scan %d: %s",
                        scan_db_id, nvd_result,
                    )
                except Exception as nvd_err:
                    logger.warning(
                        "[NETRIX] NVD lookup failed (non-fatal): %s", str(nvd_err)
                    )

            # ── Enrich CVE data post-save ─────────────────────────
            if scan_db_id:
                try:
                    from app.services.cve_service import enrich_scan_vulnerabilities
                    enrich_result = enrich_scan_vulnerabilities(
                        scan_db_id=scan_db_id,
                        db=db,
                    )
                    logger.info(
                        "[NETRIX] Post-scan enrichment for scan %d: %s",
                        scan_db_id, enrich_result,
                    )
                except Exception as enrich_err:
                    logger.warning(
                        "[NETRIX] Post-scan enrichment failed (non-fatal): %s",
                        str(enrich_err),
                    )

            # ── Query real vuln counts from DB after enrichment ───
            # summary.total_vulnerabilities only counts NSE-detected vulns.
            # Service-based CVE matching adds more records to the DB after
            # save_to_database, so we query the actual count here.
            actual_vuln_count = summary.total_vulnerabilities
            actual_critical = summary.critical_hosts
            if scan_db_id:
                try:
                    from app.models.vulnerability import Vulnerability as _VulnModel
                    actual_vuln_count = db.query(_VulnModel).filter(
                        _VulnModel.scan_id == scan_db_id
                    ).count()
                    actual_critical = db.query(_VulnModel).filter(
                        _VulnModel.scan_id == scan_db_id,
                        _VulnModel.severity == "critical",
                    ).count()
                except Exception:
                    pass

            # Push scan_complete event
            duration_secs = summary.duration_seconds
            minutes = int(duration_secs // 60)
            seconds = int(duration_secs % 60)
            duration_str = f"{minutes} min {seconds} sec" if minutes else f"{seconds} sec"

            self.push_event(scan_id, {
                "event": "scan_complete",
                "progress": 100,
                "total_hosts": summary.hosts_up,
                "total_ports": summary.total_open_ports,
                "total_vulns": actual_vuln_count,
                "critical_count": actual_critical,
                "duration": duration_str,
                "message": "✅ Scan completed successfully!",
            })

            logger.info(
                "[NETRIX] %s | Scan %s completed and saved",
                datetime.now(timezone.utc).isoformat(), scan_id,
            )

        except Exception as thread_err:
            # Mark as failed in DB
            from app.models.scan import Scan

            try:
                scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
                if scan:
                    scan.status = "failed"
                    scan.error_message = str(thread_err)[:2000]
                    scan.completed_at = datetime.now(timezone.utc)
                    db.commit()
            except Exception as db_err:
                db.rollback()
                logger.error("[NETRIX] DB update failed after scan error: %s", str(db_err))

            if scan_id in self.active_scans:
                self.active_scans[scan_id]["status"] = "failed"
                self.active_scans[scan_id]["progress"] = 100
                self.active_scans[scan_id]["message"] = str(thread_err)

            # Push error event
            self.push_event(scan_id, {
                "event": "error",
                "message": f"❌ Scan failed: {str(thread_err)[:200]}",
            })

            logger.error(
                "[NETRIX] Scan %s failed: %s",
                scan_id, str(thread_err),
            )

        finally:
            db.close()
            # Remove from active after a brief delay to allow status polling
            self.active_scans.pop(scan_id, None)

    # ─────────────────────────────────────
    # Progress broadcasting
    # ─────────────────────────────────────
    async def broadcast_progress(
        self,
        scan_id: str,
        progress: int,
        status: str,
        message: str = "",
    ) -> Dict[str, Any]:
        """
        Build a WebSocket-ready progress payload.

        The actual WebSocket push is left to the caller (e.g. a
        FastAPI endpoint or background task).

        Returns:
            dict: ``{scan_id, progress, status, message, timestamp}``.
        """
        payload = {
            "scan_id": scan_id,
            "progress": progress,
            "status": status,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        logger.debug("[NETRIX] Progress broadcast: %s", payload)
        return payload

    # ─────────────────────────────────────
    # Active scan listing
    # ─────────────────────────────────────
    def get_active_scans(self) -> List[Dict[str, Any]]:
        """Return a list of all currently running or pending scans."""
        return list(self.active_scans.values())

    # ─────────────────────────────────────
    # Rate-limit helper
    # ─────────────────────────────────────
    def get_scan_count_for_user(
        self,
        user_id: int,
        db_session: Session,
        hours: int = 1,
    ) -> int:
        """
        Count how many scans a user has initiated in the last
        *hours* hours.

        Args:
            user_id:    Database ID of the user.
            db_session: Active SQLAlchemy session.
            hours:      Look-back window in hours.

        Returns:
            int: Number of scans within the window.
        """
        from app.models.scan import Scan

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        try:
            count = (
                db_session.query(Scan)
                .filter(
                    Scan.user_id == user_id,
                    Scan.created_at >= cutoff,
                )
                .count()
            )
            return count
        except Exception as count_err:
            logger.warning(
                "[NETRIX] Could not count user scans: %s", str(count_err),
            )
            return 0

    # ─────────────────────────────────────
    # Cleanup
    # ─────────────────────────────────────
    def shutdown(self) -> None:
        """
        Gracefully shut down the thread pool.

        Called during application shutdown (e.g. FastAPI lifespan).
        """
        logger.info("[NETRIX] Shutting down Scan Manager …")
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.active_scans.clear()
        logger.info("[NETRIX] Scan Manager shut down complete")
