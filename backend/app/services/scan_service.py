# ─────────────────────────────────────────
# Netrix — services/scan_service.py
# Purpose: Business logic for scan lifecycle management.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.exceptions import (
    ScanAlreadyRunningException,
    ScanNotFoundException,
)
from app.core.validators import validate_target
from app.models.scan import Scan
from app.models.host import Host
from app.models.port import Port
from app.scanner.nmap_engine import NmapEngine, ScanType
from app.services.cve_service import CVEService
from app.scanner.scan_manager import ScanManager
import asyncio

logger = logging.getLogger("netrix")


class ScanService:
    """Service layer for scan CRUD operations and lifecycle management."""

    def __init__(self, db: Session) -> None:
        """
        Initialize the scan service.

        Args:
            db: SQLAlchemy database session.
        """
        self.db = db
        self.settings = get_settings()

    @staticmethod
    def _generate_scan_id() -> str:
        """Generate a unique human-readable scan identifier."""
        short_uuid = uuid.uuid4().hex[:8].upper()
        return f"NETRIX_{short_uuid}"

    def create_scan(
        self,
        target: str,
        scan_type: str,
        user_id: int,
        custom_args: Optional[str] = None,
        custom_ports: Optional[str] = None,
    ) -> Scan:
        """
        Create a new scan record and queue it for execution.

        Args:
            target:      The scan target (IP, CIDR or domain).
            scan_type:   Type of scan to perform.
            user_id:     ID of the user initiating the scan.
            custom_args: Optional custom Nmap arguments.
            custom_ports: Optional port specification.

        Returns:
            Scan: The created scan ORM object.

        Raises:
            InvalidTargetException: If the target is invalid.
            ScanAlreadyRunningException: If a scan is already running.
        """
        cleaned_target, target_type = validate_target(target, allow_private=True)

        existing_scan = self.db.query(Scan).filter(
            Scan.target == cleaned_target,
            Scan.user_id == user_id,
            Scan.status.in_(["pending", "running"]),
        ).first()

        if existing_scan:
            raise ScanAlreadyRunningException(
                details=f"Scan ID {existing_scan.scan_id} is already "
                        f"{existing_scan.status} for {cleaned_target}.",
            )

        scan_id = self._generate_scan_id()

        new_scan = Scan(
            scan_id=scan_id,
            user_id=user_id,
            target=cleaned_target,
            target_type=target_type,
            scan_type=scan_type,
            scan_args=custom_args,
            status="pending",
            progress=0,
        )
        self.db.add(new_scan)
        self.db.commit()
        self.db.refresh(new_scan)

        logger.info(
            "[NETRIX] Scan %s created for target %s by user %d",
            scan_id, cleaned_target, user_id,
        )
        return new_scan

    async def start_scan_async(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        user_id: int,
        db=None,
    ):
        """
        Execute the scan in the background.

        IMPORTANT: This method creates its OWN database session
        using SessionLocal() so it is fully independent of the
        request lifecycle. The ``db`` parameter is accepted for
        backward compatibility but is IGNORED.
        """
        from app.database.session import SessionLocal
        import traceback

        own_db = SessionLocal()
        scan = None
        try:
            # Step 1: Get scan from DB
            scan = own_db.query(Scan).filter(
                Scan.scan_id == scan_id
            ).first()

            if not scan:
                print(f"[NETRIX] Scan {scan_id} not found!")
                return

            # Step 2: Update status to running
            scan.status = "running"
            scan.started_at = datetime.now(timezone.utc)
            scan.progress = 10
            own_db.commit()
            print(f"[NETRIX] Scan {scan_id} started!")

            # Step 3: Run Nmap in thread executor
            engine = NmapEngine()
            loop = asyncio.get_event_loop()

            summary = await loop.run_in_executor(
                None,
                lambda: engine.run_scan(
                    target=target,
                    scan_type=ScanType(scan_type),
                    scan_id=scan_id,
                ),
            )

            # Step 4: Update progress
            scan.progress = 70
            own_db.commit()

            # Step 5: Save each host
            hosts_saved = 0
            ports_saved = 0
            for host_result in summary.hosts:
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
                    risk_score=host_result.risk_score or 0,
                    risk_level=host_result.risk_level or "info",
                    uptime=str(host_result.uptime or ""),
                    tcp_sequence=str(
                        getattr(host_result, "tcp_sequence", "")
                        or ""
                    ),
                )
                own_db.add(db_host)
                own_db.flush()  # Get host ID
                hosts_saved += 1

                # Step 6: Save ports for this host
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
                    own_db.add(db_port)
                    ports_saved += 1

            # Step 7: Update scan record
            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.total_hosts = summary.total_hosts or 0
            scan.hosts_up = summary.hosts_up or 0
            scan.hosts_down = summary.hosts_down or 0
            scan.progress = 100
            own_db.commit()

            print(f"[NETRIX] ✅ Scan {scan_id} complete!")
            print(f"[NETRIX]    Hosts saved: {hosts_saved}")
            print(f"[NETRIX]    Ports saved: {ports_saved}")

        except Exception as e:
            print(f"[NETRIX] ❌ Scan error: {e}")
            traceback.print_exc()

            try:
                scan = own_db.query(Scan).filter(
                    Scan.scan_id == scan_id
                ).first()
                if scan:
                    scan.status = "failed"
                    scan.error_message = str(e)[:2000]
                    scan.progress = 0
                    scan.completed_at = datetime.now(timezone.utc)
                    own_db.commit()
            except Exception as db_err:
                print(f"[NETRIX] ❌ DB error: {db_err}")
                own_db.rollback()
        finally:
            own_db.close()
            print(f"[NETRIX] DB session closed for scan {scan_id}")

    def get_scan(self, scan_id: int, user_id: int) -> Scan:
        """
        Retrieve a scan by primary key, ensuring ownership.

        Args:
            scan_id: The scan's database ID.
            user_id: The ID of the requesting user.

        Returns:
            Scan: The scan ORM object.

        Raises:
            ScanNotFoundException: If the scan does not exist or
                                   does not belong to the user.
        """
        scan = self.db.query(Scan).filter(
            Scan.id == scan_id, Scan.user_id == user_id,
        ).first()
        if not scan:
            raise ScanNotFoundException(details=f"Scan ID {scan_id} not found.")
        return scan
    
    async def get_scan_by_scan_id(self, scan_id_str: str, user_id: int) -> Scan:
        """
        Retrieve a scan by its human-readable scan_id string.

        Args:
            scan_id_str: The NETRIX_XXXX scan identifier.
            user_id:     The ID of the requesting user.

        Returns:
            Scan: The scan ORM object.

        Raises:
            ScanNotFoundException: If the scan does not exist.
        """
        scan = self.db.query(Scan).filter(
            Scan.scan_id == scan_id_str, Scan.user_id == user_id,
        ).first()
        if not scan:
            raise ScanNotFoundException(
                details=f"Scan '{scan_id_str}' not found.",
            )
        return scan

    async def get_scan_status(
        self,
        scan_id: int,
        user_id: int,
        scan_manager: Optional[ScanManager] = None,
    ) -> Dict:
        """
        Get live scan status, combining DB record with active scan info.

        Args:
            scan_id:      The scan's database ID.
            user_id:      The requesting user's ID.
            scan_manager: Optional ScanManager for live progress.

        Returns:
            dict: Status dictionary with scan_id, status, progress, timestamps.
        """
        scan = self.get_scan(scan_id, user_id)

        result = {
            "scan_id": scan.scan_id,
            "status": scan.status,
            "progress": scan.progress,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
        }

        # Overlay live progress from ScanManager if the scan is active
        if scan_manager and scan.status in ("pending", "running"):
            live_status = await scan_manager.get_scan_status(scan.scan_id)
            if live_status:
                result["progress"] = live_status.get("progress", scan.progress)
                result["status"] = live_status.get("status", scan.status)

        return result

    def list_scans(
        self,
        user_id: int,
        page: int = 1,
        page_size: int = 20,
        status: Optional[str] = None,
    ) -> Tuple[List[Scan], int]:
        """
        List scans for a user with pagination and optional status filter.

        Args:
            user_id:   The user whose scans to list.
            page:      The page number (1-indexed).
            page_size: Number of scans per page.
            status:    Optional status filter.

        Returns:
            tuple: (list of Scan objects, total count).
        """
        query = self.db.query(Scan).filter(Scan.user_id == user_id)

        if status:
            query = query.filter(Scan.status == status)

        total = query.count()
        scans = (
            query.order_by(Scan.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )
        return scans, total

    def delete_scan(self, scan_id: int, user_id: int) -> None:
        """
        Delete a scan record and all associated data.

        Only completed, failed or cancelled scans can be deleted.

        Args:
            scan_id: The scan's database ID.
            user_id: The requesting user's ID.

        Raises:
            ScanNotFoundException: If the scan does not exist.
            ScanAlreadyRunningException: If the scan is still in progress.
        """
        scan = self.get_scan(scan_id, user_id)

        # Removed condition to allow users to force delete stuck pending/running scans

        self.db.delete(scan)
        self.db.commit()
        logger.info("[NETRIX] Scan %s deleted by user %d.", scan.scan_id, user_id)

    def cancel_scan(self, scan_id: int, user_id: int) -> Scan:
        """
        Cancel a pending or running scan.

        Args:
            scan_id: The scan's database ID.
            user_id: The ID of the requesting user.

        Returns:
            Scan: The updated scan ORM object.

        Raises:
            ScanNotFoundException: If the scan does not exist.
        """
        scan = self.get_scan(scan_id, user_id)
        if scan.status in ("pending", "running"):
            scan.status = "failed"
            scan.error_message = "Cancelled by user."
            scan.completed_at = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(scan)
            logger.info(
                "[NETRIX] Scan %s cancelled by user %d.",
                scan.scan_id, user_id,
            )
        return scan
