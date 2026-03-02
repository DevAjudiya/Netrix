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
from app.scanner.scan_manager import ScanManager

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
        scan: Scan,
        scan_manager: ScanManager,
    ) -> None:
        """
        Start a scan asynchronously via the ScanManager.

        Args:
            scan:         The Scan ORM object to start.
            scan_manager: The shared ScanManager instance.
        """
        await scan_manager.launch_scan(
            target=scan.target,
            scan_type=scan.scan_type,
            scan_id=scan.scan_id,
            user_id=scan.user_id,
            custom_args=scan.scan_args or "",
            custom_ports="",
        )
        logger.info("[NETRIX] Scan %s queued for async execution.", scan.scan_id)

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

        if scan.status in ("pending", "running"):
            raise ScanAlreadyRunningException(
                message="Cannot delete a scan that is still in progress.",
                details=f"Scan {scan.scan_id} is currently '{scan.status}'.",
            )

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
