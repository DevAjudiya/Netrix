# ─────────────────────────────────────────
# Netrix — dependencies.py
# Purpose: Shared FastAPI dependency injection functions.
# Author: Netrix Development Team
# ─────────────────────────────────────────

import logging
from typing import Optional

from fastapi import Depends
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.core.security import get_current_user
from app.database.session import get_db

logger = logging.getLogger("netrix")

# ── Singleton instances ──────────────────────────────────────────────
_scan_manager_instance = None
_cve_engine_instance = None


async def get_current_active_user(
    current_user=Depends(get_current_user),
):
    """
    FastAPI dependency that returns the current authenticated and active user.

    This is a convenience wrapper around get_current_user that can be
    extended with additional checks (e.g. email verification).

    Args:
        current_user: The user object from the get_current_user dependency.

    Returns:
        User: The authenticated and active User ORM object.
    """
    return current_user


async def get_admin_user(
    current_user=Depends(get_current_user),
):
    """
    FastAPI dependency that ensures the current user has admin privileges.

    Args:
        current_user: The user object from the get_current_user dependency.

    Returns:
        User: The authenticated admin User ORM object.

    Raises:
        InsufficientPermissionsException: If the user is not an admin.
    """
    from app.core.exceptions import InsufficientPermissionsException

    if current_user.role != "admin":
        raise InsufficientPermissionsException(
            message="Administrator privileges are required for this action.",
            details=f"User '{current_user.username}' has role '{current_user.role}'.",
        )
    return current_user


def get_settings_dep() -> Settings:
    """
    FastAPI dependency that provides access to the application settings.

    Returns:
        Settings: The cached application settings instance.
    """
    return get_settings()


def get_scan_manager():
    """
    FastAPI dependency that provides a singleton ScanManager instance.

    The ScanManager is created once and reused across all requests
    to maintain a shared thread pool and active-scan tracker.

    Returns:
        ScanManager: The shared scan manager instance.
    """
    global _scan_manager_instance
    if _scan_manager_instance is None:
        from app.scanner.scan_manager import ScanManager
        _scan_manager_instance = ScanManager()
        logger.info("[NETRIX] ScanManager singleton created.")
    return _scan_manager_instance


def get_cve_engine():
    """
    FastAPI dependency that provides a singleton CVEEngine instance.

    The CVEEngine is created once to reuse its HTTP session and
    offline database cache across all requests.

    Returns:
        CVEEngine: The shared CVE engine instance.
    """
    global _cve_engine_instance
    if _cve_engine_instance is None:
        from app.scanner.vuln_engine import CVEEngine
        _cve_engine_instance = CVEEngine()
        logger.info("[NETRIX] CVEEngine singleton created.")
    return _cve_engine_instance


async def verify_scan_ownership(
    scan_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    FastAPI dependency that verifies the requesting user owns the scan.

    Admin users bypass the ownership check.

    Args:
        scan_id:      The database ID of the scan to verify.
        current_user: The authenticated user.
        db:           The database session.

    Returns:
        Scan: The verified Scan ORM object.

    Raises:
        ScanNotFoundException: If the scan does not exist or does not
                               belong to the requesting user.
    """
    from app.core.exceptions import ScanNotFoundException
    from app.models.scan import Scan

    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    if not scan:
        raise ScanNotFoundException(details=f"Scan ID {scan_id} not found.")

    if current_user.role != "admin" and scan.user_id != current_user.id:
        raise ScanNotFoundException(
            message="You do not have access to this scan.",
            details=f"Scan ID {scan_id} does not belong to user '{current_user.username}'.",
        )

    return scan
