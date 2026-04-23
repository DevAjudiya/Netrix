# ─────────────────────────────────────────
# Netrix — Admin API (v1)
# Purpose: User management endpoints restricted to admin role.
#   GET    /admin/users              — paginated user list with search
#   PATCH  /admin/users/{id}         — update role / active / ban status
#   DELETE /admin/users/{id}         — soft-delete (is_active = False)
#   POST   /admin/users/{id}/reset-password — generate & return temp password
#   GET    /admin/stats              — platform-wide user statistics
# ─────────────────────────────────────────

import asyncio
import logging
import math
import secrets
import string
from datetime import datetime, timezone
from typing import Optional

import requests as _requests
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.security import get_password_hash
from app.database.session import get_db
from app.dependencies import get_admin_user, get_scan_manager
from app.models.audit_log import AuditLog
from app.models.scan import Scan
from app.models.user import User
from app.schemas.admin import (
    AdminHealthResponse,
    AdminLogListResponse,
    AdminLogResponse,
    AdminMetricsResponse,
    AdminScanListResponse,
    AdminScanResponse,
    AdminStats,
    AdminUserListResponse,
    AdminUserResponse,
    AdminUserUpdate,
    CVEEntry,
    CVEListResponse,
    CVERematchResponse,
    CVEStatusResponse,
    CVESyncResponse,
    PasswordResetResponse,
    SystemMetricPoint,
)
from app.services.audit_service import log_event

logger = logging.getLogger("netrix")

router = APIRouter()

# ── Helpers ───────────────────────────────────────────────────────────────


def _scan_count_for(user_id: int, db: Session) -> int:
    """Return the number of scans belonging to the given user."""
    result = db.query(func.count(Scan.id)).filter(Scan.user_id == user_id).scalar()
    return result or 0


def _to_response(user: User, db: Session) -> AdminUserResponse:
    return AdminUserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        is_banned=user.is_banned,
        ban_reason=user.ban_reason,
        scan_count=_scan_count_for(user.id, db),
        last_login=user.last_login,
        created_at=user.created_at,
    )


def _get_user_or_404(user_id: int, db: Session) -> User:

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found.",
        )
    return user


def _generate_temp_password(length: int = 16) -> str:
    """
    Generate a cryptographically secure temporary password that satisfies
    the application's password policy (upper, digit, special char).
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%^&*()" for c in pwd)
        ):
            return pwd


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.get(
    "/users",
    response_model=AdminUserListResponse,
    status_code=status.HTTP_200_OK,
    summary="List all users (admin)",
)
async def list_users(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page"),
    search: Optional[str] = Query(None, description="Filter by username or email"),
    _admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Return a paginated list of all user accounts.

    Supports optional ``search`` filtering by username or email (case-insensitive).
    """
    query = db.query(User)

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            User.username.ilike(term) | User.email.ilike(term)
        )

    total = query.count()
    total_pages = max(1, math.ceil(total / page_size))
    offset = (page - 1) * page_size

    users = query.order_by(User.id.asc()).offset(offset).limit(page_size).all()

    return AdminUserListResponse(
        users=[_to_response(u, db) for u in users],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/stats",
    response_model=AdminStats,
    status_code=status.HTTP_200_OK,
    summary="Get platform-wide statistics (admin)",
)
async def get_admin_stats(
    request: Request,
    _admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Return summary counts across users, scans, reports, and CVE database.

    Used by the admin dashboard widget and the AdminUsers page stats row.
    """
    from datetime import date, timedelta
    from app.models.report import Report
    from app.scanner.vuln_engine import CVEEngine

    # ── User counts ───────────────────────────────────────────────────
    total = db.query(func.count(User.id)).scalar() or 0
    active = db.query(func.count(User.id)).filter(User.is_active == True).scalar() or 0  # noqa: E712
    banned = db.query(func.count(User.id)).filter(User.is_banned == True).scalar() or 0  # noqa: E712
    admins = db.query(func.count(User.id)).filter(User.role == "admin").scalar() or 0
    analysts = db.query(func.count(User.id)).filter(User.role == "analyst").scalar() or 0

    # ── Scan counts ───────────────────────────────────────────────────
    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    scans_today = (
        db.query(func.count(Scan.id))
        .filter(Scan.created_at >= today_start)
        .scalar()
    ) or 0

    # ── Report count ──────────────────────────────────────────────────
    reports_generated = db.query(func.count(Report.id)).scalar() or 0

    # ── CVE database ──────────────────────────────────────────────────
    try:
        cve_count = len(CVEEngine()._offline_db)
    except Exception:
        cve_count = 0

    last_cve_sync: Optional[datetime] = None
    redis = getattr(request.app.state, "redis", None)
    if redis:
        try:
            raw = await redis.get("netrix:cve:last_sync")
            if raw:
                last_cve_sync = datetime.fromisoformat(raw)
        except Exception:
            pass

    return AdminStats(
        total_users=total,
        active_users=active,
        banned_users=banned,
        admins=admins,
        analysts=analysts,
        total_scans_all_users=total_scans,
        scans_today=scans_today,
        reports_generated=reports_generated,
        cve_count=cve_count,
        last_cve_sync=last_cve_sync,
    )


@router.patch(
    "/users/{user_id}",
    response_model=AdminUserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update user role / status / ban (admin)",
)
async def update_user(
    user_id: int,
    body: AdminUserUpdate,
    request: Request,
    admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Update role, is_active, is_banned, or ban_reason for any user.

    Admins cannot demote themselves or ban themselves.
    """

    user = _get_user_or_404(user_id, db)

    # Self-protection: admins cannot demote or ban themselves
    if user.id == admin.id:
        if body.role is not None and body.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Admins cannot demote their own account.",
            )
        if body.is_banned is True:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Admins cannot ban their own account.",
            )

    if body.role is not None:
        if body.role not in ("admin", "analyst"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="role must be 'admin' or 'analyst'.",
            )
        user.role = body.role

    if body.is_active is not None:
        user.is_active = body.is_active

    if body.is_banned is not None:
        user.is_banned = body.is_banned
        # Clear ban_reason when unbanning (unless a new reason is also supplied)
        if not body.is_banned and body.ban_reason is None:
            user.ban_reason = None

    if body.ban_reason is not None:
        user.ban_reason = body.ban_reason if body.ban_reason.strip() else None

    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    logger.info(
        "[NETRIX] Admin '%s' updated user '%s': role=%s active=%s banned=%s",
        admin.username, user.username, user.role, user.is_active, user.is_banned,
    )

    # Emit targeted audit events for role changes and bans
    if body.role is not None:
        log_event(db, admin.id, "role_change", request,
                  {"target_user_id": user.id, "target_username": user.username, "new_role": user.role})
    if body.is_banned is not None:
        log_event(db, admin.id, "user_ban", request,
                  {"target_user_id": user.id, "target_username": user.username,
                   "banned": user.is_banned, "reason": user.ban_reason})

    return _to_response(user, db)


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Soft-delete a user (admin)",
)
async def delete_user(
    user_id: int,
    admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Soft-delete a user by setting ``is_active = False``.

    Scans belonging to the user are marked orphaned (user_id set to NULL).
    The user record is never hard-deleted.

    Admins cannot soft-delete themselves.
    """

    user = _get_user_or_404(user_id, db)

    if user.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admins cannot delete their own account.",
        )

    user.is_active = False
    user.updated_at = datetime.now(timezone.utc)

    db.commit()

    logger.info(
        "[NETRIX] Admin '%s' soft-deleted user '%s' (ID %d).",
        admin.username, user.username, user.id,
    )

    return {
        "message": f"User '{user.username}' has been deactivated.",
        "user_id": user.id,
    }


@router.post(
    "/users/{user_id}/reset-password",
    response_model=PasswordResetResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset a user's password (admin)",
)
async def reset_user_password(
    user_id: int,
    request: Request,
    admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Generate a secure temporary password, hash it, persist it, and return
    the plain-text value **once** to the requesting admin.

    The event is recorded in the application audit log.
    """
    user = _get_user_or_404(user_id, db)

    temp_password = _generate_temp_password()
    user.password_hash = get_password_hash(temp_password)
    user.updated_at = datetime.now(timezone.utc)
    db.commit()

    log_event(db, admin.id, "password_reset", request,
              {"target_user_id": user.id, "target_username": user.username})
    logger.warning(
        "[AUDIT] Admin '%s' (ID %d) reset the password for user '%s' (ID %d) at %s.",
        admin.username,
        admin.id,
        user.username,
        user.id,
        datetime.now(timezone.utc).isoformat(),
    )

    return PasswordResetResponse(
        message=f"Password for '{user.username}' has been reset. Share this temporary password securely — it will not be shown again.",
        username=user.username,
        temp_password=temp_password,
    )


# ── Scan Oversight ────────────────────────────────────────────────────────


def _scan_to_response(scan: Scan) -> AdminScanResponse:
    """Flatten a Scan + its User relationship into AdminScanResponse."""
    owner = scan.user  # eager-loaded via join in the list query
    return AdminScanResponse(
        id=scan.id,
        scan_id=scan.scan_id,
        target=scan.target,
        target_type=scan.target_type,
        scan_type=scan.scan_type,
        status=scan.status,
        progress=scan.progress,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        created_at=scan.created_at,
        total_hosts=scan.total_hosts,
        hosts_up=scan.hosts_up,
        error_message=scan.error_message,
        user_id=scan.user_id,
        username=owner.username if owner else "—",
        email=owner.email if owner else "—",
    )


def _get_scan_or_404(scan_id: int, db: Session) -> Scan:

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found.",
        )
    return scan


@router.get(
    "/scans",
    response_model=AdminScanListResponse,
    status_code=status.HTTP_200_OK,
    summary="List all scans across all users (admin)",
)
async def list_all_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user_id: Optional[int] = Query(None, description="Filter by owner user ID"),
    scan_status: Optional[str] = Query(None, alias="status", description="Comma-separated statuses: pending,running,completed,failed"),
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    date_from: Optional[str] = Query(None, description="ISO date lower bound on created_at (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="ISO date upper bound on created_at (YYYY-MM-DD)"),
    _admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Return a paginated, filterable list of all scans regardless of owner.

    Filters:
    - ``user_id``: show only scans belonging to this user
    - ``status``: comma-separated subset of pending|running|completed|failed
    - ``scan_type``: quick|stealth|full|aggressive|vulnerability|custom
    - ``date_from`` / ``date_to``: ISO date strings bounding ``created_at``
    """
    from datetime import date

    query = db.query(Scan).join(User, Scan.user_id == User.id)

    if user_id is not None:
        query = query.filter(Scan.user_id == user_id)

    if scan_status:
        statuses = [s.strip() for s in scan_status.split(",") if s.strip()]
        if statuses:
            query = query.filter(Scan.status.in_(statuses))

    if scan_type:
        query = query.filter(Scan.scan_type == scan_type)

    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            query = query.filter(Scan.created_at >= dt_from)
        except ValueError:
            pass

    if date_to:
        try:
            # Include the full day_to by moving to end-of-day
            dt_to = datetime.fromisoformat(date_to).replace(
                hour=23, minute=59, second=59
            )
            query = query.filter(Scan.created_at <= dt_to)
        except ValueError:
            pass

    total = query.count()
    total_pages = max(1, math.ceil(total / page_size))
    offset = (page - 1) * page_size

    scans = (
        query.order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(page_size)
        .all()
    )

    return AdminScanListResponse(
        scans=[_scan_to_response(s) for s in scans],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.delete(
    "/scans/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Force-delete any scan (admin)",
)
async def admin_delete_scan(
    scan_id: int,
    request: Request,
    admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Hard-delete a scan and all cascaded records (hosts, ports,
    vulnerabilities, reports) regardless of owner or current status.
    """
    scan = _get_scan_or_404(scan_id, db)
    scan_id_str = scan.scan_id
    owner_username = scan.user.username if scan.user else "unknown"

    db.delete(scan)
    db.commit()

    logger.warning(
        "[AUDIT] Admin '%s' (ID %d) force-deleted scan '%s' (DB id=%d, owner=%s) at %s.",
        admin.username,
        admin.id,
        scan_id_str,
        scan_id,
        owner_username,
        datetime.now(timezone.utc).isoformat(),
    )

    log_event(db, admin.id, "scan_delete", request, {
        "scan_id": scan_id_str,
        "db_id": scan_id,
        "owner": owner_username,
    })

    return {
        "message": f"Scan '{scan_id_str}' and all associated data have been deleted.",
        "scan_id": scan_id_str,
    }


@router.post(
    "/scans/{scan_id}/stop",
    status_code=status.HTTP_200_OK,
    summary="Force-stop a running scan (admin)",
)
async def admin_stop_scan(
    scan_id: int,
    request: Request,
    admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
    scan_manager=Depends(get_scan_manager),
):
    """
    Force-terminate a running or pending scan.

    Sets the scan status to ``failed``, removes it from the active
    scan tracker, and attempts to clear any Redis progress key.
    """

    scan = _get_scan_or_404(scan_id, db)

    if scan.status not in ("running", "pending"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan '{scan.scan_id}' is not running (current status: {scan.status}).",
        )

    scan_id_str = scan.scan_id
    owner_username = scan.user.username if scan.user else "unknown"

    # ── Mark failed in DB ────────────────────────────────────────────
    scan.status = "failed"
    scan.error_message = f"Force-stopped by admin '{admin.username}'."
    scan.completed_at = datetime.now(timezone.utc)
    db.commit()

    # ── Remove from ScanManager in-memory tracker ────────────────────
    scan_manager.active_scans.pop(scan_id_str, None)

    # ── Clear Redis scan progress key (best-effort) ──────────────────
    redis = getattr(request.app.state, "redis", None)
    if redis:
        try:
            await redis.delete(f"netrix:scan:{scan_id_str}")
            await redis.delete(f"netrix:scan:{scan_id_str}:progress")
        except Exception as redis_err:
            logger.warning(
                "[NETRIX] Could not clear Redis keys for scan %s: %s",
                scan_id_str, str(redis_err),
            )

    logger.warning(
        "[AUDIT] Admin '%s' (ID %d) force-stopped scan '%s' (DB id=%d, owner=%s) at %s.",
        admin.username,
        admin.id,
        scan_id_str,
        scan_id,
        owner_username,
        datetime.now(timezone.utc).isoformat(),
    )

    return {
        "message": f"Scan '{scan_id_str}' has been force-stopped.",
        "scan_id": scan_id_str,
        "status": "failed",
    }


# ── Audit Logs ────────────────────────────────────────────────────────────


def _log_to_response(entry: AuditLog) -> AdminLogResponse:
    owner = entry.user  # eagerly loaded via joined relationship
    return AdminLogResponse(
        id=entry.id,
        action=entry.action,
        ip_address=entry.ip_address,
        details=entry.details,
        created_at=entry.created_at,
        user_id=entry.user_id,
        username=owner.username if owner else None,
        email=owner.email if owner else None,
    )


@router.get(
    "/logs",
    response_model=AdminLogListResponse,
    status_code=status.HTTP_200_OK,
    summary="List audit logs (admin)",
)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    action: Optional[str] = Query(None, description="Filter by action type"),
    ip_address: Optional[str] = Query(None, description="Filter by IP address (prefix match)"),
    date_from: Optional[str] = Query(None, description="ISO date lower bound (YYYY-MM-DD)"),
    date_to: Optional[str] = Query(None, description="ISO date upper bound (YYYY-MM-DD)"),
    _admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Return a paginated, filterable audit log sorted newest-first.

    Filters: ``user_id``, ``action``, ``ip_address`` (prefix), ``date_from``, ``date_to``.
    """
    query = db.query(AuditLog)

    if user_id is not None:
        query = query.filter(AuditLog.user_id == user_id)

    if action:
        query = query.filter(AuditLog.action == action)

    if ip_address:
        query = query.filter(AuditLog.ip_address.like(f"{ip_address}%"))

    if date_from:
        try:
            query = query.filter(AuditLog.created_at >= datetime.fromisoformat(date_from))
        except ValueError:
            pass

    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to).replace(hour=23, minute=59, second=59)
            query = query.filter(AuditLog.created_at <= dt_to)
        except ValueError:
            pass

    total = query.count()
    total_pages = max(1, math.ceil(total / page_size))
    offset = (page - 1) * page_size

    entries = (
        query.order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(page_size)
        .all()
    )

    return AdminLogListResponse(
        logs=[_log_to_response(e) for e in entries],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


# ── System Health ──────────────────────────────────────────────────────────


@router.get(
    "/health",
    response_model=AdminHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Real-time system health snapshot (admin)",
)
async def admin_health(
    request: Request,
    _admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Returns a live health check covering MySQL, Redis, Nmap, and system
    resource utilisation.  Also reports active scan count, Redis queue
    depth, and failed scans in the last 24 hours.
    """
    from datetime import timedelta
    from app.database.session import engine as db_engine
    from app.services.health_service import (
        check_mysql, check_redis, check_nmap,
        get_redis_queue_depth, get_cpu_percent, get_memory_percent,
    )

    redis_client = getattr(request.app.state, "redis", None)

    mysql_ok, redis_ok, nmap_ok, queue_depth = await asyncio.gather(
        check_mysql(db_engine),
        check_redis(redis_client),
        check_nmap(),
        get_redis_queue_depth(redis_client),
    )

    cpu = get_cpu_percent()
    memory = get_memory_percent()

    # Active scans from ScanManager
    try:
        from app.services.scan_manager import get_scan_manager_instance
        sm = get_scan_manager_instance()
        active_scans = len(sm.active_scans)
    except Exception:
        active_scans = 0

    # Failed scans in the last 24 hours
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    failed_24h = (
        db.query(func.count(Scan.id))
        .filter(Scan.status == "failed", Scan.completed_at >= cutoff_24h)
        .scalar()
    ) or 0

    return AdminHealthResponse(
        mysql_status=mysql_ok,
        redis_status=redis_ok,
        nmap_status=nmap_ok,
        active_scans=active_scans,
        queue_depth=queue_depth,
        failed_scans_24h=failed_24h,
        cpu_percent=cpu,
        memory_percent=memory,
    )


@router.get(
    "/metrics",
    response_model=AdminMetricsResponse,
    status_code=status.HTTP_200_OK,
    summary="Time-series system metrics (admin)",
)
async def admin_metrics(
    hours: int = Query(24, ge=1, le=168, description="How many hours of history to return"),
    _admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Return time-series CPU and memory snapshots for the last ``hours`` hours,
    drawn from the ``system_metrics`` table populated by the background task.
    """
    from datetime import timedelta
    from app.models.system_metric import SystemMetric

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (
        db.query(SystemMetric)
        .filter(SystemMetric.recorded_at >= cutoff)
        .order_by(SystemMetric.recorded_at.asc())
        .all()
    )

    points = [
        SystemMetricPoint(
            recorded_at=row.recorded_at,
            cpu_percent=row.cpu_percent,
            memory_percent=row.memory_percent,
        )
        for row in rows
    ]

    return AdminMetricsResponse(hours=hours, points=points)


# ── CVE Control ────────────────────────────────────────────────────────────


_NVD_CHECK_TTL = 300  # cache result for 5 minutes


def _check_nvd_connectivity(nvd_url: str) -> bool:
    """Synchronous NVD ping — called in a background thread, never blocks a request.

    NVD/Cloudflare takes 12-20s to respond. timeout=25 gives it enough room.
    Sends the API key when configured for the authenticated rate-limit tier.
    """
    from app.config import get_settings
    cfg = get_settings()
    headers = {"User-Agent": "Netrix/1.0"}
    if cfg.NVD_API_KEY:
        headers["apiKey"] = cfg.NVD_API_KEY
    try:
        resp = _requests.get(
            nvd_url,
            params={"resultsPerPage": 1},
            timeout=25,
            headers=headers,
        )
        return resp.status_code == 200
    except Exception:
        return False


async def _bg_nvd_check(nvd_url: str, redis) -> None:
    """Fire-and-forget background coroutine: ping NVD and write result to Redis."""
    try:
        result = await asyncio.to_thread(_check_nvd_connectivity, nvd_url)
        if redis:
            now = datetime.now(timezone.utc).isoformat()
            await redis.set("netrix:cve:nvd_online", "1" if result else "0", ex=_NVD_CHECK_TTL)
            await redis.set("netrix:cve:nvd_last_checked", now, ex=_NVD_CHECK_TTL)
            await redis.delete("netrix:cve:nvd_checking")
    except Exception:
        if redis:
            try:
                await redis.delete("netrix:cve:nvd_checking")
            except Exception:
                pass


@router.get(
    "/cve/status",
    response_model=CVEStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="CVE database status (admin)",
)
async def cve_status(
    request: Request,
    force: bool = False,
    _admin=Depends(get_admin_user),
):
    """
    Returns the current state of the offline CVE database and NVD connectivity.

    The NVD ping runs as a background task so this endpoint always responds
    immediately. Pass ?force=true to bust the cache and re-check right now.
    While the background check is running, nvd_check_pending=true is returned
    so the frontend can show a 'Checking…' state and auto-poll.
    """
    from app.config import get_settings
    from app.scanner.vuln_engine import CVEEngine

    settings = get_settings()
    engine = CVEEngine()
    total_cves = len(engine._offline_db)

    redis = getattr(request.app.state, "redis", None)
    last_sync: Optional[datetime] = None
    cves_added_last_sync = 0
    sync_in_progress = False

    if redis:
        try:
            raw = await redis.get("netrix:cve:last_sync")
            if raw:
                last_sync = datetime.fromisoformat(raw)
        except Exception:
            pass
        try:
            raw = await redis.get("netrix:cve:last_sync_count")
            if raw:
                cves_added_last_sync = int(raw)
        except Exception:
            pass
        try:
            sync_in_progress = bool(await redis.get("netrix:cve:sync_in_progress"))
        except Exception:
            pass

    # ── NVD connectivity — never blocks the response ──────────────────────
    nvd_api_online = False
    nvd_last_checked: Optional[datetime] = None
    nvd_check_pending = False
    cached_online = None

    if force and redis:
        # Bust the cache so the background task re-pings immediately
        try:
            await redis.delete("netrix:cve:nvd_online", "netrix:cve:nvd_last_checked", "netrix:cve:nvd_checking")
        except Exception:
            pass

    if redis:
        try:
            cached_online = await redis.get("netrix:cve:nvd_online")
            cached_ts = await redis.get("netrix:cve:nvd_last_checked")
            checking = await redis.get("netrix:cve:nvd_checking")
            if cached_online is not None:
                nvd_api_online = cached_online == "1"
                if cached_ts:
                    nvd_last_checked = datetime.fromisoformat(cached_ts)
            nvd_check_pending = bool(checking)
        except Exception:
            pass

    # No cached result and no check already running → spawn background ping
    if cached_online is None and not nvd_check_pending:
        nvd_check_pending = True
        if redis:
            try:
                await redis.set("netrix:cve:nvd_checking", "1", ex=60)
            except Exception:
                pass
        asyncio.create_task(_bg_nvd_check(settings.NVD_API_URL, redis))

    return CVEStatusResponse(
        total_cves=total_cves,
        last_sync=last_sync,
        cves_added_last_sync=cves_added_last_sync,
        nvd_api_online=nvd_api_online,
        nvd_last_checked=nvd_last_checked,
        nvd_check_pending=nvd_check_pending,
        sync_in_progress=sync_in_progress,
    )


@router.post(
    "/cve/sync",
    response_model=CVESyncResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger manual NVD sync (admin)",
)
async def trigger_cve_sync(
    request: Request,
    background_tasks: BackgroundTasks,
    admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Enqueue a background NVD synchronisation task.

    Sets ``netrix:cve:sync_in_progress`` in Redis, then launches
    ``sync_nvd_database()`` as a background task.  Returns 202 immediately.
    Returns 409 if a sync is already running.
    """
    from app.services.cve_service import sync_nvd_database

    redis = getattr(request.app.state, "redis", None)
    if redis:
        try:
            in_progress = await redis.get("netrix:cve:sync_in_progress")
            if in_progress:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A CVE sync is already in progress.",
                )
            await redis.set("netrix:cve:sync_in_progress", "true", ex=3600)
        except HTTPException:
            raise
        except Exception as redis_err:
            logger.warning("[CVE] Could not set sync flag in Redis: %s", redis_err)

    background_tasks.add_task(sync_nvd_database)
    log_event(db, admin.id, "cve_sync", request, {"trigger": "manual_sync"})
    logger.info("[CVE] Admin '%s' triggered manual NVD sync.", admin.username)

    return CVESyncResponse(
        message="CVE synchronisation has been queued and will run in the background.",
        status="accepted",
    )


@router.post(
    "/cve/rematch",
    response_model=CVERematchResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Re-match CVEs against all scan port data (admin)",
)
async def trigger_cve_rematch(
    request: Request,
    background_tasks: BackgroundTasks,
    admin=Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    """
    Re-run CVE matching for every port across all scans.

    For each port that has service/version data, queries the CVE engine
    (offline DB + NVD) and inserts newly discovered vulnerabilities.
    Runs as a background task; returns 202 immediately.
    """
    from app.services.cve_service import _rematch_background_task

    background_tasks.add_task(_rematch_background_task)
    log_event(db, admin.id, "cve_sync", request, {"trigger": "rematch_all_scans"})
    logger.info("[CVE] Admin '%s' triggered CVE rematch across all scans.", admin.username)

    return CVERematchResponse(
        message="CVE rematch has been queued and will run in the background.",
        status="accepted",
    )


@router.get(
    "/cve/list",
    response_model=CVEListResponse,
    status_code=status.HTTP_200_OK,
    summary="List CVEs in the offline database (admin)",
)
async def list_cves(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    search: Optional[str] = Query(None, description="Filter by CVE ID, description, or affected product"),
    severity: Optional[str] = Query(None, description="Filter by severity: critical|high|medium|low"),
    _admin=Depends(get_admin_user),
):
    """
    Return a paginated, searchable list of CVEs stored in the offline database.

    Results are sorted by CVSS score descending.
    Supports filtering by severity and full-text search across CVE ID,
    description, and affected product list.
    """
    from app.scanner.vuln_engine import CVEEngine

    offline_db = CVEEngine()._offline_db

    search_lower = search.lower().strip() if search and search.strip() else None
    sev_filter = severity.lower().strip() if severity and severity.strip() else None

    items: list[CVEEntry] = []
    for cve_id, entry in offline_db.items():
        if sev_filter and entry.get("severity", "").lower() != sev_filter:
            continue
        if search_lower:
            haystack = " ".join([
                cve_id,
                entry.get("description", ""),
                " ".join(entry.get("affected", [])),
            ]).lower()
            if search_lower not in haystack:
                continue
        items.append(CVEEntry(
            cve_id=cve_id,
            title=entry.get("title", cve_id),
            description=entry.get("description", ""),
            cvss_score=float(entry.get("cvss_score", 0.0)),
            cvss_vector=entry.get("cvss_vector", ""),
            severity=entry.get("severity", "info"),
            published_date=entry.get("published_date", ""),
            affected=entry.get("affected", []),
            remediation=entry.get("remediation", ""),
            references=entry.get("references", []),
        ))

    items.sort(key=lambda x: x.cvss_score, reverse=True)

    total = len(items)
    total_pages = max(1, math.ceil(total / page_size))
    offset = (page - 1) * page_size

    return CVEListResponse(
        cves=items[offset:offset + page_size],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
