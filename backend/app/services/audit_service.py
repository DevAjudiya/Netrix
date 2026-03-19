# ─────────────────────────────────────────
# Netrix — Audit Logger Service
# Purpose: Fire-and-forget helper for writing immutable audit events.
#          log_event() never raises; failures are silently swallowed
#          so audit logic can never break a live request.
# ─────────────────────────────────────────

import logging
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

logger = logging.getLogger("netrix")


def _extract_ip(request) -> Optional[str]:
    """
    Extract the client IP from a FastAPI/Starlette Request object.

    Respects X-Forwarded-For (takes the first address in the chain).
    Returns None when called without a Request (background tasks etc.).
    """
    if request is None:
        return None
    try:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        if request.client:
            return request.client.host
    except Exception:
        pass
    return None


def log_event(
    db: Session,
    user_id: Optional[int],
    action: str,
    request=None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Append an audit event to the ``audit_logs`` table.

    This function is intentionally synchronous and fire-and-forget:
    it opens its own database session so that the caller's transaction
    cannot affect (or be affected by) the audit write.

    Args:
        db:         Caller's DB session (used only as a session factory
                    reference — not directly written to).
        user_id:    Performing user's ID (None for anonymous / failed-login).
        action:     One of the AUDIT_ACTIONS enum values.
        request:    FastAPI ``Request`` object for IP extraction (optional).
        details:    Arbitrary JSON-serialisable dict of event metadata.
        ip_address: Explicit IP override; takes precedence over ``request``.
    """
    from app.database.session import SessionLocal
    from app.models.audit_log import AuditLog

    # IP resolution — explicit override wins over header extraction
    ip = ip_address or _extract_ip(request)

    audit_db = SessionLocal()
    try:
        entry = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip,
            details=details or {},
        )
        audit_db.add(entry)
        audit_db.commit()
    except Exception as exc:
        # Audit failure must never crash the calling endpoint
        logger.warning("[AUDIT] Failed to write audit log (%s): %s", action, exc)
        try:
            audit_db.rollback()
        except Exception:
            pass
    finally:
        try:
            audit_db.close()
        except Exception:
            pass
