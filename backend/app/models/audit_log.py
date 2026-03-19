# ─────────────────────────────────────────
# Netrix — AuditLog Model
# Table: audit_logs
# ─────────────────────────────────────────

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.mysql import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base

AUDIT_ACTIONS = (
    "login",
    "logout",
    "login_failed",
    "scan_start",
    "scan_delete",
    "report_download",
    "user_ban",
    "role_change",
    "password_reset",
    "cve_sync",
)


class AuditLog(Base):
    """
    Immutable record of a sensitive platform event.

    Rows are append-only — never updated or deleted by application code.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Nullable — login failures may reference a non-existent username
    user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    action: Mapped[str] = mapped_column(
        Enum(*AUDIT_ACTIONS, name="audit_action"),
        nullable=False,
        index=True,
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),  # IPv4 or IPv6
        nullable=True,
    )

    details: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # ── Relationships ────────────────────────────────────────────
    user = relationship("User", lazy="joined", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<AuditLog(action='{self.action}', user_id={self.user_id})>"
