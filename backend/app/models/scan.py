# ─────────────────────────────────────────
# Netrix — Scan Model
# Table: scans
# ─────────────────────────────────────────

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Scan(Base):
    """
    ORM model representing a network scan execution.

    Each scan targets a single IP, CIDR range or domain and tracks
    its progress from ``pending`` through ``completed`` or ``failed``.
    """

    __tablename__ = "scans"

    # ── Primary Key ──────────────────────────────────────────────
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    # ── Human-readable ID (e.g. NETRIX_ABC123) ───────────────────
    scan_id: Mapped[str] = mapped_column(
        String(20),
        unique=True,
        nullable=False,
        index=True,
    )

    # ── Owner ────────────────────────────────────────────────────
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Target Definition ────────────────────────────────────────
    target: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    target_type: Mapped[str] = mapped_column(
        Enum("ip", "cidr", "domain", name="target_type"),
        nullable=False,
    )
    scan_type: Mapped[str] = mapped_column(
        Enum(
            "quick", "stealth", "full",
            "aggressive", "vulnerability", "custom",
            name="scan_type",
        ),
        nullable=False,
        default="full",
    )
    scan_args: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # ── Status & Progress ────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        Enum("pending", "running", "completed", "failed", name="scan_status"),
        nullable=False,
        default="pending",
        server_default="pending",
        index=True,
    )
    progress: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    # ── Timing ───────────────────────────────────────────────────
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Results Summary ──────────────────────────────────────────
    total_hosts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    hosts_up: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    hosts_down: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    # ── Metadata ─────────────────────────────────────────────────
    nmap_version: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ────────────────────────────────────────────
    user = relationship(
        "User",
        back_populates="scans",
    )
    hosts = relationship(
        "Host",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )
    reports = relationship(
        "Report",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    # ── Computed Properties ──────────────────────────────────────
    @property
    def duration(self) -> Optional[float]:
        """
        Calculate scan duration in seconds.

        Returns:
            Optional[float]: Duration in seconds, or ``None`` if the scan
            has not started or has not yet finished.
        """
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    # ── Methods ──────────────────────────────────────────────────
    def __repr__(self) -> str:
        return (
            f"<Scan(scan_id='{self.scan_id}', target='{self.target}', "
            f"status='{self.status}')>"
        )

    def to_dict(self) -> dict:
        """Serialise the scan to a dictionary suitable for API responses."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "user_id": self.user_id,
            "target": self.target,
            "target_type": self.target_type,
            "scan_type": self.scan_type,
            "scan_args": self.scan_args,
            "status": self.status,
            "progress": self.progress,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.duration,
            "total_hosts": self.total_hosts,
            "hosts_up": self.hosts_up,
            "hosts_down": self.hosts_down,
            "nmap_version": self.nmap_version,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
