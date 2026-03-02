# ─────────────────────────────────────────
# Netrix — Host Model
# Table: hosts
# ─────────────────────────────────────────

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Host(Base):
    """
    ORM model representing a discovered network host.

    A host belongs to exactly one scan and may have multiple open
    ports. OS-detection results, MAC address, and uptime are stored
    when available.
    """

    __tablename__ = "hosts"

    # ── Primary Key ──────────────────────────────────────────────
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    # ── Parent Scan ──────────────────────────────────────────────
    scan_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Network Identity ─────────────────────────────────────────
    ip_address: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        index=True,
    )
    hostname: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        Enum("up", "down", "unknown", name="host_status"),
        nullable=False,
        default="unknown",
        server_default="unknown",
    )

    # ── OS Detection ─────────────────────────────────────────────
    os_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    os_accuracy: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    os_family: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    os_generation: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    os_cpe: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── Hardware / Layer-2 ───────────────────────────────────────
    mac_address: Mapped[Optional[str]] = mapped_column(
        String(17),
        nullable=True,
    )
    mac_vendor: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── Metadata ─────────────────────────────────────────────────
    uptime: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    tcp_sequence: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    # ── Risk Assessment ──────────────────────────────────────────
    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    risk_level: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", "info", name="risk_level"),
        nullable=False,
        default="info",
        server_default="info",
    )

    # ── Timestamp ────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ────────────────────────────────────────────
    scan = relationship(
        "Scan",
        back_populates="hosts",
    )
    ports = relationship(
        "Port",
        back_populates="host",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    # ── Computed Properties ──────────────────────────────────────
    @property
    def risk_level_color(self) -> str:
        """
        Return a hex colour code corresponding to the current risk level.

        Returns:
            str: Hex colour string.
        """
        colours = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFD700",
            "low": "#00CC00",
            "info": "#0088FF",
        }
        return colours.get(self.risk_level, "#808080")

    # ── Methods ──────────────────────────────────────────────────
    def __repr__(self) -> str:
        return (
            f"<Host(ip_address='{self.ip_address}', status='{self.status}', "
            f"risk_score={self.risk_score})>"
        )

    def to_dict(self) -> dict:
        """Serialise the host to a dictionary suitable for API responses."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "status": self.status,
            "os_name": self.os_name,
            "os_accuracy": self.os_accuracy,
            "os_family": self.os_family,
            "os_generation": self.os_generation,
            "os_cpe": self.os_cpe,
            "mac_address": self.mac_address,
            "mac_vendor": self.mac_vendor,
            "uptime": self.uptime,
            "tcp_sequence": self.tcp_sequence,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_level_color": self.risk_level_color,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
