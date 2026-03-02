# ─────────────────────────────────────────
# Netrix — Port Model
# Table: ports
# ─────────────────────────────────────────

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base

# Ports that are considered critical from a security perspective
CRITICAL_PORTS = frozenset({
    22, 23, 25, 53, 80, 443, 445,
    3306, 3389, 5432, 6379, 8080, 8443,
})

# Common web-service ports
WEB_PORTS = frozenset({80, 443, 8080, 8443, 8000, 8888})

# Common database ports
DATABASE_PORTS = frozenset({3306, 5432, 1433, 1521, 27017, 6379, 5984, 9200})


class Port(Base):
    """
    ORM model representing an open (or filtered) port on a host.

    Stores service fingerprint data, version information, and the raw
    output of any NSE scripts executed against this port.
    """

    __tablename__ = "ports"

    # ── Primary Key ──────────────────────────────────────────────
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    # ── Parent Host ──────────────────────────────────────────────
    host_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Port Identification ──────────────────────────────────────
    port_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
    )
    protocol: Mapped[str] = mapped_column(
        Enum("tcp", "udp", name="port_protocol"),
        nullable=False,
        default="tcp",
        server_default="tcp",
    )
    state: Mapped[str] = mapped_column(
        Enum("open", "closed", "filtered", "open|filtered", name="port_state"),
        nullable=False,
        default="open",
        server_default="open",
    )

    # ── Service Fingerprint ──────────────────────────────────────
    service_name: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    product: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    version: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    extra_info: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    cpe: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # ── NSE Script Output (MySQL JSON column) ────────────────────
    nse_output: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON,
        nullable=True,
    )

    # ── Flags ────────────────────────────────────────────────────
    is_critical_port: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="0",
    )

    # ── Timestamp ────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ────────────────────────────────────────────
    host = relationship(
        "Host",
        back_populates="ports",
    )
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="port",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    # ── Computed Properties ──────────────────────────────────────
    @property
    def is_web_port(self) -> bool:
        """Return ``True`` if this port typically serves HTTP/HTTPS."""
        return self.port_number in WEB_PORTS

    @property
    def is_database_port(self) -> bool:
        """Return ``True`` if this port typically serves a database."""
        return self.port_number in DATABASE_PORTS

    # ── Methods ──────────────────────────────────────────────────
    def __repr__(self) -> str:
        return (
            f"<Port(port_number={self.port_number}, "
            f"service_name='{self.service_name}', state='{self.state}')>"
        )

    def to_dict(self) -> dict:
        """Serialise the port to a dictionary suitable for API responses."""
        return {
            "id": self.id,
            "host_id": self.host_id,
            "port_number": self.port_number,
            "protocol": self.protocol,
            "state": self.state,
            "service_name": self.service_name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "cpe": self.cpe,
            "nse_output": self.nse_output,
            "is_critical_port": self.is_critical_port,
            "is_web_port": self.is_web_port,
            "is_database_port": self.is_database_port,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
