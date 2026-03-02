# ─────────────────────────────────────────
# Netrix — Report Model
# Table: reports
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


class Report(Base):
    """
    ORM model representing a generated scan report.

    Reports are produced in one of four formats (PDF, JSON, CSV, HTML)
    and their physical files are stored in the configured reports
    directory.
    """

    __tablename__ = "reports"

    # ── Primary Key ──────────────────────────────────────────────
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    # ── Foreign Keys ─────────────────────────────────────────────
    scan_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ── Report Metadata ──────────────────────────────────────────
    report_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    format: Mapped[str] = mapped_column(
        Enum("pdf", "json", "csv", "html", name="report_format"),
        nullable=False,
    )
    file_path: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )
    file_size: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    # ── Scan Summary (denormalised for fast queries) ──────────────
    total_hosts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    total_vulnerabilities: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    critical_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    high_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    medium_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    low_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    # ── Timestamps & Download Tracking ───────────────────────────
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    download_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    last_downloaded: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────
    scan = relationship(
        "Scan",
        back_populates="reports",
    )
    user = relationship(
        "User",
        back_populates="reports",
    )

    # ── Computed Properties ──────────────────────────────────────
    @property
    def file_size_readable(self) -> str:
        """
        Return a human-friendly file size string (e.g. ``"1.23 MB"``).

        Returns:
            str: Formatted size string, or ``"0 B"`` if size is unknown.
        """
        if self.file_size is None or self.file_size == 0:
            return "0 B"

        size = float(self.file_size)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    # ── Methods ──────────────────────────────────────────────────
    def __repr__(self) -> str:
        return (
            f"<Report(report_name='{self.report_name}', "
            f"format='{self.format}')>"
        )

    def to_dict(self) -> dict:
        """Serialise the report to a dictionary suitable for API responses."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "user_id": self.user_id,
            "report_name": self.report_name,
            "format": self.format,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "file_size_readable": self.file_size_readable,
            "total_hosts": self.total_hosts,
            "total_vulnerabilities": self.total_vulnerabilities,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
            "download_count": self.download_count,
            "last_downloaded": self.last_downloaded.isoformat() if self.last_downloaded else None,
        }
