# ─────────────────────────────────────────
# Netrix — SystemMetric Model
# Purpose: Stores periodic system health snapshots (CPU, memory, service status).
# ─────────────────────────────────────────

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base


class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cpu_percent: Mapped[float] = mapped_column(nullable=False)
    memory_percent: Mapped[float] = mapped_column(nullable=False)
    redis_status: Mapped[bool] = mapped_column(Boolean, nullable=False)
    mysql_status: Mapped[bool] = mapped_column(Boolean, nullable=False)
    nmap_status: Mapped[bool] = mapped_column(Boolean, nullable=False)
    active_scans: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    queue_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
