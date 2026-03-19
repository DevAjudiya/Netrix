# ─────────────────────────────────────────
# Netrix — User Model
# Table: users
# ─────────────────────────────────────────

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class User(Base):
    """
    ORM model representing a user account on the Netrix platform.

    Users can be either ``admin`` (full access) or ``analyst`` (standard
    scanning and reporting permissions).
    """

    __tablename__ = "users"

    # ── Primary Key ──────────────────────────────────────────────
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    # ── Identity ─────────────────────────────────────────────────
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # ── Role & Status ────────────────────────────────────────────
    role: Mapped[str] = mapped_column(
        Enum("admin", "analyst", name="user_role"),
        nullable=False,
        default="analyst",
        server_default="analyst",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="1",
    )
    is_banned: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="0",
    )
    ban_reason: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    # ── Timestamps ───────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Relationships ────────────────────────────────────────────
    scans = relationship(
        "Scan",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    reports = relationship(
        "Report",
        back_populates="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    # ── Methods ──────────────────────────────────────────────────
    def __repr__(self) -> str:
        return f"<User(username='{self.username}', role='{self.role}')>"

    def to_dict(self) -> dict:
        """
        Serialise the user to a dictionary suitable for API responses.

        .. warning::
            ``password_hash`` is **never** included in the output.
        """
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "is_banned": self.is_banned,
            "ban_reason": self.ban_reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
