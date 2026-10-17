"""SQLAlchemy rows for loopback-only Department Cockpit identity mapping."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .models import IDENTITY, Base


class CockpitLocalAccountRow(Base):
    """Loopback D0 account; not the company Human Identity authority."""

    __tablename__ = "control_plane_cockpit_local_accounts"
    __table_args__ = (
        UniqueConstraint("account_id", name="uq_cockpit_local_account_id"),
        UniqueConstraint("username", name="uq_cockpit_local_username"),
        UniqueConstraint("local_human_ref", name="uq_cockpit_local_human_ref"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    account_id: Mapped[str] = mapped_column(String(96), nullable=False)
    username: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(96), nullable=False)
    local_human_ref: Mapped[str] = mapped_column(String(96), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role_ref: Mapped[str] = mapped_column(String(96), nullable=False)
    department_id: Mapped[str | None] = mapped_column(String(96), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    failed_login_count: Mapped[int] = mapped_column(nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    approved_by_ref: Mapped[str | None] = mapped_column(String(96), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class CockpitLocalSessionRow(Base):
    """Hashed server-side session for the loopback D0 cockpit."""

    __tablename__ = "control_plane_cockpit_local_sessions"
    __table_args__ = (
        UniqueConstraint("session_id", name="uq_cockpit_local_session_id"),
        UniqueConstraint("session_digest", name="uq_cockpit_local_session_digest"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(96), nullable=False)
    session_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    account_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

