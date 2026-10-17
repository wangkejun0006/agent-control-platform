"""Add loopback D0 cockpit local accounts and sessions.

Revision ID: 20260901_0006
Revises: 20260831_0005
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260901_0006"
down_revision = "20260831_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "control_plane_cockpit_local_accounts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("account_id", sa.String(length=96), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=96), nullable=False),
        sa.Column("local_human_ref", sa.String(length=96), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role_ref", sa.String(length=96), nullable=False),
        sa.Column("department_id", sa.String(length=96), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by_ref", sa.String(length=96), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_id", name="uq_cockpit_local_account_id"),
        sa.UniqueConstraint("username", name="uq_cockpit_local_username"),
        sa.UniqueConstraint("local_human_ref", name="uq_cockpit_local_human_ref"),
    )
    op.create_index(
        "ix_control_plane_cockpit_local_accounts_username",
        "control_plane_cockpit_local_accounts",
        ["username"],
    )
    op.create_table(
        "control_plane_cockpit_local_sessions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("session_id", sa.String(length=96), nullable=False),
        sa.Column("session_digest", sa.String(length=71), nullable=False),
        sa.Column("account_id", sa.String(length=96), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id", name="uq_cockpit_local_session_id"),
        sa.UniqueConstraint(
            "session_digest", name="uq_cockpit_local_session_digest"
        ),
    )
    op.create_index(
        "ix_control_plane_cockpit_local_sessions_account_id",
        "control_plane_cockpit_local_sessions",
        ["account_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_control_plane_cockpit_local_sessions_account_id",
        table_name="control_plane_cockpit_local_sessions",
    )
    op.drop_table("control_plane_cockpit_local_sessions")
    op.drop_index(
        "ix_control_plane_cockpit_local_accounts_username",
        table_name="control_plane_cockpit_local_accounts",
    )
    op.drop_table("control_plane_cockpit_local_accounts")

