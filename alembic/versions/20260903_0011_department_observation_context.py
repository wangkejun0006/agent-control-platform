"""Add short-lived company-admin department observation contexts.

Revision ID: 20260903_0011
Revises: 20260902_0010
"""

import sqlalchemy as sa

from alembic import op

revision = "20260903_0011"
down_revision = "20260902_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "control_plane_lan_department_observation_contexts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("context_id", sa.String(128), nullable=False),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "context_id", name="uq_lan_department_observation_context_id"
        ),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_lan_department_observation_context_idempotency",
        ),
    )
    op.create_index(
        "ix_lan_department_observation_context_session",
        "control_plane_lan_department_observation_contexts",
        ["session_id"],
    )
    op.create_index(
        "ix_lan_department_observation_context_department",
        "control_plane_lan_department_observation_contexts",
        ["department_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_lan_department_observation_context_department",
        table_name="control_plane_lan_department_observation_contexts",
    )
    op.drop_index(
        "ix_lan_department_observation_context_session",
        table_name="control_plane_lan_department_observation_contexts",
    )
    op.drop_table("control_plane_lan_department_observation_contexts")

