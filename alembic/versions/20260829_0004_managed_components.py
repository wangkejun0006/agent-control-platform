"""Add durable internal managed-component registration.

Revision ID: 20260829_0004
Revises: 20260828_0003
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260829_0004"
down_revision = "20260828_0003"
branch_labels = None
depends_on = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "control_plane_managed_components",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("component_id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("descriptor_digest", sa.String(length=71), nullable=False),
        sa.Column("descriptor", JSON_DOCUMENT, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("term_ref", sa.String(length=160), nullable=False),
        sa.Column("concept_refs", JSON_DOCUMENT, nullable=False),
        sa.Column("authority_claim", sa.String(length=32), nullable=False),
        sa.Column("creates_human_checkpoint", sa.Boolean(), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "component_id",
            "version",
            name="uq_managed_component_version",
        ),
        sa.UniqueConstraint(
            "descriptor_digest",
            name="uq_managed_component_descriptor_digest",
        ),
    )
    op.create_index(
        "ix_control_plane_managed_components_component_id",
        "control_plane_managed_components",
        ["component_id"],
    )
    op.create_table(
        "control_plane_automation_supervisor_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("scope_ref", sa.String(length=240), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(length=48), nullable=False),
        sa.Column("idempotency_key", sa.String(length=192), nullable=False),
        sa.Column("event_digest", sa.String(length=71), nullable=False),
        sa.Column("payload", JSON_DOCUMENT, nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scope_ref",
            "sequence",
            name="uq_automation_supervisor_scope_sequence",
        ),
        sa.UniqueConstraint(
            "idempotency_key",
            name="uq_automation_supervisor_idempotency",
        ),
        sa.UniqueConstraint(
            "event_digest",
            name="uq_automation_supervisor_event_digest",
        ),
    )
    op.create_index(
        "ix_control_plane_automation_supervisor_events_scope_ref",
        "control_plane_automation_supervisor_events",
        ["scope_ref"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_control_plane_automation_supervisor_events_scope_ref",
        table_name="control_plane_automation_supervisor_events",
    )
    op.drop_table("control_plane_automation_supervisor_events")
    op.drop_index(
        "ix_control_plane_managed_components_component_id",
        table_name="control_plane_managed_components",
    )
    op.drop_table("control_plane_managed_components")

