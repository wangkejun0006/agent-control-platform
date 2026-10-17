"""Add durable signed grants and Runtime queue state.

Revision ID: 20260828_0002
Revises: 20260828_0001
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260828_0002"
down_revision = "20260828_0001"
branch_labels = None
depends_on = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "control_plane_signed_grants",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("grant_id", sa.String(length=128), nullable=False),
        sa.Column("grant_digest", sa.String(length=71), nullable=False),
        sa.Column("key_id", sa.String(length=96), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("grant_id", name="uq_signed_grant_id"),
        sa.UniqueConstraint("grant_digest", name="uq_signed_grant_digest"),
    )
    op.create_table(
        "control_plane_runtime_runs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("task_id", sa.String(length=128), nullable=False),
        sa.Column("grant_id", sa.String(length=128), nullable=False),
        sa.Column("grant_digest", sa.String(length=71), nullable=False),
        sa.Column("composition_digest", sa.String(length=71), nullable=False),
        sa.Column("runtime_source_digest", sa.String(length=71), nullable=False),
        sa.Column("invocation_digest", sa.String(length=71), nullable=False),
        sa.Column("idempotency_key", sa.String(length=192), nullable=False),
        sa.Column("invocation", JSON_DOCUMENT, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("worker_identity", sa.String(length=160), nullable=True),
        sa.Column("cancel_reason_code", sa.String(length=96), nullable=True),
        sa.Column("failure_reason_code", sa.String(length=96), nullable=True),
        sa.Column("result_document", JSON_DOCUMENT, nullable=True),
        sa.Column("result_digest", sa.String(length=71), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", name="uq_runtime_run_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_runtime_run_idempotency"),
    )
    op.create_table(
        "control_plane_runtime_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(length=96), nullable=False),
        sa.Column("event_digest", sa.String(length=71), nullable=False),
        sa.Column("payload", JSON_DOCUMENT, nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "sequence", name="uq_runtime_event_sequence"),
        sa.UniqueConstraint("event_digest", name="uq_runtime_event_digest"),
    )
    op.create_index(
        "ix_control_plane_runtime_events_run_id",
        "control_plane_runtime_events",
        ["run_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_control_plane_runtime_events_run_id",
        table_name="control_plane_runtime_events",
    )
    op.drop_table("control_plane_runtime_events")
    op.drop_table("control_plane_runtime_runs")
    op.drop_table("control_plane_signed_grants")

