"""Add company control console Model Route decisions and Task scope audits.

Revision ID: 20260901_0007
Revises: 20260901_0006
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "20260901_0007"
down_revision = "20260901_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "control_plane_model_route_decisions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("decision_id", sa.String(length=128), nullable=False),
        sa.Column("decision_digest", sa.String(length=71), nullable=False),
        sa.Column("idempotency_key", sa.String(length=192), nullable=False),
        sa.Column("route_id", sa.String(length=128), nullable=False),
        sa.Column("route_revision_digest", sa.String(length=71), nullable=False),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("snapshot_digest", sa.String(length=71), nullable=True),
        sa.Column("source_decision_id", sa.String(length=128), nullable=True),
        sa.Column("actor_ref", sa.String(length=160), nullable=False),
        sa.Column("actor_role_ref", sa.String(length=160), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("receipt_id", sa.String(length=128), nullable=False),
        sa.Column("receipt_digest", sa.String(length=71), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("decision_id", name="uq_model_route_decision_id"),
        sa.UniqueConstraint(
            "decision_digest", name="uq_model_route_decision_digest"
        ),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_model_route_decision_idempotency"
        ),
        sa.UniqueConstraint("receipt_id", name="uq_model_route_decision_receipt"),
    )
    op.create_index(
        "ix_control_plane_model_route_decisions_route_id",
        "control_plane_model_route_decisions",
        ["route_id"],
    )
    op.create_table(
        "control_plane_task_scope_audits",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("audit_record_id", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=192), nullable=False),
        sa.Column("task_id", sa.String(length=160), nullable=False),
        sa.Column("task_revision", sa.BigInteger(), nullable=False),
        sa.Column("task_digest", sa.String(length=71), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("reason_codes", sa.JSON(), nullable=False),
        sa.Column("grant_id", sa.String(length=128), nullable=True),
        sa.Column("grant_action", sa.String(length=32), nullable=False),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("receipt_id", sa.String(length=128), nullable=False),
        sa.Column("receipt_digest", sa.String(length=71), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "audit_record_id", name="uq_task_scope_audit_record_id"
        ),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_task_scope_audit_idempotency"
        ),
        sa.UniqueConstraint("receipt_id", name="uq_task_scope_audit_receipt"),
    )
    op.create_index(
        "ix_control_plane_task_scope_audits_task_id",
        "control_plane_task_scope_audits",
        ["task_id"],
    )
    op.create_table(
        "control_plane_console_commands",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("idempotency_key", sa.String(length=192), nullable=False),
        sa.Column("command_kind", sa.String(length=96), nullable=False),
        sa.Column("target_ref", sa.String(length=240), nullable=False),
        sa.Column("request_digest", sa.String(length=71), nullable=False),
        sa.Column("response", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_control_console_command_idempotency"
        ),
    )


def downgrade() -> None:
    op.drop_table("control_plane_console_commands")
    op.drop_index(
        "ix_control_plane_task_scope_audits_task_id",
        table_name="control_plane_task_scope_audits",
    )
    op.drop_table("control_plane_task_scope_audits")
    op.drop_index(
        "ix_control_plane_model_route_decisions_route_id",
        table_name="control_plane_model_route_decisions",
    )
    op.drop_table("control_plane_model_route_decisions")

