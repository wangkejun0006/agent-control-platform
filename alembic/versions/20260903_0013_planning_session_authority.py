"""Persist planning authority, turns, commands and redacted invocation evidence.

Revision ID: 20260903_0013
Revises: 20260903_0012
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260903_0013"
down_revision = "20260903_0012"
branch_labels = None
depends_on = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "control_plane_planning_sessions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("session_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("parent_task_id", sa.String(160), nullable=False),
        sa.Column("professional_task_id", sa.String(160), nullable=True),
        sa.Column("predecessor_session_id", sa.String(160), nullable=True),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("status", sa.String(48), nullable=False),
        sa.Column("stage", sa.String(64), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("round_count", sa.Integer(), nullable=False),
        sa.Column("route_id", sa.String(160), nullable=False),
        sa.Column("route_revision_digest", sa.String(71), nullable=False),
        sa.Column("route_selection_digest", sa.String(71), nullable=False),
        sa.Column("grant_id", sa.String(160), nullable=False),
        sa.Column("grant_digest", sa.String(71), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id", name="uq_planning_session_id"),
        sa.UniqueConstraint("parent_task_id", name="uq_planning_parent_task"),
        sa.UniqueConstraint(
            "professional_task_id", name="uq_planning_professional_task"
        ),
    )
    op.create_index(
        "ix_planning_session_department",
        "control_plane_planning_sessions",
        ["department_id"],
    )
    op.create_table(
        "control_plane_planning_turns",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("turn_id", sa.String(160), nullable=False),
        sa.Column("session_id", sa.String(160), nullable=False),
        sa.Column("round_number", sa.Integer(), nullable=False),
        sa.Column("question_request_id", sa.String(160), nullable=False),
        sa.Column("question_revision", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("question_document", JSON_DOCUMENT, nullable=False),
        sa.Column("answer_document", JSON_DOCUMENT, nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("turn_id", name="uq_planning_turn_id"),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_planning_turn_idempotency"
        ),
        sa.UniqueConstraint(
            "session_id", "round_number", name="uq_planning_turn_round"
        ),
    )
    op.create_index(
        "ix_planning_turn_session", "control_plane_planning_turns", ["session_id"]
    )
    op.create_table(
        "control_plane_planning_commands",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("command_id", sa.String(160), nullable=False),
        sa.Column("session_id", sa.String(160), nullable=False),
        sa.Column("command_kind", sa.String(48), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("result_revision", sa.BigInteger(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("command_id", name="uq_planning_command_id"),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_planning_command_idempotency"
        ),
    )
    op.create_index(
        "ix_planning_command_session",
        "control_plane_planning_commands",
        ["session_id"],
    )
    op.create_table(
        "control_plane_planning_invocation_evidence",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("invocation_id", sa.String(160), nullable=False),
        sa.Column("session_id", sa.String(160), nullable=False),
        sa.Column("round_number", sa.Integer(), nullable=False),
        sa.Column("stage", sa.String(64), nullable=False),
        sa.Column("route_id", sa.String(160), nullable=False),
        sa.Column("route_revision_digest", sa.String(71), nullable=False),
        sa.Column("grant_id", sa.String(160), nullable=False),
        sa.Column("provider_request_id", sa.String(192), nullable=True),
        sa.Column("returned_model_id", sa.String(192), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False),
        sa.Column("output_tokens", sa.Integer(), nullable=False),
        sa.Column("cost_cny_micros", sa.BigInteger(), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("response_digest", sa.String(71), nullable=False),
        sa.Column("schema_valid", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(48), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("invocation_id", name="uq_planning_invocation_id"),
    )
    op.create_index(
        "ix_planning_invocation_session",
        "control_plane_planning_invocation_evidence",
        ["session_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_planning_invocation_session",
        table_name="control_plane_planning_invocation_evidence",
    )
    op.drop_table("control_plane_planning_invocation_evidence")
    op.drop_index(
        "ix_planning_command_session", table_name="control_plane_planning_commands"
    )
    op.drop_table("control_plane_planning_commands")
    op.drop_index(
        "ix_planning_turn_session", table_name="control_plane_planning_turns"
    )
    op.drop_table("control_plane_planning_turns")
    op.drop_index(
        "ix_planning_session_department",
        table_name="control_plane_planning_sessions",
    )
    op.drop_table("control_plane_planning_sessions")

