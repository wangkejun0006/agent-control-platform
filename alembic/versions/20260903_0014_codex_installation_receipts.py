"""Persist Codex CLI installation attempts, stage events and terminal receipts.

Revision ID: 20260903_0014
Revises: 20260903_0013
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260903_0014"
down_revision = "20260903_0013"
branch_labels = None
depends_on = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "control_plane_lan_codex_installation_attempts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("attempt_id", sa.String(128), nullable=False),
        sa.Column("predecessor_attempt_id", sa.String(128), nullable=True),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("codex_cli_version", sa.String(32), nullable=False),
        sa.Column("target_platform", sa.String(96), nullable=False),
        sa.Column("release_manifest_digest", sa.String(71), nullable=False),
        sa.Column("archive_digest", sa.String(71), nullable=False),
        sa.Column("latest_sequence", sa.BigInteger(), nullable=False),
        sa.Column("current_stage", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("failure_code", sa.String(64), nullable=True),
        sa.Column("intermediate_events_available", sa.Boolean(), nullable=False),
        sa.Column("resource_revision", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("attempt_id", name="uq_lan_codex_install_attempt_id"),
    )
    op.create_index(
        "ix_lan_codex_install_attempt_node",
        "control_plane_lan_codex_installation_attempts",
        ["node_id"],
    )
    op.create_index(
        "ix_lan_codex_install_attempt_department",
        "control_plane_lan_codex_installation_attempts",
        ["department_id"],
    )
    op.create_table(
        "control_plane_lan_codex_installation_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(128), nullable=False),
        sa.Column("attempt_id", sa.String(128), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("failure_code", sa.String(64), nullable=True),
        sa.Column("document_digest", sa.String(71), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id", name="uq_lan_codex_install_event_id"),
        sa.UniqueConstraint(
            "attempt_id", "sequence", name="uq_lan_codex_install_event_sequence"
        ),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_lan_codex_install_event_idempotency"
        ),
    )
    op.create_index(
        "ix_lan_codex_install_event_attempt",
        "control_plane_lan_codex_installation_events",
        ["attempt_id"],
    )
    op.create_index(
        "ix_lan_codex_install_event_department",
        "control_plane_lan_codex_installation_events",
        ["department_id"],
    )
    op.create_table(
        "control_plane_lan_codex_installation_receipts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("receipt_id", sa.String(128), nullable=False),
        sa.Column("attempt_id", sa.String(128), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("codex_cli_version", sa.String(32), nullable=False),
        sa.Column("target_platform", sa.String(96), nullable=False),
        sa.Column("release_manifest_digest", sa.String(71), nullable=False),
        sa.Column("archive_digest", sa.String(71), nullable=False),
        sa.Column("evidence_source", sa.String(48), nullable=False),
        sa.Column("intermediate_events_available", sa.Boolean(), nullable=False),
        sa.Column("receipt_digest", sa.String(71), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("receipt_id", name="uq_lan_codex_install_receipt_id"),
        sa.UniqueConstraint("attempt_id", name="uq_lan_codex_install_receipt_attempt"),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_lan_codex_install_receipt_idempotency"
        ),
    )
    op.create_index(
        "ix_lan_codex_install_receipt_node",
        "control_plane_lan_codex_installation_receipts",
        ["node_id"],
    )
    op.create_index(
        "ix_lan_codex_install_receipt_department",
        "control_plane_lan_codex_installation_receipts",
        ["department_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_lan_codex_install_receipt_department",
        table_name="control_plane_lan_codex_installation_receipts",
    )
    op.drop_index(
        "ix_lan_codex_install_receipt_node",
        table_name="control_plane_lan_codex_installation_receipts",
    )
    op.drop_table("control_plane_lan_codex_installation_receipts")
    op.drop_index(
        "ix_lan_codex_install_event_department",
        table_name="control_plane_lan_codex_installation_events",
    )
    op.drop_index(
        "ix_lan_codex_install_event_attempt",
        table_name="control_plane_lan_codex_installation_events",
    )
    op.drop_table("control_plane_lan_codex_installation_events")
    op.drop_index(
        "ix_lan_codex_install_attempt_department",
        table_name="control_plane_lan_codex_installation_attempts",
    )
    op.drop_index(
        "ix_lan_codex_install_attempt_node",
        table_name="control_plane_lan_codex_installation_attempts",
    )
    op.drop_table("control_plane_lan_codex_installation_attempts")

