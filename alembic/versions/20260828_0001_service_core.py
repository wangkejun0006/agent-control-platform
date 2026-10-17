"""Create Control Plane service core tables.

Revision ID: 20260828_0001
Revises: None
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260828_0001"
down_revision = None
branch_labels = None
depends_on = None

JSON_DOCUMENT = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "control_plane_stream_heads",
        sa.Column("stream_name", sa.String(length=96), nullable=False),
        sa.Column("next_sequence", sa.BigInteger(), nullable=False),
        sa.Column("last_record_hash", sa.String(length=71), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("stream_name"),
    )
    op.create_table(
        "control_plane_qualification_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("stream_name", sa.String(length=96), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("record_id", sa.String(length=96), nullable=False),
        sa.Column("record_type", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("idempotency_key", sa.String(length=192), nullable=False),
        sa.Column("previous_record_hash", sa.String(length=71), nullable=False),
        sa.Column("payload", JSON_DOCUMENT, nullable=False),
        sa.Column("record_hash", sa.String(length=71), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key", name="uq_qualification_idempotency"),
        sa.UniqueConstraint("record_id", name="uq_qualification_record_id"),
        sa.UniqueConstraint(
            "stream_name", "sequence", name="uq_qualification_sequence"
        ),
    )
    op.create_index(
        "ix_control_plane_qualification_events_run_id",
        "control_plane_qualification_events",
        ["run_id"],
    )
    op.create_table(
        "control_plane_outbox_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.String(length=96), nullable=False),
        sa.Column("topic", sa.String(length=128), nullable=False),
        sa.Column("aggregate_ref", sa.String(length=240), nullable=False),
        sa.Column("payload", JSON_DOCUMENT, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id", name="uq_outbox_event_id"),
    )
    op.create_table(
        "control_plane_policy_activations",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("policy_id", sa.String(length=128), nullable=False),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("policy_digest", sa.String(length=71), nullable=False),
        sa.Column("approval_digest", sa.String(length=71), nullable=False),
        sa.Column("receipt_id", sa.String(length=128), nullable=False),
        sa.Column("receipt_digest", sa.String(length=71), nullable=False),
        sa.Column("approval_document", JSON_DOCUMENT, nullable=False),
        sa.Column("receipt_document", JSON_DOCUMENT, nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_status", sa.String(length=32), nullable=False),
        sa.Column("synthetic_only", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("policy_digest", name="uq_policy_activation_digest"),
        sa.UniqueConstraint("receipt_id", name="uq_policy_activation_receipt"),
    )
    op.create_index(
        "ix_control_plane_policy_activations_policy_id",
        "control_plane_policy_activations",
        ["policy_id"],
    )
    op.create_table(
        "control_plane_receipts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("receipt_id", sa.String(length=128), nullable=False),
        sa.Column("receipt_type", sa.String(length=96), nullable=False),
        sa.Column("receipt_digest", sa.String(length=71), nullable=False),
        sa.Column("subject_ref", sa.String(length=240), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("receipt_digest", name="uq_receipt_digest"),
        sa.UniqueConstraint("receipt_id", name="uq_receipt_id"),
    )
    op.create_table(
        "control_plane_grant_revocations",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("grant_id", sa.String(length=128), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("reason_code", sa.String(length=96), nullable=False),
        sa.Column("revoked_by_ref", sa.String(length=128), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("grant_id", name="uq_grant_revocation_grant"),
    )
    op.create_table(
        "control_plane_worker_leases",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("lease_id", sa.String(length=128), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("worker_identity", sa.String(length=160), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome", sa.String(length=48), nullable=True),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("lease_id", name="uq_worker_lease_id"),
        sa.UniqueConstraint("run_id", name="uq_worker_lease_run"),
    )
    op.create_table(
        "control_plane_audit_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("audit_id", sa.String(length=128), nullable=False),
        sa.Column("correlation_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=96), nullable=False),
        sa.Column("actor_ref", sa.String(length=160), nullable=False),
        sa.Column("payload", JSON_DOCUMENT, nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("audit_id", name="uq_audit_id"),
    )
    op.create_index(
        "ix_control_plane_audit_events_correlation_id",
        "control_plane_audit_events",
        ["correlation_id"],
    )
    op.create_table(
        "control_plane_reconciliation_claims",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("worker_identity", sa.String(length=160), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", name="uq_reconciliation_run"),
    )
    op.create_table(
        "control_plane_adapter_evidence",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("role", sa.String(length=96), nullable=False),
        sa.Column("component_id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("digest", sa.String(length=71), nullable=False),
        sa.Column("evidence_status", sa.String(length=32), nullable=False),
        sa.Column("capabilities", JSON_DOCUMENT, nullable=False),
        sa.Column("synthetic_only", sa.Boolean(), nullable=False),
        sa.Column("runtime_verified", sa.Boolean(), nullable=False),
        sa.Column("evidence_ref", sa.Text(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("role", name="uq_adapter_evidence_role"),
    )


def downgrade() -> None:
    op.drop_table("control_plane_adapter_evidence")
    op.drop_table("control_plane_reconciliation_claims")
    op.drop_index(
        "ix_control_plane_audit_events_correlation_id",
        table_name="control_plane_audit_events",
    )
    op.drop_table("control_plane_audit_events")
    op.drop_table("control_plane_worker_leases")
    op.drop_table("control_plane_grant_revocations")
    op.drop_table("control_plane_receipts")
    op.drop_index(
        "ix_control_plane_policy_activations_policy_id",
        table_name="control_plane_policy_activations",
    )
    op.drop_table("control_plane_policy_activations")
    op.drop_table("control_plane_outbox_events")
    op.drop_index(
        "ix_control_plane_qualification_events_run_id",
        table_name="control_plane_qualification_events",
    )
    op.drop_table("control_plane_qualification_events")
    op.drop_table("control_plane_stream_heads")

