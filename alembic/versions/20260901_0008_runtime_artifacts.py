"""Add D0 Runtime Artifact, node, container evidence, and Task decisions.

Revision ID: 20260901_0008
Revises: 20260901_0007
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260901_0008"
down_revision = "20260901_0007"
branch_labels = None
depends_on = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.add_column("control_plane_runtime_runs", sa.Column("runtime_artifact_digest", sa.String(71), nullable=True))
    op.add_column("control_plane_runtime_runs", sa.Column("runtime_image_digest", sa.String(71), nullable=True))
    op.add_column("control_plane_runtime_runs", sa.Column("isolation_profile_digest", sa.String(71), nullable=True))
    op.add_column("control_plane_runtime_runs", sa.Column("input_snapshot_refs", JSON_DOCUMENT, nullable=True))

    op.create_table(
        "control_plane_runtime_artifact_revisions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("artifact_id", sa.String(160), nullable=False),
        sa.Column("revision_digest", sa.String(71), nullable=False),
        sa.Column("runtime_family", sa.String(96), nullable=False),
        sa.Column("runtime_source_digest", sa.String(71), nullable=False),
        sa.Column("runtime_image_digest", sa.String(71), nullable=False),
        sa.Column("isolation_profile_digest", sa.String(71), nullable=False),
        sa.Column("adapter_digest", sa.String(71), nullable=False),
        sa.Column("target_platform", sa.String(64), nullable=False),
        sa.Column("bundle_ref", sa.String(384), nullable=False),
        sa.Column("bundle_digest", sa.String(71), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("recorded_by_ref", sa.String(160), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("revision_digest", name="uq_runtime_artifact_revision_digest"),
    )
    op.create_index("ix_control_plane_runtime_artifact_revisions_artifact_id", "control_plane_runtime_artifact_revisions", ["artifact_id"])

    op.create_table(
        "control_plane_runtime_artifact_revocations",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("revocation_id", sa.String(128), nullable=False),
        sa.Column("artifact_id", sa.String(160), nullable=False),
        sa.Column("revision_digest", sa.String(71), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("revoked_by_ref", sa.String(160), nullable=False),
        sa.Column("receipt_id", sa.String(128), nullable=False),
        sa.Column("receipt_digest", sa.String(71), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("revocation_id", name="uq_runtime_artifact_revocation_id"),
        sa.UniqueConstraint("artifact_id", "revision_digest", name="uq_runtime_artifact_revocation"),
        sa.UniqueConstraint("idempotency_key", name="uq_runtime_artifact_revocation_idempotency"),
        sa.UniqueConstraint("receipt_id", name="uq_runtime_artifact_revocation_receipt"),
    )
    op.create_index("ix_control_plane_runtime_artifact_revocations_artifact_id", "control_plane_runtime_artifact_revocations", ["artifact_id"])

    op.create_table(
        "control_plane_runtime_node_capability_reports",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("report_digest", sa.String(71), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("reason_codes", JSON_DOCUMENT, nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_digest", name="uq_runtime_node_capability_digest"),
        sa.UniqueConstraint("idempotency_key", name="uq_runtime_node_capability_idempotency"),
    )
    op.create_index("ix_control_plane_runtime_node_capability_reports_node_id", "control_plane_runtime_node_capability_reports", ["node_id"])

    op.create_table(
        "control_plane_runtime_artifact_import_receipts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("receipt_id", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("artifact_id", sa.String(160), nullable=False),
        sa.Column("revision_digest", sa.String(71), nullable=False),
        sa.Column("runtime_image_digest", sa.String(71), nullable=False),
        sa.Column("capability_report_digest", sa.String(71), nullable=True),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("receipt_digest", sa.String(71), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("receipt_id", name="uq_runtime_artifact_import_receipt"),
        sa.UniqueConstraint("idempotency_key", name="uq_runtime_artifact_import_idempotency"),
    )
    op.create_index("ix_control_plane_runtime_artifact_import_receipts_node_id", "control_plane_runtime_artifact_import_receipts", ["node_id"])

    op.create_table(
        "control_plane_runtime_node_lease_claims",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("lease_id", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("run_id", sa.String(128), nullable=False),
        sa.Column("invocation_digest", sa.String(71), nullable=False),
        sa.Column("capability_report_digest", sa.String(71), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("lease_id", name="uq_runtime_node_lease_claim_lease"),
        sa.UniqueConstraint("run_id", name="uq_runtime_node_lease_claim_run"),
        sa.UniqueConstraint("idempotency_key", name="uq_runtime_node_lease_claim_idempotency"),
    )
    op.create_index("ix_control_plane_runtime_node_lease_claims_node_id", "control_plane_runtime_node_lease_claims", ["node_id"])

    op.create_table(
        "control_plane_runtime_container_evidence",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("run_id", sa.String(128), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("evidence_type", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("evidence_digest", sa.String(71), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id", "sequence", name="uq_runtime_container_sequence"),
        sa.UniqueConstraint("evidence_digest", name="uq_runtime_container_digest"),
        sa.UniqueConstraint("idempotency_key", name="uq_runtime_container_idempotency"),
    )
    op.create_index("ix_control_plane_runtime_container_evidence_run_id", "control_plane_runtime_container_evidence", ["run_id"])

    op.create_table(
        "control_plane_model_gateway_token_exchanges",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("attempt_id", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("task_id", sa.String(160), nullable=False),
        sa.Column("grant_id", sa.String(128), nullable=False),
        sa.Column("run_id", sa.String(128), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(96), nullable=False),
        sa.Column("token_issued", sa.Boolean(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("attempt_id", name="uq_model_gateway_exchange_attempt"),
        sa.UniqueConstraint("idempotency_key", name="uq_model_gateway_exchange_idempotency"),
    )

    op.create_table(
        "control_plane_department_task_decisions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("decision_id", sa.String(128), nullable=False),
        sa.Column("decision_digest", sa.String(71), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("task_id", sa.String(160), nullable=False),
        sa.Column("task_revision", sa.BigInteger(), nullable=False),
        sa.Column("task_scope_digest", sa.String(71), nullable=False),
        sa.Column("package_id", sa.String(160), nullable=False),
        sa.Column("package_digest", sa.String(71), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("actor_role_ref", sa.String(160), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("receipt_id", sa.String(128), nullable=False),
        sa.Column("receipt_digest", sa.String(71), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("decision_id", name="uq_department_task_decision_id"),
        sa.UniqueConstraint("decision_digest", name="uq_department_task_decision_digest"),
        sa.UniqueConstraint("idempotency_key", name="uq_department_task_decision_idempotency"),
        sa.UniqueConstraint("task_id", "task_revision", name="uq_department_task_decision_subject"),
        sa.UniqueConstraint("receipt_id", name="uq_department_task_decision_receipt"),
    )
    op.create_index("ix_control_plane_department_task_decisions_department_id", "control_plane_department_task_decisions", ["department_id"])
    op.create_index("ix_control_plane_department_task_decisions_task_id", "control_plane_department_task_decisions", ["task_id"])


def downgrade() -> None:
    op.drop_index("ix_control_plane_department_task_decisions_task_id", table_name="control_plane_department_task_decisions")
    op.drop_index("ix_control_plane_department_task_decisions_department_id", table_name="control_plane_department_task_decisions")
    op.drop_table("control_plane_department_task_decisions")
    op.drop_table("control_plane_model_gateway_token_exchanges")
    op.drop_index("ix_control_plane_runtime_container_evidence_run_id", table_name="control_plane_runtime_container_evidence")
    op.drop_table("control_plane_runtime_container_evidence")
    op.drop_index("ix_control_plane_runtime_node_lease_claims_node_id", table_name="control_plane_runtime_node_lease_claims")
    op.drop_table("control_plane_runtime_node_lease_claims")
    op.drop_index("ix_control_plane_runtime_artifact_import_receipts_node_id", table_name="control_plane_runtime_artifact_import_receipts")
    op.drop_table("control_plane_runtime_artifact_import_receipts")
    op.drop_index("ix_control_plane_runtime_node_capability_reports_node_id", table_name="control_plane_runtime_node_capability_reports")
    op.drop_table("control_plane_runtime_node_capability_reports")
    op.drop_index("ix_control_plane_runtime_artifact_revocations_artifact_id", table_name="control_plane_runtime_artifact_revocations")
    op.drop_table("control_plane_runtime_artifact_revocations")
    op.drop_index("ix_control_plane_runtime_artifact_revisions_artifact_id", table_name="control_plane_runtime_artifact_revisions")
    op.drop_table("control_plane_runtime_artifact_revisions")
    op.drop_column("control_plane_runtime_runs", "input_snapshot_refs")
    op.drop_column("control_plane_runtime_runs", "isolation_profile_digest")
    op.drop_column("control_plane_runtime_runs", "runtime_image_digest")
    op.drop_column("control_plane_runtime_runs", "runtime_artifact_digest")

