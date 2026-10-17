"""Add Stage-1 LAN identity, enrollment, node and artifact evidence.

Revision ID: 20260901_0009
Revises: 20260901_0008
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260901_0009"
down_revision = "20260901_0008"
branch_labels = None
depends_on = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "control_plane_lan_human_accounts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("account_id", sa.String(96), nullable=False),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(96), nullable=False),
        sa.Column("human_ref", sa.String(128), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role_ref", sa.String(96), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("failed_window_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by_ref", sa.String(128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("account_id", name="uq_lan_human_account_id"),
        sa.UniqueConstraint("username", name="uq_lan_human_username"),
        sa.UniqueConstraint("human_ref", name="uq_lan_human_ref"),
    )
    op.create_index("ix_control_plane_lan_human_accounts_username", "control_plane_lan_human_accounts", ["username"])
    op.create_table(
        "control_plane_lan_invites",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("invite_id", sa.String(128), nullable=False),
        sa.Column("token_digest", sa.String(71), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("role_ref", sa.String(96), nullable=False),
        sa.Column("invited_by_ref", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_by_ref", sa.String(128), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("invite_id", name="uq_lan_invite_id"),
        sa.UniqueConstraint("token_digest", name="uq_lan_invite_token_digest"),
        sa.UniqueConstraint("idempotency_key", name="uq_lan_invite_idempotency"),
    )
    op.create_index("ix_control_plane_lan_invites_department_id", "control_plane_lan_invites", ["department_id"])
    op.create_table(
        "control_plane_lan_sessions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("session_digest", sa.String(71), nullable=False),
        sa.Column("csrf_digest", sa.String(71), nullable=False),
        sa.Column("account_id", sa.String(96), nullable=False),
        sa.Column("login_idempotency_key", sa.String(192), nullable=False),
        sa.Column("login_request_digest", sa.String(71), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reauthenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id", name="uq_lan_session_id"),
        sa.UniqueConstraint("session_digest", name="uq_lan_session_digest"),
        sa.UniqueConstraint("login_idempotency_key", name="uq_lan_session_login_idempotency"),
    )
    op.create_index("ix_control_plane_lan_sessions_account_id", "control_plane_lan_sessions", ["account_id"])
    op.create_table(
        "control_plane_lan_enrollment_codes",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("enrollment_id", sa.String(128), nullable=False),
        sa.Column("code_digest", sa.String(71), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("expected_uri_san", sa.String(384), nullable=False),
        sa.Column("created_by_ref", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_attempt_count", sa.Integer(), nullable=False),
        sa.Column("failed_window_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("enrollment_id", name="uq_lan_enrollment_id"),
        sa.UniqueConstraint("code_digest", name="uq_lan_enrollment_code_digest"),
        sa.UniqueConstraint("idempotency_key", name="uq_lan_enrollment_idempotency"),
    )
    op.create_index("ix_control_plane_lan_enrollment_codes_node_id", "control_plane_lan_enrollment_codes", ["node_id"])
    op.create_table(
        "control_plane_lan_certificate_bindings",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("binding_id", sa.String(128), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("uri_san", sa.String(384), nullable=False),
        sa.Column("fingerprint", sa.String(71), nullable=False),
        sa.Column("serial_number", sa.String(96), nullable=False),
        sa.Column("certificate_der", sa.LargeBinary(), nullable=False),
        sa.Column("public_key_digest", sa.String(71), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("renewal_after", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("binding_id", name="uq_lan_cert_binding_id"),
        sa.UniqueConstraint("fingerprint", name="uq_lan_cert_fingerprint"),
        sa.UniqueConstraint("serial_number", name="uq_lan_cert_serial"),
    )
    op.create_index("ix_control_plane_lan_certificate_bindings_node_id", "control_plane_lan_certificate_bindings", ["node_id"])
    op.create_table(
        "control_plane_lan_certificate_revocations",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("revocation_id", sa.String(128), nullable=False),
        sa.Column("fingerprint", sa.String(71), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("revoked_by_ref", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("revocation_id", name="uq_lan_cert_revocation_id"),
        sa.UniqueConstraint("fingerprint", name="uq_lan_cert_revoked_fingerprint"),
        sa.UniqueConstraint("idempotency_key", name="uq_lan_cert_revocation_idempotency"),
    )
    op.create_table(
        "control_plane_lan_node_heartbeats",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("heartbeat_id", sa.String(128), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("capability_report_digest", sa.String(71), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("heartbeat_id", name="uq_lan_heartbeat_id"),
        sa.UniqueConstraint("node_id", "sequence", name="uq_lan_heartbeat_sequence"),
        sa.UniqueConstraint("idempotency_key", name="uq_lan_heartbeat_idempotency"),
    )
    op.create_index("ix_control_plane_lan_node_heartbeats_node_id", "control_plane_lan_node_heartbeats", ["node_id"])
    op.create_table(
        "control_plane_lan_artifact_download_assignments",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("assignment_id", sa.String(128), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("artifact_id", sa.String(160), nullable=False),
        sa.Column("revision_digest", sa.String(71), nullable=False),
        sa.Column("bundle_digest", sa.String(71), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_by_ref", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "assignment_id", name="uq_lan_artifact_assignment_id"
        ),
        sa.UniqueConstraint(
            "department_id", "artifact_id", "revision_digest",
            name="uq_lan_artifact_assignment_subject",
        ),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_lan_artifact_assignment_idempotency"
        ),
    )
    op.create_index(
        "ix_control_plane_lan_artifact_assignments_department_id",
        "control_plane_lan_artifact_download_assignments", ["department_id"],
    )
    op.create_table(
        "control_plane_lan_deployment_release_locks",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("lock_id", sa.String(128), nullable=False),
        sa.Column("lock_digest", sa.String(71), nullable=False),
        sa.Column("architecture_commit", sa.String(40), nullable=False),
        sa.Column("control_plane_commit", sa.String(40), nullable=False),
        sa.Column("department_cockpit_commit", sa.String(40), nullable=False),
        sa.Column("semantic_authority_release_id", sa.String(96), nullable=False),
        sa.Column("semantic_authority_manifest_digest", sa.String(71), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("created_by_ref", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("lock_id", name="uq_lan_deployment_release_lock_id"),
        sa.UniqueConstraint(
            "lock_digest", name="uq_lan_deployment_release_lock_digest"
        ),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_lan_deployment_release_lock_idempotency"
        ),
    )
    op.create_table(
        "control_plane_lan_artifact_download_receipts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("receipt_id", sa.String(128), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("artifact_id", sa.String(160), nullable=False),
        sa.Column("revision_digest", sa.String(71), nullable=False),
        sa.Column("bundle_digest", sa.String(71), nullable=False),
        sa.Column("etag", sa.String(96), nullable=False),
        sa.Column("range_start", sa.BigInteger(), nullable=False),
        sa.Column("range_end", sa.BigInteger(), nullable=False),
        sa.Column("total_size", sa.BigInteger(), nullable=False),
        sa.Column("completed", sa.Boolean(), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("receipt_id", name="uq_lan_download_receipt_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_lan_download_idempotency"),
    )
    op.create_index("ix_control_plane_lan_artifact_download_receipts_node_id", "control_plane_lan_artifact_download_receipts", ["node_id"])
    op.create_table(
        "control_plane_lan_mutation_commands",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("operation", sa.String(96), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("response_document", JSON_DOCUMENT, nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key", name="uq_lan_mutation_idempotency"),
    )


def downgrade() -> None:
    op.drop_table("control_plane_lan_mutation_commands")
    op.drop_index("ix_control_plane_lan_artifact_download_receipts_node_id", table_name="control_plane_lan_artifact_download_receipts")
    op.drop_table("control_plane_lan_artifact_download_receipts")
    op.drop_table("control_plane_lan_deployment_release_locks")
    op.drop_index(
        "ix_control_plane_lan_artifact_assignments_department_id",
        table_name="control_plane_lan_artifact_download_assignments",
    )
    op.drop_table("control_plane_lan_artifact_download_assignments")
    op.drop_index("ix_control_plane_lan_node_heartbeats_node_id", table_name="control_plane_lan_node_heartbeats")
    op.drop_table("control_plane_lan_node_heartbeats")
    op.drop_table("control_plane_lan_certificate_revocations")
    op.drop_index("ix_control_plane_lan_certificate_bindings_node_id", table_name="control_plane_lan_certificate_bindings")
    op.drop_table("control_plane_lan_certificate_bindings")
    op.drop_index("ix_control_plane_lan_enrollment_codes_node_id", table_name="control_plane_lan_enrollment_codes")
    op.drop_table("control_plane_lan_enrollment_codes")
    op.drop_index("ix_control_plane_lan_sessions_account_id", table_name="control_plane_lan_sessions")
    op.drop_table("control_plane_lan_sessions")
    op.drop_index("ix_control_plane_lan_invites_department_id", table_name="control_plane_lan_invites")
    op.drop_table("control_plane_lan_invites")
    op.drop_index("ix_control_plane_lan_human_accounts_username", table_name="control_plane_lan_human_accounts")
    op.drop_table("control_plane_lan_human_accounts")

