"""Add outbound assisted-maintenance evidence tables.

Revision ID: 20260902_0010
Revises: 20260901_0009
"""

from alembic import op
import sqlalchemy as sa

from orbit_agent_control_plane.service_runtime.models import JSON_DOCUMENT

revision = "20260902_0010"
down_revision = "20260901_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "control_plane_lan_assisted_maintenance_sessions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("session_digest", sa.String(71), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("certificate_fingerprint", sa.String(71), nullable=False),
        sa.Column("allowed_handler_ids", JSON_DOCUMENT, nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("close_reason", sa.String(96), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id", name="uq_lan_maintenance_session_id"),
        sa.UniqueConstraint("session_digest", name="uq_lan_maintenance_session_digest"),
        sa.UniqueConstraint("idempotency_key", name="uq_lan_maintenance_session_idempotency"),
    )
    op.create_index("ix_lan_maintenance_sessions_node_id", "control_plane_lan_assisted_maintenance_sessions", ["node_id"])
    op.create_table(
        "control_plane_lan_maintenance_jobs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("job_id", sa.String(128), nullable=False),
        sa.Column("job_digest", sa.String(71), nullable=False),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("handler_id", sa.String(128), nullable=False),
        sa.Column("asset_name", sa.String(128), nullable=False),
        sa.Column("asset_digest", sa.String(71), nullable=False),
        sa.Column("nonce_digest", sa.String(71), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_by_identity", sa.String(192), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id", name="uq_lan_maintenance_job_id"),
        sa.UniqueConstraint("job_digest", name="uq_lan_maintenance_job_digest"),
        sa.UniqueConstraint("idempotency_key", name="uq_lan_maintenance_job_idempotency"),
    )
    op.create_index("ix_lan_maintenance_jobs_session_id", "control_plane_lan_maintenance_jobs", ["session_id"])
    op.create_index("ix_lan_maintenance_jobs_node_id", "control_plane_lan_maintenance_jobs", ["node_id"])
    op.create_table(
        "control_plane_lan_maintenance_receipts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("receipt_id", sa.String(128), nullable=False),
        sa.Column("receipt_digest", sa.String(71), nullable=False),
        sa.Column("session_id", sa.String(128), nullable=False),
        sa.Column("job_id", sa.String(128), nullable=False),
        sa.Column("job_digest", sa.String(71), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("handler_id", sa.String(128), nullable=False),
        sa.Column("asset_digest", sa.String(71), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(96), nullable=False),
        sa.Column("sanitized_summary", sa.Text(), nullable=False),
        sa.Column("output_digest", sa.String(71), nullable=False),
        sa.Column("output_truncated", sa.Boolean(), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("receipt_id", name="uq_lan_maintenance_receipt_id"),
        sa.UniqueConstraint("job_id", name="uq_lan_maintenance_receipt_job"),
        sa.UniqueConstraint("idempotency_key", name="uq_lan_maintenance_receipt_idempotency"),
    )
    op.create_index("ix_lan_maintenance_receipts_session_id", "control_plane_lan_maintenance_receipts", ["session_id"])
    op.create_index("ix_lan_maintenance_receipts_node_id", "control_plane_lan_maintenance_receipts", ["node_id"])


def downgrade() -> None:
    op.drop_index("ix_lan_maintenance_receipts_node_id", table_name="control_plane_lan_maintenance_receipts")
    op.drop_index("ix_lan_maintenance_receipts_session_id", table_name="control_plane_lan_maintenance_receipts")
    op.drop_table("control_plane_lan_maintenance_receipts")
    op.drop_index("ix_lan_maintenance_jobs_node_id", table_name="control_plane_lan_maintenance_jobs")
    op.drop_index("ix_lan_maintenance_jobs_session_id", table_name="control_plane_lan_maintenance_jobs")
    op.drop_table("control_plane_lan_maintenance_jobs")
    op.drop_index("ix_lan_maintenance_sessions_node_id", table_name="control_plane_lan_assisted_maintenance_sessions")
    op.drop_table("control_plane_lan_assisted_maintenance_sessions")

