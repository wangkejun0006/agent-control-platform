"""Add durable Model Route authentication and Runtime adapter evidence.

Revision ID: 20260903_0012
Revises: 20260903_0011
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260903_0012"
down_revision = "20260903_0011"
branch_labels = None
depends_on = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("control_plane_model_route_revisions") as batch:
        batch.alter_column("secret_ref", nullable=True)
        batch.add_column(sa.Column("route_version", sa.String(96), nullable=True))
        batch.add_column(sa.Column("authentication", JSON_DOCUMENT, nullable=True))
        batch.add_column(sa.Column("credential_scope", sa.String(48), nullable=True))
        batch.add_column(sa.Column("authorized_node_refs", JSON_DOCUMENT, nullable=True))
        batch.add_column(
            sa.Column("qualification_evidence_refs", JSON_DOCUMENT, nullable=True)
        )
        batch.add_column(
            sa.Column("budget_control_mode", sa.String(48), nullable=True)
        )
    with op.batch_alter_table("control_plane_model_route_snapshots") as batch:
        batch.alter_column("secret_ref", nullable=True)

    op.create_table(
        "control_plane_model_route_credential_bindings",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("binding_id", sa.String(160), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("route_id", sa.String(128), nullable=False),
        sa.Column("route_revision_digest", sa.String(71), nullable=False),
        sa.Column("authentication_mode", sa.String(48), nullable=False),
        sa.Column("credential_binding_ref", sa.String(240), nullable=False),
        sa.Column("credential_scope", sa.String(48), nullable=False),
        sa.Column("authorized_node_refs", JSON_DOCUMENT, nullable=False),
        sa.Column("qualification_evidence_refs", JSON_DOCUMENT, nullable=False),
        sa.Column("status", sa.String(48), nullable=False),
        sa.Column("secret_fingerprint", sa.String(71), nullable=True),
        sa.Column("secret_version", sa.String(96), nullable=True),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "binding_id", name="uq_model_route_credential_binding_id"
        ),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_model_route_credential_binding_idempotency"
        ),
    )
    op.create_index(
        "ix_model_route_credential_binding_route",
        "control_plane_model_route_credential_bindings",
        ["route_id"],
    )

    op.create_table(
        "control_plane_model_route_retirements",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("retirement_id", sa.String(160), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("route_id", sa.String(128), nullable=False),
        sa.Column("route_revision_digest", sa.String(71), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("receipt_id", sa.String(160), nullable=False),
        sa.Column("receipt_digest", sa.String(71), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("retirement_id", name="uq_model_route_retirement_id"),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_model_route_retirement_idempotency"
        ),
    )
    op.create_index(
        "ix_model_route_retirement_route",
        "control_plane_model_route_retirements",
        ["route_id"],
    )

    op.create_table(
        "control_plane_runtime_adapter_capability_reports",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("report_id", sa.String(160), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("node_id", sa.String(160), nullable=False),
        sa.Column("adapter_id", sa.String(160), nullable=False),
        sa.Column("adapter_revision_digest", sa.String(71), nullable=False),
        sa.Column("authentication_modes", JSON_DOCUMENT, nullable=False),
        sa.Column("capability_digest", sa.String(71), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("status", sa.String(48), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "report_id", name="uq_runtime_adapter_capability_report_id"
        ),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_runtime_adapter_capability_idempotency"
        ),
    )
    op.create_index(
        "ix_runtime_adapter_capability_node",
        "control_plane_runtime_adapter_capability_reports",
        ["node_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_runtime_adapter_capability_node",
        table_name="control_plane_runtime_adapter_capability_reports",
    )
    op.drop_table("control_plane_runtime_adapter_capability_reports")
    op.drop_index(
        "ix_model_route_retirement_route",
        table_name="control_plane_model_route_retirements",
    )
    op.drop_table("control_plane_model_route_retirements")
    op.drop_index(
        "ix_model_route_credential_binding_route",
        table_name="control_plane_model_route_credential_bindings",
    )
    op.drop_table("control_plane_model_route_credential_bindings")
    with op.batch_alter_table("control_plane_model_route_snapshots") as batch:
        batch.alter_column("secret_ref", nullable=False)
    with op.batch_alter_table("control_plane_model_route_revisions") as batch:
        for column in (
            "budget_control_mode",
            "qualification_evidence_refs",
            "authorized_node_refs",
            "credential_scope",
            "authentication",
            "route_version",
        ):
            batch.drop_column(column)
        batch.alter_column("secret_ref", nullable=False)

