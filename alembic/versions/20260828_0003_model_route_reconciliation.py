"""Add immutable Model Route reconciliation records.

Revision ID: 20260828_0003
Revises: 20260828_0002
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260828_0003"
down_revision = "20260828_0002"
branch_labels = None
depends_on = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "control_plane_model_route_revisions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("route_id", sa.String(length=128), nullable=False),
        sa.Column("revision_digest", sa.String(length=71), nullable=False),
        sa.Column("provider", sa.String(length=96), nullable=False),
        sa.Column("endpoint", sa.String(length=512), nullable=False),
        sa.Column("requested_model", sa.String(length=160), nullable=False),
        sa.Column("parameters", JSON_DOCUMENT, nullable=False),
        sa.Column("data_classification", sa.String(length=48), nullable=False),
        sa.Column("budget_policy", JSON_DOCUMENT, nullable=False),
        sa.Column("resolution_mode", sa.String(length=48), nullable=False),
        sa.Column("secret_ref", sa.String(length=240), nullable=False),
        sa.Column("approved_scope", JSON_DOCUMENT, nullable=False),
        sa.Column("runtime_binding", JSON_DOCUMENT, nullable=False),
        sa.Column("policy_binding", JSON_DOCUMENT, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "revision_digest", name="uq_model_route_revision_digest"
        ),
    )
    op.create_index(
        "ix_control_plane_model_route_revisions_route_id",
        "control_plane_model_route_revisions",
        ["route_id"],
    )
    op.create_table(
        "control_plane_provider_observations",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("provider", sa.String(length=96), nullable=False),
        sa.Column("requested_model", sa.String(length=160), nullable=False),
        sa.Column("resolved_model_id", sa.String(length=192), nullable=False),
        sa.Column(
            "input_usd_per_million_tokens", sa.String(length=48), nullable=False
        ),
        sa.Column(
            "output_usd_per_million_tokens", sa.String(length=48), nullable=False
        ),
        sa.Column(
            "cached_input_usd_per_million_tokens",
            sa.String(length=48),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=512), nullable=False),
        sa.Column("source_kind", sa.String(length=48), nullable=False),
        sa.Column("regression_status", sa.String(length=32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_digest", sa.String(length=71), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "observation_digest", name="uq_provider_observation_digest"
        ),
    )
    op.create_index(
        "ix_control_plane_provider_observations_provider",
        "control_plane_provider_observations",
        ["provider"],
    )
    op.create_table(
        "control_plane_model_route_snapshots",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("route_id", sa.String(length=128), nullable=False),
        sa.Column("route_revision_digest", sa.String(length=71), nullable=False),
        sa.Column("observation_digest", sa.String(length=71), nullable=True),
        sa.Column("secret_ref", sa.String(length=240), nullable=False),
        sa.Column("secret_binding_version", sa.String(length=128), nullable=True),
        sa.Column("requested_model", sa.String(length=160), nullable=False),
        sa.Column("resolved_model_id", sa.String(length=192), nullable=True),
        sa.Column("endpoint", sa.String(length=512), nullable=False),
        sa.Column("budget_policy", JSON_DOCUMENT, nullable=False),
        sa.Column("worst_case_cost", JSON_DOCUMENT, nullable=False),
        sa.Column("runtime_binding", JSON_DOCUMENT, nullable=False),
        sa.Column("policy_binding", JSON_DOCUMENT, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reason_codes", JSON_DOCUMENT, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("snapshot_digest", sa.String(length=71), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("snapshot_digest", name="uq_model_route_snapshot_digest"),
    )
    op.create_index(
        "ix_control_plane_model_route_snapshots_route_id",
        "control_plane_model_route_snapshots",
        ["route_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_control_plane_model_route_snapshots_route_id",
        table_name="control_plane_model_route_snapshots",
    )
    op.drop_table("control_plane_model_route_snapshots")
    op.drop_index(
        "ix_control_plane_provider_observations_provider",
        table_name="control_plane_provider_observations",
    )
    op.drop_table("control_plane_provider_observations")
    op.drop_index(
        "ix_control_plane_model_route_revisions_route_id",
        table_name="control_plane_model_route_revisions",
    )
    op.drop_table("control_plane_model_route_revisions")

