"""Add company model catalog and immutable department Agent proposals.

Revision ID: 20260903_0015
Revises: 20260903_0014
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260903_0015"
down_revision = "20260903_0014"
branch_labels = None
depends_on = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "control_plane_provider_model_discoveries",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("discovery_id", sa.String(160), nullable=False),
        sa.Column("discovery_digest", sa.String(71), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("provider_preset_id", sa.String(160), nullable=False),
        sa.Column("provider_preset_revision_digest", sa.String(71), nullable=False),
        sa.Column("region_id", sa.String(96), nullable=False),
        sa.Column("connection_alias", sa.String(160), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("discovery_id", name="uq_provider_model_discovery_id"),
        sa.UniqueConstraint("discovery_digest", name="uq_provider_model_discovery_digest"),
        sa.UniqueConstraint("idempotency_key", name="uq_provider_model_discovery_idempotency"),
    )
    op.create_index("ix_provider_model_discovery_preset", "control_plane_provider_model_discoveries", ["provider_preset_id"])
    op.create_table(
        "control_plane_provider_onboarding_proposals",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("proposal_id", sa.String(160), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("proposal_id", name="uq_provider_onboarding_proposal_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_provider_onboarding_idempotency"),
    )
    op.create_table(
        "control_plane_model_catalog_entries",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("entry_id", sa.String(160), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("entry_revision_digest", sa.String(71), nullable=False),
        sa.Column("provider_preset_id", sa.String(160), nullable=False),
        sa.Column("discovery_digest", sa.String(71), nullable=False),
        sa.Column("lifecycle_state", sa.String(48), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("created_by_ref", sa.String(160), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entry_revision_digest", name="uq_model_catalog_entry_revision"),
    )
    op.create_index("ix_model_catalog_entry_id", "control_plane_model_catalog_entries", ["entry_id"])
    op.create_table(
        "control_plane_model_catalog_credential_bindings",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("binding_id", sa.String(160), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("entry_id", sa.String(160), nullable=False),
        sa.Column("entry_revision_digest", sa.String(71), nullable=False),
        sa.Column("authentication_mode", sa.String(48), nullable=False),
        sa.Column("credential_binding_ref", sa.String(240), nullable=False),
        sa.Column("qualification_evidence_refs", JSON_DOCUMENT, nullable=False),
        sa.Column("status", sa.String(48), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("binding_id", name="uq_model_catalog_credential_binding_id"),
        sa.UniqueConstraint("idempotency_key", name="uq_model_catalog_credential_idempotency"),
    )
    op.create_index("ix_model_catalog_credential_entry", "control_plane_model_catalog_credential_bindings", ["entry_id"])
    op.create_table(
        "control_plane_model_catalog_lifecycle_receipts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("receipt_id", sa.String(160), nullable=False),
        sa.Column("receipt_digest", sa.String(71), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("entry_id", sa.String(160), nullable=False),
        sa.Column("entry_revision_digest", sa.String(71), nullable=False),
        sa.Column("transition", sa.String(64), nullable=False),
        sa.Column("from_state", sa.String(48), nullable=False),
        sa.Column("to_state", sa.String(48), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("receipt_id", name="uq_model_catalog_lifecycle_receipt_id"),
        sa.UniqueConstraint("receipt_digest", name="uq_model_catalog_lifecycle_receipt_digest"),
        sa.UniqueConstraint("idempotency_key", name="uq_model_catalog_lifecycle_idempotency"),
    )
    op.create_index("ix_model_catalog_lifecycle_entry", "control_plane_model_catalog_lifecycle_receipts", ["entry_id"])
    op.create_table(
        "control_plane_department_agent_proposals",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("proposal_id", sa.String(160), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("package_digest", sa.String(71), nullable=False),
        sa.Column("supersedes_package_digest", sa.String(71), nullable=True),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("department_id", sa.String(96), nullable=False),
        sa.Column("selected_catalog_entry_id", sa.String(160), nullable=False),
        sa.Column("selected_catalog_entry_revision_digest", sa.String(71), nullable=False),
        sa.Column("agent_definition_digest", sa.String(71), nullable=False),
        sa.Column("agent_binding_digest", sa.String(71), nullable=False),
        sa.Column("model_route_id", sa.String(160), nullable=False),
        sa.Column("model_route_revision_digest", sa.String(71), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("submitted_by_ref", sa.String(160), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("package_digest", name="uq_department_agent_proposal_package"),
        sa.UniqueConstraint("idempotency_key", name="uq_department_agent_proposal_idempotency"),
    )
    op.create_index("ix_department_agent_proposal_id", "control_plane_department_agent_proposals", ["proposal_id"])
    op.create_index("ix_department_agent_proposal_department", "control_plane_department_agent_proposals", ["department_id"])
    op.create_index("ix_department_agent_proposal_route", "control_plane_department_agent_proposals", ["model_route_id"])
    op.create_table(
        "control_plane_department_agent_proposal_decisions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("decision_id", sa.String(160), nullable=False),
        sa.Column("decision_digest", sa.String(71), nullable=False),
        sa.Column("idempotency_key", sa.String(192), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("proposal_id", sa.String(160), nullable=False),
        sa.Column("package_digest", sa.String(71), nullable=False),
        sa.Column("agent_definition_digest", sa.String(71), nullable=False),
        sa.Column("decision_scope", sa.String(48), nullable=False),
        sa.Column("action", sa.String(48), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("decision_id", name="uq_department_agent_proposal_decision_id"),
        sa.UniqueConstraint("decision_digest", name="uq_department_agent_proposal_decision_digest"),
        sa.UniqueConstraint("idempotency_key", name="uq_department_agent_proposal_decision_idempotency"),
        sa.UniqueConstraint("package_digest", name="uq_department_agent_proposal_terminal_decision"),
    )
    op.create_index("ix_department_agent_proposal_decision_proposal", "control_plane_department_agent_proposal_decisions", ["proposal_id"])


def downgrade() -> None:
    op.drop_index("ix_department_agent_proposal_decision_proposal", table_name="control_plane_department_agent_proposal_decisions")
    op.drop_table("control_plane_department_agent_proposal_decisions")
    op.drop_index("ix_department_agent_proposal_route", table_name="control_plane_department_agent_proposals")
    op.drop_index("ix_department_agent_proposal_department", table_name="control_plane_department_agent_proposals")
    op.drop_index("ix_department_agent_proposal_id", table_name="control_plane_department_agent_proposals")
    op.drop_table("control_plane_department_agent_proposals")
    op.drop_index("ix_model_catalog_lifecycle_entry", table_name="control_plane_model_catalog_lifecycle_receipts")
    op.drop_table("control_plane_model_catalog_lifecycle_receipts")
    op.drop_index("ix_model_catalog_credential_entry", table_name="control_plane_model_catalog_credential_bindings")
    op.drop_table("control_plane_model_catalog_credential_bindings")
    op.drop_index("ix_model_catalog_entry_id", table_name="control_plane_model_catalog_entries")
    op.drop_table("control_plane_model_catalog_entries")
    op.drop_table("control_plane_provider_onboarding_proposals")
    op.drop_index("ix_provider_model_discovery_preset", table_name="control_plane_provider_model_discoveries")
    op.drop_table("control_plane_provider_model_discoveries")

