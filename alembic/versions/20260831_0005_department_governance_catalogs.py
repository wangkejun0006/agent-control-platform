"""Add semantic projections, Tool scopes, Systems, and controlled artifacts.

Revision ID: 20260831_0005
Revises: 20260829_0004
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260831_0005"
down_revision = "20260829_0004"
branch_labels = None
depends_on = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "control_plane_semantic_authority_releases",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("release_id", sa.String(length=160), nullable=False),
        sa.Column("manifest_digest", sa.String(length=71), nullable=False),
        sa.Column("authority_lock_digest", sa.String(length=71), nullable=False),
        sa.Column("architecture_commit", sa.String(length=40), nullable=False),
        sa.Column("source_digests", JSON_DOCUMENT, nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("authority_claim", sa.String(length=32), nullable=False),
        sa.Column("release_authorization", sa.Boolean(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("release_id", name="uq_semantic_authority_release_id"),
        sa.UniqueConstraint(
            "manifest_digest", name="uq_semantic_authority_manifest_digest"
        ),
    )
    op.create_table(
        "control_plane_semantic_terms",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("release_id", sa.String(length=160), nullable=False),
        sa.Column("term_id", sa.String(length=192), nullable=False),
        sa.Column("term_zh", sa.String(length=160), nullable=False),
        sa.Column("term_en", sa.String(length=160), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("publication_status", sa.String(length=32), nullable=False),
        sa.Column("evidence_status", sa.String(length=48), nullable=False),
        sa.Column("definition", sa.Text(), nullable=False),
        sa.Column("mapped_concept_refs", JSON_DOCUMENT, nullable=False),
        sa.Column("depends_on_term_refs", JSON_DOCUMENT, nullable=False),
        sa.Column("not_a", JSON_DOCUMENT, nullable=False),
        sa.Column("invariants", JSON_DOCUMENT, nullable=False),
        sa.Column("operator_exposure", sa.String(length=48), nullable=False),
        sa.Column("authority_claim", sa.String(length=32), nullable=False),
        sa.Column("creates_human_checkpoint", sa.Boolean(), nullable=False),
        sa.Column("source_digest", sa.String(length=71), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "release_id", "term_id", name="uq_semantic_term_release_id"
        ),
    )
    op.create_index(
        "ix_control_plane_semantic_terms_release_id",
        "control_plane_semantic_terms",
        ["release_id"],
    )
    op.create_index(
        "ix_control_plane_semantic_terms_term_id",
        "control_plane_semantic_terms",
        ["term_id"],
    )
    op.create_table(
        "control_plane_tool_semantic_scopes",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("scope_id", sa.String(length=160), nullable=False),
        sa.Column("tool_id", sa.String(length=160), nullable=False),
        sa.Column("tool_version", sa.String(length=32), nullable=False),
        sa.Column("manifest_digest", sa.String(length=71), nullable=False),
        sa.Column("operation_id", sa.String(length=160), nullable=False),
        sa.Column("capability", sa.String(length=160), nullable=False),
        sa.Column("domain", sa.String(length=96), nullable=False),
        sa.Column("resource_kind", sa.String(length=96), nullable=False),
        sa.Column("action", sa.String(length=96), nullable=False),
        sa.Column("side_effect_class", sa.String(length=64), nullable=False),
        sa.Column("canonical_scope_key", sa.String(length=384), nullable=False),
        sa.Column("relationship_mode", sa.String(length=32), nullable=False),
        sa.Column("target_scope_id", sa.String(length=160), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("evidence_status", sa.String(length=48), nullable=False),
        sa.Column("owner_ref", sa.String(length=160), nullable=False),
        sa.Column("source_release_id", sa.String(length=160), nullable=False),
        sa.Column("registration_only", sa.Boolean(), nullable=False),
        sa.Column("activation_authorization", sa.Boolean(), nullable=False),
        sa.Column("production_authorized", sa.Boolean(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scope_id", name="uq_tool_semantic_scope_id"),
        sa.UniqueConstraint(
            "tool_id",
            "tool_version",
            "operation_id",
            name="uq_tool_semantic_scope_operation",
        ),
    )
    op.create_index(
        "ix_control_plane_tool_semantic_scopes_tool_id",
        "control_plane_tool_semantic_scopes",
        ["tool_id"],
    )
    op.create_table(
        "control_plane_system_registry",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("system_id", sa.String(length=160), nullable=False),
        sa.Column("system_version", sa.String(length=32), nullable=False),
        sa.Column("display_name", sa.String(length=192), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=32), nullable=False),
        sa.Column("ownership_status", sa.String(length=48), nullable=False),
        sa.Column("department_ref", sa.String(length=160), nullable=False),
        sa.Column("responsible_role_ref", sa.String(length=160), nullable=False),
        sa.Column("composition_ref", sa.String(length=384), nullable=False),
        sa.Column("source_locations", JSON_DOCUMENT, nullable=False),
        sa.Column("migration_status", sa.String(length=48), nullable=False),
        sa.Column("decision_refs", JSON_DOCUMENT, nullable=False),
        sa.Column("evidence_status", sa.String(length=48), nullable=False),
        sa.Column("runtime_effective", sa.Boolean(), nullable=False),
        sa.Column("production_authorized", sa.Boolean(), nullable=False),
        sa.Column("source_release_id", sa.String(length=160), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "system_id", "system_version", name="uq_system_registry_version"
        ),
    )
    op.create_index(
        "ix_control_plane_system_registry_system_id",
        "control_plane_system_registry",
        ["system_id"],
    )
    op.create_table(
        "control_plane_controlled_artifacts",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("artifact_ref", sa.String(length=384), nullable=False),
        sa.Column("department_id", sa.String(length=96), nullable=False),
        sa.Column("filename", sa.String(length=192), nullable=False),
        sa.Column("media_type", sa.String(length=128), nullable=False),
        sa.Column("byte_size", sa.BigInteger(), nullable=False),
        sa.Column("content_digest", sa.String(length=71), nullable=False),
        sa.Column("data_classification", sa.String(length=48), nullable=False),
        sa.Column("scan_status", sa.String(length=48), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column("uploaded_by_ref", sa.String(length=160), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_ref", name="uq_controlled_artifact_ref"),
    )
    op.create_index(
        "ix_control_plane_controlled_artifacts_department_id",
        "control_plane_controlled_artifacts",
        ["department_id"],
    )
    op.create_table(
        "control_plane_department_cockpit_objects",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("object_type", sa.String(length=48), nullable=False),
        sa.Column("object_id", sa.String(length=160), nullable=False),
        sa.Column("department_id", sa.String(length=96), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "object_type", "object_id", name="uq_department_cockpit_object"
        ),
    )
    op.create_index(
        "ix_control_plane_department_cockpit_objects_object_type",
        "control_plane_department_cockpit_objects",
        ["object_type"],
    )
    op.create_index(
        "ix_control_plane_department_cockpit_objects_department_id",
        "control_plane_department_cockpit_objects",
        ["department_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_control_plane_department_cockpit_objects_department_id",
        table_name="control_plane_department_cockpit_objects",
    )
    op.drop_index(
        "ix_control_plane_department_cockpit_objects_object_type",
        table_name="control_plane_department_cockpit_objects",
    )
    op.drop_table("control_plane_department_cockpit_objects")
    op.drop_index(
        "ix_control_plane_controlled_artifacts_department_id",
        table_name="control_plane_controlled_artifacts",
    )
    op.drop_table("control_plane_controlled_artifacts")
    op.drop_index(
        "ix_control_plane_system_registry_system_id",
        table_name="control_plane_system_registry",
    )
    op.drop_table("control_plane_system_registry")
    op.drop_index(
        "ix_control_plane_tool_semantic_scopes_tool_id",
        table_name="control_plane_tool_semantic_scopes",
    )
    op.drop_table("control_plane_tool_semantic_scopes")
    op.drop_index(
        "ix_control_plane_semantic_terms_term_id",
        table_name="control_plane_semantic_terms",
    )
    op.drop_index(
        "ix_control_plane_semantic_terms_release_id",
        table_name="control_plane_semantic_terms",
    )
    op.drop_table("control_plane_semantic_terms")
    op.drop_table("control_plane_semantic_authority_releases")

