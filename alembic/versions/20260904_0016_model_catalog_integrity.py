"""Catalog command replay, unique revisions and onboarding review evidence.

Existing rows are never edited. Duplicate legacy revisions stop migration for
an explicit reconciliation; migration does not delete evidence to make it pass.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "20260904_0016"
down_revision = "20260903_0015"
branch_labels = None
depends_on = None
JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
IDENTITY = sa.BigInteger().with_variant(sa.Integer(), "sqlite")


def upgrade():
    op.add_column(
        "control_plane_model_catalog_credential_bindings",
        sa.Column("binding_version", sa.String(160), nullable=True),
    )
    op.create_index(
        "uq_model_catalog_subject_revision",
        "control_plane_model_catalog_entries",
        ["entry_id", "revision"],
        unique=True,
    )
    op.create_index(
        "uq_agent_proposal_subject_revision",
        "control_plane_department_agent_proposals",
        ["proposal_id", "revision"],
        unique=True,
    )
    op.create_table(
        "control_plane_model_catalog_commands",
        sa.Column("id", IDENTITY, primary_key=True, autoincrement=True),
        sa.Column("idempotency_key", sa.String(192), nullable=False, unique=True),
        sa.Column("operation", sa.String(96), nullable=False),
        sa.Column("actor_ref", sa.String(160), nullable=False),
        sa.Column("request_digest", sa.String(71), nullable=False),
        sa.Column("response", JSON_DOCUMENT, nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "control_plane_provider_onboarding_reviews",
        sa.Column("id", IDENTITY, primary_key=True, autoincrement=True),
        sa.Column("proposal_id", sa.String(160), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("review_digest", sa.String(71), nullable=False, unique=True),
        sa.Column("document", JSON_DOCUMENT, nullable=False),
        sa.UniqueConstraint(
            "proposal_id", "revision", name="uq_provider_onboarding_review_revision"
        ),
    )


def downgrade():
    # Only for isolated migration tests; never run against the business ledger.
    op.drop_column("control_plane_model_catalog_credential_bindings", "binding_version")
    op.drop_table("control_plane_provider_onboarding_reviews")
    op.drop_table("control_plane_model_catalog_commands")
    op.drop_index(
        "uq_agent_proposal_subject_revision",
        table_name="control_plane_department_agent_proposals",
    )
    op.drop_index(
        "uq_model_catalog_subject_revision",
        table_name="control_plane_model_catalog_entries",
    )

