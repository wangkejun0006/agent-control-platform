"""Add local delivery workflow index and immutable evidence, preserving legacy rows."""
import sqlalchemy as sa
from alembic import op

revision = "20261016_0017"
down_revision = "20260904_0016"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("orbit_delivery_records",
        sa.Column("record_id", sa.String(192), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("workflow_id", sa.String(160)),
        sa.Column("department_id", sa.String(96)),
        sa.Column("document", sa.JSON(), nullable=False),
        sa.Column("document_digest", sa.String(71), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False))
    for name in ("kind", "workflow_id", "department_id"):
        op.create_index("ix_orbit_delivery_records_" + name, "orbit_delivery_records", [name])


def downgrade():
    raise RuntimeError("delivery_workbench_evidence_requires_explicit_backup_before_removal")
