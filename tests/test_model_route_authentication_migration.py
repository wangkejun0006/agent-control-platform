from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "alembic/versions/20260903_0012_model_route_authentication.py"


class ModelRouteAuthenticationMigrationTests(unittest.TestCase):
    def test_upgrade_and_downgrade_preserve_legacy_secret_columns(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "model_route_authentication_migration", MIGRATION
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        engine = create_engine("sqlite+pysqlite:///:memory:")
        metadata = sa.MetaData()
        sa.Table(
            "control_plane_model_route_revisions",
            metadata,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("secret_ref", sa.String(240), nullable=False),
        )
        sa.Table(
            "control_plane_model_route_snapshots",
            metadata,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("secret_ref", sa.String(240), nullable=False),
        )
        metadata.create_all(engine)
        with engine.begin() as connection:
            module.op = Operations(MigrationContext.configure(connection))
            module.upgrade()
            inspector = inspect(connection)
            columns = {
                item["name"]: item
                for item in inspector.get_columns("control_plane_model_route_revisions")
            }
            self.assertTrue(columns["secret_ref"]["nullable"])
            self.assertTrue(
                {
                    "route_version", "authentication", "credential_scope",
                    "authorized_node_refs", "qualification_evidence_refs",
                    "budget_control_mode",
                }.issubset(columns)
            )
            self.assertTrue(
                {
                    "control_plane_model_route_credential_bindings",
                    "control_plane_model_route_retirements",
                    "control_plane_runtime_adapter_capability_reports",
                }.issubset(inspector.get_table_names())
            )
            module.downgrade()
            inspector = inspect(connection)
            self.assertFalse(
                {
                    "control_plane_model_route_credential_bindings",
                    "control_plane_model_route_retirements",
                    "control_plane_runtime_adapter_capability_reports",
                }.intersection(inspector.get_table_names())
            )
            columns = {
                item["name"]: item
                for item in inspector.get_columns("control_plane_model_route_revisions")
            }
            self.assertEqual({"id", "secret_ref"}, set(columns))
            self.assertFalse(columns["secret_ref"]["nullable"])
        engine.dispose()


if __name__ == "__main__":
    unittest.main()

