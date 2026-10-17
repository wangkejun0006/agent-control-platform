from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "alembic/versions/20260903_0015_model_catalog_agent_proposals.py"


class ModelCatalogMigrationTests(unittest.TestCase):
    def test_upgrade_and_downgrade_are_reversible(self) -> None:
        spec = importlib.util.spec_from_file_location("model_catalog_migration", MIGRATION)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        engine = create_engine("sqlite+pysqlite:///:memory:")
        tables = {
            "control_plane_provider_model_discoveries",
            "control_plane_provider_onboarding_proposals",
            "control_plane_model_catalog_entries",
            "control_plane_model_catalog_credential_bindings",
            "control_plane_model_catalog_lifecycle_receipts",
            "control_plane_department_agent_proposals",
            "control_plane_department_agent_proposal_decisions",
        }
        with engine.begin() as connection:
            module.op = Operations(MigrationContext.configure(connection))
            module.upgrade()
            self.assertTrue(tables.issubset(inspect(connection).get_table_names()))
            module.downgrade()
            self.assertTrue(tables.isdisjoint(inspect(connection).get_table_names()))
        engine.dispose()


if __name__ == "__main__":
    unittest.main()

