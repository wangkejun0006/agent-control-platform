from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "alembic/versions/20260903_0011_department_observation_context.py"
)


class DepartmentObservationMigrationTests(unittest.TestCase):
    def test_upgrade_and_downgrade_are_reversible(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "department_observation_migration", MIGRATION
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        engine = create_engine("sqlite+pysqlite:///:memory:")
        with engine.begin() as connection:
            module.op = Operations(MigrationContext.configure(connection))
            module.upgrade()
            inspector = inspect(connection)
            table = "control_plane_lan_department_observation_contexts"
            self.assertIn(table, inspector.get_table_names())
            self.assertEqual(
                {
                    "ix_lan_department_observation_context_session",
                    "ix_lan_department_observation_context_department",
                },
                {item["name"] for item in inspector.get_indexes(table)},
            )
            module.downgrade()
            self.assertNotIn(table, inspect(connection).get_table_names())
        engine.dispose()


if __name__ == "__main__":
    unittest.main()

