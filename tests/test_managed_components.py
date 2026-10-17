from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.managed_components import (
    CONCEPT_CATALOG_DIGEST,
    GOVERNED_RELEASE_PIPELINE_COMPONENT_ID,
    SEMANTIC_AUTHORITY_LOCK_DIGEST,
    TERM_REGISTRY_DIGEST,
    ManagedComponentRegistry,
    build_governed_release_pipeline_descriptor,
)
from orbit_agent_control_plane.service_runtime.models import (
    AuditEventRow,
    Base,
    OutboxEventRow,
)
from orbit_agent_control_plane.service_runtime.repositories import (
    ServiceRepositoryError,
)

ROOT = Path(__file__).resolve().parents[1]


class ManagedComponentRegistryTests(unittest.TestCase):
    def test_registration_is_idempotent_persistent_and_non_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "control-plane.sqlite3"
            database_url = f"sqlite+pysqlite:///{database_path}"
            database = Database(database_url)
            Base.metadata.create_all(database.engine)
            descriptor = build_governed_release_pipeline_descriptor(ROOT)
            registry = ManagedComponentRegistry(database)
            self.assertTrue(registry.register(descriptor))
            self.assertFalse(registry.register(descriptor))
            value = registry.current(GOVERNED_RELEASE_PIPELINE_COMPONENT_ID)
            self.assertIsNotNone(value)
            assert value is not None
            self.assertEqual("registered", value["status"])
            self.assertEqual("none", value["authority_claim"])
            self.assertFalse(value["creates_human_checkpoint"])
            self.assertFalse(value["release_authorization"])
            self.assertEqual(
                SEMANTIC_AUTHORITY_LOCK_DIGEST,
                value["descriptor"]["architecture_mapping"][
                    "semantic_authority_lock_digest"
                ],
            )
            self.assertEqual(
                CONCEPT_CATALOG_DIGEST,
                value["descriptor"]["architecture_mapping"][
                    "concept_catalog_digest"
                ],
            )
            self.assertEqual(
                TERM_REGISTRY_DIGEST,
                value["descriptor"]["architecture_mapping"][
                    "term_registry_digest"
                ],
            )
            with database.session() as session:
                self.assertEqual(1, session.query(AuditEventRow).count())
                self.assertEqual(1, session.query(OutboxEventRow).count())
            database.dispose()

            restarted = Database(database_url)
            replayed = ManagedComponentRegistry(restarted).current(
                GOVERNED_RELEASE_PIPELINE_COMPONENT_ID
            )
            self.assertEqual(value["descriptor_digest"], replayed["descriptor_digest"])
            restarted.dispose()

    def test_architecture_mapping_matches_current_consumer_lock(self) -> None:
        lock = json.loads(
            (ROOT / "references" / "semantic-authority-lock.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            SEMANTIC_AUTHORITY_LOCK_DIGEST,
            lock["authority"]["semantic_authority_lock_sha256"],
        )
        self.assertEqual(
            CONCEPT_CATALOG_DIGEST,
            lock["sources"]["concept_catalog"]["sha256"],
        )
        self.assertEqual(
            TERM_REGISTRY_DIGEST,
            lock["sources"]["term_registry"]["sha256"],
        )
        self.assertEqual(
            "contract-v0.2.0-alpha.1",
            lock["contract_release"]["release_id"],
        )

    def test_same_version_source_drift_fails_closed(self) -> None:
        database = Database("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(database.engine)
        registry = ManagedComponentRegistry(database)
        descriptor = build_governed_release_pipeline_descriptor(ROOT)
        registry.register(descriptor)
        changed = dict(descriptor)
        changed["descriptor_digest"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(
            ServiceRepositoryError,
            "managed_component_descriptor_invalid",
        ):
            registry.register(changed)
        database.dispose()


if __name__ == "__main__":
    unittest.main()

