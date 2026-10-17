from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.model_route import (
    FixtureProviderObserver,
    ModelRouteError,
    ModelRouteReconciler,
    ModelRouteStore,
    OwnerOnlyFileSecretProvider,
    WeMetaProviderObserver,
)
from orbit_agent_control_plane.service_runtime.model_route_cli import main as cli_main
from orbit_agent_control_plane.service_runtime.models import (
    AuditEventRow,
    Base,
    ModelRouteRevisionRow,
    ModelRouteSnapshotRow,
    OutboxEventRow,
    ProviderObservationRow,
)

ROOT = Path(__file__).resolve().parents[1]
ROUTE_PATH = ROOT / (
    "references/model-route-revisions/"
    "disease-r2-fixture-fixture-structured-v1.public.json"
)
OBSERVATION_PATH = ROOT / (
    "evidence/model-route/2026-08-28/"
    "fixture-fixture-structured-v1-observation.public.json"
)
NOW = datetime(2026, 8, 28, 9, 0, tzinfo=timezone.utc)
SECRET_VALUE = "provider-secret-must-never-persist"


def route_document() -> dict:
    return json.loads(ROUTE_PATH.read_text(encoding="utf-8"))


def observation_document(
    *,
    observed_at: datetime | None = None,
    expires_at: datetime | None = None,
    resolved_model_id: str = "fixture-structured-v1-2026-07-09",
    regression_status: str = "not_run",
    input_price: str = "5.00",
    output_price: str = "30.00",
) -> dict:
    observed = observed_at or NOW - timedelta(minutes=10)
    expires = expires_at or observed + timedelta(hours=6)
    value = json.loads(OBSERVATION_PATH.read_text(encoding="utf-8"))
    value.update(
        {
            "observed_at": observed.isoformat().replace("+00:00", "Z"),
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
            "resolved_model_id": resolved_model_id,
            "regression_status": regression_status,
            "input_usd_per_million_tokens": input_price,
            "output_usd_per_million_tokens": output_price,
        }
    )
    return value


class ModelRouteReconcilerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="orbit-model-route-")
        self.root = Path(self.temporary.name)
        self.database_path = self.root / "state.sqlite3"
        self.database = Database(f"sqlite+pysqlite:///{self.database_path}")
        Base.metadata.create_all(self.database.engine)
        self.store = ModelRouteStore(self.database)
        self.secret_current = self.root / "fixture-current"
        self.secret_next = self.root / "fixture-next"
        self.secret_current.write_text(SECRET_VALUE, encoding="utf-8")
        self.secret_next.write_text("rotated-provider-secret", encoding="utf-8")
        os.chmod(self.secret_current, 0o600)
        os.chmod(self.secret_next, 0o600)
        self.bindings = self.root / "model-route-secret-bindings.json"
        self._write_bindings()
        self.secrets = OwnerOnlyFileSecretProvider(self.bindings)

    def tearDown(self) -> None:
        self.database.dispose()
        self.temporary.cleanup()

    def _write_bindings(self) -> None:
        self.bindings.write_text(
            json.dumps(
                {
                    "binding_version": "orbit.model-route-secret-bindings/1",
                    "bindings": {
                        "secret://local/fixture/current": {
                            "path": str(self.secret_current),
                            "version": "fixture-key-v1",
                        },
                        "secret://local/fixture/next": {
                            "path": str(self.secret_next),
                            "version": "fixture-key-v2",
                        },
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        os.chmod(self.bindings, 0o600)

    def _ready_reconciler(
        self,
        *,
        route: dict | None = None,
        observation: dict | None = None,
    ) -> ModelRouteReconciler:
        self.store.record_route(route or route_document())
        self.store.record_observation(observation or observation_document())
        return ModelRouteReconciler(
            store=self.store,
            secret_provider=self.secrets,
            now=lambda: NOW,
        )

    def test_route_revision_is_immutable_idempotent_and_replays_after_restart(
        self,
    ) -> None:
        route = route_document()
        digest, appended = self.store.record_route(route)
        self.assertTrue(appended)
        self.assertEqual((digest, False), self.store.record_route(route))
        changed = copy.deepcopy(route)
        changed["parameters"]["timeout_seconds"] = 29
        changed_digest, changed_appended = self.store.record_route(changed)
        self.assertTrue(changed_appended)
        self.assertNotEqual(digest, changed_digest)
        self.database.dispose()
        self.database = Database(f"sqlite+pysqlite:///{self.database_path}")
        restarted = ModelRouteStore(self.database)
        self.assertEqual(changed_digest, restarted.latest_route(route["route_id"]).revision_digest)

    def test_snapshot_digest_outbox_and_audit_are_idempotent(self) -> None:
        reconciler = self._ready_reconciler()
        first = reconciler.reconcile(route_document()["route_id"])
        second = reconciler.reconcile(route_document()["route_id"])
        self.assertEqual("ready", first["status"])
        self.assertEqual(first["snapshot_digest"], second["snapshot_digest"])
        self.assertTrue(first["appended"])
        self.assertFalse(second["appended"])
        with self.database.session() as session:
            self.assertEqual(1, len(tuple(session.scalars(select(ModelRouteSnapshotRow)))))
            self.assertEqual(1, len(tuple(session.scalars(select(OutboxEventRow)))))
            self.assertEqual(1, len(tuple(session.scalars(select(AuditEventRow)))))

    def test_secret_never_enters_database_documents_or_errors(self) -> None:
        reconciler = self._ready_reconciler()
        snapshot = reconciler.reconcile(route_document()["route_id"])
        self.assertNotIn(SECRET_VALUE, json.dumps(snapshot, sort_keys=True))
        with self.database.session() as session:
            documents = []
            for row_type in (
                ModelRouteRevisionRow,
                ProviderObservationRow,
                ModelRouteSnapshotRow,
                OutboxEventRow,
                AuditEventRow,
            ):
                for row in session.scalars(select(row_type)):
                    documents.append(str(row.__dict__))
        self.assertNotIn(SECRET_VALUE, "\n".join(documents))
        self.secret_current.unlink()
        with self.assertRaises(ModelRouteError) as context:
            self.secrets.health("secret://local/fixture/current")
        self.assertEqual("model_route_secret_file_invalid", context.exception.reason_code)
        self.assertNotIn(SECRET_VALUE, str(context.exception))
        self.assertIsNone(context.exception.__cause__)

    def test_secret_permissions_symlink_hardlink_and_missing_fail_closed(self) -> None:
        os.chmod(self.secret_current, 0o640)
        with self.assertRaises(ModelRouteError):
            self.secrets.health("secret://local/fixture/current")
        os.chmod(self.secret_current, 0o600)
        hardlink = self.root / "fixture-hardlink"
        os.link(self.secret_current, hardlink)
        with self.assertRaises(ModelRouteError):
            self.secrets.health("secret://local/fixture/current")
        hardlink.unlink()
        self.secret_current.unlink()
        symlink_target = self.root / "symlink-target"
        symlink_target.write_text("secret", encoding="utf-8")
        os.chmod(symlink_target, 0o600)
        self.secret_current.symlink_to(symlink_target)
        with self.assertRaises(ModelRouteError):
            self.secrets.health("secret://local/fixture/current")
        self.secret_current.unlink()
        with self.assertRaises(ModelRouteError):
            self.secrets.health("secret://local/fixture/current")

    def test_secret_current_next_switch_is_atomic_and_offline(self) -> None:
        before = self.secrets.health("secret://local/fixture/current")
        promoted = self.secrets.promote_next("secret://local/fixture")
        after_next = self.secrets.health("secret://local/fixture/next")
        self.assertEqual("fixture-key-v1", before["binding_version"])
        self.assertEqual("fixture-key-v2", promoted["binding_version"])
        self.assertEqual("fixture-key-v1", after_next["binding_version"])
        self.assertEqual(0o600, self.bindings.stat().st_mode & 0o777)

    def test_expired_observation_and_deployment_age_fail_closed(self) -> None:
        expired = observation_document(
            observed_at=NOW - timedelta(hours=7),
            expires_at=NOW - timedelta(hours=1),
        )
        reconciler = self._ready_reconciler(observation=expired)
        snapshot = reconciler.reconcile(route_document()["route_id"])
        self.assertEqual("blocked", snapshot["status"])
        self.assertIn("provider_observation_expired", snapshot["reason_codes"])
        preflight = reconciler.deploy_preflight(route_document()["route_id"])
        self.assertEqual("blocked", preflight["status"])
        self.assertIn("model_route_snapshot_expired", preflight["reason_codes"])

    def test_price_increase_within_cap_refreshes_but_cap_break_blocks(self) -> None:
        within = observation_document(input_price="5.50", output_price="31.00")
        reconciler = self._ready_reconciler(observation=within)
        first = reconciler.reconcile(route_document()["route_id"])
        self.assertEqual("ready", first["status"])
        over = observation_document(input_price="20.00", output_price="100.00")
        over["observed_at"] = (NOW - timedelta(minutes=5)).isoformat().replace(
            "+00:00", "Z"
        )
        over["expires_at"] = (NOW + timedelta(hours=5, minutes=55)).isoformat().replace(
            "+00:00", "Z"
        )
        observer = FixtureProviderObserver(over)
        blocked = ModelRouteReconciler(
            store=self.store,
            secret_provider=self.secrets,
            provider_observer=observer,
            now=lambda: NOW,
        ).reconcile(route_document()["route_id"], refresh=True)
        self.assertEqual("blocked", blocked["status"])
        self.assertIn("model_route_budget_hard_cap_exceeded", blocked["reason_codes"])

    def test_requested_resolved_exactness_family_and_wildcards(self) -> None:
        family = observation_document(
            resolved_model_id="fixture-structured-v1-2026-08-01",
            regression_status="pass",
        )
        reconciler = self._ready_reconciler(observation=family)
        self.assertEqual("ready", reconciler.reconcile(route_document()["route_id"])["status"])
        unknown = observation_document(
            resolved_model_id="gpt-5.7-sol-2026-08-01",
            regression_status="pass",
        )
        self.store.record_observation(unknown)
        blocked = reconciler.reconcile(route_document()["route_id"])
        self.assertIn("model_route_model_family_drift", blocked["reason_codes"])
        wildcard = observation_document(resolved_model_id="fixture-structured-v1-*")
        with self.assertRaises(ModelRouteError):
            self.store.record_observation(wildcard)

    def test_pinned_mode_requires_exact_resolved_model(self) -> None:
        route = route_document()
        route["resolution_mode"] = "pinned"
        observation = observation_document(resolved_model_id="fixture-structured-v1-2026-08-01")
        reconciler = self._ready_reconciler(route=route, observation=observation)
        snapshot = reconciler.reconcile(route["route_id"])
        self.assertIn("model_route_resolved_model_not_pinned", snapshot["reason_codes"])

    def test_provider_endpoint_classification_and_permission_drift_block(self) -> None:
        cases = (
            ("provider", "other-provider", "model_route_provider_drift"),
            (
                "endpoint",
                "https://other.example/v1/chat/completions",
                "model_route_endpoint_drift",
            ),
            (
                "data_classification",
                "internal",
                "model_route_data_classification_drift",
            ),
        )
        for index, (field, value, reason) in enumerate(cases):
            with self.subTest(field=field):
                route = route_document()
                route["route_id"] += f"_{index}"
                route[field] = value
                observation = observation_document()
                observation["provider"] = route["provider"]
                self.store.record_route(route)
                self.store.record_observation(observation)
                snapshot = ModelRouteReconciler(
                    store=self.store,
                    secret_provider=self.secrets,
                    now=lambda: NOW,
                ).reconcile(route["route_id"])
                self.assertIn(reason, snapshot["reason_codes"])
        route = route_document()
        route["route_id"] += "_permission"
        route["parameters"]["permissions"] = ["model.invoke", "network.general"]
        self.store.record_route(route)
        snapshot = ModelRouteReconciler(
            store=self.store,
            secret_provider=self.secrets,
            now=lambda: NOW,
        ).reconcile(route["route_id"])
        self.assertIn("model_route_permission_drift", snapshot["reason_codes"])

    def test_preflight_rejects_stale_observation_and_secret_version_drift(self) -> None:
        observed = observation_document(
            observed_at=NOW - timedelta(minutes=31),
            expires_at=NOW + timedelta(hours=5, minutes=29),
        )
        reconciler = self._ready_reconciler(observation=observed)
        snapshot = reconciler.reconcile(route_document()["route_id"])
        self.assertEqual("ready", snapshot["status"])
        preflight = reconciler.deploy_preflight(route_document()["route_id"])
        self.assertIn("provider_observation_too_old_for_deployment", preflight["reason_codes"])
        self.secrets.promote_next("secret://local/fixture")
        drifted = reconciler.deploy_preflight(route_document()["route_id"])
        self.assertIn("model_route_secret_binding_drift", drifted["reason_codes"])

    def test_fixture_observer_requires_explicit_official_machine_source(self) -> None:
        observer = WeMetaProviderObserver(machine_source_url=None)
        with self.assertRaises(ModelRouteError) as context:
            observer.observe(route_document())
        self.assertEqual("fixture_machine_source_unconfigured", context.exception.reason_code)
        denied = WeMetaProviderObserver(
            machine_source_url="https://example.com/models.json",
            transport=lambda _url, _model: {},
        )
        with self.assertRaises(ModelRouteError) as context:
            denied.observe(route_document())
        self.assertEqual("fixture_machine_source_not_allowed", context.exception.reason_code)
        machine = WeMetaProviderObserver(
            machine_source_url="https://models.paper-orbit.invalid/public/models.json",
            transport=lambda _url, model: {
                "source_version": "fixture.model-price/1",
                "provider": "fixture",
                "requested_model": model,
                "resolved_model_id": "fixture-structured-v1-2026-07-09",
                "input_usd_per_million_tokens": "5.00",
                "output_usd_per_million_tokens": "30.00",
                "cached_input_usd_per_million_tokens": "0.50",
                "observed_at": "2026-08-28T09:00:00Z",
                "expires_at": "2026-08-28T15:00:00Z",
            },
        )
        refreshed = machine.observe(route_document())
        self.assertEqual("official_machine_readable", refreshed["source_kind"])
        self.assertEqual("not_run", refreshed["regression_status"])

    def test_cli_import_reconcile_status_and_preflight_are_non_executing(self) -> None:
        route_path = self.root / "route.json"
        observation_path = self.root / "observation.json"
        route_path.write_text(json.dumps(route_document()), encoding="utf-8")
        observation_path.write_text(
            json.dumps(
                observation_document(
                    observed_at=datetime.now(timezone.utc) - timedelta(minutes=5),
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=5),
                )
            ),
            encoding="utf-8",
        )
        database_url = f"sqlite+pysqlite:///{self.database_path}"
        commands = (
            ["import-route", "--document", str(route_path)],
            [
                "import-observation",
                "--document",
                str(observation_path),
            ],
            [
                "reconcile",
                "--route-id",
                route_document()["route_id"],
                "--secret-bindings",
                str(self.bindings),
            ],
            [
                "status",
                "--route-id",
                route_document()["route_id"],
                "--secret-bindings",
                str(self.bindings),
            ],
            [
                "deploy-preflight",
                "--route-id",
                route_document()["route_id"],
                "--secret-bindings",
                str(self.bindings),
            ],
        )
        with mock.patch.dict(
            os.environ,
            {"ORBIT_MODEL_ROUTE_DATABASE_URL": database_url},
            clear=False,
        ):
            outputs = []
            for command in commands:
                stream = io.StringIO()
                with redirect_stdout(stream):
                    exit_code = cli_main(command)
                self.assertEqual(0, exit_code, command)
                outputs.append(json.loads(stream.getvalue()))
        self.assertEqual("route_revision", outputs[0]["kind"])
        self.assertEqual("provider_observation", outputs[1]["kind"])
        self.assertEqual("ready", outputs[2]["status"])
        self.assertEqual("ready", outputs[3]["snapshot_status"])
        self.assertEqual("ready", outputs[4]["status"])
        self.assertFalse(outputs[4]["provider_execution_started"])

    def test_dataset_d0_frozen_evidence_remains_byte_exact(self) -> None:
        baseline = json.loads(
            (
                ROOT
                / "evidence/publication-baseline/2026-08-26/"
                "publication-baseline.synthetic.json"
            ).read_text(encoding="utf-8")
        )
        dataset_artifacts = [
            item
            for item in baseline["artifacts"]
            if item["role"]
            in {
                "dataset_d0_acceptance_report",
                "dataset_d0_result",
                "dataset_d0_composition_lock",
                "dataset_d0_skill_review",
            }
        ]
        self.assertEqual(4, len(dataset_artifacts))
        for item in dataset_artifacts:
            actual = "sha256:" + hashlib.sha256(
                (ROOT / item["path"]).read_bytes()
            ).hexdigest()
            self.assertEqual(item["sha256"], actual, item["path"])


if __name__ == "__main__":
    unittest.main()

