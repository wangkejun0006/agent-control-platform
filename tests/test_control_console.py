from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from orbit_agent_control_plane.qualification.automation import canonical_digest
from orbit_agent_control_plane.service_runtime.control_console import (
    ControlConsoleError,
    ControlConsoleService,
)
from orbit_agent_control_plane.service_runtime.control_console_models import (
    ModelRouteDecisionRow,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.model_route import (
    ModelRouteReconciler,
    ModelRouteStore,
)
from orbit_agent_control_plane.service_runtime.models import (
    AuditEventRow,
    Base,
    DepartmentCockpitObjectRow,
    GrantRevocationRow,
    ReceiptRow,
)
from orbit_agent_control_plane.service_runtime.repositories import (
    SqlGrantRevocationRegistry,
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
NOW = datetime(2026, 9, 1, 3, 0, tzinfo=timezone.utc)
ACTOR = "human_control_plane_admin_syn"
ROLE = "role_control_plane_admin"


class HealthyLogicalSecretProvider:
    def health(self, logical_ref: str) -> dict:
        return {
            "logical_ref": logical_ref,
            "binding_version": "synthetic-binding-v1",
            "healthy": True,
        }

    def read(self, logical_ref: str) -> bytes:
        raise AssertionError(f"secret bytes must not be read: {logical_ref}")


def route_document() -> dict:
    return json.loads(ROUTE_PATH.read_text(encoding="utf-8"))


def observation_document(now: datetime = NOW) -> dict:
    value = json.loads(OBSERVATION_PATH.read_text(encoding="utf-8"))
    value["observed_at"] = (now - timedelta(minutes=2)).isoformat().replace(
        "+00:00", "Z"
    )
    value["expires_at"] = (now + timedelta(hours=5, minutes=58)).isoformat().replace(
        "+00:00", "Z"
    )
    return value


class ControlConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="orbit-control-console-")
        self.database = Database(
            f"sqlite+pysqlite:///{Path(self.temporary.name) / 'state.sqlite3'}"
        )
        Base.metadata.create_all(self.database.engine)
        self.clock = [NOW]
        self.store = ModelRouteStore(self.database)
        self.reconciler = ModelRouteReconciler(
            store=self.store,
            secret_provider=HealthyLogicalSecretProvider(),
            now=lambda: self.clock[0],
        )
        self.revocations = SqlGrantRevocationRegistry(self.database)
        self.service = ControlConsoleService(
            database=self.database,
            model_routes=self.reconciler,
            grant_revocations=self.revocations,
            now=lambda: self.clock[0],
        )

    def tearDown(self) -> None:
        self.database.dispose()
        self.temporary.cleanup()

    def _ready_candidate(self) -> tuple[dict, str, str]:
        route = route_document()
        candidate = self.service.submit_model_route_candidate(
            document=route,
            expected_latest_revision_digest="none",
            reason="导入精确的公开合成 Route 候选",
            idempotency_key="candidate:ready:0001",
            actor_ref=ACTOR,
        )
        self.service.record_provider_observation(
            route_id=route["route_id"],
            expected_revision_digest=candidate["revision_digest"],
            document=observation_document(self.clock[0]),
            reason="记录公开合成 Provider Observation",
            idempotency_key="observation:ready:0001",
            actor_ref=ACTOR,
        )
        snapshot = self.service.reconcile_model_route(
            route_id=route["route_id"],
            expected_revision_digest=candidate["revision_digest"],
            reason="生成当前 Route 的合成 Preflight 证据",
            idempotency_key="reconcile:ready:0001",
            actor_ref=ACTOR,
        )
        self.assertEqual("ready", snapshot["status"])
        return route, candidate["revision_digest"], snapshot["snapshot_digest"]

    def _approve(self) -> tuple[dict, str]:
        route, revision_digest, snapshot_digest = self._ready_candidate()
        decision = self.service.decide_model_route(
            route_id=route["route_id"],
            expected_revision_digest=revision_digest,
            expected_snapshot_digest=snapshot_digest,
            decision="approved",
            reason="批准该精确合成 Revision 进入公司可选目录",
            idempotency_key="decision:approve:0001",
            actor_ref=ACTOR,
            actor_role_ref=ROLE,
        )
        return decision, revision_digest

    def test_approval_health_and_eligibility_remain_independent(self) -> None:
        decision, revision_digest = self._approve()
        route_id = route_document()["route_id"]
        self.assertTrue(decision["eligible"])
        current = self.service.list_model_routes()["items"][0]
        self.assertEqual("approved", current["approval_status"])
        self.assertTrue(current["eligible"])

        self.clock[0] = NOW + timedelta(hours=7)
        expired = self.service.list_model_routes()["items"][0]
        self.assertEqual("approved", expired["approval_status"])
        self.assertFalse(expired["eligible"])
        self.assertIn("model_route_snapshot_expired", expired["health"]["reason_codes"])

        self.service.record_provider_observation(
            route_id=route_id,
            expected_revision_digest=revision_digest,
            document=observation_document(self.clock[0]),
            reason="刷新批准包络内的公开 Provider Observation",
            idempotency_key="observation:refresh:0002",
            actor_ref=ACTOR,
        )
        self.service.reconcile_model_route(
            route_id=route_id,
            expected_revision_digest=revision_digest,
            reason="在原批准包络内刷新 Snapshot",
            idempotency_key="reconcile:refresh:0002",
            actor_ref=ACTOR,
        )
        restored = self.service.list_model_routes()["items"][0]
        self.assertTrue(restored["eligible"])
        with self.database.session() as session:
            self.assertEqual(1, len(tuple(session.scalars(select(ModelRouteDecisionRow)))))

    def test_scope_expansion_creates_new_unapproved_revision(self) -> None:
        _, revision_digest = self._approve()
        expanded = copy.deepcopy(route_document())
        expanded["approved_scope"]["permissions"].append("model.tools")
        created = self.service.submit_model_route_candidate(
            document=expanded,
            expected_latest_revision_digest=revision_digest,
            reason="扩大 Route 允许用途并形成新的 Revision",
            idempotency_key="candidate:expanded:0002",
            actor_ref=ACTOR,
        )
        self.assertNotEqual(revision_digest, created["revision_digest"])
        summary = self.service.list_model_routes()["items"][0]
        self.assertEqual("not_reviewed", summary["approval_status"])
        self.assertFalse(summary["eligible"])

    def test_expired_snapshot_blocks_approval_but_still_allows_rejection(self) -> None:
        route, revision_digest, snapshot_digest = self._ready_candidate()
        self.clock[0] = NOW + timedelta(hours=7)
        with self.assertRaises(ControlConsoleError) as context:
            self.service.decide_model_route(
                route_id=route["route_id"],
                expected_revision_digest=revision_digest,
                expected_snapshot_digest=snapshot_digest,
                decision="approved",
                reason="过期 Snapshot 不得批准进入公司可选目录",
                idempotency_key="decision:expired:approve:0001",
                actor_ref=ACTOR,
                actor_role_ref=ROLE,
            )
        self.assertEqual("model_route_preflight_blocked", context.exception.reason_code)
        rejected = self.service.decide_model_route(
            route_id=route["route_id"],
            expected_revision_digest=revision_digest,
            expected_snapshot_digest=snapshot_digest,
            decision="rejected",
            reason="拒绝当前健康证据已过期的精确 Revision",
            idempotency_key="decision:expired:reject:0002",
            actor_ref=ACTOR,
            actor_role_ref=ROLE,
        )
        self.assertEqual("rejected", rejected["decision"])
        self.assertFalse(rejected["eligible"])

    def test_revocation_preserves_evidence_and_denies_new_references(self) -> None:
        approved, revision_digest = self._approve()
        route_id = route_document()["route_id"]
        revoked = self.service.revoke_model_route_approval(
            route_id=route_id,
            expected_revision_digest=revision_digest,
            expected_approval_decision_digest=approved["decision_digest"],
            reason="撤销该精确 Revision 的公司目录批准",
            idempotency_key="decision:revoke:0002",
            actor_ref=ACTOR,
            actor_role_ref=ROLE,
        )
        self.assertFalse(revoked["eligible"])
        self.assertFalse(revoked["new_grant_references_allowed"])
        evidence = self.service.model_route_evidence(route_id=route_id)
        self.assertEqual(1, len(evidence["revisions"]))
        self.assertEqual(1, len(evidence["snapshots"]))
        self.assertEqual(["approved", "revoked"], [item["action"] for item in evidence["decisions"]])
        self.assertGreaterEqual(len(evidence["audit_events"]), 4)

    def test_every_mutation_replays_or_conflicts_by_idempotency_key(self) -> None:
        route = route_document()
        kwargs = {
            "document": route,
            "expected_latest_revision_digest": "none",
            "reason": "导入精确的公开合成 Route 候选",
            "idempotency_key": "candidate:replay:0001",
            "actor_ref": ACTOR,
        }
        first = self.service.submit_model_route_candidate(**kwargs)
        second = self.service.submit_model_route_candidate(**kwargs)
        self.assertEqual(first["revision_digest"], second["revision_digest"])
        self.assertTrue(second["idempotent_replay"])
        with self.assertRaises(ControlConsoleError) as context:
            self.service.submit_model_route_candidate(
                **{**kwargs, "reason": "使用相同幂等键提交不同请求必须冲突"}
            )
        self.assertEqual("control_console_idempotency_conflict", context.exception.reason_code)

    def test_task_scope_pass_and_violation_do_not_mutate_task(self) -> None:
        approved, revision_digest = self._approve()
        del approved
        route_id = route_document()["route_id"]
        task = {
            "task_id": "task_scope_syn_001",
            "revision": 4,
            "title": "合成 Scope 子集任务",
            "authority_state": "approved_by_department",
            "data_classification": "public",
            "side_effects": False,
            "requested_tool_refs": ["tool_public_read"],
            "allowed_tool_refs": ["tool_public_read"],
            "requested_dataset_refs": [],
            "allowed_dataset_refs": [],
            "requested_max_cost_usd": "0.05",
            "allowed_max_cost_usd": "0.20",
            "expires_at": (NOW + timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
            "model_route_id": route_id,
            "model_route_revision_digest": revision_digest,
            "runtime_adapter_selectable": True,
            "policy_allows_scope": True,
            "agent_binding_allows_scope": True,
        }
        self._insert_task(task)
        before = canonical_digest(task)
        passed = self.service.reconcile_task_scope(
            task_id=task["task_id"],
            expected_revision=4,
            expected_task_digest=before,
            reason="核对公开合成任务是否保持批准 Scope 子集",
            idempotency_key="task-audit:pass:0001",
            actor_ref=ACTOR,
        )
        self.assertEqual("allow", passed["decision"])
        self.assertEqual("none", passed["grant"]["action"])
        self.assertEqual(before, canonical_digest(self._task_document(task["task_id"])))

        violating = copy.deepcopy(task)
        violating["task_id"] = "task_scope_syn_002"
        violating["requested_tool_refs"] = ["tool_unapproved_write"]
        violating["execution_grant_id"] = "grant_task_scope_syn_002"
        self._insert_task(violating)
        violating_digest = canonical_digest(violating)
        denied = self.service.reconcile_task_scope(
            task_id=violating["task_id"],
            expected_revision=4,
            expected_task_digest=violating_digest,
            reason="核对越界 Tool 并撤销现有合成 Grant",
            idempotency_key="task-audit:deny:0002",
            actor_ref=ACTOR,
        )
        self.assertEqual("deny", denied["decision"])
        self.assertIn("task_tool_scope_out_of_scope", denied["reason_codes"])
        self.assertEqual("revoked", denied["grant"]["action"])
        self.assertEqual(violating_digest, canonical_digest(self._task_document(violating["task_id"])))
        with self.database.session() as session:
            self.assertIsNotNone(
                session.scalar(
                    select(GrantRevocationRow).where(
                        GrantRevocationRow.grant_id == "grant_task_scope_syn_002"
                    )
                )
            )
            self.assertGreaterEqual(len(tuple(session.scalars(select(ReceiptRow)))), 3)
            task_events = tuple(
                session.scalars(
                    select(AuditEventRow).where(
                        AuditEventRow.correlation_id == violating["task_id"]
                    )
                )
            )
            self.assertEqual("workload_task_scope_auditor", task_events[-1].actor_ref)

    def test_task_scope_data_budget_and_deadline_violations_block_issuance(self) -> None:
        _, revision_digest = self._approve()
        route_id = route_document()["route_id"]
        base = {
            "revision": 5,
            "title": "合成 Scope 越界矩阵",
            "authority_state": "approved_by_department",
            "data_classification": "public",
            "side_effects": False,
            "requested_tool_refs": [],
            "allowed_tool_refs": [],
            "requested_dataset_refs": [],
            "allowed_dataset_refs": [],
            "requested_max_cost_usd": "0.05",
            "allowed_max_cost_usd": "0.20",
            "expires_at": (NOW + timedelta(hours=2)).isoformat().replace(
                "+00:00", "Z"
            ),
            "model_route_id": route_id,
            "model_route_revision_digest": revision_digest,
            "runtime_adapter_selectable": True,
            "policy_allows_scope": True,
            "agent_binding_allows_scope": True,
        }
        variants = (
            (
                "dataset",
                {"requested_dataset_refs": ["dataset_unapproved_syn"]},
                "task_data_scope_out_of_scope",
            ),
            (
                "classification",
                {"data_classification": "restricted"},
                "task_data_classification_out_of_scope",
            ),
            (
                "budget",
                {"requested_max_cost_usd": "0.21"},
                "task_budget_out_of_scope",
            ),
            (
                "deadline",
                {
                    "expires_at": (NOW - timedelta(seconds=1))
                    .isoformat()
                    .replace("+00:00", "Z")
                },
                "task_deadline_expired",
            ),
        )
        for index, (name, mutation, reason_code) in enumerate(variants, start=1):
            with self.subTest(name=name):
                task = {
                    **base,
                    **mutation,
                    "task_id": f"task_scope_matrix_syn_{index:02d}",
                }
                self._insert_task(task)
                task_digest = canonical_digest(task)
                denied = self.service.reconcile_task_scope(
                    task_id=task["task_id"],
                    expected_revision=task["revision"],
                    expected_task_digest=task_digest,
                    reason=f"核对 {name} 越界且在无 Grant 时阻断签发",
                    idempotency_key=f"task-audit:matrix:{index:04d}",
                    actor_ref=ACTOR,
                )
                self.assertEqual("deny", denied["decision"])
                self.assertIn(reason_code, denied["reason_codes"])
                self.assertEqual("block_issuance", denied["grant"]["action"])
                self.assertEqual(
                    task_digest,
                    canonical_digest(self._task_document(task["task_id"])),
                )

    def _insert_task(self, task: dict) -> None:
        with self.database.session() as session:
            session.add(
                DepartmentCockpitObjectRow(
                    object_type="task",
                    object_id=task["task_id"],
                    department_id="technology_center",
                    revision=task["revision"],
                    document=task,
                    updated_at=NOW,
                )
            )

    def _task_document(self, task_id: str) -> dict:
        with self.database.session() as session:
            row = session.scalar(
                select(DepartmentCockpitObjectRow).where(
                    DepartmentCockpitObjectRow.object_id == task_id
                )
            )
            return row.document


if __name__ == "__main__":
    unittest.main()

