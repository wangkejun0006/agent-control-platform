from __future__ import annotations

import copy
import unittest

from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.control_console import ControlConsoleService
from orbit_agent_control_plane.service_runtime.department_cockpit import (
    DepartmentCockpitService,
)
from orbit_agent_control_plane.service_runtime.lan_stage1_api import (
    _apply_codex_installation_readiness,
    _department_readiness_matrix,
)
from orbit_agent_control_plane.service_runtime.model_catalog_models import (
    DepartmentAgentProposalRow,
)
from orbit_agent_control_plane.service_runtime.models import AuditEventRow
from orbit_agent_control_plane.service_runtime.model_route import _route_document
from tests import test_model_catalog as catalog_fixture
from tests import test_model_catalog_integrity as proposal_fixture


class CockpitAuditRegressionTests(unittest.TestCase):
    setUp = catalog_fixture.ModelCatalogTests.setUp
    tearDown = catalog_fixture.ModelCatalogTests.tearDown
    _available_entry = catalog_fixture.ModelCatalogTests._available_entry
    proposal_request = proposal_fixture.ModelCatalogIntegrityTests.proposal_request

    def _events(self, department="technology_center", **kwargs):
        return DepartmentCockpitService(database=self.database)._audit_events(
            department, **kwargs
        )

    def _add_event(self, index, department, event_type="synthetic_audit", correlation="synthetic_scope"):
        with self.database.session() as session:
            session.add(AuditEventRow(
                audit_id=f"audit_synthetic_{index}",
                correlation_id=correlation,
                event_type=event_type,
                actor_ref="human_admin_syn",
                payload={} if department is None else {"department_id": department},
                recorded_at=catalog_fixture.NOW,
            ))

    def test_department_limit_is_applied_after_scope_filter(self):
        for index in range(55):
            self._add_event(index, "technology_center")
        for index in range(55, 106):
            self._add_event(index, "market_center")
        self._add_event(106, None)
        self._add_event(107, ["technology_center"])
        events = self._events()
        self.assertEqual(
            [f"audit_synthetic_{index}" for index in range(54, 4, -1)],
            [event["audit_id"] for event in events],
        )
        self.assertEqual(events, self._events())

    def test_correlation_never_expands_department_scope(self):
        self._add_event(0, "technology_center")
        self._add_event(1, "market_center")
        self._add_event(2, None)
        self._add_event(3, "technology_center")
        self.assertEqual(
            ["audit_synthetic_0", "audit_synthetic_3"],
            [event["audit_id"] for event in self._events(correlation_id="synthetic_scope")],
        )

    def test_proposal_and_activation_audits_bind_exact_trusted_objects(self):
        entry = self._available_entry("provider_preset_openai_codex")
        request = self.proposal_request(entry)
        proposal = self.service.submit_agent_proposal(**request)
        self.service.submit_agent_proposal(**request)
        decision_request = dict(
            proposal_id=proposal["proposal_id"],
            expected_package_digest=proposal["package_digest"],
            expected_agent_definition_digest=proposal["agent_binding"]["agent_definition_digest"],
            decision="approved",
            reason="合成候选的精确审批边界已核对",
            idempotency_key="audit:activation:synthetic:0001",
            actor_ref="human_admin_syn",
        )
        decision = self.service.decide_agent_activation(**decision_request)
        self.service.decide_agent_activation(**decision_request)
        with self.database.session() as session:
            stored = session.scalar(select(DepartmentAgentProposalRow))
        expected = {
            "department_id": stored.department_id,
            "proposal_id": stored.proposal_id,
            "package_digest": stored.package_digest,
            "agent_definition_ref": stored.document["package"]["agent_definition"]["ref"],
            "agent_definition_digest": stored.agent_definition_digest,
            "agent_binding_ref": stored.document["package"]["agent_binding"]["ref"],
            "agent_binding_digest": stored.agent_binding_digest,
            "model_route_id": stored.model_route_id,
            "model_route_revision_digest": stored.model_route_revision_digest,
        }
        events = self._events(correlation_id=stored.proposal_id)
        self.assertEqual(
            ["department_agent_proposal_submitted", "agent_activation_decided"],
            [event["event_type"] for event in events],
        )
        for event in events:
            with self.subTest(event=event["event_type"]):
                self.assertEqual(expected, {key: event["payload"].get(key) for key in expected})
                self.assertEqual("approval", event["category"])
                self.assertNotEqual("驾驶舱事件已记录。", event["summary"])
                self.assertFalse(event["payload"]["execution_grant_issued"])
        self.assertEqual(decision["decision_digest"], events[-1]["payload"]["decision_digest"])
        self.assertEqual([], self._events("market_center", correlation_id=stored.proposal_id))

    def test_returned_activation_decision_is_visible_in_department(self):
        entry = self._available_entry("provider_preset_openai_codex")
        proposal = self.service.submit_agent_proposal(**self.proposal_request(entry))
        self.service.decide_agent_activation(
            proposal_id=proposal["proposal_id"],
            expected_package_digest=proposal["package_digest"],
            expected_agent_definition_digest=proposal["agent_binding"]["agent_definition_digest"],
            decision="revision_required",
            reason="合成候选需要补齐职责边界",
            idempotency_key="audit:activation:return:0001",
            actor_ref="human_admin_syn",
        )
        events = self._events(correlation_id=proposal["proposal_id"])
        self.assertEqual("revision_required", events[-1]["payload"].get("decision"))

    def test_identity_and_route_events_have_meaningful_categories(self):
        expected = {
            "lan_invite_consumed": "identity",
            "lan_account_approved": "identity",
            "model_route_candidate_recorded": "route",
            "model_route_snapshot_recorded": "route",
            "model_route_approval_approved": "approval",
            "model_route_approval_rejected": "approval",
            "model_route_approval_revoked": "approval",
        }
        for index, event_type in enumerate(expected):
            self._add_event(index, "technology_center", event_type)
        for event in self._events():
            with self.subTest(event=event["event_type"]):
                self.assertEqual(expected[event["event_type"]], event["category"])
                self.assertNotEqual("驾驶舱事件已记录。", event["summary"])

    def _route_audit_flow(self, *, change_revision=False, ambiguous_department=False):
        entry = self._available_entry("provider_preset_openai_codex")
        proposal = self.service.submit_agent_proposal(**self.proposal_request(entry))
        route_id = proposal["model_route"]["route_id"]
        revision = proposal["model_route"]["revision_digest"]
        if ambiguous_department:
            with self.database.session() as session:
                original = session.scalar(select(DepartmentAgentProposalRow))
                values = {column.name: copy.deepcopy(getattr(original, column.name))
                          for column in DepartmentAgentProposalRow.__table__.columns if column.name != "id"}
                values.update(
                    proposal_id="proposal_synthetic_conflict",
                    package_digest="sha256:" + "f" * 64,
                    department_id="market_center",
                    idempotency_key="audit:synthetic:conflict:0001",
                )
                session.add(DepartmentAgentProposalRow(**values))
        console = ControlConsoleService(
            database=self.database, model_routes=self.service.model_routes,
            grant_revocations=None, now=lambda: catalog_fixture.NOW,
        )
        document = _route_document(self.service.model_routes.store.latest_route(route_id))
        if change_revision:
            document["parameters"]["max_retries"] = 0
        candidate = console.submit_model_route_candidate(
            document=document, expected_latest_revision_digest=revision,
            reason="合成路线审计核验", idempotency_key="audit:route:candidate:0001",
            actor_ref="human_admin_syn",
        )
        revision = candidate["revision_digest"]
        snapshot = console.reconcile_model_route(
            route_id=route_id, expected_revision_digest=revision,
            reason="合成路线资格核验", idempotency_key="audit:route:reconcile:0001",
            actor_ref="human_admin_syn",
        )
        console.decide_model_route(
            route_id=route_id, expected_revision_digest=revision,
            expected_snapshot_digest=snapshot["snapshot_digest"],
            decision="rejected", reason="缺少合成资格证据，拒绝此修订",
            idempotency_key="audit:route:decision:0001",
            actor_ref="human_admin_syn", actor_role_ref="role_control_plane_admin",
        )
        return proposal, route_id, revision

    def test_route_events_inherit_only_exact_accepted_proposal_scope(self):
        proposal, route_id, revision = self._route_audit_flow()
        events = self._events(correlation_id=route_id)
        self.assertEqual({
            "model_route_candidate_recorded", "model_route_snapshot_recorded",
            "model_route_reconcile_requested", "model_route_approval_rejected",
        }, {event["event_type"] for event in events})
        for event in events:
            with self.subTest(event=event["event_type"]):
                self.assertEqual("technology_center", event["payload"]["department_id"])
                self.assertEqual(proposal["proposal_id"], event["payload"]["proposal_id"])
                self.assertEqual(proposal["package_digest"], event["payload"]["package_digest"])
                self.assertEqual(route_id, event["payload"]["route_id"])
                self.assertEqual(revision, event["payload"]["route_revision_digest"])
        self.assertEqual([], self._events("market_center", correlation_id=route_id))

    def test_unassociated_revision_stays_in_company_audit(self):
        _, route_id, revision = self._route_audit_flow(change_revision=True)
        self.assertEqual([], self._events(correlation_id=route_id))
        with self.database.session() as session:
            rows = tuple(session.scalars(select(AuditEventRow).where(AuditEventRow.correlation_id == route_id)))
        self.assertEqual(4, len(rows))
        for row in rows:
            self.assertNotIn("department_id", row.payload)
            self.assertEqual(revision, row.payload.get("route_revision_digest"))

    def test_ambiguous_route_department_is_not_guessed(self):
        _, route_id, _ = self._route_audit_flow(ambiguous_department=True)
        self.assertEqual([], self._events(correlation_id=route_id))
        self.assertEqual([], self._events("market_center", correlation_id=route_id))


class CockpitReadinessRegressionTests(unittest.TestCase):
    def _bootstrap(self, *, heartbeat="current", certificate="valid"):
        return {
            "observed_at": "2026-09-05T02:00:00Z",
            "department_accounts": [{
                "department_id": department,
                "role_ref": "role_department_owner", "status": "active",
                "display_name": "合成负责人",
            } for department in ("technology_center", "market_center")],
            "runtime_nodes": [{
                "department_ref": department, "display_name": "合成固定节点",
                "certificate_status": certificate, "heartbeat_status": heartbeat,
            } for department in ("technology_center", "market_center")],
            "department_model_resources": [{
                "department_id": "technology_center",
                "agents": [{"kind": "department_planning", "current_route": {
                    "selectable": True, "company_approval_status": "approved",
                    "health_status": "ready", "display_name": "合成规划路线",
                }}],
            }],
        }

    def _service(self, status="complete"):
        class SyntheticInstallation:
            def projection(self, *, department_id):
                return {
                    "overall_status": status if department_id == "technology_center" else "not_applicable",
                    "codex_cli_version": "synthetic-test",
                    "evidence": {"recorded_at": "2026-09-01T00:00:00Z"},
                    "failure_code": "synthetic_install_failure" if status == "failed" else None,
                }
        return SyntheticInstallation()

    def test_cli_receipt_cannot_override_stale_or_revoked_node(self):
        for heartbeat, certificate in (("stale", "valid"), ("current", "revoked")):
            with self.subTest(heartbeat=heartbeat, certificate=certificate):
                rows = _department_readiness_matrix(self._bootstrap(heartbeat=heartbeat, certificate=certificate))
                before = copy.deepcopy(rows)
                _apply_codex_installation_readiness(rows, self._service())
                self.assertEqual(
                    [row["cells"]["fixed_node"] for row in before],
                    [row["cells"]["fixed_node"] for row in rows],
                )

    def test_non_applicable_cli_cannot_block_market_node(self):
        rows = _department_readiness_matrix(self._bootstrap())
        _apply_codex_installation_readiness(rows, self._service())
        market = next(row for row in rows if row["department_id"] == "market_center")
        self.assertEqual("ready", market["cells"]["fixed_node"]["status"])
        self.assertIsNone(market["cells"]["fixed_node"]["blocker_reason"])
        self.assertEqual("not_applicable", market["codex_installation"]["overall_status"])
        tech = next(row for row in rows if row["department_id"] == "technology_center")
        self.assertEqual("complete", tech["codex_installation"]["overall_status"])

    def test_cli_failure_or_pending_cannot_override_current_node(self):
        for status in ("failed", "waiting_for_device_receipt"):
            with self.subTest(status=status):
                rows = _department_readiness_matrix(self._bootstrap())
                before = copy.deepcopy(rows)
                _apply_codex_installation_readiness(rows, self._service(status))
                self.assertEqual(
                    [row["cells"]["fixed_node"] for row in before],
                    [row["cells"]["fixed_node"] for row in rows],
                )

    def test_route_health_is_not_evidence_of_live_planning_transport(self):
        rows = _department_readiness_matrix(self._bootstrap())
        tech = next(row for row in rows if row["department_id"] == "technology_center")
        planning = tech["cells"]["planning_model"]
        self.assertNotEqual("ready", planning["status"])
        self.assertEqual("registry_projection", planning["evidence_level"])
        self.assertEqual("planning_model_transport_not_verified", planning["blocker_reason"])
        self.assertNotEqual("ready", tech["cells"]["evidence_freshness"]["status"])


if __name__ == "__main__":
    unittest.main()

