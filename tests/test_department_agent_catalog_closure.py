"""Local synthetic regression coverage for proposal identity across department views."""

import copy
import unittest
from unittest import mock

from sqlalchemy import func, select

from orbit_agent_control_plane.service_runtime.department_cockpit import (
    DepartmentCockpitError,
    DepartmentCockpitService,
    SqlCompanyModelRouteCatalog,
)
from orbit_agent_control_plane.service_runtime.models import (
    AuditEventRow, DepartmentCockpitObjectRow, ReceiptRow,
)
from orbit_agent_control_plane.service_runtime.model_catalog_models import DepartmentAgentProposalRow
from tests import test_model_catalog as catalog_fixture
from tests import test_model_catalog_api_flow as flow_fixture
from tests import test_model_catalog_integrity as integrity_fixture


class DepartmentAgentCatalogClosureTests(unittest.TestCase):
    setUp = flow_fixture.ModelCatalogApiFlowTests.setUp
    tearDown = flow_fixture.ModelCatalogApiFlowTests.tearDown
    headers = flow_fixture.ModelCatalogApiFlowTests.headers
    post = flow_fixture.ModelCatalogApiFlowTests.post

    def _propose(self):
        entry = catalog_fixture.ModelCatalogTests._available_entry(self, "provider_preset_openai_codex")
        request = integrity_fixture.ModelCatalogIntegrityTests.proposal_request(self, entry)
        proposal = self.service.submit_agent_proposal(**request)
        self.department.model_route_catalog = SqlCompanyModelRouteCatalog(self.database)
        return request, proposal

    def _decide(self, proposal, action, key):
        return self.service.decide_agent_activation(
            proposal_id=proposal["proposal_id"],
            expected_package_digest=proposal["package_digest"],
            expected_agent_definition_digest=proposal["agent_binding"]["agent_definition_digest"],
            decision=action, reason="合成候选范围审核，不代表登记或执行", idempotency_key=key,
            actor_ref="human_admin_syn",
        )

    def _counts(self):
        with self.database.session() as session:
            return tuple(session.scalar(select(func.count()).select_from(model))
                         for model in (ReceiptRow, AuditEventRow, DepartmentCockpitObjectRow))

    def test_latest_candidate_visible_in_both_views_without_mutating_or_replacing_builtin(self):
        _request, proposal = self._propose()
        before = self._counts()
        bootstrap = self.department.bootstrap(department_id="technology_center")
        models = self.department.model_resources(department_id="technology_center")
        candidate_id = proposal["agent_definition"]["agent_id"]
        candidate = next(item for item in bootstrap["agents"] if item["agent_id"] == candidate_id)
        resource = next(item for item in models["agents"] if item["agent_ref"] == candidate_id)
        self.assertEqual("department_proposal", candidate["source_kind"])
        self.assertEqual("awaiting_registration", candidate["registry_status"])
        self.assertEqual(proposal["package_digest"], resource["package_digest"])
        self.assertEqual(candidate["agent_binding_ref"], resource["agent_binding_ref"])
        self.assertEqual(proposal["model_route"]["revision_digest"], resource["current_route"]["route_revision_digest"])
        self.assertFalse(resource["current_route"]["selected"])
        self.assertFalse(resource["current_route"]["selectable"])
        self.assertIsNone(resource["selected_at"])
        self.assertFalse(candidate["task_selectable"])
        self.assertEqual(2, sum(item["source_kind"] == "builtin" for item in bootstrap["agents"]))
        self.assertEqual(before, self._counts(), "Reading candidate projections must not create receipts or selections")
        self.assertNotIn("secret://", str(bootstrap) + str(models))
        self.assertNotIn("api.openai", str(bootstrap) + str(models))

    def test_revised_candidate_replaces_only_its_projection_and_old_binding_is_rejected(self):
        request, first = self._propose()
        self._decide(first, "revision_required", "catalog-closure:return")
        second = self.service.submit_agent_proposal(**{
            **request, "supersedes_package_digest": first["package_digest"],
            "task_scope": "合成快照只读核对，增加明确验收范围", "idempotency_key": "catalog-closure:revision",
        })
        agents = self.department.bootstrap(department_id="technology_center")["agents"]
        candidates = [item for item in agents if item["source_kind"] == "department_proposal"]
        self.assertEqual([second["package_digest"]], [item["package_digest"] for item in candidates])
        history = self.service.list_agent_route_reviews(department_id="technology_center")["items"]
        self.assertEqual(2, len(history))
        self.assertEqual(first["agent_definition"], history[1]["agent_definition"])
        result = self.client.post(
            "/v1/department-cockpit/technology_center/agent-model-route-selections",
            headers=self.headers("role_department_owner"),
            json={"agent_binding_ref": first["agent_binding"]["binding_id"],
                  "route_id": first["model_route"]["route_id"],
                  "route_revision_digest": first["model_route"]["revision_digest"],
                  "expected_selection_digest": "sha256:" + "a" * 64,
                  "idempotency_key": "catalog-closure:stale-select"},
        )
        self.assertEqual(404, result.status_code, result.text)

    def test_candidate_is_never_implicitly_executable_or_cross_department_visible(self):
        _request, proposal = self._propose()
        self._decide(proposal, "approved", "catalog-closure:approve")
        candidate_id = proposal["agent_definition"]["agent_id"]
        resources = self.department.model_resources(department_id="technology_center")
        candidate = next(item for item in resources["agents"] if item["agent_ref"] == candidate_id)
        before = self._counts()
        result = self.client.post(
            "/v1/department-cockpit/technology_center/agent-model-route-selections",
            headers=self.headers("role_department_owner"),
            json={"agent_binding_ref": candidate["agent_binding_ref"],
                  "route_id": proposal["model_route"]["route_id"],
                  "route_revision_digest": proposal["model_route"]["revision_digest"],
                  "expected_selection_digest": candidate["selection_digest"],
                  "idempotency_key": "catalog-closure:blocked-select"},
        )
        self.assertEqual(409, result.status_code, result.text)
        self.assertEqual("agent_registry_activation_missing", result.json()["detail"])
        self.assertEqual(before, self._counts())
        other = self.department.bootstrap(department_id="market_center")
        self.assertNotIn(candidate_id, str(other))
        self.assertNotIn(candidate_id, str(self.department.tasks))
        restarted = DepartmentCockpitService(database=self.database, agent_proposals=self.service,
                                             model_route_catalog=SqlCompanyModelRouteCatalog(self.database))
        projected = next(item for item in restarted.model_resources(department_id="technology_center")["agents"]
                         if item["agent_ref"] == candidate_id)
        self.assertEqual(candidate["selection_digest"], projected["selection_digest"])

    def test_double_approval_remains_explicitly_candidate_and_shows_same_identity(self):
        flow_fixture.ModelCatalogApiFlowTests.test_company_catalog_department_revision_and_independent_decisions(self)
        self.department.model_route_catalog = SqlCompanyModelRouteCatalog(self.database)
        history = self.service.list_agent_route_reviews(department_id="technology_center")["items"]
        latest = next(item for item in history if item["is_latest"])
        self.assertTrue(latest["agent_and_route_eligible"])
        candidate = next(item for item in self.department.bootstrap(department_id="technology_center")["agents"]
                         if item["agent_id"] == latest["agent_definition"]["agent_id"])
        self.assertEqual("awaiting_registration", candidate["qualification_status"])
        self.assertFalse(candidate["task_selectable"])
        self.assertTrue(candidate["candidate_only"])
        self.assertFalse(latest["execution_grant_issued"])

    def test_proposal_route_keeps_public_model_name_and_department_scope(self):
        _request, proposal = self._propose()
        route = proposal["model_route"]
        resources = self.department.model_resources(department_id="technology_center")
        candidate = next(item for item in resources["agents"]
                         if item.get("proposal_id") == proposal["proposal_id"])
        self.assertEqual(route["model_display_name"], candidate["current_route"]["model_display_name"])
        self.assertEqual(route["model_version_label"], candidate["current_route"]["model_version_label"])
        other = self.department.model_resources(department_id="market_center")
        self.assertNotIn(route["route_id"], str(other))
        self.assertNotIn("api.openai", str(resources))
        self.assertNotIn("secret://", str(resources))

    def test_proposal_route_unknown_revision_or_ambiguous_owner_is_not_projected(self):
        _request, proposal = self._propose()
        catalog = self.department.model_route_catalog
        with self.database.session() as session:
            row = session.scalar(select(DepartmentAgentProposalRow))
            row.model_route_revision_digest = "sha256:" + "f" * 64
        self.assertEqual([], catalog.routes(department_id="technology_center"))
        with self.database.session() as session:
            row = session.scalar(select(DepartmentAgentProposalRow))
            row.model_route_revision_digest = proposal["model_route"]["revision_digest"]
            values = {column.name: copy.deepcopy(getattr(row, column.name))
                      for column in DepartmentAgentProposalRow.__table__.columns if column.name != "id"}
            values.update(proposal_id="proposal_synthetic_scope_conflict",
                          package_digest="sha256:" + "e" * 64,
                          department_id="market_center", idempotency_key="catalog-closure:scope-conflict")
            session.add(DepartmentAgentProposalRow(**values))
        self.assertEqual([], catalog.routes(department_id="technology_center"))
        self.assertEqual([], catalog.routes(department_id="market_center"))

    def test_builtin_selection_does_not_depend_on_proposal_feed(self):
        self._propose()
        binding_ref = "binding_technology_center_planning_d0"
        expected = self.department._agent_model_route_selection("technology_center", binding_ref)
        with mock.patch.object(self.service, "list_agent_route_reviews", side_effect=RuntimeError("proposal feed unavailable")):
            actual = self.department._agent_model_route_selection("technology_center", binding_ref)
        self.assertEqual(expected, actual)

    def test_inconsistent_candidate_identity_fails_before_projection(self):
        _request, proposal = self._propose()
        changed = copy.deepcopy(self.service.list_agent_route_reviews(department_id="technology_center"))
        changed["items"][0]["agent_definition"]["department_id"] = "market_center"
        before = self._counts()
        with mock.patch.object(self.service, "list_agent_route_reviews", return_value=changed):
            with self.assertRaisesRegex(DepartmentCockpitError, "agent_proposal_projection_binding_drift"):
                self.department.department_agents("technology_center")
        self.assertEqual(before, self._counts())

    def test_route_rejection_reason_is_not_hidden_by_agent_approval(self):
        _request, proposal = self._propose()
        self._decide(proposal, "approved", "catalog-closure:reason-approve")
        route = proposal["model_route"]
        snapshot = self.service.model_routes.reconcile(route["route_id"])
        self.console.decide_model_route(
            route_id=route["route_id"], expected_revision_digest=route["revision_digest"],
            expected_snapshot_digest=snapshot["snapshot_digest"], decision="rejected",
            reason="合成路线需补充协议能力验证后提交新修订", idempotency_key="catalog-closure:route-reject",
            actor_ref="human_admin_syn", actor_role_ref="role_control_plane_admin",
        )
        latest = self.service.list_agent_route_reviews(department_id="technology_center")["items"][0]
        self.assertIn("协议能力", latest["model_route_review_reason"])
        self.assertIn("范围审核", latest["agent_review_reason"])
        self.assertEqual(latest["model_route_review_reason"], latest["review_reason"])
        self.assertTrue(latest["can_revise"])


if __name__ == "__main__":
    unittest.main()

