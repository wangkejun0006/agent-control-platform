"""Synthetic HTTP flow with explicit principal/health stubs; no account login."""

import unittest
from datetime import timedelta

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from orbit_agent_control_plane.service_runtime.control_console import (
    ControlConsoleService,
)
from orbit_agent_control_plane.service_runtime.control_console_api import (
    install_control_console_routes,
)
from orbit_agent_control_plane.service_runtime.department_cockpit import (
    DepartmentCockpitService,
)
from orbit_agent_control_plane.service_runtime.department_cockpit_api import (
    install_department_cockpit_routes,
)
from orbit_agent_control_plane.service_runtime.model_route_credentials import (
    ModelRouteCredentialService,
)
from tests import test_model_catalog as fixture
from tests import test_model_catalog_integrity as requests_fixture
from tests.test_model_route_credentials import observation


class SyntheticHealth:
    def health(self, logical_ref):
        return {
            "healthy": True,
            "binding_version": "synthetic-v1",
            "secret_fingerprint": "sha256:" + "f" * 64,
        }

    def read(self, logical_ref):
        raise AssertionError("HTTP catalog tests must not read credentials")


class ModelCatalogApiFlowTests(unittest.TestCase):
    def test_onboarding_review_preserves_source_and_exact_history(self):
        proposal = self.post(
            "/v1/control/provider-onboarding-proposals",
            {
                "display_name": "合成供应商核验请求",
                "requested_regions": ["global_service"],
                "required_protocols": ["openai_responses"],
                "reason": "请求核对受控来源，不能自动准入",
                "idempotency_key": "api:onboarding:request",
            },
        )
        url = (
            "/v1/control/provider-onboarding-proposals/"
            + proposal["proposal_id"]
            + "/reviews"
        )
        request = {
            "expected_proposal_digest": proposal["proposal_digest"],
            "status": "revision_required",
            "reason": "请补充来源摘要与协议核验材料",
            "idempotency_key": "api:onboarding:return",
        }
        first = self.post(url, request)
        self.assertEqual(
            403,
            self.client.get(
                "/v1/control/provider-onboarding-proposals",
                headers=self.headers("role_department_user"),
            ).status_code,
        )
        preset = next(
            item
            for item in self.service.list_provider_presets()["items"]
            if item["provider_preset_id"] == "provider_preset_openai_codex"
        )
        linked = self.post(
            url,
            {
                **request,
                "expected_review_digest": first["review_digest"],
                "status": "linked_to_preset",
                "reason": "仅关联已存在的合成预设精确修订",
                "provider_preset_id": preset["provider_preset_id"],
                "provider_preset_revision_digest": preset["revision_digest"],
                "idempotency_key": "api:onboarding:link",
            },
        )
        self.assertEqual("linked_to_preset", linked["status"])
        history = self.client.get(
            "/v1/control/provider-onboarding-proposals", headers=self.headers()
        ).json()["items"][0]
        self.assertEqual(2, len(history["review_history"]))
        self.assertEqual(3, len(self.service.list_provider_presets()["items"]))

    def setUp(self):
        fixture.ModelCatalogTests.setUp(self)
        self.now = fixture.NOW
        self.service.now = lambda: self.now
        routes = self.service.model_routes
        routes.now = lambda: self.now
        routes.secret_provider = SyntheticHealth()
        credentials = ModelRouteCredentialService(
            database=self.database,
            secret_provider=routes.secret_provider,
            now=lambda: self.now,
        )
        routes.credential_health_provider = credentials
        self.console = ControlConsoleService(
            database=self.database,
            model_routes=routes,
            grant_revocations=None,
            credentials=credentials,
            model_catalog=self.service,
            now=lambda: self.now,
        )
        self.department = DepartmentCockpitService(
            database=self.database, agent_proposals=self.service
        )
        app = FastAPI()

        # This fixture only exercises guard invocation, role and department scope.
        # It does not emulate or claim a successful identity-provider login.
        def principal(request, *, required_roles):
            role = request.headers.get("x-synthetic-role", "role_department_user")
            if role not in required_roles:
                raise HTTPException(403, "synthetic_role_denied")
            return {
                "human_ref": "human_synthetic_" + role,
                "account_id": "synthetic-owner",
                "role_refs": [role],
                "department_refs": ["technology_center"],
            }

        def mutating(request, *, required_roles):
            if request.headers.get("x-synthetic-confirmation") != "yes":
                raise HTTPException(403, "synthetic_confirmation_missing")
            return principal(request, required_roles=required_roles)

        install_control_console_routes(
            app,
            service=self.console,
            authenticate_human=principal,
            require_mutating_human=mutating,
        )
        install_department_cockpit_routes(
            app,
            service=self.department,
            authenticate_human=principal,
            require_mutating_human=mutating,
        )
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        fixture.ModelCatalogTests.tearDown(self)

    def headers(self, role="role_control_plane_admin"):
        return {"x-synthetic-role": role, "x-synthetic-confirmation": "yes"}

    def post(self, url, payload, role="role_control_plane_admin", expected=201):
        response = self.client.post(url, json=payload, headers=self.headers(role))
        self.assertEqual(expected, response.status_code, response.text)
        return response.json()

    def test_company_catalog_department_revision_and_independent_decisions(self):
        presets = self.client.get(
            "/v1/control/model-provider-presets", headers=self.headers()
        ).json()["items"]
        preset = next(
            item
            for item in presets
            if item["provider_preset_id"] == "provider_preset_openai_codex"
        )
        discovery_request = {
            "provider_preset_id": preset["provider_preset_id"],
            "provider_preset_revision_digest": preset["revision_digest"],
            "region_id": "global_service",
            "connection_alias": "Codex 公司连接",
            "idempotency_key": "api:catalog:discovery",
        }
        discovery = self.post(
            "/v1/control/provider-model-discoveries", discovery_request
        )
        entry = self.post(
            "/v1/control/model-catalog-entries",
            {
                "discovery_digest": discovery["discovery_digest"],
                "provider_model_key": discovery["models"][0]["provider_model_key"],
                "idempotency_key": "api:catalog:entry",
            },
        )
        entry_url = "/v1/control/model-catalog-entries/" + entry["entry_id"]
        self.post(
            entry_url + "/credential-bindings",
            {
                "expected_entry_revision_digest": entry["entry_revision_digest"],
                "authentication_mode": "api_key_ref",
                "expected_binding_version": "synthetic-v1",
                "idempotency_key": "api:catalog:credential",
            },
        )
        published = self.post(
            entry_url + "/availability-receipts",
            {
                "expected_entry_revision_digest": entry["entry_revision_digest"],
                "reason": "只核对合成凭据版本与目录资格",
                "idempotency_key": "api:catalog:publish",
            },
        )
        entry["entry_revision_digest"] = published["entry_revision_digest"]
        dept_url = "/v1/department-cockpit/technology_center/agent-proposals"
        request = requests_fixture.ModelCatalogIntegrityTests.proposal_request(
            self, entry
        )
        request.pop("actor_ref")
        request.pop("department_id")
        self.post(dept_url, request, "role_department_user", expected=403)
        self.post(
            dept_url,
            {**request, "proposer_account_ref": "account://forged/owner"},
            "role_department_owner",
            expected=422,
        )
        missing_confirmation = self.client.post(
            dept_url,
            json=request,
            headers={"x-synthetic-role": "role_department_owner"},
        )
        self.assertEqual(403, missing_confirmation.status_code)
        first = self.post(dept_url, request, "role_department_owner")
        activation_url = (
            "/v1/control/department-agent-proposals/"
            + first["proposal_id"]
            + "/activation-decisions"
        )
        returned = self.post(
            activation_url,
            {
                "decision_scope": "agent_activation",
                "expected_package_digest": first["package_digest"],
                "expected_agent_definition_digest": first["agent_binding"][
                    "agent_definition_digest"
                ],
                "decision": "revision_required",
                "reason": "请补充范围后由部门重新申报",
                "idempotency_key": "api:activation:return",
            },
        )
        self.assertTrue(returned["model_route_approval_unchanged"])
        revised_request = {
            **request,
            "supersedes_package_digest": first["package_digest"],
            "idempotency_key": "api:proposal:revision",
            "task_scope": "只读核对合成源码快照与边界，补充输出验收条件",
        }
        second = self.post(dept_url, revised_request, "role_department_owner")
        self.assertEqual(2, second["revision"])
        history = self.client.get(
            dept_url, headers=self.headers("role_department_owner")
        ).json()["items"]
        self.assertEqual(2, len(history))
        self.assertFalse(
            next(item for item in history if item["revision"] == 1)["can_revise"]
        )
        for suffix in ["", "/" + first["package_digest"] + "/exchange"]:
            self.assertEqual(
                403,
                self.client.get(
                    "/v1/department-cockpit/market_center/agent-proposals" + suffix,
                    headers=self.headers("role_department_owner"),
                ).status_code,
            )
        exchange = self.client.get(
            dept_url + "/" + second["package_digest"] + "/exchange",
            headers=self.headers("role_department_owner"),
        )
        self.assertEqual(200, exchange.status_code, exchange.text)
        self.assertEqual(
            1,
            exchange.json()["document"]["spec"]["supersedes"]["version"].count(
                "candidate.1"
            ),
        )
        self.post(
            activation_url,
            {
                "decision_scope": "agent_activation",
                "expected_package_digest": second["package_digest"],
                "expected_agent_definition_digest": second["agent_binding"][
                    "agent_definition_digest"
                ],
                "decision": "approved",
                "reason": "仅批准这个合成定义的独立激活候选",
                "idempotency_key": "api:activation:approve",
            },
        )
        readback = self.client.get(
            dept_url, headers=self.headers("role_department_owner")
        ).json()["items"][0]
        self.assertEqual("not_reviewed", readback["model_route_approval_status"])
        self.assertFalse(readback["agent_and_route_eligible"])
        route = second["model_route"]
        # Controlled fixture observation and qualification, with no network/secret read.
        self.console.credentials.qualify_api_key_binding(
            route_id=route["route_id"],
            expected_revision_digest=route["revision_digest"],
            expected_binding_version="synthetic-v1",
            reason="合成 API 闭环的逻辑凭据健康桩",
            idempotency_key="api:route:credential",
            actor_ref="human_admin_syn",
        )
        observed = observation(self.now, provider="openai")
        observed.update(
            requested_model="codex-cli",
            resolved_model_id="codex-cli",
            source="synthetic-catalog-api-fixture",
        )
        self.post(
            "/v1/provider-observations",
            {
                "route_id": route["route_id"],
                "expected_revision_digest": route["revision_digest"],
                "document": observed,
                "reason": "零费用确定性合成观察，无模型调用",
                "idempotency_key": "api:route:observation",
            },
        )
        snapshot = self.post(
            "/v1/model-routes/" + route["route_id"] + "/reconcile",
            {
                "expected_revision_digest": route["revision_digest"],
                "reason": "仅重算合成候选的资格快照",
                "idempotency_key": "api:route:reconcile",
            },
            expected=200,
        )
        self.post(
            "/v1/approval-decisions",
            {
                "decision_scope": "model_route_approval",
                "route_id": route["route_id"],
                "expected_revision_digest": route["revision_digest"],
                "expected_snapshot_digest": snapshot["snapshot_digest"],
                "decision": "approved",
                "reason": "只批准精确合成路线修订，无任务授权",
                "idempotency_key": "api:route:approval",
            },
        )
        readback = self.client.get(
            dept_url, headers=self.headers("role_department_owner")
        ).json()["items"][0]
        self.assertTrue(readback["agent_and_route_eligible"])
        self.assertFalse(readback["execution_grant_issued"])
        self.assertNotIn("secret://", str(readback))
        self.assertNotIn("https://api.", str(readback))
        self.now += timedelta(hours=25)
        replay = self.post(dept_url, revised_request, "role_department_owner")
        self.assertTrue(replay["historical_receipt_only"])
        self.assertEqual(second["package_digest"], replay["package_digest"])
        fresh_discovery = self.post(
            "/v1/control/provider-model-discoveries",
            {**discovery_request, "idempotency_key": "api:discovery:renewal"},
        )
        renewed = self.post(
            "/v1/control/model-catalog-entries",
            {
                "discovery_digest": fresh_discovery["discovery_digest"],
                "provider_model_key": discovery["models"][0]["provider_model_key"],
                "expected_entry_revision_digest": entry["entry_revision_digest"],
                "idempotency_key": "api:entry:renewal",
            },
        )
        self.assertEqual("not_bound", renewed["credential_health"])
        self.assertFalse(renewed["can_be_used_for_new_proposals"])

