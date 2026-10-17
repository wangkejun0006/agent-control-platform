from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from orbit_agent_control_plane.service_runtime.control_console_d0_main import (
    build_d0_app,
)
from tests.test_control_console import route_document

ORIGIN_HEADERS = {
    "Origin": "http://testserver",
    "X-Orbit-Request": "control-console",
}


class ControlConsoleApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="orbit-console-api-")
        self.database_path = Path(self.temporary.name) / "console.sqlite3"
        self.client = TestClient(build_d0_app(database_path=self.database_path))

    def tearDown(self) -> None:
        self.client.close()
        self.temporary.cleanup()

    def test_loopback_d0_model_route_closes_with_server_readback(self) -> None:
        bootstrap = self.client.get("/v1/control-console/bootstrap")
        self.assertEqual(200, bootstrap.status_code)
        self.assertEqual(
            [True, True, False, False, True, True],
            [item["enabled"] for item in bootstrap.json()["navigation"]],
        )
        route = self.client.get("/v1/model-routes").json()["items"][0]
        self.assertNotIn("provider", route)
        self.assertNotIn("requested_model", route)
        self.assertFalse(route["raw_endpoint_visible"])
        self.assertFalse(route["provider_model_id_visible"])
        self.assertFalse(route["credential_ref_visible"])
        self.assertEqual("not_reviewed", route["approval_status"])
        self.assertEqual("ready", route["health"]["status"])
        payload = {
            "decision_scope": "model_route_approval",
            "route_id": route["route_id"],
            "expected_revision_digest": route["revision_digest"],
            "expected_snapshot_digest": route["health"]["snapshot_digest"],
            "decision": "approved",
            "reason": "批准 D0 精确 Revision 进入公司可选目录",
            "idempotency_key": "api:decision:approve:0001",
        }
        denied = self.client.post("/v1/approval-decisions", json=payload)
        self.assertEqual(403, denied.status_code)
        approved = self.client.post(
            "/v1/approval-decisions", json=payload, headers=ORIGIN_HEADERS
        )
        self.assertEqual(201, approved.status_code, approved.text)
        self.assertFalse(approved.json()["execution_grant_issued"])
        reread = self.client.get("/v1/model-routes").json()["items"][0]
        self.assertEqual("approved", reread["approval_status"])
        self.assertTrue(reread["eligible"])
        evidence = self.client.get(
            f"/v1/model-routes/{route['route_id']}/evidence"
        ).json()
        self.assertEqual(1, len(evidence["decisions"]))
        self.assertEqual(1, len(evidence["receipts"]))
        self.assertGreaterEqual(len(evidence["snapshots"]), 1)
        self.assertGreaterEqual(len(evidence["audit_events"]), 2)
        self.assertTrue(
            all("endpoint" not in item["document"] for item in evidence["revisions"])
        )
        self.assertTrue(
            all("secret_ref" not in item for item in evidence["snapshots"])
        )

    def test_forged_actor_and_secret_field_are_rejected(self) -> None:
        route = self.client.get("/v1/model-routes").json()["items"][0]
        forged = {
            "decision_scope": "model_route_approval",
            "route_id": route["route_id"],
            "expected_revision_digest": route["revision_digest"],
            "expected_snapshot_digest": route["health"]["snapshot_digest"],
            "decision": "approved",
            "reason": "伪造操作者字段必须被请求模型拒绝",
            "idempotency_key": "api:forged:actor:0001",
            "actor_ref": "human_forged",
        }
        response = self.client.post(
            "/v1/approval-decisions", json=forged, headers=ORIGIN_HEADERS
        )
        self.assertEqual(422, response.status_code)

        secret_route = copy.deepcopy(route_document())
        secret_route["route_id"] = "model_route_secret_field_syn"
        secret_route["secret_bytes"] = "must-not-enter-browser-or-service"
        response = self.client.post(
            "/v1/model-route-candidates",
            headers=ORIGIN_HEADERS,
            json={
                "document": secret_route,
                "expected_latest_revision_digest": "none",
                "reason": "带 Secret 字节的候选必须失败关闭",
                "idempotency_key": "api:secret:reject:0001",
            },
        )
        self.assertEqual(410, response.status_code)
        self.assertNotIn("must-not-enter-browser-or-service", response.text)

    def test_legacy_route_creation_is_closed_even_for_company_admin(self) -> None:
        before = self.client.get("/v1/model-routes").json()
        response = self.client.post(
            "/v1/model-route-candidates", headers=ORIGIN_HEADERS,
            json={"document": route_document(), "expected_latest_revision_digest": "none",
                  "reason": "公司不能替部门直接生成路线", "idempotency_key": "legacy:closed:0001"},
        )
        self.assertEqual(410, response.status_code)
        self.assertEqual("model_route_candidate_requires_department_agent_proposal", response.json()["detail"])
        self.assertEqual(before, self.client.get("/v1/model-routes").json())

    def test_task_scope_audit_never_changes_department_task_or_approval(self) -> None:
        route = self.client.get("/v1/model-routes").json()["items"][0]
        approval = self.client.post(
            "/v1/approval-decisions",
            headers=ORIGIN_HEADERS,
            json={
                "decision_scope": "model_route_approval",
                "route_id": route["route_id"],
                "expected_revision_digest": route["revision_digest"],
                "expected_snapshot_digest": route["health"]["snapshot_digest"],
                "decision": "approved",
                "reason": "先批准合成 Route 以验证 Scope 子集通过",
                "idempotency_key": "api:task:route-approval:0001",
            },
        )
        self.assertEqual(201, approval.status_code, approval.text)
        audits = self.client.get("/v1/task-scope-audits").json()["items"]
        task = next(item for item in audits if item["task_id"] == "task_technology_syn_001")
        before_state = task["authority_state"]
        response = self.client.post(
            f"/v1/task-scope-audits/{task['task_id']}/reconcile",
            headers=ORIGIN_HEADERS,
            json={
                "expected_revision": task["revision"],
                "expected_task_digest": task["task_digest"],
                "reason": "触发确定性 Scope 核对且不修改部门 Task",
                "idempotency_key": "api:task:audit:0001",
            },
        )
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual("allow", response.json()["decision"])
        self.assertFalse(response.json()["task_content_changed"])
        self.assertFalse(response.json()["department_approval_state_changed"])
        detail = self.client.get(
            f"/v1/task-scope-audits/{task['task_id']}/revisions/{task['revision']}"
        ).json()
        self.assertEqual(task["task_digest"], detail["task"]["task_digest"])
        self.assertEqual(before_state, detail["task"]["authority_state"])
        self.assertNotIn("approve", str(detail).lower())

    def test_company_catalog_starts_with_provider_and_does_not_create_route(self) -> None:
        presets = self.client.get("/v1/control/model-provider-presets")
        self.assertEqual(200, presets.status_code, presets.text)
        preset = next(
            item
            for item in presets.json()["items"]
            if item["provider_preset_id"] == "provider_preset_minimax_cn"
        )
        self.assertNotIn("https://", str(presets.json()).lower())
        discovery = self.client.post(
            "/v1/control/provider-model-discoveries",
            headers=ORIGIN_HEADERS,
            json={
                "provider_preset_id": preset["provider_preset_id"],
                "provider_preset_revision_digest": preset["revision_digest"],
                "region_id": "cn_mainland",
                "connection_alias": "MiniMax 中国连接",
                "idempotency_key": "api:catalog:discovery:0001",
            },
        )
        self.assertEqual(201, discovery.status_code, discovery.text)
        self.assertFalse(discovery.json()["automatically_published"])
        created = self.client.post(
            "/v1/control/model-catalog-entries",
            headers=ORIGIN_HEADERS,
            json={
                "discovery_digest": discovery.json()["discovery_digest"],
                "provider_model_key": "minimax_text_d0",
                "idempotency_key": "api:catalog:candidate:0001",
            },
        )
        self.assertEqual(201, created.status_code, created.text)
        self.assertEqual("candidate", created.json()["lifecycle_state"])
        self.assertFalse(created.json()["raw_endpoint_visible"])
        routes = self.client.get("/v1/model-routes").json()["items"]
        self.assertEqual(1, len(routes), "catalog candidate must not create a route")


if __name__ == "__main__":
    unittest.main()

