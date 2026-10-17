"""Native approval, recovery and a five-call fake-wire rework closure."""

import copy
import json
import unittest
from unittest.mock import patch

from orbit_agent_control_plane.service_runtime.department_cockpit import (
    PlanningModelTransportError,
)
from showcase.live_budget import Campaign, LiveError, encoded
from showcase.workbench.live_validation import WorkbenchValidation
from showcase.workbench.sharing_policy import POLICY_TEXT
from showcase.workbench.sharing_validation import REWORK
from tests import test_delivery_workbench as helpers
from tests.test_workbench_live import fake_provider


class ReworkNativeTests(unittest.TestCase):
    setUp = helpers.DeliveryWorkbenchTests.setUp
    tearDown = helpers.DeliveryWorkbenchTests.tearDown
    auth = helpers.DeliveryWorkbenchTests.auth
    post = helpers.DeliveryWorkbenchTests.post
    create = helpers.DeliveryWorkbenchTests.create
    activate_assets = helpers.DeliveryWorkbenchTests.activate_assets
    prepare = helpers.DeliveryWorkbenchTests.prepare
    detail = helpers.DeliveryWorkbenchTests.detail
    node = helpers.DeliveryWorkbenchTests.node
    plan = helpers.DeliveryWorkbenchTests.plan
    execute = helpers.DeliveryWorkbenchTests.execute
    approve = helpers.DeliveryWorkbenchTests.approve

    def test_host_rechecks_prose_and_source_facts_before_approval(self):
        workflow = self.prepare()
        node = self.execute(workflow, "product_center")
        original_get = self.service.store.get
        key = "candidate:" + node["attempt_id"]
        original = original_get(key)
        for bad in (
            "不保留派生副本。",
            "本提案仅使用本部门已批准并显式共享的产物版本。",
            "修复澄清结构契约后提供本业务方案。",
            None,
        ):
            changed = copy.deepcopy(original)
            payload = changed["payload"]
            if bad:
                old = payload["authored_prose"]
                payload["authored_prose"] += bad
                payload["body"] = payload["body"].replace(
                    old, payload["authored_prose"]
                )
            else:
                payload["source_manifest"][0]["source_kind"] = (
                    "approved_shared_artifact"
                )
            changed["checks_passed"] = True
            with (
                self.subTest(bad=bad),
                patch.object(
                    self.service.store,
                    "get",
                    side_effect=lambda k, changed=changed: (
                        changed if k == key else original_get(k)
                    ),
                ),
            ):
                self.post(
                    f"/v1/workflows/{workflow}/departments/product_center/review",
                    {
                        "candidate_digest": original["candidate_digest"],
                        "revision": node["revision"],
                        "decision": "approve",
                        "reason": "不能相信预先保存的PASS，需要独立复核。",
                    },
                    expected=409,
                )
        self.assertEqual(original_get(key), original)
        self.assertEqual(self.service.store.list("review", workflow), [])

    def test_recovery_notes_are_preserved_but_never_become_business_feedback(self):
        workflow = self.prepare()
        prefix = f"/v1/workflows/{workflow}/departments/product_center"
        with patch.object(
            self.service.cockpit.model_port,
            "invoke",
            side_effect=PlanningModelTransportError("offline_injected_failure"),
        ):
            self.post(prefix + "/plan")
        old = self.node(workflow, "product_center")
        self.assertEqual(old["status"], "failed_recoverable")
        reason = "修复澄清结构契约，保留旧失败尝试；JSON协议修复仅供运维审计。"
        self.post(
            prefix + "/revise",
            {
                "reason": reason,
                "acknowledge_uncertain": True,
                "revision_kind": "execution_recovery",
            },
        )
        new = self.node(workflow, "product_center")
        self.assertNotEqual(new["attempt_id"], old["attempt_id"])
        self.assertEqual(new["attempt"]["review_feedback"], "")
        self.assertEqual(new["attempt"]["business_feedback"], "")
        self.assertEqual(new["attempt"]["recovery_notes"], reason)
        self.assertNotIn(
            reason,
            self.service.cockpit.sessions[new["attempt"]["session_id"]]["message"],
        )
        result = self.execute(workflow, "product_center", start=False)
        self.assertNotIn("旧失败尝试", result["candidate"]["payload"]["body"])
        self.assertTrue(result["candidate"]["checks_passed"])
        self.assertTrue(self.service.store.get(old["attempt_id"])["invalidated"])

    def test_five_fake_calls_finish_rework_review_without_rewriting_old_candidate(self):
        workflow = self.prepare()
        for department, target in (
            ("product_center", "technology_center"),
            ("technology_center", "market_center"),
        ):
            node = self.execute(workflow, department)
            self.approve(workflow, department, node, target)
        old = self.execute(workflow, "market_center")
        self.post(
            f"/v1/workflows/{workflow}/departments/market_center/review",
            {
                "candidate_digest": old["candidate"]["candidate_digest"],
                "revision": old["revision"],
                "decision": "request_changes",
                "reason": REWORK,
            },
        )
        old_bytes = json.dumps(
            self.service.store.get("candidate:" + old["attempt_id"]), sort_keys=True
        )
        # Close the offline service first: no competing reconciler may consume
        # explicitly live-tagged fixture runs with the wrong mode.
        self.client.__exit__(None, None, None)

        def transport(raw):
            status, raw_response = fake_provider(raw)
            response = json.loads(raw_response)
            for call in response["choices"][0]["message"].get("tool_calls", []):
                if call["function"]["name"] == "propose_delivery_candidate":
                    call["function"]["arguments"] = json.dumps(
                        {
                            "body": POLICY_TEXT
                            + "交接产物[0]只供本部门在批准范围内使用，不能读取来源部门其他资料。"
                            "\n## 三态决策表\n|状态|读取决定|原因|\n|未共享资料|拒绝|无共享授权|\n|仅批准未共享产物|拒绝|批准不等于共享|\n|已批准且显式共享产物|在授权范围内允许|接收部门与绑定版本相符|"
                            "\n## 交接验收清单\n- 核对接收部门。\n- 核对绑定版本及授权范围。\n- 撤权或失效后停止后续使用，历史审核证据保留。\n"
                            "本候选只按实际检查结果陈述，须负责人审核，不承诺生产可用或零幻觉。",
                            "citation_indices": [0],
                        },
                        ensure_ascii=False,
                    )
            return status, encoded(response)

        campaign = Campaign.authorize(
            self.root / "new-offline-campaign",
            authorization_ref="offline-proposed-five-call-plan",
            max_requests=5,
            max_cost_micros=300_000,
            input_price=3,
            output_price=12,
            transport=transport,
        )
        runner = WorkbenchValidation(campaign, self.root)
        self.app, self.client, self.service = (
            runner.app,
            runner.client,
            runner.app.state.delivery,
        )
        self.client.__enter__()
        with patch(
            "showcase.live_budget.load_secret",
            side_effect=AssertionError("no_keys_offline"),
        ):
            self.auth(
                "login", {"username": "administrator", "password": helpers.PASSWORD}
            )
            runner.workflow = workflow
            runner.post(
                f"/v1/workflows/{workflow}/departments/market_center/revise",
                {"reason": REWORK, "acknowledge_uncertain": True},
            )
            revised = runner.execute("market_center", start=False)
            runner.post(
                f"/v1/workflows/{workflow}/departments/market_center/review",
                {
                    "candidate_digest": old["candidate"]["candidate_digest"],
                    "revision": old["revision"],
                    "decision": "approve",
                    "reason": "旧候选版本必须拒绝批准。",
                },
                expected=409,
            )
            runner.review("market_center", revised)
            delivered = runner.post(
                f"/v1/workflows/{workflow}/deliver",
                {"reason": "自动化离线测试验证交付，不是用户真人或生产批准。"},
            )
            self.assertEqual(delivered["status"], "delivered")
            self.assertEqual(
                self.client.get(f"/v1/workflows/{workflow}/download").content[:2], b"PK"
            )
            self.assertEqual(len(campaign.state()["attempts"]), 5)
            with self.assertRaisesRegex(LiveError, "request_budget_exhausted"):
                campaign.chat(
                    key="forbidden-sixth",
                    phase="negative_budget_check",
                    messages=[{"role": "user", "content": "离线测试不得发第六次请求"}],
                )
            self.assertEqual(len(campaign.state()["attempts"]), 5)
            self.assertEqual(
                json.dumps(
                    self.service.store.get("candidate:" + old["attempt_id"]),
                    sort_keys=True,
                ),
                old_bytes,
            )
            self.assertEqual(revised["attempt"]["business_feedback"], REWORK)
            self.assertIn(
                "|仅批准未共享产物|拒绝|",
                revised["candidate"]["payload"]["authored_prose"],
            )
            # Changing an upstream dependency must not replace this department's
            # own review with another department's wording.
            actor = self.client.get("/v1/control-console/bootstrap").json()["principal"]
            self.service.invalidate(
                workflow,
                "product_center",
                "上游来源版本改变，仅作为依赖变更事件保留。",
                actor,
            )
            market = self.service.attempt(workflow, "market_center")
            self.assertEqual(market["business_feedback"], REWORK)
            self.assertEqual(
                market["dependency_notes"]["source_department"], "product_center"
            )
        campaign.close("offline_fixture_completed")
