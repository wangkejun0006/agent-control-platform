"""Bounded semantic regressions and native approve-then-share enforcement."""

import copy
import json
import unittest
from unittest.mock import patch

from showcase.live_budget import LiveError
from showcase.workbench.live import stage_request, validate_calls
from showcase.workbench.sharing_policy import (
    POLICY_TEXT,
    enforce_sharing_prose,
    sharing_checks,
)
from tests import test_delivery_workbench as helpers


class SharingSemanticTests(unittest.TestCase):
    def test_canonical_and_qualified_rules_pass(self):
        for suffix in (
            "",
            "未经共享的跨部门资料不得访问。",
            "批准不代表可以读取全部资料。",
        ):
            with self.subTest(suffix=suffix):
                self.assertTrue(
                    all(c["passed"] for c in sharing_checks(POLICY_TEXT + suffix))
                )

    def test_append_correct_words_cannot_hide_contradictory_claim(self):
        for bad in (
            "跨部门资料不得进入结果集。",
            "不能访问任何跨部门资料。",
            "已批准并显式共享的产物不能交接使用。",
            "批准后即可读取全部资料。",
            "交接后可以访问来源部门所有资料。",
        ):
            with self.subTest(bad=bad):
                checks = sharing_checks(bad + POLICY_TEXT)
                self.assertFalse(
                    next(
                        c for c in checks if c["code"] == "no_conflicting_blanket_claim"
                    )["passed"]
                )
                with self.assertRaisesRegex(LiveError, "sharing_semantics_rejected"):
                    enforce_sharing_prose(bad + POLICY_TEXT)

    def test_missing_share_approval_or_scope_is_not_accepted(self):
        for bad in (
            "所有资料均可读取。",
            POLICY_TEXT.replace("已批准并显式共享", "已批准"),
            POLICY_TEXT.replace("绑定版本", "范围"),
            POLICY_TEXT.replace("仅批准不等于共享", "共享无需额外决定"),
            POLICY_TEXT.replace("未经共享的资料不能访问、读取或检索。", ""),
        ):
            with self.subTest(text=bad):
                self.assertFalse(all(c["passed"] for c in sharing_checks(bad)))

    def test_live_tool_gate_rejects_bad_prose_without_provider_request(self):
        arguments = {
            "body": "跨部门资料不得进入结果集。"
            + POLICY_TEXT
            + "候选需人工复核。" * 15,
            "citation_indices": [0],
        }
        response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "type": "function",
                                "id": "offline",
                                "function": {
                                    "name": "propose_delivery_candidate",
                                    "arguments": json.dumps(arguments),
                                },
                            }
                        ]
                    }
                }
            ]
        }
        with patch(
            "showcase.live_budget.load_secret",
            side_effect=AssertionError("offline_only"),
        ):
            with self.assertRaisesRegex(LiveError, "sharing_semantics_rejected"):
                validate_calls(response, 2, {"retrieve_evidence": {"citations": [{}]}})
            corrected = copy.deepcopy(response)
            arguments["body"] = (
                POLICY_TEXT + "[0]"
                + "该产物仅为本地候选，须负责人核查来源版本和交接记录，不是生产批准。"
                * 4
            )
            corrected["choices"][0]["message"]["tool_calls"][0]["function"][
                "arguments"
            ] = json.dumps(arguments)
            self.assertEqual(
                validate_calls(
                    corrected, 2, {"retrieve_evidence": {"citations": [{}]}}
                )[0]["name"],
                "propose_delivery_candidate",
            )

    def test_professional_prompts_include_shared_exception_at_every_stage(self):
        snapshot = {
            "goal": "虚构需求",
            "department_id": "market_center",
            "review_feedback": "",
        }
        results = {}
        for stage in range(3):
            if stage == 1:
                results = {
                    "query_documents": {"documents": []},
                    "retrieve_evidence": {"citations": []},
                }
            if stage == 2:
                results |= {
                    "validate_requirements": {"checks": []},
                    "run_acceptance": {"checks": []},
                }
            prompt = stage_request(snapshot, stage, results)["messages"][0]["content"]
            self.assertIn(POLICY_TEXT, prompt)

    def test_planning_output_with_contradiction_fails_closed_offline(self):
        import tempfile
        from pathlib import Path

        from orbit_agent_control_plane.service_runtime.department_cockpit import (
            PlanningModelTransportError,
        )
        from showcase.live_budget import Campaign, encoded
        from showcase.workbench.live import LiveDeliveryPlanningPort, LiveDeliveryRoutes
        from tests.test_workbench_live import fake_provider

        def bad_fixture(raw):
            self.assertIn(POLICY_TEXT, json.loads(raw)["messages"][0]["content"])
            status, body = fake_provider(raw)
            value = json.loads(body)
            output = json.loads(value["choices"][0]["message"]["content"])
            output["risk_summary"] = (
                "跨部门资料不得进入结果集。" + POLICY_TEXT
            )
            value["choices"][0]["message"]["content"] = json.dumps(output)
            return status, encoded(value)

        with (
            tempfile.TemporaryDirectory() as folder,
            patch(
                "showcase.live_budget.load_secret",
                side_effect=AssertionError("offline_only"),
            ),
        ):
            campaign = Campaign.authorize(
                Path(folder) / "fixture",
                authorization_ref="offline-only",
                input_price=3,
                output_price=12,
                transport=bad_fixture,
            )
            route = LiveDeliveryRoutes().routes(department_id="market_center")[0]
            with self.assertRaises(PlanningModelTransportError):
                LiveDeliveryPlanningPort(campaign).invoke(
                    stage="generate_task_package",
                    route_id=route["route_id"],
                    route_revision_digest=route["route_revision_digest"],
                    grant_id="grant_offline_semantics",
                    payload={
                        "department_id": "market_center",
                        "goal": "虚构资料的知识助手权限与交接评审",
                        "strict_workflow": True,
                    },
                )
            self.assertEqual(
                len(campaign.state()["attempts"]), 1
            )  # fixture transport only


class SharingNativeBoundaryTests(unittest.TestCase):
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

    def test_legacy_pass_cannot_bypass_new_approval_and_handoff_gates(self):
        workflow = self.prepare()
        node = self.execute(workflow, "product_center")
        identity = "candidate:" + node["attempt_id"]
        original_get = self.service.store.get
        original = copy.deepcopy(original_get(identity))
        legacy = copy.deepcopy(original)
        legacy["payload"].pop("authored_prose")
        legacy["payload"].pop("sharing_policy_version")

        def get_legacy(key):
            return copy.deepcopy(legacy) if key == identity else original_get(key)

        prefix = f"/v1/workflows/{workflow}/departments/product_center"
        with patch.object(self.service.store, "get", side_effect=get_legacy):
            self.assertFalse(
                self.node(workflow, "product_center")["current_sharing_passed"]
            )
            self.post(
                prefix + "/review",
                {
                    "revision": node["revision"],
                    "candidate_digest": node["candidate"]["candidate_digest"],
                    "decision": "approve",
                    "reason": "旧的通过标记不能代替当前共享语义检查",
                },
                expected=409,
            )
        self.approve(workflow, "product_center", node)
        with patch.object(self.service.store, "get", side_effect=get_legacy):
            self.post(
                prefix + "/handoff",
                {"target_department": "technology_center"},
                expected=409,
            )
            self.post(
                f"/v1/workflows/{workflow}/departments/technology_center/plan",
                expected=409,
            )
        self.assertEqual(original_get(identity), original)

    def test_forged_worker_pass_cannot_approve_contradictory_prose(self):
        import os

        from showcase.workbench.tools import run_professional
        from showcase.workbench.worker import run_once

        workflow = self.prepare()
        prefix = self.plan(workflow, "product_center")
        self.post(prefix + "/execute")
        attempt = self.node(workflow, "product_center")["attempt"]
        snapshot = json.loads((self.root / (attempt["grant_id"] + ".json")).read_text())
        forged = run_professional(snapshot)
        bad = "跨部门资料不得进入结果集。" + POLICY_TEXT
        forged["body"] = bad
        forged["authored_prose"] = bad
        for check in forged["checks"]:
            check["passed"] = True
        with (
            patch("showcase.workbench.worker.run_professional", return_value=forged),
            patch.dict(
                os.environ, {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, clear=True
            ),
        ):
            run_once(self.root)
        self.service.reconcile()
        node = self.node(workflow, "product_center")
        self.assertFalse(node["candidate"]["checks_passed"])
        self.assertFalse(
            next(
                c
                for c in node["candidate"]["payload"]["checks"]
                if c.get("code") == "no_conflicting_blanket_claim"
            )["passed"]
        )
        self.post(
            prefix + "/review",
            {
                "revision": node["revision"],
                "candidate_digest": node["candidate"]["candidate_digest"],
                "decision": "approve",
                "reason": "错误正文即使回传PASS也必须禁止批准",
            },
            expected=409,
        )

    def test_approval_alone_does_not_share_then_explicit_handoff_allows_plan(self):
        workflow = self.prepare()
        product = self.execute(workflow, "product_center")
        for department in ("product_center",):
            checks = self.node(workflow, department)["candidate"]["payload"]["checks"]
            self.assertTrue(all(c["passed"] for c in checks if c.get("code")))
        self.approve(workflow, "product_center", product)
        target = f"/v1/workflows/{workflow}/departments/technology_center"
        self.post(target + "/plan", expected=409)
        self.post(
            f"/v1/workflows/{workflow}/departments/product_center/handoff",
            {"target_department": "technology_center"},
        )
        self.post(target + "/plan")
        detail = self.detail(workflow)
        self.assertEqual(len(detail["handoffs"]), 1)
        self.assertEqual(
            detail["handoffs"][0]["candidate_digest"],
            product["candidate"]["candidate_digest"],
        )
