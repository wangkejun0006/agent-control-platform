"""Offline exact-driver tests; old budgets and provider secrets are forbidden."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from showcase.live_budget import Campaign, LiveError, encoded
from showcase.workbench.content_contract import enforce_content
from showcase.workbench.minimal_validation import rework_body_checks, run_campaign
from showcase.workbench.planning_contract import assemble_package, prose_slots
from showcase.workbench.sharing_policy import POLICY_TEXT
from tests.test_workbench_live import fake_provider


def minimal_fixture(raw):
    status, body = fake_provider(raw)
    value = json.loads(body)
    for call in value["choices"][0]["message"].get("tool_calls", []):
        if call["function"]["name"] == "propose_delivery_candidate":
            call["function"]["arguments"] = json.dumps(
                {
                    "body": POLICY_TEXT
                    + "交接产物[0]仅供本部门在指定版本和授权范围内使用。"
                    "\n## 三态决策表\n|状态|读取决定|原因|\n|未共享资料|不读取、不检索、不进入执行快照|没有共享授权|"
                    "\n|仅批准未共享产物|不读取|批准不等于共享|\n|已批准并显式共享产物|在接收部门、绑定版本、授权范围内读取使用|接收部门与版本符合|"
                    "\n## 交接验收清单\n- 接收部门必须匹配。\n- 核对绑定版本与授权范围。\n- 撤权或失效后停止后续使用，历史审计证据保留。"
                    "本候选须负责人核对引用和实际工具回执，不承诺生产可用或零幻觉。",
                    "citation_indices": [0],
                },
                ensure_ascii=False,
            )
    return status, encoded(value)


class MinimalValidationTests(unittest.TestCase):
    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.secret_guard = patch(
            "showcase.live_budget.load_secret",
            side_effect=AssertionError("offline_no_key"),
        )
        self.network_guard = patch(
            "showcase.live_budget.live_post",
            side_effect=AssertionError("offline_no_provider"),
        )
        self.secret_guard.start()
        self.network_guard.start()
        original_open = os.open

        def budget_guard(path, *args, **kwargs):
            if (
                isinstance(path, (str, os.PathLike))
                and Path(path).name == "budget.json"
                and Path(path).parent != self.root / "campaign"
            ):
                raise AssertionError("historical_budget_access_forbidden")
            return original_open(path, *args, **kwargs)

        self.old_guard = patch("os.open", side_effect=budget_guard)
        self.old_guard.start()

    def tearDown(self):
        self.old_guard.stop()
        self.network_guard.stop()
        self.secret_guard.stop()
        self.temporary.cleanup()
        os.umask(self.previous_umask)

    def campaign(self, transport):
        return Campaign.authorize(
            self.root / "campaign",
            authorization_ref="offline-only-minimal-five",
            max_requests=5,
            max_cost_micros=300_000,
            input_price=3,
            output_price=12,
            transport=transport,
        )

    def test_exact_driver_five_calls_and_closed_local_delivery_without_old_budget_access(
        self,
    ):
        campaign = self.campaign(minimal_fixture)
        report = run_campaign(
            campaign, self.root / "state", self.root / "report.json", offline=True
        )
        self.assertEqual(report["status"], "passed", report["events"][-2:])
        self.assertEqual(report["requests"], 5)
        self.assertTrue(report["closed"])
        self.assertTrue(all(c["passed"] for c in report["checks"]))
        self.assertEqual((campaign.root / "delivery.zip").read_bytes()[:2], b"PK")
        with self.assertRaises(LiveError):
            campaign.chat(
                key="no_sixth",
                phase="budget_test",
                messages=[{"role": "user", "content": "test"}],
            )
        self.assertEqual(len(campaign.state()["attempts"]), 5)

    def test_first_bad_response_stops_and_retains_without_retry(self):
        calls = []

        def bad(raw):
            calls.append(True)
            status, body = minimal_fixture(raw)
            value = json.loads(body)
            value["choices"][0]["message"]["content"] = "{}"
            return status, encoded(value)

        campaign = self.campaign(bad)
        report = run_campaign(
            campaign, self.root / "state", self.root / "report.json", offline=True
        )
        self.assertEqual(report["status"], "stopped")
        self.assertEqual(report["requests"], 1)
        self.assertTrue(report["closed"])
        self.assertEqual(len(calls), 1)
        self.assertTrue((campaign.root / "response-01.json").is_file())
        self.assertFalse((campaign.root / "delivery.zip").exists())

    def test_negation_reversal_stops_before_new_review_and_delivery(self):
        def reversed_decision(raw):
            status, body = minimal_fixture(raw)
            value = json.loads(body)
            for call in value["choices"][0]["message"].get("tool_calls", []):
                if call["function"]["name"] == "propose_delivery_candidate":
                    args = json.loads(call["function"]["arguments"])
                    args["body"] = args["body"].replace(
                        "|未共享资料|不读取、不检索、不进入执行快照|",
                        "|未共享资料|不能拒绝读取|",
                    )
                    call["function"]["arguments"] = json.dumps(args, ensure_ascii=False)
            return status, encoded(value)

        campaign = self.campaign(reversed_decision)
        report = run_campaign(
            campaign, self.root / "state", self.root / "report.json", offline=True
        )
        self.assertEqual(report["status"], "stopped")
        self.assertEqual(report["requests"], 5)
        self.assertTrue(report["closed"])
        self.assertEqual(report["phase"], "model_free_review")
        self.assertFalse(
            next(
                c["passed"]
                for c in report["checks"]
                if c["name"] == "unshared_row_denied"
            )
        )
        self.assertFalse((campaign.root / "delivery.zip").exists())
        self.assertFalse((campaign.root / "final-workflow.json").exists())

    def test_refusing_all_rows_is_not_success(self):
        self.assertFalse(
            all(
                c["passed"]
                for c in rework_body_checks(
                    "|未共享资料|拒绝|无授权|\n|仅批准未共享产物|拒绝|无共享|\n|已批准并显式共享产物|拒绝|不能使用|"
                )
            )
        )

    def test_valid_prose_slots_cannot_invent_evidence_during_planning(self):
        example = {
            "result_kind": "task_package_candidate",
            "candidate": {
                "sections": [
                    {
                        "name": "渠道与合规",
                        "summary": "本章节描述本部门的规划范围，尚未查询实际资料或验证引用。",
                    }
                ],
                "risk_summary": POLICY_TEXT,
            },
        }
        wire = prose_slots(example)
        wire["section_updates"][0]["summary"] += (
            "本部门资料[0]属本部门授权原始资料，交接产物[1]须有显式共享。"
        )
        assembled = assemble_package(example, wire)
        self.assertEqual(assembled["result_kind"], "task_package_candidate")
        with self.assertRaisesRegex(LiveError, "source_basis_consistent"):
            enforce_content(
                assembled["candidate"]["sections"][0]["summary"], planning=True
            )
