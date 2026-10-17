"""Offline adversarial cases for the observed package and prose failures."""

import copy
import json
import unittest
from unittest.mock import patch

from showcase.live_budget import LiveError
from showcase.workbench.content_contract import (
    content_checks,
    enforce_content,
    source_manifest,
)
from showcase.workbench.live import stage_request, validate_calls
from showcase.workbench.planning_contract import assemble_package, prose_slots
from showcase.workbench.sharing_policy import POLICY_TEXT

LOCAL = {
    "artifact_ref": "local",
    "filename": "approved-looking.md",
    "version": 1,
    "content_digest": "sha256:local",
    "department_id": "market_center",
    "shared_with": ["market_center"],
}
SHARED = {
    "artifact_ref": "shared",
    "filename": "upstream.md",
    "version": 2,
    "content_digest": "sha256:shared",
    "department_id": "market_center",
    "shared_with": ["technology_center", "market_center"],
    "source_department": "technology_center",
    "source_candidate_digest": "sha256:approved",
}
DOCS = [LOCAL, SHARED]
RECEIPTS = [
    {"operation": k, "actual_execution": True}
    for k in ("validate_requirements", "run_acceptance")
]
SAFE = (
    POLICY_TEXT
    + "本部门资料[0]按部门授权使用，交接产物[1]只在批准范围内引用。撤权后停止后续使用，历史审计证据保留。不承诺生产可用或零幻觉。"
)


class ReworkContractTests(unittest.TestCase):
    def setUp(self):
        self.guard = patch(
            "showcase.live_budget.load_secret",
            side_effect=AssertionError("offline_only"),
        )
        self.guard.start()
        self.addCleanup(self.guard.stop)
        self.example = {
            "result_kind": "task_package_candidate",
            "candidate": {
                "sections": [
                    {
                        "name": "受众与目标",
                        "summary": "仅作示例的原生章节，模型不得更改名称、次序或数量。",
                    },
                    {
                        "name": "衡量方式",
                        "summary": "仅作示例的原生章节，模型可以为它规划正文中的表格与验收清单。",
                    },
                ],
                "risk_summary": POLICY_TEXT,
            },
        }

    def test_package_fixed_identity_and_structure_are_host_owned(self):
        before = copy.deepcopy(self.example)
        wire = prose_slots(self.example)
        wire["section_updates"][1]["summary"] = (
            "在本章节内规划三态决策表与交接验收清单，具体内容待工具执行后形成正文供负责人审核。"
        )
        package = assemble_package(self.example, wire)
        self.assertEqual(package["result_kind"], "task_package_candidate")
        self.assertEqual(
            [x["name"] for x in package["candidate"]["sections"]],
            ["受众与目标", "衡量方式"],
        )
        self.assertIn("三态决策表", package["candidate"]["sections"][1]["summary"])
        self.assertEqual(self.example, before)

    def test_old_malformed_response_and_slot_attacks_fail_closed(self):
        good = prose_slots(self.example)
        attacks = [
            {
                "type": "json_object",
                "candidate": {"sections": [{"name": "三态决策表"}]},
            },
            {**good, "result_kind": "task_package_candidate"},
            {**good, "risk_summary": True},
            {**good, "section_updates": good["section_updates"] * 2},
            {**good, "section_updates": list(reversed(good["section_updates"]))},
            {
                **good,
                "section_updates": [
                    {**s, "name": "替换审批结构"} for s in good["section_updates"]
                ],
            },
            {**good, "section_updates": [good["section_updates"][0]] * 2},
        ]
        for value in attacks:
            with self.subTest(value=value), self.assertRaises(LiveError):
                assemble_package(self.example, value)

    def context(self):
        return {
            "documents": DOCS,
            "department": "market_center",
            "citations": [{"artifact_ref": "local"}, {"artifact_ref": "shared"}],
            "receipts": RECEIPTS,
        }

    def test_source_roles_come_from_records_not_filename(self):
        manifest = source_manifest(DOCS, "market_center")
        self.assertEqual(manifest[0]["source_kind"], "local_department_source")
        self.assertEqual(manifest[0]["access_basis"], "department_authorization")
        self.assertEqual(manifest[1]["source_department"], "technology_center")
        self.assertTrue(
            all(c["passed"] for c in content_checks(SAFE, **self.context()))
        )
        for bad in (
            "本提案仅使用本部门已批准并显式共享的产物版本。",
            "本部门资料[1]",
            "交接产物[0]",
            "本次直接读取upstream.md。",
        ):
            with self.subTest(bad=bad), self.assertRaises(LiveError):
                enforce_content(SAFE + bad, **self.context())

    def test_recovery_leak_and_receipt_contradiction_cannot_be_hidden_by_policy(self):
        for bad in (
            "已修复澄清结构契约。",
            "旧失败尝试无需处理。",
            "供应商重试是本业务的目标。",
            "校验与验收不重复执行。",
        ):
            with self.subTest(bad=bad), self.assertRaises(LiveError):
                enforce_content(SAFE + bad, **self.context())
        with self.assertRaises(LiveError):
            enforce_content("验收已通过。", planning=True)
        self.assertTrue(
            all(
                c["passed"]
                for c in content_checks(SAFE + "验收已通过。", **self.context())
            )
        )

    def test_unsupported_promises_and_safe_negative_statements(self):
        for bad in (
            "不保留派生副本。",
            "撤权后立即清除全部历史证据。",
            "保证零幻觉。",
            "已经生产可用。",
            "不承诺生产可用。但我们保证零幻觉。",
        ):
            with self.subTest(bad=bad), self.assertRaises(LiveError):
                enforce_content(SAFE + bad, **self.context())
        enforce_content(
            SAFE + "不得承诺自动删除副本；不保证零幻觉，历史记录保留。",
            **self.context(),
        )

    def test_prompt_exposes_host_provenance_without_recovery_notes(self):
        hit = {
            "artifact_ref": "shared",
            "filename": "upstream.md",
            "version": 2,
            "line": 1,
            "text": "权限与验收",
        }
        snapshot = {
            "goal": "虚构任务",
            "department_id": "market_center",
            "documents": DOCS,
            "review_feedback": "新增三态决策表",
            "recovery_notes": "JSON协议修复SECRET_SENTINEL",
        }
        results = {
            "query_documents": {"documents": []},
            "retrieve_evidence": {"citations": [hit]},
            "validate_requirements": {},
            "run_acceptance": {},
        }
        request = stage_request(snapshot, 2, results)
        context = json.loads(request["messages"][1]["content"])
        self.assertEqual(
            context["evidence"][0]["source_kind"], "approved_shared_artifact"
        )
        self.assertEqual(context["handoff_evidence_indices"], [0])
        self.assertNotIn("SECRET_SENTINEL", json.dumps(request))
        self.assertIn("新增三态决策表", context["revision_feedback"])

    def test_candidate_calls_must_use_selected_actual_shared_evidence(self):
        citations = [{"artifact_ref": "local"}, {"artifact_ref": "shared"}]
        body = SAFE + "按固定工具结果形成待审候选，尚需负责人核查。" * 8

        def response(text, indices):
            return {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "draft",
                                    "type": "function",
                                    "function": {
                                        "name": "propose_delivery_candidate",
                                        "arguments": json.dumps(
                                            {"body": text, "citation_indices": indices}
                                        ),
                                    },
                                }
                            ]
                        }
                    }
                ]
            }

        results = {
            "retrieve_evidence": {"citations": citations},
            "validate_requirements": {},
            "run_acceptance": {},
        }
        snapshot = {"department_id": "market_center", "documents": DOCS}
        validate_calls(response(body, [0, 1]), 2, results, snapshot=snapshot)
        for text, indices in (
            (body, [0]),
            (body.replace("[1]", "[0]"), [0]),
            (body + "[7]", [0, 1]),
            (body + "不保留派生副本。", [0, 1]),
        ):
            with self.subTest(text=text), self.assertRaises(LiveError):
                validate_calls(response(text, indices), 2, results, snapshot=snapshot)
