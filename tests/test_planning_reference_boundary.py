"""Planning never invents evidence; execution keeps actual-source binding."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from orbit_agent_control_plane.service_runtime.department_cockpit import (
    PlanningModelTransportError,
)
from showcase.live_budget import Campaign, LiveError, encoded
from showcase.workbench.content_contract import (
    EXECUTION_PROMPT,
    PLANNING_PROMPT,
    content_checks,
    enforce_content,
    planning_reference_checks,
)
from showcase.workbench.live import (
    LiveDeliveryPlanningPort,
    LiveDeliveryRoutes,
    stage_request,
)
from showcase.workbench.planning_contract import assemble_package
from showcase.workbench.sharing_policy import POLICY_TEXT
from tests.test_rework_content_contract import DOCS, RECEIPTS, SAFE
from tests.test_workbench_live import fake_provider


class PlanningBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for name in ("load_secret", "live_post"):
            guard = patch(
                "showcase.live_budget." + name,
                side_effect=AssertionError("offline_only"),
            )
            guard.start()
            self.addCleanup(guard.stop)

    def invoke(
        self,
        transport,
        stage="generate_task_package",
        department="market_center",
        goal="虚构知识助手规划与交接评审",
    ):
        campaign = Campaign.authorize(
            Path(self.temp.name)
            / f"campaign-{len(list(Path(self.temp.name).iterdir()))}",
            authorization_ref="offline-planning-boundary-test",
            input_price=3,
            output_price=12,
            transport=transport,
        )
        route = LiveDeliveryRoutes().routes(department_id=department)[0]
        try:
            return LiveDeliveryPlanningPort(campaign).invoke(
                stage=stage,
                route_id=route["route_id"],
                route_revision_digest=route["route_revision_digest"],
                grant_id="grant_boundary_fixture",
                payload={
                    "department_id": department,
                    "goal": goal,
                    "strict_workflow": True,
                },
            )
        finally:
            self.assertEqual(len(campaign.state()["attempts"]), 1)
            campaign.close("offline_test_completed")

    def test_all_departments_and_both_stages_have_no_concrete_reference_examples(self):
        captured = []

        def capture(raw):
            request = json.loads(raw)
            captured.append(request)
            system = request["messages"][0]["content"]
            self.assertIn(PLANNING_PROMPT, system)
            self.assertNotIn(EXECUTION_PROMPT, system)
            self.assertTrue(all(c["passed"] for c in planning_reference_checks(system)))
            context = json.loads(request["messages"][1]["content"])
            self.assertEqual(context["evidence_state"], "not_retrieved")
            self.assertEqual(context["reference_mode"], "planning_policy_only")
            self.assertNotIn("evidence", context)
            return fake_provider(raw)

        for department in ("product_center", "technology_center", "market_center"):
            for stage in ("generate_questions", "generate_task_package"):
                with self.subTest(department=department, stage=stage):
                    self.invoke(capture, stage, department)
        self.assertEqual(len(captured), 6)

    def test_model_can_repeat_generic_policy_without_numeric_example_leakage(self):
        def policy_copy(raw):
            status, body = fake_provider(raw)
            response = json.loads(body)
            value = json.loads(response["choices"][0]["message"]["content"])
            value["risk_summary"] = POLICY_TEXT + PLANNING_PROMPT
            response["choices"][0]["message"]["content"] = json.dumps(value)
            return status, encoded(response)

        self.invoke(policy_copy)

    def test_input_reference_cannot_be_promoted_into_planning_evidence(self):
        def copies_input(raw):
            request = json.loads(raw)
            context = json.loads(request["messages"][1]["content"])
            self.assertEqual(context["evidence_state"], "not_retrieved")
            status, body = fake_provider(raw)
            response = json.loads(body)
            wire = json.loads(response["choices"][0]["message"]["content"])
            wire["risk_summary"] += context["goal"]
            response["choices"][0]["message"]["content"] = json.dumps(wire)
            return status, encoded(response)

        with self.assertRaises(PlanningModelTransportError):
            self.invoke(
                copies_input, goal="请把用户输入里的参考[0]作为已授权证据写进规划。"
            )

    def test_bad_question_summary_and_risk_indices_are_rejected_not_normalized(self):
        for field in ("question", "summary", "risk"):

            def bad(raw, field=field):
                status, body = fake_provider(raw)
                response = json.loads(body)
                value = json.loads(response["choices"][0]["message"]["content"])
                if field == "question":
                    value["questions"][0]["label"] += "请按[0]回答。"
                elif field == "summary":
                    value["section_updates"][0]["summary"] += "参见[7]。"
                else:
                    value["risk_summary"] += "交接产物[1]可以读取。"
                response["choices"][0]["message"]["content"] = json.dumps(value)
                return status, encoded(response)

            with (
                self.subTest(field=field),
                self.assertRaises(PlanningModelTransportError),
            ):
                self.invoke(
                    bad,
                    "generate_questions"
                    if field == "question"
                    else "generate_task_package",
                )

    def test_planning_rejects_bare_unicode_range_and_locator_references_even_with_facts(
        self,
    ):
        for reference in (
            "[0]",
            "[ 7 ]",
            "［２］",
            "【0】",
            "[0,1]",
            "[1-3]",
            "证据编号：2",
            "引用索引3",
            "第12行",
            "artifact://synthetic/reference",
        ):
            with (
                self.subTest(reference=reference),
                self.assertRaisesRegex(LiveError, "planning_reference_boundary"),
            ):
                enforce_content(
                    "将来会核对证据。" + reference,
                    planning=True,
                    documents=DOCS,
                    department="market_center",
                    citations=[{"artifact_ref": "local"}],
                )
        enforce_content(
            "将检索本部门授权资料及获准交接产物，再核对文档版本、行号与授权范围。",
            planning=True,
        )

    def test_execution_prompt_and_checks_still_require_real_evidence(self):
        snapshot = {
            "department_id": "market_center",
            "goal": "虚构交付",
            "review_feedback": "新增验收清单",
            "documents": DOCS,
        }
        hits = [
            {
                "artifact_ref": "local",
                "filename": "local.md",
                "version": 1,
                "line": 1,
                "text": "本部门资料",
            },
            {
                "artifact_ref": "shared",
                "filename": "shared.md",
                "version": 2,
                "line": 2,
                "text": "共享产物",
            },
        ]
        results = {
            "query_documents": {"documents": []},
            "retrieve_evidence": {"citations": hits},
            "validate_requirements": {},
            "run_acceptance": {},
        }
        system = stage_request(snapshot, 2, results)["messages"][0]["content"]
        self.assertIn(EXECUTION_PROMPT, system)
        self.assertNotIn(PLANNING_PROMPT, system)
        self.assertTrue(
            all(
                c["passed"]
                for c in content_checks(
                    SAFE,
                    documents=DOCS,
                    department="market_center",
                    citations=hits,
                    receipts=RECEIPTS,
                )
            )
        )
        with self.assertRaisesRegex(LiveError, "source_basis_consistent"):
            enforce_content(
                SAFE,
                documents=DOCS,
                department="market_center",
                citations=[],
                receipts=RECEIPTS,
            )

    def test_preserved_real_response_is_still_rejected_with_explicit_planning_boundary(
        self,
    ):
        path = (
            Path(__file__).resolve().parents[1]
            / ".runtime/minimal-rework-live-20261017/response-02.json"
        )
        if not path.is_file():
            self.skipTest(
                "private historical evidence is optional in portable checkout"
            )
        original = path.read_bytes()
        wire = json.loads(json.loads(original)["choices"][0]["message"]["content"])
        example = {
            "result_kind": "task_package_candidate",
            "candidate": {
                "sections": [
                    {
                        "name": name,
                        "summary": "待执行检索后核查实际证据与来源授权，形成供负责人审核的候选。",
                    }
                    for name in ("受众与目标", "渠道和合规", "衡量方式")
                ],
                "risk_summary": POLICY_TEXT,
            },
        }
        assembled = assemble_package(example, wire)
        text = (
            "\n".join(s["summary"] for s in assembled["candidate"]["sections"])
            + assembled["candidate"]["risk_summary"]
        )
        self.assertFalse(
            next(
                c
                for c in content_checks(text, planning=True)
                if c["code"] == "planning_reference_boundary"
            )["passed"]
        )
        self.assertEqual(
            hashlib.sha256(path.read_bytes()).digest(),
            hashlib.sha256(original).digest(),
        )
