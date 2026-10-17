"""Offline live-wire fixtures: never resolve a key or contact a provider."""

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from showcase.live_budget import Campaign, LiveError, encoded
from showcase.workbench.api import create_workbench_app
from showcase.workbench.live import stage_request, validate_calls
from showcase.workbench.sharing_policy import POLICY_TEXT
from tests import test_delivery_workbench as offline_helpers


def fake_provider(raw):
    request = json.loads(raw)
    tools = request.get("tools")
    message = {}
    if tools:
        calls = []
        for tool in tools:
            name = tool["function"]["name"]
            arguments = {}
            if name == "retrieve_evidence":
                arguments = {"query": "权限 引用 撤权 验收 用户"}
            elif name == "propose_delivery_candidate":
                context = json.loads(request["messages"][1]["content"])
                arguments = {
                    "body": "本段是离线协议测试夹具，不是真实模型输出。[0] SQLite单Worker、本机身份非企业OIDC、无OS沙箱。"
                    + context.get("revision_feedback", "")
                    + POLICY_TEXT
                    + "按部门权限检索资料并保留版本与引用，撤权后停止后续调用，证据不足时交由人工确认，禁止自动批准或发布。"
                    * 5,
                    "citation_indices": [0],
                }
            calls.append(
                {
                    "id": "call_" + name,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": json.dumps(arguments, ensure_ascii=False),
                    },
                }
            )
        message["tool_calls"] = calls
    else:
        instruction = request["messages"][0]["content"]
        value, _ = json.JSONDecoder().raw_decode(instruction[instruction.index("{") :])
        if "section_updates" in value:
            for section in value["section_updates"]:
                section["summary"] = (
                    "先核对授权与输入资料版本，再执行固定工具并形成有证据的部门产物，交由负责人审核。"
                )
        message["content"] = json.dumps(value, ensure_ascii=False)
    return 200, encoded(
        {
            "id": "offline-wire-fixture",
            "model": request["model"],
            "usage": {"prompt_tokens": 100, "completion_tokens": 100},
            "choices": [
                {"finish_reason": "tool_calls" if tools else "stop", "message": message}
            ],
        }
    )


class LiveWorkbenchTests(unittest.TestCase):
    # Reuse only API helpers, not offline-specific assertions or test methods.
    auth = offline_helpers.DeliveryWorkbenchTests.auth
    post = offline_helpers.DeliveryWorkbenchTests.post
    create = offline_helpers.DeliveryWorkbenchTests.create
    activate_assets = offline_helpers.DeliveryWorkbenchTests.activate_assets
    prepare = offline_helpers.DeliveryWorkbenchTests.prepare
    detail = offline_helpers.DeliveryWorkbenchTests.detail
    node = offline_helpers.DeliveryWorkbenchTests.node
    plan = offline_helpers.DeliveryWorkbenchTests.plan
    execute = offline_helpers.DeliveryWorkbenchTests.execute
    approve = offline_helpers.DeliveryWorkbenchTests.approve

    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "state"
        self.campaign = Campaign.authorize(
            Path(self.temporary.name) / "campaign",
            authorization_ref="offline-protocol-test",
            input_price=3,
            output_price=12,
            transport=fake_provider,
        )
        self.secret_guard = patch(
            "showcase.live_budget.load_secret",
            side_effect=AssertionError("offline_test_must_not_read_key"),
        )
        self.secret_guard.start()
        self.app = create_workbench_app(
            state_root=self.root,
            start_worker=False,
            password_scrypt_n=1024,
            live_campaign=self.campaign,
        )
        self.service = self.app.state.delivery
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.headers = {
            "Origin": "http://testserver",
            "X-Orbit-Request": "department-cockpit",
        }
        data = {
            "username": "live_wire_admin",
            "password": "offline-fixture-password",
            "display_name": "协议测试账号",
        }
        self.auth("register", data)
        self.auth("login", {k: data[k] for k in ("username", "password")})

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.secret_guard.stop()
        self.temporary.cleanup()
        os.umask(self.previous_umask)

    def test_full_native_handoff_and_rework_with_shared_live_budget(self):
        workflow = self.prepare()
        for department, target in (
            ("product_center", "technology_center"),
            ("technology_center", "market_center"),
        ):
            node = self.execute(workflow, department)
            self.assertTrue(
                node["candidate"]["checks_passed"],
                node["candidate"]["payload"]["checks"],
            )
            self.assertEqual(node["candidate"]["payload"]["model_requests"], 3)
            self.assertEqual(len(node["candidate"]["payload"]["tool_receipts"]), 5)
            self.approve(workflow, department, node, target)
        node = self.execute(workflow, "market_center")
        self.approve(workflow, "market_center", node, decision="request_changes")
        self.post(
            f"/v1/workflows/{workflow}/departments/market_center/revise",
            {
                "reason": "补充本地单Worker限制及上线前验证清单，逐项回应意见。",
                "acknowledge_uncertain": True,
            },
        )
        revised = self.execute(workflow, "market_center", start=False)
        self.assertEqual(revised["revision"], 2)
        self.assertNotEqual(
            revised["candidate"]["candidate_digest"],
            node["candidate"]["candidate_digest"],
        )
        self.post(
            f"/v1/workflows/{workflow}/departments/market_center/review",
            {
                "revision": 1,
                "candidate_digest": node["candidate"]["candidate_digest"],
                "decision": "approve",
                "reason": "尝试旧版本审批必须失败",
            },
            expected=409,
        )
        self.approve(workflow, "market_center", revised)
        self.post(
            f"/v1/workflows/{workflow}/deliver",
            {"reason": "离线协议测试确认三个部门回执及审核完整，仅本地交付。"},
        )
        state = self.campaign.state()
        self.assertEqual(len(state["attempts"]), 20)
        self.assertTrue(all(a["status"] == "succeeded" for a in state["attempts"]))
        self.assertEqual(state["attempts"][0]["reserved_micros"], 48576)
        self.assertEqual(state["attempts"][0]["actual_cost_micros"], 1500)

    def test_broker_rejects_unbound_request_without_spending(self):
        self.app.state.delivery_broker.close()
        broker_root = self.root / "model-ipc"
        from showcase.live_budget import (
            atomic_private,
            digest,
            private_read,
            strict_json,
        )

        request = {
            "grant_id": "grant_delivery_unknown",
            "snapshot_digest": "sha256:wrong",
            "stage": 0,
            "results": {},
        }
        path = broker_root / "bad.request.json"
        atomic_private(path, request)
        # Missing snapshot is rejected before any network, even at this boundary.
        self.app.state.delivery_broker.process(path)
        answer = strict_json(private_read(broker_root / "bad.response.json"))
        self.assertFalse(answer["ok"])
        self.assertEqual(len(self.campaign.state()["attempts"]), 0)
        self.assertTrue(digest(request))
        self.assertTrue(callable(private_read) and callable(strict_json))

    def test_historical_evidence_is_authenticated_read_only_and_cannot_spend(self):
        from fastapi.testclient import TestClient

        evidence = self.root / "readonly-evidence"
        reports = evidence / "reports"
        reports.mkdir(parents=True)
        (reports / "workbench-live-validation.json").write_text(
            '{"requests":22,"closed":true}'
        )
        private = evidence / "examples/historical-workbench"
        private.mkdir(parents=True)
        (private / "rework-comparison.json").write_text(
            '{"fixture":"not real responses"}'
        )
        (private / "delivery.zip").write_bytes(b"PK-offline-fixture")
        (private / "artifact-sha256.json").write_text(
            json.dumps(
                {
                    name: hashlib.sha256((private / name).read_bytes()).hexdigest()
                    for name in ("rework-comparison.json", "delivery.zip")
                }
            )
        )
        for name in ("rework-comparison.json", "delivery.zip"):
            (private / name).chmod(0o644)
        with patch("showcase.workbench.api.ROOT", evidence):
            for suffix in ("report", "comparison", "delivery"):
                path = "/v1/showcase/workbench-live-" + suffix
                self.assertEqual(TestClient(self.app).get(path).status_code, 401)
                self.assertEqual(self.client.get(path).status_code, 200)
                self.assertEqual(self.client.post(path, json={}).status_code, 405)
            (private / "delivery.zip").write_bytes(b"PK-tampered")
            self.assertEqual(
                self.client.get("/v1/showcase/workbench-live-delivery").status_code, 409
            )
        self.assertEqual(len(self.campaign.state()["attempts"]), 0)


class LiveWireContracts(unittest.TestCase):
    def test_exact_validation_driver_offline_before_real_run(self):
        from showcase.workbench.live_validation import WorkbenchValidation

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "showcase.live_budget.load_secret",
                side_effect=AssertionError("no_keys_in_offline_validation"),
            ),
        ):
            campaign = Campaign.authorize(
                Path(temporary) / "campaign",
                authorization_ref="fixture-only",
                input_price=3,
                output_price=12,
                transport=fake_provider,
            )
            runner = WorkbenchValidation(campaign, Path(temporary) / "state")
            runner.run()
            self.assertEqual(len(campaign.state()["attempts"]), 22)
            self.assertTrue((campaign.root / "delivery.zip").is_file())
            self.assertTrue(all(c["passed"] for c in runner.checks))

    def test_twenty_four_and_cost_caps_stop_before_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            campaign = Campaign.authorize(
                Path(temporary) / "budget",
                authorization_ref="fixture-only",
                input_price=3,
                output_price=12,
                transport=fake_provider,
            )
            for n in range(24):
                campaign.chat(
                    key=str(n),
                    phase="fixture",
                    messages=[{"role": "system", "content": '{"decision":"reject"}'}],
                )
            with self.assertRaisesRegex(LiveError, "request_budget_exhausted"):
                campaign.chat(key="25", phase="fixture", messages=[])
            self.assertEqual(len(campaign.state()["attempts"]), 24)
            capped = Campaign.authorize(
                Path(temporary) / "cost",
                authorization_ref="fixture-only",
                max_cost_micros=48000,
                input_price=3,
                output_price=12,
                transport=fake_provider,
            )
            with self.assertRaisesRegex(LiveError, "cost_budget_exhausted"):
                capped.chat(key="1", phase="fixture", messages=[])
            self.assertEqual(len(capped.state()["attempts"]), 0)

    def test_arbitrary_tool_and_bad_citation_rejected(self):
        response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "type": "function",
                                "id": "x",
                                "function": {"name": "shell", "arguments": "{}"},
                            }
                        ]
                    }
                }
            ]
        }
        with self.assertRaises(LiveError):
            validate_calls(response, 2, {})
        with self.assertRaises(LiveError):
            stage_request({}, 1, {})

    def test_failed_request_keeps_new_price_reservation_and_closed_stays_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "campaign"

            def fail(_raw):
                raise LiveError("transport_failed_or_unknown")

            campaign = Campaign.authorize(
                root,
                authorization_ref="fixture-only",
                input_price=3,
                output_price=12,
                transport=fail,
            )
            with self.assertRaises(LiveError):
                campaign.chat(
                    key="failure",
                    phase="fixture",
                    messages=[{"role": "user", "content": "fixture"}],
                )
            self.assertEqual(campaign.charge(campaign.state()), 48576)
            campaign.close("fixture_complete")
            with self.assertRaises(LiveError):
                campaign.chat(key="after-close", phase="fixture", messages=[])
