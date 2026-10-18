"""Offline native integration; no credentials, provider or original repository."""

import base64
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from showcase.workbench.api import create_workbench_app
from showcase.workbench.model_gateway import DeliveryModelGateway

PASSWORD = "local-test-only-password"


class DeliveryWorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.app = create_workbench_app(
            state_root=self.root, start_worker=False, password_scrypt_n=1024
        )
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.headers = {
            "Origin": "http://testserver",
            "X-Orbit-Request": "department-cockpit",
        }
        self.auth(
            "register",
            {
                "username": "administrator",
                "password": PASSWORD,
                "display_name": "本机管理员",
            },
        )
        self.auth("login", {"username": "administrator", "password": PASSWORD})
        self.service = self.app.state.delivery

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.temporary.cleanup()
        os.umask(self.previous_umask)

    def auth(self, action, data):
        response = self.client.post(
            "/v1/auth/" + action, json=data, headers=self.headers
        )
        self.assertIn(response.status_code, (200, 201, 204), response.text)
        return response.json() if response.content else None

    def post(self, path, data=None, *, expected=200, key=None):
        response = self.client.post(
            path,
            json={**(data or {}), "idempotency_key": key or "test:" + uuid.uuid4().hex},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, expected, response.text)
        return response.json()

    def create(self, scenario="normal"):
        return self.post(
            "/v1/workflows",
            {
                "title": "团队知识助手交付",
                "goal": "开发虚构团队知识助手，明确部门权限、引用证据、撤权和人工验收边界。",
                "scenario": scenario,
            },
            expected=201,
        )["workflow_id"]

    def activate_assets(self):
        assets = self.client.get("/v1/workbench/assets").json()
        for kind in ("agents", "tools"):
            for asset in assets[kind]:
                for action in ("evaluate", "activate"):
                    self.post(f"/v1/workbench/assets/{kind}/{asset['id']}/{action}")

    def prepare(self, scenario="normal"):
        self.activate_assets()
        workflow = self.create(scenario)
        self.post(f"/v1/workflows/{workflow}/import-fixtures")
        return workflow

    def detail(self, workflow):
        response = self.client.get(f"/v1/workflows/{workflow}")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def node(self, workflow, department):
        return next(
            n
            for n in self.detail(workflow)["nodes"]
            if n["department_id"] == department
        )

    def plan(self, workflow, department, *, start=True):
        prefix = f"/v1/workflows/{workflow}/departments/{department}"
        if start:
            self.post(prefix + "/plan")
        node = self.node(workflow, department)
        questions = node["planning"]["question_card"]["questions"]
        answers = {
            q["question_id"]: next(
                o["option_id"] for o in q["options"] if o["recommended"]
            )
            for q in questions
        }
        self.post(
            prefix + "/answers",
            {
                "answers": answers,
                "supplement": "先核验部门权限与引用，再形成交付候选，不能自动批准或发布。",
            },
        )
        node = self.node(workflow, department)
        self.post(
            prefix + "/approve-plan",
            {
                "package_digest": node["planning"]["task_approval_subject"][
                    "package_digest"
                ],
                "reason": "负责人确认离线演示的计划和固定工具范围。",
            },
        )
        return prefix

    def execute(self, workflow, department, *, start=True):
        prefix = self.plan(workflow, department, start=start)
        self.post(prefix + "/execute")
        worker = subprocess.run(
            [
                sys.executable,
                "-m",
                "showcase.workbench.worker",
                "--root",
                str(self.root),
                "--once",
            ],
            cwd=Path(__file__).resolve().parents[1],
            check=False,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "LANG": "C.UTF-8",
                "PYTHONHASHSEED": "0",
            },
            capture_output=True,
            text=True,
        )
        self.assertEqual(worker.returncode, 0, worker.stderr)
        self.service.reconcile()
        node = self.node(workflow, department)
        self.assertIsNotNone(node.get("candidate"), str(node.get("runtime")))
        return node

    def approve(self, workflow, department, node, target=None, decision="approve"):
        return self.post(
            f"/v1/workflows/{workflow}/departments/{department}/review",
            {
                "candidate_digest": node["candidate"]["candidate_digest"],
                "revision": node["revision"],
                "decision": decision,
                "reason": "请明确保留证据边界，并逐项核对权限和验收结果。",
                **({"handoff_to": target} if target else {}),
            },
        )

    def test_browser_api_full_delivery_uses_native_queue_and_receipts(self):
        workflow = self.prepare()
        departments = ("product_center", "technology_center", "market_center")
        for index, department in enumerate(departments):
            node = self.execute(workflow, department)
            self.assertTrue(
                node["candidate"]["checks_passed"],
                node["candidate"]["payload"]["checks"],
            )
            self.assertEqual(len(node["candidate"]["payload"]["tool_receipts"]), 5)
            self.assertEqual(node["candidate"]["payload"]["model_requests"], 0)
            self.approve(
                workflow,
                department,
                node,
                departments[index + 1] if index < 2 else None,
            )
        final = self.post(
            f"/v1/workflows/{workflow}/deliver",
            {"reason": "最终审核确认三个部门的当前产物与证据齐备，仅交付本地文件。"},
        )
        self.assertEqual(final["status"], "delivered")
        self.assertEqual(
            self.client.get(f"/v1/workflows/{workflow}/download").status_code, 200
        )
        runs = self.client.get("/v1/workbench/runtime").json()["runs"]
        self.assertEqual(len(runs), 3)
        self.assertTrue(
            all(
                r["lease"]["status"] == "closed"
                and r["lease"]["outcome"] == "completed"
                for r in runs
            )
        )

    def test_read_projections_follow_current_handoff_without_rewriting_history(self):
        workflow = self.prepare()
        first = self.detail(workflow)
        self.assertTrue(first["nodes"][0]["has_documents"])
        self.assertIn("资料已就绪", first["nodes"][0]["next_action"])
        self.assertFalse(first["nodes"][1]["upstream_ready"])
        self.assertIn("等待上游", first["nodes"][1]["next_action"])
        product = self.execute(workflow, "product_center")
        self.assertEqual(product["runtime"]["status"], "completed")
        self.assertEqual(product["status"], "awaiting_review")
        old_digest = product["candidate"]["candidate_digest"]
        self.approve(workflow, "product_center", product, "technology_center")
        view = self.detail(workflow)
        self.assertEqual(view["nodes"][0]["runtime"]["status"], "completed")
        self.assertIsNotNone(view["nodes"][0]["outgoing_handoff"])
        self.assertTrue(view["nodes"][1]["upstream_ready"])
        self.assertEqual(view["nodes"][1]["incoming_handoff"]["source_attempt"], product["attempt_id"])
        for _ in range(2):
            current = self.detail(workflow)
            self.assertEqual(current["nodes"][0]["candidate"]["candidate_digest"], old_digest)
        technology = self.execute(workflow, "technology_center")
        self.approve(workflow, "technology_center", technology, "market_center")
        market = self.execute(workflow, "market_center")
        self.approve(workflow, "market_center", market)
        self.post(f"/v1/workflows/{workflow}/deliver", {"reason": "核对当前三部门版本，仅批准本地虚构交付。"})
        delivered = self.detail(workflow)
        self.assertEqual(delivered["status"], "delivered")
        self.assertTrue(all("已纳入当前本地交付" in n["next_action"] for n in delivered["nodes"]))
        self.assertTrue(all(n["runtime"]["status"] == "completed" for n in delivered["nodes"]))

    def test_no_approval_no_execution_and_idempotent_create(self):
        key = "same-create-key-0001"
        data = {
            "title": "重复点击保护",
            "goal": "需要以部门权限和引用证据完成知识助手交付。",
        }
        first = self.post("/v1/workflows", data, expected=201, key=key)
        second = self.post("/v1/workflows", data, expected=201, key=key)
        self.assertEqual(first["workflow_id"], second["workflow_id"])
        self.post("/v1/workflows", {**data, "title": "冲突任务"}, expected=409, key=key)
        workflow = first["workflow_id"]
        self.post(f"/v1/workflows/{workflow}/import-fixtures")
        self.post(f"/v1/workflows/{workflow}/departments/product_center/plan")
        self.post(
            f"/v1/workflows/{workflow}/departments/product_center/execute", expected=409
        )

    def test_rework_preserves_old_candidate_and_rejects_old_approval(self):
        workflow = self.prepare()
        node = self.execute(workflow, "product_center")
        old_digest = node["candidate"]["candidate_digest"]
        self.approve(workflow, "product_center", node, decision="request_changes")
        self.post(
            f"/v1/workflows/{workflow}/departments/product_center/revise",
            {
                "reason": "补充范围限制和可执行的负责人验收清单。",
                "acknowledge_uncertain": True,
            },
        )
        self.assertEqual(self.node(workflow, "product_center")["revision"], 2)
        self.post(
            f"/v1/workflows/{workflow}/departments/product_center/review",
            {
                "candidate_digest": old_digest,
                "revision": 1,
                "decision": "approve",
                "reason": "尝试批准旧版，应被版本门禁拒绝。",
            },
            expected=409,
        )
        self.assertEqual(len(self.node(workflow, "product_center")["history"]), 2)
        revised = self.execute(workflow, "product_center", start=False)
        self.assertTrue(revised["candidate"]["checks_passed"])
        self.assertNotEqual(old_digest, revised["candidate"]["candidate_digest"])
        self.assertIn("范围限制与证据边界", revised["candidate"]["payload"]["authored_prose"])
        self.assertIn("负责人逐项验收清单", revised["candidate"]["payload"]["authored_prose"])
        self.approve(workflow, "product_center", revised, "technology_center")
        self.assertEqual(self.node(workflow, "product_center")["status"], "approved")

    def test_unsupported_offline_rework_blocks_approval_and_preserves_original(self):
        workflow = self.prepare()
        node = self.execute(workflow, "product_center")
        old_digest = node["candidate"]["candidate_digest"]
        self.approve(workflow, "product_center", node, decision="request_changes")
        self.post(
            f"/v1/workflows/{workflow}/departments/product_center/revise",
            {"reason": "补充验收清单，并新增短信通知功能。", "acknowledge_uncertain": True},
        )
        revised = self.execute(workflow, "product_center", start=False)
        self.assertEqual(revised["status"], "blocked")
        self.assertFalse(revised["candidate"]["checks_passed"])
        response = revised["candidate"]["payload"]["rework_response"]
        self.assertTrue(any(i["status"] == "unresolved" for i in response["items"]))
        self.post(
            f"/v1/workflows/{workflow}/departments/product_center/review",
            {"candidate_digest": revised["candidate"]["candidate_digest"], "revision": 2,
             "decision": "approve", "reason": "不能用规则通过冒充意见已落实。"},
            expected=409,
        )
        self.assertEqual(revised["history"][0]["candidate"]["candidate_digest"], old_digest)
        self.assertEqual(self.detail(workflow)["model_requests"], 0)

    def test_same_version_conflict_is_detected_from_actual_uploaded_documents(self):
        workflow = self.prepare()
        self.post(
            f"/v1/workflows/{workflow}/artifacts",
            {
                "department_id": "product_center",
                "filename": "conflicting-requirements.md",
                "document_id": "requirements",
                "version": 2,
                "content_base64": base64.b64encode(
                    "权限、引用、撤权和验收要求发生未解决的冲突。".encode()
                ).decode(),
            },
        )
        node = self.execute(workflow, "product_center")
        self.assertFalse(node["candidate"]["checks_passed"])
        self.assertTrue(
            any(
                c["name"] == "同一文档版本没有内容冲突" and not c["passed"]
                for c in node["candidate"]["payload"]["checks"]
            )
        )

    def test_upstream_revision_invalidates_downstream_approval(self):
        workflow = self.prepare()
        product = self.execute(workflow, "product_center")
        self.approve(workflow, "product_center", product, "technology_center")
        technology = self.execute(workflow, "technology_center")
        self.approve(workflow, "technology_center", technology, "market_center")
        self.post(
            f"/v1/workflows/{workflow}/departments/product_center/revise",
            {
                "reason": "上游需求范围变更，技术与市场的旧结论需要重新验收。",
                "acknowledge_uncertain": True,
            },
        )
        self.assertEqual(self.node(workflow, "technology_center")["status"], "stale")
        self.post(
            f"/v1/workflows/{workflow}/departments/technology_center/review",
            {
                "candidate_digest": technology["candidate"]["candidate_digest"],
                "revision": 1,
                "decision": "approve",
                "reason": "旧的下游结论不能再次支撑交付。",
            },
            expected=409,
        )

    def test_asset_batch_requires_exact_release_and_explicit_approval(self):
        assets = self.client.get("/v1/workbench/assets").json()
        items = [
            {"kind": kind, "id": a["id"], "release_digest": a["release_digest"]}
            for kind in ("agents", "tools")
            for a in assets[kind]
        ]
        self.post("/v1/workbench/assets/batch/activate", {"items": items}, expected=409)
        self.post("/v1/workbench/assets/batch/evaluate", {"items": items})
        activated = self.post("/v1/workbench/assets/batch/activate", {"items": items})
        self.assertTrue(
            all(
                a["status"] == "active"
                for kind in ("agents", "tools")
                for a in activated[kind]
            )
        )

    def test_snapshot_tampering_is_rejected_before_tools_execute(self):
        import json

        from showcase.live_budget import atomic_private

        workflow = self.prepare()
        prefix = self.plan(workflow, "product_center")
        self.post(prefix + "/execute")
        node = self.node(workflow, "product_center")
        path = self.root / (node["attempt"]["grant_id"] + ".json")
        snapshot = json.loads(path.read_text())
        snapshot["goal"] = "未批准的目标变更"
        atomic_private(path, snapshot)
        worker = self.worker_process()
        worker.wait(timeout=10)
        self.service.reconcile()
        node = self.node(workflow, "product_center")
        self.assertEqual(
            node["runtime"]["failure_reason_code"], "execution_grant_snapshot_mismatch"
        )
        self.assertIsNone(node["candidate"])

    def test_review_and_native_receipt_are_atomic(self):
        from sqlalchemy.orm import Session

        from orbit_agent_control_plane.service_runtime.models import ReceiptRow

        workflow = self.prepare()
        node = self.execute(workflow, "product_center")
        original_add = Session.add

        def fail_receipt(session, instance, *args, **kwargs):
            if (
                isinstance(instance, ReceiptRow)
                and instance.receipt_type == "local_delivery_candidate_review"
            ):
                raise ValueError("injected_receipt_write_failure")
            return original_add(session, instance, *args, **kwargs)

        with patch.object(Session, "add", fail_receipt):
            self.post(
                f"/v1/workflows/{workflow}/departments/product_center/review",
                {
                    "candidate_digest": node["candidate"]["candidate_digest"],
                    "revision": 1,
                    "decision": "approve",
                    "reason": "模拟回执写入失败，不能留下单独的批准记录。",
                },
                expected=409,
            )
        self.assertEqual(self.service.store.list("review", workflow), [])
        self.assertEqual(
            self.node(workflow, "product_center")["status"], "awaiting_review"
        )
        self.approve(workflow, "product_center", node, "technology_center")
        self.assertEqual(self.node(workflow, "product_center")["status"], "approved")

    def test_evidence_gate_and_department_dependency(self):
        workflow = self.prepare("missing_evidence")
        self.post(
            f"/v1/workflows/{workflow}/departments/technology_center/plan", expected=409
        )
        node = self.execute(workflow, "product_center")
        self.assertFalse(node["candidate"]["checks_passed"])
        self.post(
            f"/v1/workflows/{workflow}/departments/product_center/review",
            {
                "candidate_digest": node["candidate"]["candidate_digest"],
                "revision": 1,
                "decision": "approve",
                "reason": "尝试批准缺证据产物，必须拒绝。",
            },
            expected=409,
        )

    def test_parse_failures_do_not_claim_understanding(self):
        workflow = self.create()
        for name, raw in (
            ("bad.json", b'{"x":1,"x":2}'),
            ("bad.txt", b"\xff\xfe"),
            ("file.pdf", b"%PDF"),
        ):
            self.post(
                f"/v1/workflows/{workflow}/artifacts",
                {
                    "department_id": "product_center",
                    "filename": name,
                    "content_base64": base64.b64encode(raw).decode(),
                },
                expected=409,
            )
        self.assertEqual(len(self.detail(workflow)["documents"]), 0)

    def test_auth_and_csrf_required(self):
        self.auth("logout", {})
        self.assertEqual(self.client.get("/v1/workflows").status_code, 401)
        self.assertEqual(
            self.client.post(
                "/v1/auth/login",
                json={"username": "administrator", "password": PASSWORD},
            ).status_code,
            403,
        )

    def test_department_user_cannot_approve_or_read_other_department(self):
        workflow = self.create()
        self.post(f"/v1/workflows/{workflow}/import-fixtures")
        ordinary = TestClient(self.app)
        registered = ordinary.post(
            "/v1/auth/register",
            headers=self.headers,
            json={
                "username": "product_member",
                "password": PASSWORD,
                "display_name": "产品部门用户",
                "department_id": "product_center",
            },
        )
        self.assertEqual(registered.status_code, 201)
        account_id = registered.json()["account_id"]
        approved = self.client.post(
            f"/v1/auth/accounts/{account_id}/approve",
            headers=self.headers,
            json={"role_ref": "role_department_user"},
        )
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(
            ordinary.post(
                "/v1/auth/login",
                headers=self.headers,
                json={"username": "product_member", "password": PASSWORD},
            ).status_code,
            200,
        )
        view = ordinary.get(f"/v1/workflows/{workflow}").json()
        self.assertTrue(
            all(d["department_id"] == "product_center" for d in view["documents"])
        )
        self.assertFalse(view["nodes"][1]["accessible"])
        self.assertEqual(ordinary.get("/v1/workbench/runtime").status_code, 403)
        self.assertEqual(ordinary.get("/v1/control-console/bootstrap").status_code, 403)
        for action, department in (
            ("approve-plan", "product_center"),
            ("plan", "technology_center"),
        ):
            rejected = ordinary.post(
                f"/v1/workflows/{workflow}/departments/{department}/{action}",
                headers=self.headers,
                json={"idempotency_key": "denied:" + uuid.uuid4().hex},
            )
            self.assertEqual(rejected.status_code, 409, rejected.text)

    def test_persistence_checkpoint_and_no_secret_loading(self):
        with patch(
            "showcase.live_budget.load_secret",
            side_effect=AssertionError("offline must not load credentials"),
        ):
            workflow = self.create()
            self.post(f"/v1/workflows/{workflow}/import-fixtures")
            self.post(f"/v1/workflows/{workflow}/departments/product_center/plan")
            checkpoint = self.node(workflow, "product_center")["planning"]
            from orbit_agent_control_plane.service_runtime.database import Database
            from orbit_agent_control_plane.service_runtime.department_cockpit import (
                DepartmentCockpitService,
                LangGraphPlanningTransport,
            )

            restored_db = Database(
                "sqlite+pysqlite:///" + str(self.root / "state.sqlite3")
            )
            restored = DepartmentCockpitService(
                database=restored_db,
                transport=LangGraphPlanningTransport(
                    checkpoint_path=self.root / "cockpit.langgraph.sqlite3"
                ),
            )
            reread = restored.planning_session(
                department_id="product_center", session_id=checkpoint["session_id"]
            )
            self.assertEqual(reread["question_card"], checkpoint["question_card"])
            self.assertEqual(reread["status"], "needs_input")
            restored.transport.close()
            restored_db.dispose()
            with self.assertRaisesRegex(Exception, "real_model_not_authorized"):
                DeliveryModelGateway().chat(
                    key="not-authorized", phase="test", messages=[]
                )

    def worker_process(self):
        return subprocess.Popen(
            [
                sys.executable,
                "-m",
                "showcase.workbench.worker",
                "--root",
                str(self.root),
                "--once",
            ],
            cwd=Path(__file__).resolve().parents[1],
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "LANG": "C.UTF-8",
                "PYTHONHASHSEED": "0",
            },
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def wait_child(self, workflow):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            node = self.node(workflow, "product_center")
            if node["attempt"].get("grant_id"):
                path = self.root / ("process-" + node["attempt"]["grant_id"] + ".json")
                if path.exists():
                    import json

                    return json.loads(path.read_text())["pid"]
            time.sleep(0.05)
        self.fail("Worker did not enter an actual handler process")

    @staticmethod
    def process_running(pid):
        path = Path(f"/proc/{pid}/stat")
        return path.exists() and path.read_text().rsplit(") ", 1)[1].split()[0] != "Z"

    def test_running_revoke_kills_process_and_closes_lease(self):
        workflow = self.prepare("slow")
        prefix = self.plan(workflow, "product_center")
        self.post(prefix + "/execute")
        worker = self.worker_process()
        try:
            pid = self.wait_child(workflow)
            self.assertTrue(self.process_running(pid))
            self.post(prefix + "/revoke")
            worker.wait(timeout=10)
            self.service.reconcile()
            self.assertFalse(self.process_running(pid))
            node = self.node(workflow, "product_center")
            self.assertEqual(node["runtime"]["status"], "cancelled")
            runs = self.client.get("/v1/workbench/runtime").json()["runs"]
            self.assertEqual(runs[0]["lease"]["outcome"], "cancelled")
        finally:
            if worker.poll() is None:
                worker.kill()
                worker.wait(timeout=3)

    def test_worker_death_is_unknown_and_never_automatically_replayed(self):
        workflow = self.prepare("slow")
        prefix = self.plan(workflow, "product_center")
        self.post(prefix + "/execute")
        worker = self.worker_process()
        pid = self.wait_child(workflow)
        worker.send_signal(signal.SIGKILL)
        worker.wait(timeout=5)
        recovered = self.worker_process()
        recovered.wait(timeout=10)
        self.assertEqual(recovered.returncode, 0)
        self.service.reconcile()
        node = self.node(workflow, "product_center")
        self.assertEqual(
            node["runtime"]["failure_reason_code"], "runtime_interrupted_unknown"
        )
        self.assertFalse(self.process_running(pid))
        self.assertIsNone(node["candidate"])
        self.assertEqual(
            len(self.client.get("/v1/workbench/runtime").json()["runs"]), 1
        )
        self.post(prefix + "/execute", expected=409)

    def test_timeout_is_preserved_and_requires_explicit_new_attempt(self):
        workflow = self.prepare("timeout")
        prefix = self.plan(workflow, "product_center")
        self.post(prefix + "/execute")
        worker = self.worker_process()
        worker.wait(timeout=10)
        self.service.reconcile()
        node = self.node(workflow, "product_center")
        self.assertEqual(
            node["runtime"]["failure_reason_code"], "runtime_handler_timeout"
        )
        self.assertIsNone(node["candidate"])
        self.post(
            prefix + "/revise",
            {
                "reason": "核查超时记录后，允许创建新版本。",
                "acknowledge_uncertain": False,
            },
            expected=409,
        )


if __name__ == "__main__":
    unittest.main()
