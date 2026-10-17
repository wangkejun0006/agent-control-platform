"""Fixed snapshot viewing must not initialize databases or execution services."""

import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from showcase.workbench.snapshot_view import (
    DEFAULT,
    create_snapshot_view,
    load_snapshot,
)


class SnapshotViewTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for target in (
            "sqlite3.connect",
            "subprocess.Popen",
            "socket.create_connection",
            "showcase.live_budget.load_secret",
            "showcase.live_budget.live_post",
        ):
            self.stack.enter_context(
                patch(target, side_effect=AssertionError("snapshot_no_execution"))
            )
        payload = {
            "authored_prose": "## 三态表\n|状态|决定|\n|---|---|\n|未共享资料|不读取|\n<script>alert('x')</script>",
            "body": "## 依据\n只读虚构引用",
            "tool_receipts": [1] * 5,
        }
        before = {
            "revision": 1,
            "candidate_digest": "old",
            "payload": {**payload, "authored_prose": "旧版原文"},
        }
        after = {"revision": 2, "candidate_digest": "new", "payload": payload}
        workflow = {
            "status": "delivered",
            "workflow_id": "fictional-test",
            "nodes": [
                {
                    "department_id": "market_center",
                    "candidate": after,
                    "history": [{"revision": 1, "candidate": before}],
                }
            ],
        }
        reviews = [
            {
                "department_id": "market_center",
                "revision": 1,
                "decision": "request_changes",
                "reason": "补齐三态表",
                "recorded_at": "2026-10-17T00:00:00Z",
                "actor": "synthetic",
                "candidate_digest": "old",
            },
            {
                "department_id": "market_center",
                "revision": 2,
                "decision": "approve",
                "reason": "本机测试批准",
                "recorded_at": "2026-10-17T01:00:00Z",
                "actor": "synthetic",
                "candidate_digest": "new",
            },
        ]
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zipped:
            zipped.writestr("market_center-evidence.json", json.dumps(payload))
            zipped.writestr("review-records.json", json.dumps(reviews))
        self.archive = buffer.getvalue()
        report = {
            "status": "passed",
            "new_model_requests": 0,
            "local_delivery_completed": True,
            "zip_sha256": hashlib.sha256(self.archive).hexdigest(),
        }
        (self.root / "local-delivery.zip").write_bytes(self.archive)
        (self.root / "final-workflow.json").write_text(json.dumps(workflow))
        (self.root / "validation-report.json").write_text(json.dumps(report))

    def test_view_reviews_escaped_prose_and_exact_download(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        with TestClient(create_snapshot_view(self.root)) as client:
            page = client.get("/")
            self.assertEqual(page.status_code, 200)
            for text in (
                "旧版原文",
                "退回修改",
                "本机测试批准",
                "返工前后",
                "0 次 / 0 元",
                "&lt;script&gt;",
            ):
                self.assertIn(text, page.text)
            self.assertNotIn("<script>", page.text)
            self.assertEqual(client.get("/download").content, self.archive)
            self.assertIn(
                "frame-ancestors 'none'", page.headers["content-security-policy"]
            )
            self.assertNotIn("set-cookie", page.headers)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_mutations_hosts_and_arbitrary_files_rejected(self):
        with TestClient(create_snapshot_view(self.root)) as client:
            for url in ("/", "/download", "/v1/workflows/test/review"):
                self.assertEqual(client.post(url, json={}).status_code, 405)
            self.assertEqual(
                client.get("/", headers={"Host": "attacker.invalid"}).status_code, 403
            )
            self.assertEqual(client.get("/state.sqlite3").status_code, 404)
            self.assertEqual(client.get("/local-signing.pem").status_code, 404)
            self.assertFalse(client.get("/health/ready").json()["database_opened"])

    def test_tampered_zip_or_incomplete_report_cannot_be_served(self):
        path = self.root / "local-delivery.zip"
        path.write_bytes(self.archive + b"changed")
        with self.assertRaisesRegex(ValueError, "integrity"):
            create_snapshot_view(self.root)
        path.write_bytes(self.archive)
        report_path = self.root / "validation-report.json"
        report = json.loads(report_path.read_text())
        report["status"] = "stopped"
        report_path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "integrity"):
            create_snapshot_view(self.root)

    def test_snapshot_file_symlink_rejected(self):
        path = self.root / "validation-report.json"
        target = self.root / "other.json"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "regular"):
            load_snapshot(self.root)

    def test_completed_private_case_exact_zip_and_history_read_only(self):
        if not DEFAULT.exists():
            self.skipTest("private delivered snapshot not present in portable checkout")
        paths = [
            DEFAULT / n
            for n in (
                "validation-report.json",
                "final-workflow.json",
                "local-delivery.zip",
            )
        ]
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        with TestClient(create_snapshot_view()) as client:
            self.assertIn("市场 v1", client.get("/").text)
            self.assertIn("市场 v2", client.get("/").text)
            self.assertEqual(
                client.get("/download").content,
                (DEFAULT / "local-delivery.zip").read_bytes(),
            )
        self.assertEqual(
            before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        )
