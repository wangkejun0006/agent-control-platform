from __future__ import annotations

import fcntl
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from orbit_agent_control_plane.dataset_agent_process import (
    BoundedProcessRunner,
    DatasetAgentProcessError,
)
from orbit_agent_control_plane.ledger import LedgerError, SyntheticTaskLedger
from showcase import demo
from showcase.server import create_showcase_app


class OfflineShowcaseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_complete_loop_refusals_cancellation_and_replay(self):
        report = demo.run_demo(self.root / "state")
        self.assertTrue(report["passed"], report["checks"])
        cases = {case["scenario"]: case for case in report["cases"]}
        self.assertEqual(0, report["model_calls"])
        self.assertEqual("0", report["cost_cny"])
        self.assertEqual(
            "cancelled", cases["cancel"]["ledger"]["tasks"][0]["worker_lease"]["status"]
        )
        self.assertEqual(
            "completed",
            cases["success"]["ledger"]["tasks"][0]["worker_lease"]["status"],
        )
        self.assertEqual(0, cases["missing_grant"]["worker_invocations"])
        self.assertFalse(
            cases["success"]["ledger"]["tasks"][0]["dataset_outcome"][
                "company_outcome"
            ]["evaluation"]["release_authorization"]
        )

    def test_digest_drift_refuses_before_start(self):
        with (
            patch.object(demo, "digest", return_value="sha256:" + "0" * 64),
            self.assertRaisesRegex(ValueError, "demo_source_digest_mismatch"),
        ):
            demo.run_scenario(self.root / "state", "success")
        self.assertFalse((self.root / "state/success.jsonl").exists())

    def test_ledger_tamper_is_detected(self):
        demo.run_scenario(self.root / "state", "success")
        path = self.root / "state/success.jsonl"
        original = path.read_text()
        path.write_text(original.replace('"completed"', '"cancelled"', 1))
        with self.assertRaises(LedgerError):
            SyntheticTaskLedger(path).replay()

    def test_concurrent_attempt_and_symlink_lock_are_rejected(self):
        root = self.root / "state"
        root.mkdir(mode=0o700)
        path = root / "success.lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "attempt_already_running"):
                demo.run_scenario(root, "success")
        finally:
            os.close(fd)
        path.unlink()
        target = self.root / "other"
        target.write_text("unchanged")
        path.symlink_to(target)
        with self.assertRaises(OSError):
            demo.run_scenario(root, "success")
        self.assertEqual("unchanged", target.read_text())

    def test_wide_permissions_and_unknown_scenario_are_rejected(self):
        root = self.root / "state"
        root.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, "owner_only_state_root_required"):
            demo.run_scenario(root, "success")
        with self.assertRaisesRegex(ValueError, "unknown_scenario"):
            demo.run_scenario(root, "arbitrary_command")

    def test_environment_is_not_inherited_and_cancellation_stops_work(self):
        with patch.dict(os.environ, {"ORBIT_TEST_SENTINEL": "private-test-value"}):
            capture = BoundedProcessRunner().run(
                (
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    "import os; print(os.environ.get('ORBIT_TEST_SENTINEL', 'absent'))",
                ),
                cwd=self.root,
                environment={},
                timeout_seconds=2,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
            )
        self.assertEqual(b"absent\n", capture.stdout)
        marker = self.root / "should-not-exist"
        script = f"import time; from pathlib import Path; time.sleep(0.8); Path({str(marker)!r}).write_text('late work')"
        started = time.monotonic()
        with self.assertRaises(DatasetAgentProcessError) as caught:
            BoundedProcessRunner().run(
                (sys.executable, "-I", "-S", "-c", script),
                cwd=self.root,
                environment={},
                timeout_seconds=2,
                max_stdout_bytes=1024,
                max_stderr_bytes=1024,
                cancellation_probe=lambda: time.monotonic() - started > 0.1,
            )
        self.assertEqual(
            "dataset_agent_process_cancelled", caught.exception.reason_code
        )
        time.sleep(0.9)
        self.assertFalse(marker.exists())

    def test_original_console_and_fixed_showcase_api(self):
        with TestClient(
            create_showcase_app(database_path=self.root / "test.sqlite3")
        ) as client:
            self.assertEqual(200, client.get("/health/live").status_code)
            self.assertEqual(
                200, client.get("/v1/control-console/bootstrap").status_code
            )
            self.assertEqual(403, client.post("/v1/showcase/run", json={}).status_code)
            self.assertEqual(
                403,
                client.post(
                    "/v1/showcase/run",
                    json={"model": "real"},
                    headers={
                        "Origin": "http://testserver",
                        "X-Orbit-Request": "control-console",
                    },
                ).status_code,
            )
            response = client.get("/v1/showcase/report")
            self.assertEqual(200, response.status_code)
            self.assertEqual(0, response.json()["model_calls"])


if __name__ == "__main__":
    unittest.main()
