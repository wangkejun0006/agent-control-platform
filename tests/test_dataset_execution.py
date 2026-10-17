from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from orbit_agent_control_plane.authorization import (
    SyntheticOperatorGrant,
    authorize_control,
)
from orbit_agent_control_plane.control import TaskController
from orbit_agent_control_plane.cli import main
from orbit_agent_control_plane.dataset_agent_process import (
    BoundedProcessRunner,
    DatasetAgentProcessError,
    dataset_synthetic_task,
)
from orbit_agent_control_plane.dataset_execution import run_dataset_with_ledger
from orbit_agent_control_plane.ledger import LedgerError, SyntheticTaskLedger
from orbit_agent_control_plane.runtime_source import materialize_dataset_runtime_source


ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_PLATFORM = ROOT.parent / "orbit-health-system" / "scientific-research-platform"


class DatasetExecutionLedgerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime_temporary = tempfile.TemporaryDirectory()
        runtime_root = Path(cls.runtime_temporary.name) / "runtime-sources"
        evidence = materialize_dataset_runtime_source(
            SCIENTIFIC_PLATFORM,
            runtime_root,
        )
        cls.runtime_source = runtime_root / evidence.runtime_source_name

    @classmethod
    def tearDownClass(cls) -> None:
        cls.runtime_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ledger_path = Path(self.temporary.name) / "dataset-ledger.synthetic.jsonl"

    def test_dataset_result_evaluation_audit_and_lease_survive_restart(self) -> None:
        run = run_dataset_with_ledger(self.ledger_path, self.runtime_source)
        replay = SyntheticTaskLedger(self.ledger_path).replay()
        state = replay.task(dataset_synthetic_task().task_id)

        self.assertEqual("pass", run.outcome.status)
        self.assertEqual("completed", state.worker_lease.status)
        self.assertEqual(1, state.worker_lease.revision)
        self.assertEqual(run.outcome, state.dataset_outcome)
        self.assertEqual("pass", state.dataset_outcome.company_outcome.evaluation.verdict)
        self.assertEqual(2, len(state.dataset_outcome.company_outcome.audit_events))
        self.assertEqual(4, len(state.dataset_outcome.adapter_evidence.domain_audit_event_refs))
        self.assertEqual(4, replay.records_checked)

        restarted = run_dataset_with_ledger(self.ledger_path, self.runtime_source)
        self.assertEqual(run.outcome, restarted.outcome)
        self.assertFalse(restarted.append_results[0][1].appended)
        self.assertEqual(4, SyntheticTaskLedger(self.ledger_path).replay().records_checked)

    def test_authority_claim_is_rejected_before_dataset_outcome_append(self) -> None:
        run = run_dataset_with_ledger(self.ledger_path, self.runtime_source)
        other_path = Path(self.temporary.name) / "invalid-outcome.synthetic.jsonl"
        ledger = SyntheticTaskLedger(other_path)
        task = dataset_synthetic_task()
        ledger.register_task(task, idempotency_key=f"register:{task.task_id}")
        ledger.start_worker_lease(
            replace(run.worker_lease, status="active", revision=0),
            idempotency_key=f"lease-start:{run.worker_lease.lease_id}",
        )
        invalid = replace(
            run.outcome,
            adapter_evidence=replace(
                run.outcome.adapter_evidence,
                storage_write_performed=True,
            ),
        )
        with self.assertRaises(LedgerError) as caught:
            ledger.record_dataset_outcome(
                invalid,
                idempotency_key=f"dataset-outcome:{task.task_id}",
            )
        self.assertEqual("dataset_evidence_authority_violated", caught.exception.reason_code)

    def test_running_process_is_killed_when_ledger_control_cancels_task(self) -> None:
        ledger = SyntheticTaskLedger(self.ledger_path)
        task = dataset_synthetic_task()
        ledger.register_task(task, idempotency_key=f"register:{task.task_id}")
        grant = SyntheticOperatorGrant(
            version="orbit.synthetic-operator-grant/1",
            grant_id="operator_grant_dataset_cancel_syn",
            operator_ref="human_operator_dataset_cancel_syn",
            task_id=task.task_id,
            allowed_actions=("cancel",),
            issued_at="2026-08-20T01:00:00Z",
            expires_at="2026-08-20T01:15:00Z",
            evidence_status="synthetic",
            synthetic_only=True,
        )

        def cancel() -> None:
            time.sleep(0.1)
            authorization = authorize_control(
                grant,
                operator_ref=grant.operator_ref,
                task_id=task.task_id,
                action="cancel",
                request_reason="D0 running Worker cancellation proof",
                checked_at="2026-08-20T01:05:00Z",
                confirmed_action="cancel",
            )
            before = ledger.replay().task(task.task_id).control_snapshot
            transition = TaskController().apply(
                before or TaskController.initial(task),
                "cancel",
                actor_id=grant.operator_ref,
            )
            ledger.record_control_attempt(
                authorization,
                transition,
                idempotency_key=f"control:{task.task_id}:running-cancel",
            )

        thread = threading.Thread(target=cancel)
        thread.start()
        started = time.monotonic()

        def cancellation_probe() -> bool:
            snapshot = (
                SyntheticTaskLedger(self.ledger_path)
                .replay()
                .task(task.task_id)
                .control_snapshot
            )
            return snapshot is not None and snapshot.task_status == "cancelled"

        with self.assertRaises(DatasetAgentProcessError) as caught:
            BoundedProcessRunner().run(
                (sys.executable, "-c", "import time; time.sleep(5)"),
                cwd=ROOT,
                environment={"PYTHONDONTWRITEBYTECODE": "1"},
                timeout_seconds=4,
                max_stdout_bytes=64,
                max_stderr_bytes=64,
                cancellation_probe=cancellation_probe,
            )
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertEqual("dataset_agent_process_cancelled", caught.exception.reason_code)
        self.assertLess(time.monotonic() - started, 1.5)

    def test_dataset_cli_run_status_and_prestart_cancel(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(
                [
                    "synthetic-dataset-ledger",
                    "run",
                    "--ledger",
                    str(self.ledger_path),
                    "--platform-root",
                    str(self.runtime_source),
                ]
            )
        document = json.loads(output.getvalue())
        self.assertEqual(0, exit_code)
        self.assertEqual("completed", document["worker_lease"]["status"])

        status_output = io.StringIO()
        with redirect_stdout(status_output):
            status_code = main(
                [
                    "synthetic-dataset-ledger",
                    "status",
                    "--ledger",
                    str(self.ledger_path),
                ]
            )
        self.assertEqual(0, status_code)
        self.assertEqual(
            "completed",
            json.loads(status_output.getvalue())["worker_lease"]["status"],
        )

        cancelled_ledger = Path(self.temporary.name) / "cancelled.synthetic.jsonl"
        now = datetime.now(timezone.utc).replace(microsecond=0)
        grant = {
            "version": "orbit.synthetic-operator-grant/1",
            "grant_id": "operator_grant_dataset_cli_cancel_syn",
            "operator_ref": "human_operator_dataset_cli_syn",
            "task_id": dataset_synthetic_task().task_id,
            "allowed_actions": ["cancel"],
            "issued_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=14)).isoformat().replace("+00:00", "Z"),
            "evidence_status": "synthetic",
            "synthetic_only": True,
        }
        grant_path = Path(self.temporary.name) / "dataset-grant.synthetic.json"
        grant_path.write_text(json.dumps(grant), encoding="utf-8")
        os.chmod(grant_path, 0o600)
        cancel_output = io.StringIO()
        with redirect_stdout(cancel_output):
            cancel_code = main(
                [
                    "synthetic-dataset-ledger",
                    "cancel",
                    "--ledger",
                    str(cancelled_ledger),
                    "--operator-grant",
                    str(grant_path),
                    "--operator-ref",
                    grant["operator_ref"],
                    "--reason",
                    "D0 cancel before Dataset Worker start",
                    "--idempotency-key",
                    "dataset-cli-cancel-001",
                    "--confirm-action",
                    "cancel",
                ]
            )
        self.assertEqual(0, cancel_code)
        blocked_output = io.StringIO()
        with redirect_stdout(blocked_output):
            blocked_code = main(
                [
                    "synthetic-dataset-ledger",
                    "run",
                    "--ledger",
                    str(cancelled_ledger),
                    "--platform-root",
                    str(self.runtime_source),
                ]
            )
        self.assertEqual(1, blocked_code)
        self.assertEqual(
            "task_control_blocks_worker_start",
            json.loads(blocked_output.getvalue())["reason_code"],
        )


if __name__ == "__main__":
    unittest.main()

