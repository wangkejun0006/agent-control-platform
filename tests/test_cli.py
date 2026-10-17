from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from orbit_agent_control_plane.authorization import (
    SyntheticOperatorGrant,
    authorize_control,
)
from orbit_agent_control_plane.cli import main
from orbit_agent_control_plane.control import TaskController
from orbit_agent_control_plane.ledger import SyntheticTaskLedger
from orbit_agent_control_plane.models import TaskEnvelope


class SyntheticControlCliTest(unittest.TestCase):
    @staticmethod
    def operator_grant(
        directory: Path,
        *,
        task_id: str = "task_company_d0_probe_syn",
        expired: bool = False,
    ) -> Path:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        issued = now - timedelta(minutes=15 if expired else 1)
        expires = now - timedelta(seconds=1) if expired else now + timedelta(minutes=14)
        grant = SyntheticOperatorGrant(
            version="orbit.synthetic-operator-grant/1",
            grant_id="operator_grant_company_control_syn",
            operator_ref="human_operator_cli_syn",
            task_id=task_id,
            allowed_actions=("pause", "revoke", "cancel", "takeover"),
            issued_at=issued.isoformat().replace("+00:00", "Z"),
            expires_at=expires.isoformat().replace("+00:00", "Z"),
            evidence_status="synthetic",
            synthetic_only=True,
        )
        path = directory / "operator-grant.synthetic.json"
        document = asdict(grant)
        document["allowed_actions"] = list(grant.allowed_actions)
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o600)
        return path

    def ledger_control_args(
        self,
        directory: Path,
        action: str,
        ledger: Path,
        *,
        grant: Path | None = None,
        confirmation: str | None = None,
        idempotency_key: str | None = None,
    ) -> list[str]:
        grant_path = grant or self.operator_grant(directory)
        return [
            "synthetic-ledger",
            action,
            "--ledger",
            str(ledger),
            "--operator-grant",
            str(grant_path),
            "--operator-ref",
            "human_operator_cli_syn",
            "--reason",
            f"D0 synthetic {action} verification",
            "--idempotency-key",
            idempotency_key or f"cli-{action}-001",
            "--confirm-action",
            confirmation or action,
        ]

    def test_each_control_action_blocks_before_worker_execution(self) -> None:
        for action in ("pause", "revoke", "cancel", "takeover"):
            with self.subTest(action=action):
                output = io.StringIO()
                with redirect_stdout(output):
                    exit_code = main(["synthetic-control", action])
                document = json.loads(output.getvalue())

                self.assertEqual(0, exit_code)
                self.assertTrue(document["control_transition"]["applied"])
                self.assertEqual(
                    "blocked", document["closed_loop"]["route_decision"]["status"]
                )
                self.assertIsNone(document["closed_loop"]["result"])
                self.assertIsNone(document["closed_loop"]["evaluation"])
                self.assertEqual(
                    document["control_transition"]["audit_event"]["event_id"],
                    document["closed_loop"]["audit_events"][0]["event_id"],
                )

    def test_ledger_run_replay_and_idempotent_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "cli-ledger.synthetic.jsonl"
            first_output = io.StringIO()
            with redirect_stdout(first_output):
                first_code = main(
                    ["synthetic-ledger", "run", "--ledger", str(ledger)]
                )
            first = json.loads(first_output.getvalue())

            second_output = io.StringIO()
            with redirect_stdout(second_output):
                second_code = main(
                    ["synthetic-ledger", "run", "--ledger", str(ledger)]
                )
            second = json.loads(second_output.getvalue())

            replay_output = io.StringIO()
            with redirect_stdout(replay_output):
                replay_code = main(
                    ["synthetic-ledger", "replay", "--ledger", str(ledger)]
                )
            replay = json.loads(replay_output.getvalue())

            self.assertEqual((0, 0, 0), (first_code, second_code, replay_code))
            self.assertEqual("pass", first["outcome"]["evaluation"]["verdict"])
            self.assertEqual(2, first["ledger"]["records_checked"])
            self.assertEqual(2, second["ledger"]["records_checked"])
            self.assertFalse(second["append_results"]["task"]["appended"])
            self.assertFalse(second["append_results"]["outcome"]["appended"])
            self.assertEqual(first["outcome"], replay["tasks"][0]["outcome"])

    def test_ledger_control_survives_replay_and_blocks_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for action in ("pause", "revoke", "cancel", "takeover"):
                with self.subTest(action=action):
                    ledger = Path(temporary) / f"{action}.synthetic.jsonl"
                    output = io.StringIO()
                    with redirect_stdout(output):
                        args = self.ledger_control_args(
                            Path(temporary), action, ledger
                        )
                        exit_code = main(args)
                    document = json.loads(output.getvalue())
                    self.assertEqual(0, exit_code)
                    self.assertEqual(
                        "blocked", document["outcome"]["route_decision"]["status"]
                    )
                    self.assertIsNone(document["outcome"]["result"])
                    self.assertEqual(3, document["ledger"]["records_checked"])
                    authorization = document["operator_authorization"]
                    self.assertTrue(authorization["allowed"])
                    self.assertEqual(
                        f"D0 synthetic {action} verification",
                        authorization["request_reason"],
                    )

                    retry_output = io.StringIO()
                    with redirect_stdout(retry_output):
                        retry_code = main(args)
                    retry = json.loads(retry_output.getvalue())
                    self.assertEqual(0, retry_code)
                    self.assertEqual(3, retry["ledger"]["records_checked"])
                    self.assertFalse(retry["append_results"]["task"]["appended"])
                    self.assertFalse(retry["append_results"]["outcome"]["appended"])

    def test_corrupt_ledger_returns_structured_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "corrupt.synthetic.jsonl"
            ledger.write_text("not-json\n", encoding="utf-8")
            ledger.chmod(0o600)
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(
                    ["synthetic-ledger", "replay", "--ledger", str(ledger)]
                )
            document = json.loads(output.getvalue())
            self.assertEqual(1, exit_code)
            self.assertEqual("blocked", document["status"])
            self.assertEqual("invalid_json", document["reason_code"])

    def test_control_retry_completes_after_outcome_write_was_interrupted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger_path = Path(temporary) / "interrupted-pause.synthetic.jsonl"
            task = TaskEnvelope(
                task_id="task_company_d0_probe_syn",
                capability="company.synthetic.echo",
                data_classification="synthetic",
                grant_id="grant_company_d0_probe_syn",
                grant_active=True,
            )
            ledger = SyntheticTaskLedger(ledger_path)
            ledger.register_task(
                task,
                idempotency_key=f"register:{task.task_id}",
            )
            transition = TaskController().apply(
                TaskController.initial(task),
                "pause",
                actor_id="human_operator_cli_syn",
            )
            now = datetime.now(timezone.utc).replace(microsecond=0)
            grant = SyntheticOperatorGrant(
                version="orbit.synthetic-operator-grant/1",
                grant_id="operator_grant_company_control_syn",
                operator_ref="human_operator_cli_syn",
                task_id=task.task_id,
                allowed_actions=("pause",),
                issued_at=(now - timedelta(minutes=1)).isoformat().replace(
                    "+00:00", "Z"
                ),
                expires_at=(now + timedelta(minutes=14)).isoformat().replace(
                    "+00:00", "Z"
                ),
                evidence_status="synthetic",
                synthetic_only=True,
            )
            authorization = authorize_control(
                grant,
                operator_ref=grant.operator_ref,
                task_id=task.task_id,
                action="pause",
                request_reason="D0 synthetic pause verification",
                checked_at=now.isoformat().replace("+00:00", "Z"),
                confirmed_action="pause",
            )
            ledger.record_control_attempt(
                authorization,
                transition,
                idempotency_key=f"control:{task.task_id}:cli-pause-001",
            )

            grant_path = Path(temporary) / "operator-grant.synthetic.json"
            grant_document = asdict(grant)
            grant_document["allowed_actions"] = list(grant.allowed_actions)
            grant_path.write_text(json.dumps(grant_document), encoding="utf-8")
            grant_path.chmod(0o600)

            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(
                    self.ledger_control_args(
                        Path(temporary),
                        "pause",
                        ledger_path,
                        grant=grant_path,
                    )
                )
            document = json.loads(output.getvalue())
            self.assertEqual(0, exit_code)
            self.assertEqual(3, document["ledger"]["records_checked"])
            self.assertFalse(
                document["append_results"]["control_attempt"]["appended"]
            )
            self.assertEqual(
                "blocked", document["outcome"]["route_decision"]["status"]
            )

    def test_run_refuses_to_relabel_an_interrupted_control_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger_path = Path(temporary) / "interrupted-control.synthetic.jsonl"
            task = TaskEnvelope(
                task_id="task_company_d0_probe_syn",
                capability="company.synthetic.echo",
                data_classification="synthetic",
                grant_id="grant_company_d0_probe_syn",
                grant_active=True,
            )
            ledger = SyntheticTaskLedger(ledger_path)
            ledger.register_task(task, idempotency_key=f"register:{task.task_id}")
            transition = TaskController().apply(
                TaskController.initial(task),
                "revoke",
                actor_id="human_operator_cli_syn",
            )
            now = datetime.now(timezone.utc).replace(microsecond=0)
            grant = SyntheticOperatorGrant(
                version="orbit.synthetic-operator-grant/1",
                grant_id="operator_grant_company_control_syn",
                operator_ref="human_operator_cli_syn",
                task_id=task.task_id,
                allowed_actions=("revoke",),
                issued_at=(now - timedelta(minutes=1)).isoformat().replace(
                    "+00:00", "Z"
                ),
                expires_at=(now + timedelta(minutes=14)).isoformat().replace(
                    "+00:00", "Z"
                ),
                evidence_status="synthetic",
                synthetic_only=True,
            )
            authorization = authorize_control(
                grant,
                operator_ref=grant.operator_ref,
                task_id=task.task_id,
                action="revoke",
                request_reason="D0 synthetic revoke verification",
                checked_at=now.isoformat().replace("+00:00", "Z"),
                confirmed_action="revoke",
            )
            ledger.record_control_attempt(
                authorization,
                transition,
                idempotency_key=f"control:{task.task_id}:revoke",
            )

            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(
                    ["synthetic-ledger", "run", "--ledger", str(ledger_path)]
                )
            document = json.loads(output.getvalue())
            self.assertEqual(1, exit_code)
            self.assertEqual("existing_control_incompatible", document["reason_code"])
            self.assertEqual(2, SyntheticTaskLedger(ledger_path).replay().records_checked)

    def test_replay_rejects_empty_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger_path = Path(temporary) / "empty.synthetic.jsonl"
            ledger_path.write_text("", encoding="utf-8")
            ledger_path.chmod(0o600)
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(
                    ["synthetic-ledger", "replay", "--ledger", str(ledger_path)]
                )
            document = json.loads(output.getvalue())
            self.assertEqual(1, exit_code)
            self.assertEqual("ledger_empty", document["reason_code"])

    def test_control_requires_grant_and_durably_records_authorization_denials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ledger = directory / "authorization-rejected.synthetic.jsonl"

            missing_output = io.StringIO()
            with redirect_stdout(missing_output):
                missing_code = main(
                    ["synthetic-ledger", "pause", "--ledger", str(ledger)]
                )
            missing = json.loads(missing_output.getvalue())
            self.assertEqual(1, missing_code)
            self.assertEqual("operator_grant_required", missing["reason_code"])
            self.assertFalse(ledger.exists())

            expired = self.operator_grant(directory, expired=True)
            expired_output = io.StringIO()
            with redirect_stdout(expired_output):
                expired_code = main(
                    self.ledger_control_args(
                        directory,
                        "pause",
                        ledger,
                        grant=expired,
                    )
                )
            expired_document = json.loads(expired_output.getvalue())
            self.assertEqual(1, expired_code)
            self.assertEqual("operator_grant_expired", expired_document["reason_code"])
            self.assertEqual(2, expired_document["ledger"]["records_checked"])
            self.assertIsNone(expired_document["control_transition"])
            expired_state = SyntheticTaskLedger(ledger).replay().task(
                "task_company_d0_probe_syn"
            )
            self.assertEqual(1, len(expired_state.control_attempts))
            self.assertFalse(expired_state.control_attempts[0].authorization.allowed)
            self.assertIsNone(expired_state.control_attempts[0].transition)

            retry_output = io.StringIO()
            with redirect_stdout(retry_output):
                retry_code = main(
                    self.ledger_control_args(
                        directory,
                        "pause",
                        ledger,
                        grant=expired,
                    )
                )
            retry_document = json.loads(retry_output.getvalue())
            self.assertEqual(1, retry_code)
            self.assertEqual(2, retry_document["ledger"]["records_checked"])
            self.assertFalse(
                retry_document["append_results"]["control_attempt"]["appended"]
            )

            active = self.operator_grant(directory)
            conflict_output = io.StringIO()
            with redirect_stdout(conflict_output):
                conflict_code = main(
                    self.ledger_control_args(
                        directory,
                        "pause",
                        ledger,
                        grant=active,
                    )
                )
            conflict_document = json.loads(conflict_output.getvalue())
            self.assertEqual(1, conflict_code)
            self.assertEqual("idempotency_conflict", conflict_document["reason_code"])
            self.assertEqual(2, SyntheticTaskLedger(ledger).replay().records_checked)

            recovery_output = io.StringIO()
            with redirect_stdout(recovery_output):
                recovery_code = main(
                    self.ledger_control_args(
                        directory,
                        "pause",
                        ledger,
                        grant=active,
                        idempotency_key="cli-pause-recovery-002",
                    )
                )
            recovery_document = json.loads(recovery_output.getvalue())
            self.assertEqual(0, recovery_code)
            self.assertEqual(4, recovery_document["ledger"]["records_checked"])
            recovered_state = SyntheticTaskLedger(ledger).replay().task(
                "task_company_d0_probe_syn"
            )
            self.assertEqual(2, len(recovered_state.control_attempts))
            self.assertFalse(recovered_state.control_attempts[0].authorization.allowed)
            self.assertTrue(recovered_state.control_attempts[1].authorization.allowed)
            self.assertEqual("paused", recovered_state.control_snapshot.task_status)

            confirmation_ledger = directory / "confirmation-rejected.synthetic.jsonl"
            confirmation_output = io.StringIO()
            with redirect_stdout(confirmation_output):
                confirmation_code = main(
                    self.ledger_control_args(
                        directory,
                        "pause",
                        confirmation_ledger,
                        grant=active,
                        confirmation="cancel",
                        idempotency_key="cli-pause-confirmation-001",
                    )
                )
            confirmation_document = json.loads(confirmation_output.getvalue())
            self.assertEqual(1, confirmation_code)
            self.assertEqual(
                "operator_confirmation_mismatch",
                confirmation_document["reason_code"],
            )
            self.assertEqual(2, confirmation_document["ledger"]["records_checked"])
            confirmation_state = SyntheticTaskLedger(confirmation_ledger).replay().task(
                "task_company_d0_probe_syn"
            )
            self.assertEqual((), confirmation_state.control_audit_events)
            self.assertIsNone(confirmation_state.outcome)

    def test_status_is_compact_and_reports_control_and_worker_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ledger = directory / "status.synthetic.jsonl"
            control_args = self.ledger_control_args(directory, "pause", ledger)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(control_args))

            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(
                    ["synthetic-ledger", "status", "--ledger", str(ledger)]
                )
            document = json.loads(output.getvalue())

            self.assertEqual(0, exit_code)
            self.assertEqual("verified", document["status"])
            self.assertFalse(document["company_authoritative"])
            self.assertEqual("synthetic", document["evidence_status"])
            self.assertEqual(3, document["records_checked"])
            task = document["tasks"][0]
            self.assertEqual("paused", task["task_status"])
            self.assertEqual("active", task["task_grant_status"])
            self.assertEqual("pause", task["last_control_attempt"]["action"])
            self.assertTrue(task["last_control_attempt"]["authorization_allowed"])
            self.assertEqual("not_started", task["worker_lease_status"])
            self.assertEqual("blocked", task["outcome_status"])
            self.assertNotIn("grant_snapshot", task["last_control_attempt"])

    def test_concurrent_denied_control_retries_reuse_one_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ledger = directory / "concurrent-denied.synthetic.jsonl"
            grant = self.operator_grant(directory, expired=True)
            arguments = self.ledger_control_args(
                directory,
                "pause",
                ledger,
                grant=grant,
                idempotency_key="concurrent-denied-001",
            )
            repository = Path(__file__).resolve().parents[1]
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(repository / "src")
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            command = [
                sys.executable,
                "-m",
                "orbit_agent_control_plane.cli",
                *arguments,
            ]
            processes = [
                subprocess.Popen(
                    command,
                    cwd=repository,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(2)
            ]
            outputs = [process.communicate(timeout=10) for process in processes]

            for process, (stdout, stderr) in zip(processes, outputs):
                self.assertEqual(1, process.returncode, msg=f"{stdout}\n{stderr}")
                self.assertEqual(
                    "operator_grant_expired",
                    json.loads(stdout)["reason_code"],
                )
            replay = SyntheticTaskLedger(ledger).replay()
            self.assertEqual(2, replay.records_checked)
            self.assertEqual(
                1,
                len(replay.task("task_company_d0_probe_syn").control_attempts),
            )


if __name__ == "__main__":
    unittest.main()

