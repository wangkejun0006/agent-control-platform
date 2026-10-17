from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from orbit_agent_control_plane.authorization import (
    SyntheticOperatorGrant,
    authorize_control,
)
from orbit_agent_control_plane.control import TaskController
from orbit_agent_control_plane.ids import deterministic_id
from orbit_agent_control_plane.ledger import LedgerError, SyntheticTaskLedger
from orbit_agent_control_plane.loop import default_synthetic_loop
from orbit_agent_control_plane.models import TaskEnvelope


class SyntheticTaskLedgerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.ledger_path = Path(self.temporary.name) / "task-ledger.synthetic.jsonl"
        self.task = TaskEnvelope(
            task_id="task_ledger_d0_syn",
            capability="company.synthetic.echo",
            data_classification="synthetic",
            grant_id="grant_ledger_d0_syn",
            grant_active=True,
        )

    def assert_reason(self, reason_code: str, callback) -> None:
        with self.assertRaises(LedgerError) as caught:
            callback()
        self.assertEqual(reason_code, caught.exception.reason_code)

    def register(self, ledger: SyntheticTaskLedger | None = None):
        selected = ledger or SyntheticTaskLedger(self.ledger_path)
        return selected.register_task(
            self.task,
            idempotency_key=f"register:{self.task.task_id}",
        )

    def authorization(self, action: str):
        grant = SyntheticOperatorGrant(
            version="orbit.synthetic-operator-grant/1",
            grant_id="operator_grant_ledger_control_syn",
            operator_ref="human_operator_ledger_test_syn",
            task_id=self.task.task_id,
            allowed_actions=("pause", "revoke", "cancel", "takeover"),
            issued_at="2026-08-19T01:00:00Z",
            expires_at="2026-08-19T01:15:00Z",
            evidence_status="synthetic",
            synthetic_only=True,
        )
        return authorize_control(
            grant,
            operator_ref=grant.operator_ref,
            task_id=self.task.task_id,
            action=action,
            request_reason=f"D0 synthetic {action} verification",
            checked_at="2026-08-19T01:05:00Z",
            confirmed_action=action,
        )

    @staticmethod
    def reseal(document: dict[str, object]) -> None:
        canonical_payload = json.dumps(
            document["payload"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        payload_digest = "sha256:" + hashlib.sha256(
            canonical_payload.encode("utf-8")
        ).hexdigest()
        document["record_id"] = deterministic_id(
            "ledger",
            str(document["record_type"]),
            str(document["task_id"]),
            str(document["idempotency_key"]),
            payload_digest,
        )
        content = {key: value for key, value in document.items() if key != "record_hash"}
        canonical_content = json.dumps(
            content,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        document["record_hash"] = "sha256:" + hashlib.sha256(
            canonical_content.encode("utf-8")
        ).hexdigest()

    @staticmethod
    def write_documents(path: Path, documents: list[dict[str, object]]) -> None:
        source = "".join(
            json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            for document in documents
        )
        path.write_text(source, encoding="utf-8")
        os.chmod(path, 0o600)

    def test_registration_is_idempotent_across_restart(self) -> None:
        first = self.register()
        second = self.register(SyntheticTaskLedger(self.ledger_path))
        replay = SyntheticTaskLedger(self.ledger_path).replay()

        self.assertTrue(first.appended)
        self.assertFalse(second.appended)
        self.assertEqual(first.record_id, second.record_id)
        self.assertEqual(1, replay.records_checked)
        self.assertEqual(self.task, replay.task(self.task.task_id).task)
        self.assertEqual(1, len(self.ledger_path.read_text(encoding="utf-8").splitlines()))

    def test_each_control_state_and_blocked_outcome_survive_restart(self) -> None:
        for action in ("pause", "revoke", "cancel", "takeover"):
            with self.subTest(action=action):
                path = Path(self.temporary.name) / f"{action}.synthetic.jsonl"
                ledger = SyntheticTaskLedger(path)
                ledger.register_task(
                    self.task,
                    idempotency_key=f"register:{self.task.task_id}",
                )
                transition = TaskController().apply(
                    TaskController.initial(self.task),
                    action,
                    actor_id="human_operator_ledger_test_syn",
                )
                ledger.record_control_attempt(
                    self.authorization(action),
                    transition,
                    idempotency_key=f"control:{self.task.task_id}:{action}",
                )

                restarted = SyntheticTaskLedger(path)
                state = restarted.replay().task(self.task.task_id)
                self.assertEqual(transition.after, state.control_snapshot)
                self.assertEqual((transition.audit_event,), state.control_audit_events)
                self.assertEqual(
                    self.authorization(action),
                    state.control_attempts[0].authorization,
                )
                self.assertEqual(transition, state.control_attempts[0].transition)

                outcome = default_synthetic_loop().run(
                    state.task,
                    control_snapshot=state.control_snapshot,
                    control_audit_events=state.control_audit_events,
                )
                self.assertEqual("blocked", outcome.route_decision.status)
                restarted.record_outcome(
                    outcome,
                    idempotency_key=f"outcome:{self.task.task_id}:{action}",
                )

                final_state = SyntheticTaskLedger(path).replay().task(self.task.task_id)
                self.assertEqual(outcome, final_state.outcome)
                self.assertEqual(3, SyntheticTaskLedger(path).replay().records_checked)

    def test_completed_outcome_is_idempotent_and_rejects_late_control(self) -> None:
        ledger = SyntheticTaskLedger(self.ledger_path)
        self.register(ledger)
        outcome = default_synthetic_loop().run(self.task)
        first = ledger.record_outcome(
            outcome,
            idempotency_key=f"outcome:{self.task.task_id}:run",
        )
        second = SyntheticTaskLedger(self.ledger_path).record_outcome(
            outcome,
            idempotency_key=f"outcome:{self.task.task_id}:run",
        )
        transition = TaskController().apply(
            TaskController.initial(self.task),
            "pause",
            actor_id="human_operator_ledger_test_syn",
        )

        self.assertTrue(first.appended)
        self.assertFalse(second.appended)
        self.assertEqual(outcome, SyntheticTaskLedger(self.ledger_path).replay().task(self.task.task_id).outcome)
        self.assert_reason(
            "control_after_outcome",
            lambda: ledger.record_control_attempt(
                self.authorization("pause"),
                transition,
                idempotency_key=f"control:{self.task.task_id}:late-pause",
            ),
        )

    def test_conflicting_idempotency_and_non_d0_task_fail_closed(self) -> None:
        ledger = SyntheticTaskLedger(self.ledger_path)
        self.register(ledger)
        conflicting = replace(self.task, capability="company.synthetic.other")
        self.assert_reason(
            "idempotency_conflict",
            lambda: ledger.register_task(
                conflicting,
                idempotency_key=f"register:{self.task.task_id}",
            ),
        )

        other_path = Path(self.temporary.name) / "non-d0.synthetic.jsonl"
        non_d0 = replace(self.task, data_classification="medical_private")
        self.assert_reason(
            "data_classification_not_allowed",
            lambda: SyntheticTaskLedger(other_path).register_task(
                non_d0,
                idempotency_key="register:non-d0",
            ),
        )

    def test_modified_or_truncated_record_fails_closed(self) -> None:
        self.register()
        original = self.ledger_path.read_text(encoding="utf-8")
        modified = original.replace("company.synthetic.echo", "company.synthetic.other")
        self.ledger_path.write_text(modified, encoding="utf-8")
        os.chmod(self.ledger_path, 0o600)
        self.assert_reason(
            "record_hash_mismatch",
            lambda: SyntheticTaskLedger(self.ledger_path).replay(),
        )

        self.ledger_path.write_text(original.rstrip("\n"), encoding="utf-8")
        os.chmod(self.ledger_path, 0o600)
        self.assert_reason(
            "truncated_record",
            lambda: SyntheticTaskLedger(self.ledger_path).replay(),
        )

    def test_duplicate_json_key_and_missing_prefix_record_fail_closed(self) -> None:
        self.register()
        original = self.ledger_path.read_text(encoding="utf-8")
        duplicate = original.replace('"sequence":0', '"sequence":0,"sequence":0', 1)
        self.ledger_path.write_text(duplicate, encoding="utf-8")
        os.chmod(self.ledger_path, 0o600)
        self.assert_reason(
            "duplicate_json_key",
            lambda: SyntheticTaskLedger(self.ledger_path).replay(),
        )

        self.ledger_path.write_text(original, encoding="utf-8")
        os.chmod(self.ledger_path, 0o600)
        ledger = SyntheticTaskLedger(self.ledger_path)
        transition = TaskController().apply(
            TaskController.initial(self.task),
            "pause",
            actor_id="human_operator_ledger_test_syn",
        )
        ledger.record_control_attempt(
            self.authorization("pause"),
            transition,
            idempotency_key="control:remove-prefix",
        )
        lines = self.ledger_path.read_text(encoding="utf-8").splitlines(keepends=True)
        self.ledger_path.write_text(lines[1], encoding="utf-8")
        os.chmod(self.ledger_path, 0o600)
        self.assert_reason(
            "sequence_mismatch",
            lambda: SyntheticTaskLedger(self.ledger_path).replay(),
        )

    def test_symlink_ledger_is_rejected(self) -> None:
        target = Path(self.temporary.name) / "target.jsonl"
        target.write_text("", encoding="utf-8")
        os.chmod(target, 0o600)
        link = Path(self.temporary.name) / "ledger-link.jsonl"
        link.symlink_to(target)
        self.assert_reason(
            "ledger_symlink_forbidden",
            lambda: SyntheticTaskLedger(link).replay(),
        )

    def test_missing_and_broad_permission_ledgers_are_rejected(self) -> None:
        self.assert_reason(
            "ledger_not_found",
            lambda: SyntheticTaskLedger(self.ledger_path).replay(),
        )
        self.register()
        os.chmod(self.ledger_path, 0o644)
        self.assert_reason(
            "ledger_permissions_too_broad",
            lambda: SyntheticTaskLedger(self.ledger_path).replay(),
        )

    def test_resealed_but_impossible_control_and_outcome_fail_semantic_replay(self) -> None:
        control_path = Path(self.temporary.name) / "forged-control.synthetic.jsonl"
        control_ledger = SyntheticTaskLedger(control_path)
        control_ledger.register_task(self.task, idempotency_key="register:forged-control")
        transition = TaskController().apply(
            TaskController.initial(self.task),
            "pause",
            actor_id="human_operator_ledger_test_syn",
        )
        control_ledger.record_control_attempt(
            self.authorization("pause"),
            transition,
            idempotency_key="control:forged",
        )
        documents = [
            json.loads(line)
            for line in control_path.read_text(encoding="utf-8").splitlines()
        ]
        documents[-1]["payload"]["transition"]["after"]["task_status"] = "active"
        self.reseal(documents[-1])
        self.write_documents(control_path, documents)
        self.assert_reason(
            "control_transition_invalid",
            lambda: SyntheticTaskLedger(control_path).replay(),
        )

        authorization_path = Path(self.temporary.name) / "forged-auth.synthetic.jsonl"
        authorization_ledger = SyntheticTaskLedger(authorization_path)
        authorization_ledger.register_task(
            self.task,
            idempotency_key="register:forged-auth",
        )
        authorization_ledger.record_control_attempt(
            self.authorization("pause"),
            transition,
            idempotency_key="control:forged-auth",
        )
        documents = [
            json.loads(line)
            for line in authorization_path.read_text(encoding="utf-8").splitlines()
        ]
        documents[-1]["payload"]["operator_authorization"]["confirmed_action"] = "cancel"
        self.reseal(documents[-1])
        self.write_documents(authorization_path, documents)
        self.assert_reason(
            "operator_authorization_invalid",
            lambda: SyntheticTaskLedger(authorization_path).replay(),
        )

        outcome_path = Path(self.temporary.name) / "forged-outcome.synthetic.jsonl"
        outcome_ledger = SyntheticTaskLedger(outcome_path)
        outcome_ledger.register_task(self.task, idempotency_key="register:forged-outcome")
        outcome_ledger.record_outcome(
            default_synthetic_loop().run(self.task),
            idempotency_key="outcome:forged",
        )
        documents = [
            json.loads(line)
            for line in outcome_path.read_text(encoding="utf-8").splitlines()
        ]
        documents[-1]["payload"]["outcome"]["evaluation"]["verdict"] = "fail"
        self.reseal(documents[-1])
        self.write_documents(outcome_path, documents)
        self.assert_reason(
            "outcome_replay_mismatch",
            lambda: SyntheticTaskLedger(outcome_path).replay(),
        )

    def test_denied_control_attempt_is_durable_idempotent_and_has_no_transition(self) -> None:
        ledger = SyntheticTaskLedger(self.ledger_path)
        self.register(ledger)
        grant = SyntheticOperatorGrant(
            version="orbit.synthetic-operator-grant/1",
            grant_id="operator_grant_ledger_control_syn",
            operator_ref="human_operator_ledger_test_syn",
            task_id=self.task.task_id,
            allowed_actions=("pause",),
            issued_at="2026-08-19T01:00:00Z",
            expires_at="2026-08-19T01:15:00Z",
            evidence_status="synthetic",
            synthetic_only=True,
        )
        denied = authorize_control(
            grant,
            operator_ref=grant.operator_ref,
            task_id=self.task.task_id,
            action="pause",
            request_reason="D0 synthetic expired pause verification",
            checked_at="2026-08-19T01:15:00Z",
            confirmed_action="pause",
        )

        first = ledger.record_control_attempt(
            denied,
            None,
            idempotency_key="control:denied-pause-001",
        )
        second = SyntheticTaskLedger(self.ledger_path).record_control_attempt(
            denied,
            None,
            idempotency_key="control:denied-pause-001",
        )
        state = SyntheticTaskLedger(self.ledger_path).replay().task(self.task.task_id)

        self.assertTrue(first.appended)
        self.assertFalse(second.appended)
        self.assertFalse(denied.allowed)
        self.assertEqual(1, len(state.control_attempts))
        self.assertIsNone(state.control_attempts[0].transition)
        self.assertIsNone(state.control_snapshot)
        self.assertEqual((), state.control_audit_events)
        self.assertIsNone(state.outcome)

        transition = TaskController().apply(
            TaskController.initial(self.task),
            "pause",
            actor_id=grant.operator_ref,
        )
        invalid_path = (
            Path(self.temporary.name) / "denied-with-transition.synthetic.jsonl"
        )
        invalid_ledger = SyntheticTaskLedger(invalid_path)
        invalid_ledger.register_task(
            self.task,
            idempotency_key="register:denied-with-transition",
        )
        self.assert_reason(
            "denied_control_has_transition",
            lambda: invalid_ledger.record_control_attempt(
                denied,
                transition,
                idempotency_key="control:denied-with-transition",
            ),
        )

    def test_concurrent_process_retries_produce_one_valid_chain(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(repository / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        command = [
            sys.executable,
            "-m",
            "orbit_agent_control_plane.cli",
            "synthetic-ledger",
            "run",
            "--ledger",
            str(self.ledger_path),
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
            self.assertEqual(0, process.returncode, msg=f"{stdout}\n{stderr}")
        replay = SyntheticTaskLedger(self.ledger_path).replay()
        self.assertEqual(2, replay.records_checked)
        self.assertEqual("pass", replay.task("task_company_d0_probe_syn").outcome.evaluation.verdict)


if __name__ == "__main__":
    unittest.main()

