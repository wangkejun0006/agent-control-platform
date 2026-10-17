"""Offline fictional workflow using the original Router, Evaluator and ledger.

The only added execution port uses an explicitly frozen SHA-256 source snapshot.
It does not pretend that the old cross-repository Git lock has been verified.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from orbit_agent_control_plane.authorization import (
    SyntheticOperatorGrant,
    authorize_control,
)
from orbit_agent_control_plane.control import TaskController
from orbit_agent_control_plane.dataset_agent_process import (
    DATASET_AGENT_ID,
    DATASET_AGENT_WORKER_ID,
    BoundedProcessRunner,
    DatasetAgentCompanyLoop,
    DatasetAgentExecutionEvidence,
    DatasetAgentProcessError,
    DatasetAgentProcessExecution,
    _load_unique_json,
    dataset_synthetic_task,
)
from orbit_agent_control_plane.ids import deterministic_id
from orbit_agent_control_plane.ledger import LedgerError, SyntheticTaskLedger
from orbit_agent_control_plane.lifecycle import (
    AgentCandidate,
    LifecycleError,
    LifecycleEvaluation,
    SyntheticAgentLifecycleLedger,
    SyntheticApprovalDecision,
)
from orbit_agent_control_plane.models import AuditEvent, TaskResult, WorkerLease

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = (
    "success",
    "bad_quality",
    "wrong_task",
    "duplicate_json",
    "timeout",
    "cancel",
    "output_limit",
    "missing_grant",
    "unknown_capability",
    "private_input",
)


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def source_revision() -> str:
    lock_path = ROOT / "showcase/source-lock.json"
    if lock_path.is_symlink():
        raise ValueError("demo_source_lock_symlink")
    lock = _load_unique_json(lock_path.read_bytes())
    if (
        set(lock) != {"schema_version", "files", "snapshot_digest"}
        or lock["schema_version"] != "orbit.demo-source/1"
    ):
        raise ValueError("demo_source_lock_invalid")
    expected_paths = {
        "showcase/worker.py",
        "showcase/fixtures/catalog.json",
        "showcase/fixtures/expected.json",
    }
    if set(lock["files"]) != expected_paths:
        raise ValueError("demo_source_file_set_drift")
    for name, expected in lock["files"].items():
        path = ROOT / name
        if (
            path.is_symlink()
            or not path.is_file()
            or digest(path.read_bytes()) != expected
        ):
            raise ValueError("demo_source_digest_mismatch")
    actual = digest(
        json.dumps(lock["files"], sort_keys=True, separators=(",", ":")).encode()
    )
    if actual != lock["snapshot_digest"]:
        raise ValueError("demo_snapshot_digest_mismatch")
    return actual


def control_cancel(ledger: SyntheticTaskLedger, task) -> None:
    now = datetime.now(timezone.utc)
    stamp = lambda value: value.isoformat().replace("+00:00", "Z")
    grant = SyntheticOperatorGrant(
        version="orbit.synthetic-operator-grant/1",
        grant_id="operator_grant_demo_cancel_syn",
        operator_ref="human_operator_demo_reviewer_syn",
        task_id=task.task_id,
        allowed_actions=("cancel",),
        issued_at=stamp(now - timedelta(seconds=1)),
        expires_at=stamp(now + timedelta(minutes=5)),
        evidence_status="synthetic",
        synthetic_only=True,
    )
    authorization = authorize_control(
        grant,
        operator_ref=grant.operator_ref,
        task_id=task.task_id,
        action="cancel",
        request_reason="Scripted fictional reviewer cancellation",
        checked_at=stamp(now),
        confirmed_action="cancel",
    )
    state = ledger.replay().task(task.task_id)
    snapshot = state.control_snapshot or TaskController().initial(task)
    transition = TaskController().apply(snapshot, "cancel", actor_id=grant.operator_ref)
    ledger.record_control_attempt(
        authorization, transition, idempotency_key="demo:cancel"
    )


class FrozenOfflinePort:
    """Explicit no-model port; reuses the original bounded process runner."""

    def __init__(self, *, scenario, revision, ledger, task):
        self.scenario, self.revision, self.ledger, self.task = (
            scenario,
            revision,
            ledger,
            task,
        )
        self.invocations = 0
        self.receipt = None
        self.cancelled_at = None

    def execute(self, task, route):
        if source_revision() != self.revision:
            raise DatasetAgentProcessError(
                "offline_source_revision_drift", "source changed"
            )
        self.invocations += 1
        started = time.monotonic()

        def cancellation_probe():
            if (
                self.scenario == "cancel"
                and time.monotonic() - started >= 0.15
                and self.cancelled_at is None
            ):
                control_cancel(self.ledger, self.task)
                self.cancelled_at = time.monotonic()
            state = self.ledger.replay().task(task.task_id)
            return (
                state.control_snapshot is not None
                and state.control_snapshot.task_status != "active"
            )

        capture = BoundedProcessRunner().run(
            (
                sys.executable,
                "-I",
                "-S",
                str(ROOT / "showcase/worker.py"),
                task.task_id,
                self.scenario,
            ),
            cwd=ROOT / "showcase",
            environment={"PYTHONHASHSEED": "0"},
            timeout_seconds=0.35 if self.scenario == "timeout" else 3.0,
            max_stdout_bytes=8192,
            max_stderr_bytes=4096,
            cancellation_probe=cancellation_probe,
        )
        if capture.returncode != 0:
            raise DatasetAgentProcessError("offline_worker_failed", "worker failed")
        doc = _load_unique_json(capture.stdout)
        self.receipt = doc
        expected_keys = {
            "schema_version",
            "task_id",
            "fixture_sha256",
            "artifact",
            "model_calls",
            "cost_cny",
            "external_side_effects",
        }
        if (
            not isinstance(doc, dict)
            or set(doc) != expected_keys
            or doc["schema_version"] != "orbit.offline-receipt/1"
        ):
            raise DatasetAgentProcessError(
                "offline_receipt_contract_invalid", "contract invalid"
            )
        if doc["task_id"] != task.task_id:
            raise DatasetAgentProcessError(
                "offline_receipt_task_mismatch", "task mismatch"
            )
        expected = json.loads((ROOT / "showcase/fixtures/expected.json").read_text())
        if (
            doc["fixture_sha256"]
            != hashlib.sha256(
                (ROOT / "showcase/fixtures/catalog.json").read_bytes()
            ).hexdigest()
            or type(doc["model_calls"]) is not int
            or doc["model_calls"] != 0
            or doc["cost_cny"] != "0"
            or doc["external_side_effects"] != []
        ):
            raise DatasetAgentProcessError(
                "offline_receipt_boundary_violated", "boundary violated"
            )
        # Golden fixture is independently authored; exact JSON types matter (True != 1 here).
        if json.dumps(doc["artifact"], sort_keys=True) != json.dumps(
            expected, sort_keys=True
        ):
            raise DatasetAgentProcessError(
                "offline_artifact_quality_failed", "golden acceptance failed"
            )
        raw = json.dumps(
            doc["artifact"], sort_keys=True, separators=(",", ":")
        ).encode()
        refs = tuple(
            deterministic_id("audit", task.task_id, name)
            for name in ("observed", "planned", "received", "evaluated")
        )
        receipt_id = deterministic_id("receipt", task.task_id, digest(raw))
        evidence = DatasetAgentExecutionEvidence(
            implementation_revision=self.revision,
            domain_schema_version="orbit.offline-receipt/1",
            agent_id=DATASET_AGENT_ID,
            runtime_family="frozen_offline_python_worker",
            receipt_id=receipt_id,
            receipt_status="verified",
            actual_size_bytes=len(raw),
            actual_sha256=hashlib.sha256(raw).hexdigest(),
            domain_evaluation_report_id=deterministic_id("evaluation", receipt_id),
            domain_evaluation_decision="pass",
            domain_audit_event_refs=refs,
            model_provider_id="synthetic-deterministic",
            model_id="structured-model-fixture-v1",
            input_tokens=0,
            output_tokens=0,
            cached_input_tokens=0,
            model_cost_cny="0",
            storage_write_performed=False,
            data_use_approved=False,
            registry_publish_performed=False,
            approved_asset_release_created=False,
        )
        audit = AuditEvent(
            deterministic_id("audit", receipt_id),
            task.task_id,
            "dataset_agent_process_completed",
            DATASET_AGENT_ID,
        )
        result = TaskResult(
            deterministic_id("result", receipt_id),
            task.task_id,
            route.target_id,
            "completed",
            f"artifact://synthetic/{task.task_id}/{receipt_id}",
            (audit.event_id,),
        )
        return DatasetAgentProcessExecution(result, audit, evidence)


def run_scenario(root: Path, scenario: str) -> dict:
    if scenario not in SCENARIOS:
        raise ValueError("unknown_scenario")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (
        root.is_symlink()
        or root.stat().st_uid != os.getuid()
        or root.stat().st_mode & 0o077
    ):
        raise ValueError("owner_only_state_root_required")
    fd = os.open(
        root / f"{scenario}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("owner_only_attempt_lock_required")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("attempt_already_running") from error
        return _run_scenario(root, scenario)
    finally:
        os.close(fd)


def _run_scenario(root: Path, scenario: str) -> dict:
    if scenario not in SCENARIOS:
        raise ValueError("unknown_scenario")
    revision = source_revision()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (
        root.is_symlink()
        or root.stat().st_uid != os.getuid()
        or root.stat().st_mode & 0o077
    ):
        raise ValueError("owner_only_state_root_required")
    ledger = SyntheticTaskLedger(root / f"{scenario}.jsonl")
    task = replace(dataset_synthetic_task(), task_id=f"task_synthetic_orbit_{scenario}")
    if scenario == "missing_grant":
        task = replace(task, grant_active=False)
    elif scenario == "unknown_capability":
        task = replace(task, capability="unregistered.operation")
    elif scenario == "private_input":
        # Ledger only admits D0 inputs: test this refusal before execution.
        try:
            ledger.register_task(
                replace(task, data_classification="private"),
                idempotency_key=f"register:{scenario}",
            )
        except LedgerError as error:
            return {
                "scenario": scenario,
                "status": "blocked",
                "reason_codes": [error.reason_code],
                "worker_invocations": 0,
            }
        raise AssertionError("private input was admitted")
    ledger.register_task(task, idempotency_key=f"register:{scenario}")
    state = ledger.replay().task(task.task_id)
    if state.dataset_outcome is not None:
        if state.worker_lease.status == "active":
            _close_lease(ledger, state.worker_lease, state.dataset_outcome)
        return {
            "scenario": scenario,
            "status": state.dataset_outcome.status,
            "replayed": True,
            "worker_invocations": 0,
            "ledger": asdict(ledger.replay()),
        }
    lease_id = deterministic_id(
        "lease", task.task_id, DATASET_AGENT_WORKER_ID, revision
    )
    lease = state.worker_lease
    if lease is not None:
        # Uncertain execution after a crash is never silently retried.
        raise ValueError("unclosed_attempt_requires_review")
    lease = WorkerLease(
        lease_id,
        task.task_id,
        DATASET_AGENT_WORKER_ID,
        revision,
        "active",
        0,
        False,
        deterministic_id("audit", lease_id, "start"),
    )
    ledger.start_worker_lease(lease, idempotency_key=f"start:{scenario}")
    port = FrozenOfflinePort(
        scenario=scenario, revision=revision, ledger=ledger, task=task
    )
    outcome = DatasetAgentCompanyLoop(port).run(task)
    latest = ledger.replay().task(task.task_id)
    if latest.control_snapshot is not None:
        outcome = replace(
            outcome,
            company_outcome=replace(
                outcome.company_outcome,
                control_snapshot=latest.control_snapshot,
                audit_events=latest.control_audit_events
                + outcome.company_outcome.audit_events,
            ),
        )
    ledger.record_dataset_outcome(outcome, idempotency_key=f"outcome:{scenario}")
    _close_lease(ledger, lease, outcome)
    return {
        "scenario": scenario,
        "status": outcome.status,
        "reason_codes": outcome.reason_codes,
        "worker_invocations": port.invocations,
        "receipt": port.receipt,
        "replayed": False,
        "ledger": asdict(ledger.replay()),
    }


def _close_lease(ledger, lease, outcome):
    cancelled = "dataset_agent_process_cancelled" in outcome.reason_codes
    status = (
        "cancelled"
        if cancelled
        else ("completed" if outcome.status == "pass" else "failed")
    )
    ledger.close_worker_lease(
        replace(
            lease,
            status=status,
            revision=lease.revision + 1,
            cancellation_requested=cancelled,
            last_event_ref=deterministic_id("audit", lease.lease_id, status),
        ),
        idempotency_key=f"close:{lease.lease_id}",
    )


def lifecycle_demo(root: Path) -> dict:
    path = root / "lifecycle.jsonl"
    ledger = SyntheticAgentLifecycleLedger(path)
    candidate = AgentCandidate(
        "agt_orbit_dataset_demo_syn",
        source_revision(),
        "definition_orbit_dataset_syn",
        "binding_orbit_dataset_syn",
        "role_demo_owner_syn",
        "agent_system_demo_syn",
        ("new_stable_agent", "purpose"),
        True,
    )
    ledger.register_candidate(candidate, idempotency_key="candidate:demo")
    blocked = None
    try:
        ledger.activate_stable(
            candidate.agent_id,
            approval_decision_ref="decision_missing_syn",
            idempotency_key="activate:missing",
        )
    except LifecycleError as error:
        blocked = error.reason_code
    evaluation = LifecycleEvaluation(
        "evaluation_demo_syn",
        candidate.agent_id,
        candidate.release_digest,
        "agt_independent_fixture_evaluator_syn",
        "pass",
        "recommend",
        ("evidence_offline_suite_syn",),
        (),
    )
    ledger.record_evaluation(evaluation, idempotency_key="evaluation:demo")
    approval = SyntheticApprovalDecision(
        "decision_demo_activate_syn",
        "activate",
        candidate.agent_id,
        candidate.release_digest,
        "human_demo_reviewer_syn",
        "approve",
        "Scripted fictional approval fixture",
    )
    ledger.record_approval(approval, idempotency_key="approval:demo")
    ledger.activate_stable(
        candidate.agent_id,
        approval_decision_ref=approval.decision_id,
        idempotency_key="activate:demo",
    )
    return {
        "without_approval": blocked,
        "scripted_fixture_only": True,
        "state": asdict(ledger.replay()),
    }


def run_demo(state_root: Path) -> dict:
    cases = [run_scenario(state_root, case) for case in SCENARIOS]
    replay = run_scenario(state_root, "success")
    lifecycle = lifecycle_demo(state_root)
    from .composition import run as compose_demo

    composition = compose_demo(state_root, source_revision())
    checks = {
        case["scenario"]: case["status"]
        == ("pass" if case["scenario"] == "success" else "blocked")
        for case in cases
    }
    expected_reasons = {
        "bad_quality": "offline_artifact_quality_failed",
        "wrong_task": "offline_receipt_task_mismatch",
        "duplicate_json": "dataset_agent_duplicate_json_key",
        "timeout": "dataset_agent_process_timeout",
        "cancel": "dataset_agent_process_cancelled",
        "output_limit": "dataset_agent_stdout_limit_exceeded",
        "missing_grant": "grant_inactive_or_expired",
        "unknown_capability": "capability_not_supported",
        "private_input": "data_classification_not_allowed",
    }
    for case in cases:
        if case["scenario"] in expected_reasons:
            reasons = case.get("reason_codes", ())
            if case.get("replayed"):
                reasons = case["ledger"]["tasks"][0]["dataset_outcome"]["reason_codes"]
            checks[case["scenario"]] &= expected_reasons[case["scenario"]] in reasons
    checks["idempotent_replay"] = (
        replay["replayed"] and replay["worker_invocations"] == 0
    )
    checks["approval_gate"] = (
        lifecycle["without_approval"] == "approval_decision_missing"
    )
    checks["runtime_composition"] = (
        len(composition["composition"]["tool_releases"]) == 3
    )
    checks["tool_operation_gate"] = (
        composition["widened_operation_refusal"] == "active_tool_release_not_found"
    )
    return {
        "schema_version": "orbit.offline-demo/1",
        "evidence_status": "synthetic",
        "model_calls": 0,
        "cost_cny": "0",
        "checks": checks,
        "passed": all(checks.values()),
        "cases": cases,
        "lifecycle": lifecycle,
        "composition": composition,
        "production_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = run_demo(args.state_root)
    if args.report:
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(
        json.dumps(
            {"passed": report["passed"], "checks": report["checks"], "model_calls": 0},
            indent=2,
        )
    )
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
