"""Restartable D0 Dataset execution with a ledger-backed Worker Lease."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .dataset_agent_process import (
    DATASET_AGENT_WORKER_ID,
    DatasetCompanyLoopOutcome,
    create_dataset_agent_company_loop,
    dataset_synthetic_task,
    load_dataset_agent_implementation_lock,
)
from .ids import deterministic_id
from .ledger import LedgerAppendResult, LedgerError, SyntheticTaskLedger
from .models import WorkerLease


@dataclass(frozen=True)
class DatasetLedgerRun:
    outcome: DatasetCompanyLoopOutcome
    worker_lease: WorkerLease
    append_results: tuple[tuple[str, LedgerAppendResult], ...]


def _control_blocks(state: Any) -> bool:
    snapshot = state.control_snapshot
    return snapshot is not None and (
        snapshot.task_status != "active"
        or snapshot.grant_status != "active"
        or snapshot.owner_kind != "control_plane"
    )


def run_dataset_with_ledger(
    ledger_path: Path | str,
    platform_root: Path | str,
) -> DatasetLedgerRun:
    """Run or replay one synthetic Dataset task without duplicating execution."""

    ledger = SyntheticTaskLedger(ledger_path)
    task = dataset_synthetic_task()
    lock = load_dataset_agent_implementation_lock()
    appends: list[tuple[str, LedgerAppendResult]] = []
    appends.append(
        (
            "task",
            ledger.register_task(
                task,
                idempotency_key=f"register:{task.task_id}",
            ),
        )
    )
    state = ledger.replay().task(task.task_id)
    if state.dataset_outcome is not None and state.worker_lease is not None:
        if state.worker_lease.status == "active":
            closed = _closed_lease(state.worker_lease, state.dataset_outcome, state)
            appends.append(
                (
                    "worker_lease_close",
                    ledger.close_worker_lease(
                        closed,
                        idempotency_key=f"lease-close:{closed.lease_id}",
                    ),
                )
            )
            state = ledger.replay().task(task.task_id)
        return DatasetLedgerRun(
            state.dataset_outcome,
            state.worker_lease,
            tuple(appends),
        )
    if _control_blocks(state):
        raise LedgerError(
            "task_control_blocks_worker_start",
            "Task control blocks Dataset Worker Lease creation",
        )

    lease = state.worker_lease
    if lease is None:
        lease_id = deterministic_id(
            "lease",
            task.task_id,
            DATASET_AGENT_WORKER_ID,
            lock.implementation_commit,
        )
        lease = WorkerLease(
            lease_id=lease_id,
            task_id=task.task_id,
            worker_id=DATASET_AGENT_WORKER_ID,
            implementation_revision=lock.implementation_commit,
            status="active",
            revision=0,
            cancellation_requested=False,
            last_event_ref=deterministic_id("audit", lease_id, "started"),
        )
        appends.append(
            (
                "worker_lease_start",
                ledger.start_worker_lease(
                    lease,
                    idempotency_key=f"lease-start:{lease.lease_id}",
                ),
            )
        )

    def cancellation_probe() -> bool:
        return _control_blocks(ledger.replay().task(task.task_id))

    state = ledger.replay().task(task.task_id)
    outcome = create_dataset_agent_company_loop(
        platform_root,
        cancellation_probe=cancellation_probe,
    ).run(
        task,
        control_snapshot=state.control_snapshot,
        control_audit_events=state.control_audit_events,
    )
    refreshed = ledger.replay().task(task.task_id)
    if refreshed.control_snapshot != state.control_snapshot:
        prior_control_ids = {event.event_id for event in state.control_audit_events}
        new_controls = tuple(
            event
            for event in refreshed.control_audit_events
            if event.event_id not in prior_control_ids
        )
        outcome = replace(
            outcome,
            company_outcome=replace(
                outcome.company_outcome,
                control_snapshot=refreshed.control_snapshot,
                audit_events=new_controls + outcome.company_outcome.audit_events,
            ),
        )
    appends.append(
        (
            "dataset_outcome",
            ledger.record_dataset_outcome(
                outcome,
                idempotency_key=f"dataset-outcome:{task.task_id}",
            ),
        )
    )
    state = ledger.replay().task(task.task_id)
    closed = _closed_lease(lease, outcome, state)
    appends.append(
        (
            "worker_lease_close",
            ledger.close_worker_lease(
                closed,
                idempotency_key=f"lease-close:{lease.lease_id}",
            ),
        )
    )
    return DatasetLedgerRun(
        outcome,
        ledger.replay().task(task.task_id).worker_lease,
        tuple(appends),
    )


def _closed_lease(
    lease: WorkerLease,
    outcome: DatasetCompanyLoopOutcome,
    state: Any,
) -> WorkerLease:
    cancelled = (
        "dataset_agent_process_cancelled" in outcome.reason_codes
        or _control_blocks(state)
    )
    status = "cancelled" if cancelled else ("completed" if outcome.status == "pass" else "failed")
    return replace(
        lease,
        status=status,
        revision=lease.revision + 1,
        cancellation_requested=cancelled,
        last_event_ref=deterministic_id("audit", lease.lease_id, status),
    )


def dataset_ledger_document(run: DatasetLedgerRun) -> dict[str, Any]:
    return {
        "status": run.outcome.status,
        "evidence_status": "synthetic",
        "company_authoritative": False,
        "worker_lease": asdict(run.worker_lease),
        "outcome": asdict(run.outcome),
        "append_results": {
            name: asdict(result) for name, result in run.append_results
        },
    }

