"""Restartable Company Watchlist Task with synthetic budgets and controls."""

from __future__ import annotations

import fcntl
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Iterator

from .evaluator import CompanyEvaluator
from .ids import COMPANY_TASK_ROUTER_AGENT_ID, deterministic_id
from .ledger import LedgerAppendResult, LedgerError, SyntheticTaskLedger
from .models import (
    AuditEvent,
    EvaluationReport,
    RouteDecision,
    RoutingTarget,
    TaskControlSnapshot,
    TaskEnvelope,
    TaskResult,
    WorkerLease,
)
from .router import CompanyTaskRouter
from .watchlist_process import (
    WatchlistImplementationLock,
    WatchlistProcessAdapter,
    WatchlistProcessError,
    load_watchlist_implementation_lock,
)


WATCHLIST_WORKER_ID = "worker_orbit_dataset_watchlist_coordinator_syn"
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{2,79}$")
_PERIOD = re.compile(r"^[0-9]{4}-(0[1-9]|1[0-2])$")


@dataclass(frozen=True)
class WatchlistTaskOutcome:
    schema_version: str
    status: str
    task: TaskEnvelope
    route_decision: RouteDecision
    result: TaskResult
    evaluation: EvaluationReport
    audit_events: tuple[AuditEvent, ...]
    control_snapshot: TaskControlSnapshot | None
    watchlist_event_ref: str | None
    watchlist_snapshot_digest: str | None
    change_state: str | None
    agent_eligible: bool | None
    domain_status: str
    reason_codes: tuple[str, ...]
    model_invocation_count: int
    worker_invocation_count: int
    monthly_period: str
    monthly_used_before_bytes: int
    monthly_budget_reserved_bytes: int
    monthly_used_after_bytes: int
    registry_implementation_revision: str
    scientific_implementation_revision: str
    runtime_bundle_revision: str
    registry_write_performed: bool
    real_data_download_performed: bool
    release_authorization: bool


@dataclass(frozen=True)
class WatchlistLedgerRun:
    outcome: WatchlistTaskOutcome
    worker_lease: WorkerLease
    append_results: tuple[tuple[str, LedgerAppendResult], ...]


def watchlist_task_envelope(
    target: str,
    run_id: str,
    *,
    implementation_lock: WatchlistImplementationLock | None = None,
) -> TaskEnvelope:
    lock = implementation_lock or load_watchlist_implementation_lock()
    if not _IDENTIFIER.fullmatch(target) or not _IDENTIFIER.fullmatch(run_id):
        raise LedgerError(
            "watchlist_task_identity_invalid",
            "Watchlist target and run id must use the D0 identifier format",
        )
    task_id = deterministic_id("task_synthetic", "dataset-watchlist", target, run_id)
    return TaskEnvelope(
        task_id=task_id,
        capability=lock.capability,
        data_classification=lock.data_classification,
        grant_id=deterministic_id("grant_synthetic", task_id, "watchlist-d0"),
        grant_active=True,
        requested_target_id=lock.coordinator_target_id,
    )


def monthly_budget_reason(
    used_bytes: int,
    candidate_bytes: int,
    *,
    task_limit_bytes: int = 20_000_000_000,
    month_limit_bytes: int = 100_000_000_000,
) -> str | None:
    if (
        type(used_bytes) is not int
        or type(candidate_bytes) is not int
        or used_bytes < 0
        or candidate_bytes <= 0
    ):
        return "watchlist_budget_input_invalid"
    if candidate_bytes > task_limit_bytes:
        return "task_size_limit_exceeded"
    if used_bytes + candidate_bytes > month_limit_bytes:
        return "month_size_limit_exceeded"
    return None


def run_watchlist_with_ledger(
    *,
    ledger_path: Path | str,
    watchlist_ledger_path: Path | str,
    registry_runtime_source: Path | str,
    scientific_runtime_source: Path | str,
    target: str,
    run_id: str,
    fixture: Path | str,
    monthly_period: str,
    process_adapter: WatchlistProcessAdapter | None = None,
) -> WatchlistLedgerRun:
    lock = load_watchlist_implementation_lock()
    if not _PERIOD.fullmatch(monthly_period):
        raise LedgerError(
            "watchlist_monthly_period_invalid", "Monthly period must use YYYY-MM"
        )
    task = watchlist_task_envelope(target, run_id, implementation_lock=lock)
    ledger = SyntheticTaskLedger(ledger_path)
    adapter = process_adapter or WatchlistProcessAdapter(
        registry_runtime_source,
        scientific_runtime_source,
        implementation_lock=lock,
    )
    appends: list[tuple[str, LedgerAppendResult]] = []

    with _watchlist_run_lock(Path(ledger_path)):
        appends.append(
            (
                "task",
                ledger.register_task(task, idempotency_key=f"register:{task.task_id}"),
            )
        )
        state = ledger.replay().task(task.task_id)
        if state.watchlist_outcome is not None and state.worker_lease is not None:
            if state.worker_lease.status == "active":
                closed = _closed_lease(state.worker_lease, state.watchlist_outcome, state)
                appends.append(
                    (
                        "worker_lease_close",
                        ledger.close_worker_lease(
                            closed, idempotency_key=f"lease-close:{closed.lease_id}"
                        ),
                    )
                )
                state = ledger.replay().task(task.task_id)
            return WatchlistLedgerRun(
                state.watchlist_outcome, state.worker_lease, tuple(appends)
            )
        if _control_blocks(state.control_snapshot):
            raise LedgerError(
                "task_control_blocks_worker_start",
                "Task control blocks Watchlist Worker Lease creation",
            )

        route = _route(task, state.control_snapshot, state.control_audit_events, lock)
        if route.status != "routed":
            raise LedgerError("watchlist_route_blocked", "Watchlist Task was not routed")
        lease = state.worker_lease
        if lease is None:
            lease_id = deterministic_id(
                "lease", task.task_id, WATCHLIST_WORKER_ID, lock.bundle_revision
            )
            lease = WorkerLease(
                lease_id=lease_id,
                task_id=task.task_id,
                worker_id=WATCHLIST_WORKER_ID,
                implementation_revision=lock.bundle_revision,
                status="active",
                revision=0,
                cancellation_requested=False,
                last_event_ref=deterministic_id("audit", lease_id, "started"),
            )
            appends.append(
                (
                    "worker_lease_start",
                    ledger.start_worker_lease(
                        lease, idempotency_key=f"lease-start:{lease.lease_id}"
                    ),
                )
            )

        def cancellation_probe() -> bool:
            return _control_blocks(ledger.replay().task(task.task_id).control_snapshot)

        event: dict[str, Any] | None = None
        domain: dict[str, Any] | None = None
        process_error: WatchlistProcessError | None = None
        monthly_used = ledger.replay().monthly_used_bytes(monthly_period)
        try:
            event = adapter.observe(
                target=target,
                run_id=run_id,
                watchlist_ledger=watchlist_ledger_path,
                fixture=fixture,
                cancellation_probe=cancellation_probe,
            )
            if not str(event["observed_at"]).startswith(monthly_period + "-"):
                raise WatchlistProcessError(
                    "watchlist_period_binding_invalid",
                    "Watchlist observation is outside the declared monthly period",
                )
            size = event["snapshot"]["declared_size_bytes"]
            budget_reason = None
            if event["candidate_changed"] and event["agent_eligible"]:
                budget_reason = monthly_budget_reason(
                    monthly_used,
                    size,
                    task_limit_bytes=lock.task_limit_bytes,
                    month_limit_bytes=lock.month_limit_bytes,
                )
            if budget_reason is not None:
                domain = _budget_blocked_domain(event, task, route, monthly_used, lock, budget_reason)
            else:
                domain = adapter.evaluate(
                    event,
                    task=task,
                    route_decision=route,
                    monthly_used_before_bytes=monthly_used,
                    cancellation_probe=cancellation_probe,
                )
        except WatchlistProcessError as error:
            process_error = error

        refreshed = ledger.replay().task(task.task_id)
        outcome = _normalize_outcome(
            task=task,
            route=route,
            control_snapshot=refreshed.control_snapshot,
            control_audit_events=refreshed.control_audit_events,
            event=event,
            domain=domain,
            process_error=process_error,
            monthly_period=monthly_period,
            monthly_used_before_bytes=monthly_used,
            implementation_lock=lock,
        )
        appends.append(
            (
                "watchlist_outcome",
                ledger.record_watchlist_outcome(
                    outcome, idempotency_key=f"watchlist-outcome:{task.task_id}"
                ),
            )
        )
        state = ledger.replay().task(task.task_id)
        closed = _closed_lease(lease, outcome, state)
        appends.append(
            (
                "worker_lease_close",
                ledger.close_worker_lease(
                    closed, idempotency_key=f"lease-close:{lease.lease_id}"
                ),
            )
        )
        return WatchlistLedgerRun(
            outcome,
            ledger.replay().task(task.task_id).worker_lease,
            tuple(appends),
        )


def watchlist_ledger_document(run: WatchlistLedgerRun) -> dict[str, Any]:
    return {
        "status": run.outcome.status,
        "evidence_status": "synthetic",
        "company_authoritative": False,
        "production_authorization": False,
        "worker_lease": asdict(run.worker_lease),
        "outcome": asdict(run.outcome),
        "append_results": {name: asdict(value) for name, value in run.append_results},
    }


def _route(
    task: TaskEnvelope,
    snapshot: TaskControlSnapshot | None,
    control_audits: tuple[AuditEvent, ...],
    lock: WatchlistImplementationLock,
) -> RouteDecision:
    target = RoutingTarget(
        target_id=lock.coordinator_target_id,
        capabilities=frozenset({lock.capability}),
        allowed_data_classifications=frozenset({lock.data_classification}),
    )
    return CompanyTaskRouter().route(task, (target,), snapshot, control_audits)


def _budget_blocked_domain(
    event: dict[str, Any],
    task: TaskEnvelope,
    route: RouteDecision,
    monthly_used: int,
    lock: WatchlistImplementationLock,
    reason: str,
) -> dict[str, Any]:
    return {
        "schema_version": lock.scientific.schema_version,
        "watchlist_event_ref": event["event_id"],
        "watchlist_snapshot_digest": event["snapshot_digest"],
        "task_binding": {
            "task_id": task.task_id,
            "route_decision_ref": route.decision_id,
            "execution_grant_ref": task.grant_id,
            "monthly_used_before_bytes": monthly_used,
            "monthly_limit_bytes": lock.month_limit_bytes,
            "max_concurrency": 1,
            "model_route_ref": lock.model_route_ref,
            "max_model_cost_cny": lock.max_model_cost_cny,
        },
        "status": "blocked",
        "reason_codes": [reason],
        "model_invocation_count": 0,
        "worker_invocation_count": 0,
        "closed_loop_result": None,
        "model_audit": [],
        "registry_write_performed": False,
        "real_data_download_performed": False,
    }


def _normalize_outcome(
    *,
    task: TaskEnvelope,
    route: RouteDecision,
    control_snapshot: TaskControlSnapshot | None,
    control_audit_events: tuple[AuditEvent, ...],
    event: dict[str, Any] | None,
    domain: dict[str, Any] | None,
    process_error: WatchlistProcessError | None,
    monthly_period: str,
    monthly_used_before_bytes: int,
    implementation_lock: WatchlistImplementationLock,
) -> WatchlistTaskOutcome:
    if process_error is not None:
        domain_status = "blocked"
        reasons = (process_error.reason_code,)
        model_count = 0
        worker_count = 0
    else:
        assert domain is not None
        domain_status = domain["status"]
        reasons = tuple(domain["reason_codes"])
        model_count = domain["model_invocation_count"]
        worker_count = domain["worker_invocation_count"]
    event_ref = None if event is None else event["event_id"]
    snapshot_digest = None if event is None else event["snapshot_digest"]
    change_state = None if event is None else event["change_state"]
    agent_eligible = None if event is None else event["agent_eligible"]
    reserved = (
        event["snapshot"]["declared_size_bytes"]
        if event is not None and domain_status == "completed" and worker_count == 1
        else 0
    )
    route_audit = AuditEvent(
        event_id=f"audit_{route.decision_id}",
        task_id=task.task_id,
        event_type="route_decision_recorded",
        subject_ref=COMPANY_TASK_ROUTER_AGENT_ID,
    )
    completion = AuditEvent(
        event_id=deterministic_id(
            "audit", task.task_id, "watchlist-task", domain_status, event_ref or "none"
        ),
        task_id=task.task_id,
        event_type="watchlist_task_completed",
        subject_ref=implementation_lock.coordinator_target_id,
    )
    accepted = domain_status in {"completed", "skipped"}
    result = TaskResult(
        result_id=deterministic_id(
            "result", task.task_id, event_ref or "none", domain_status, *reasons
        ),
        task_id=task.task_id,
        target_id=implementation_lock.coordinator_target_id,
        status="completed" if accepted else "failed",
        output_ref=(
            f"artifact://synthetic/{task.task_id}/watchlist/{event_ref or 'blocked'}"
        ),
        audit_event_refs=(completion.event_id,),
        side_effects=(),
    )
    audits = control_audit_events + (route_audit, completion)
    evaluation = CompanyEvaluator().evaluate(
        task=task,
        route_decision=route,
        result=result,
        audit_events=audits,
        subject_agent_id=implementation_lock.coordinator_target_id,
    )
    status = "pass" if evaluation.verdict == "pass" else "blocked"
    all_reasons = tuple(dict.fromkeys(reasons + evaluation.reason_codes))
    return WatchlistTaskOutcome(
        schema_version=implementation_lock.task_schema_version,
        status=status,
        task=task,
        route_decision=route,
        result=result,
        evaluation=evaluation,
        audit_events=audits,
        control_snapshot=control_snapshot,
        watchlist_event_ref=event_ref,
        watchlist_snapshot_digest=snapshot_digest,
        change_state=change_state,
        agent_eligible=agent_eligible,
        domain_status=domain_status,
        reason_codes=all_reasons,
        model_invocation_count=model_count,
        worker_invocation_count=worker_count,
        monthly_period=monthly_period,
        monthly_used_before_bytes=monthly_used_before_bytes,
        monthly_budget_reserved_bytes=reserved,
        monthly_used_after_bytes=monthly_used_before_bytes + reserved,
        registry_implementation_revision=implementation_lock.registry.implementation_commit,
        scientific_implementation_revision=implementation_lock.scientific.implementation_commit,
        runtime_bundle_revision=implementation_lock.bundle_revision,
        registry_write_performed=False,
        real_data_download_performed=False,
        release_authorization=False,
    )


def _control_blocks(snapshot: TaskControlSnapshot | None) -> bool:
    return snapshot is not None and (
        snapshot.task_status != "active"
        or snapshot.grant_status != "active"
        or snapshot.owner_kind != "control_plane"
    )


def _closed_lease(
    lease: WorkerLease,
    outcome: WatchlistTaskOutcome,
    state: Any,
) -> WorkerLease:
    cancelled = "watchlist_task_cancelled" in outcome.reason_codes or _control_blocks(
        state.control_snapshot
    )
    status = "cancelled" if cancelled else ("completed" if outcome.status == "pass" else "failed")
    return replace(
        lease,
        status=status,
        revision=lease.revision + 1,
        cancellation_requested=cancelled,
        last_event_ref=deterministic_id("audit", lease.lease_id, status),
    )


@contextmanager
def _watchlist_run_lock(ledger_path: Path) -> Iterator[None]:
    if not ledger_path.is_absolute():
        raise LedgerError("ledger_path_not_absolute", "Watchlist ledger path must be absolute")
    parent = ledger_path.parent
    if not parent.exists() or not parent.is_dir():
        raise LedgerError("ledger_parent_missing", "Watchlist ledger parent is missing")
    path = parent / (ledger_path.name + ".watchlist-run.lock")
    if path.is_symlink():
        raise LedgerError("watchlist_run_lock_symlink_forbidden", "Run lock may not be a symlink")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise LedgerError("watchlist_run_lock_open_failed", "Run lock cannot be opened") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise LedgerError("watchlist_run_lock_invalid", "Run lock must be owner-only")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise LedgerError(
                "watchlist_concurrency_limit_reached",
                "Only one Watchlist Task may run concurrently",
            ) from error
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

