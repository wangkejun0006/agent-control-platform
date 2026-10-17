"""Tamper-evident local ledger for D0 synthetic control-plane evidence.

This file is deliberately not a production or company-authoritative Task
Ledger. It provides a restartable, append-only test boundary without models,
network access, external services, credentials, or business data.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .authorization import (
    AuthorizationError,
    OperatorAuthorizationDecision,
    authorize_control,
    grant_from_mapping,
)
from .control import TaskController
from .ids import deterministic_id
from .models import (
    AuditEvent,
    ClosedLoopOutcome,
    ControlTransition,
    EvaluationReport,
    RouteDecision,
    TaskControlSnapshot,
    TaskEnvelope,
    TaskResult,
    WorkerLease,
)


LEDGER_VERSION = "orbit.synthetic-task-ledger/5"
GENESIS_HASH = "sha256:" + ("0" * 64)
MAX_LEDGER_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
ALLOWED_RECORD_TYPES = frozenset(
    {
        "task_registered",
        "control_attempt_recorded",
        "closed_loop_recorded",
        "worker_lease_started",
        "dataset_closed_loop_recorded",
        "watchlist_task_recorded",
        "disease_r1_attempt_recorded",
        "worker_lease_closed",
    }
)
ALLOWED_DATA_CLASSIFICATIONS = frozenset({"synthetic", "public"})
_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RECORD_KEYS = frozenset(
    {
        "ledger_version",
        "sequence",
        "record_id",
        "record_type",
        "task_id",
        "idempotency_key",
        "previous_record_hash",
        "payload",
        "record_hash",
    }
)


class LedgerError(ValueError):
    """Fail-closed ledger error with a stable reason code."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class LedgerAppendResult:
    record_id: str
    sequence: int
    record_hash: str
    appended: bool


@dataclass(frozen=True)
class ControlAttemptEvidence:
    idempotency_key: str
    authorization: OperatorAuthorizationDecision
    transition: ControlTransition | None


@dataclass(frozen=True)
class ReplayedTaskState:
    task: TaskEnvelope
    control_snapshot: TaskControlSnapshot | None
    control_audit_events: tuple[AuditEvent, ...]
    control_attempts: tuple[ControlAttemptEvidence, ...]
    outcome: ClosedLoopOutcome | None
    worker_lease: WorkerLease | None
    dataset_outcome: Any | None
    watchlist_outcome: Any | None
    disease_r1_outcome: Any | None


@dataclass(frozen=True)
class LedgerReplay:
    records_checked: int
    last_record_hash: str
    tasks: tuple[ReplayedTaskState, ...]

    def task(self, task_id: str) -> ReplayedTaskState:
        matches = tuple(state for state in self.tasks if state.task.task_id == task_id)
        if not matches:
            raise LedgerError("task_not_found", "task is not registered in the ledger")
        if len(matches) > 1:
            raise LedgerError("task_ambiguous", "task has ambiguous replay state")
        return matches[0]

    def monthly_used_bytes(self, period: str) -> int:
        return sum(
            state.watchlist_outcome.monthly_budget_reserved_bytes
            for state in self.tasks
            if state.watchlist_outcome is not None
            and state.watchlist_outcome.monthly_period == period
        )


@dataclass(frozen=True)
class _LedgerRecord:
    sequence: int
    record_id: str
    record_type: str
    task_id: str
    idempotency_key: str
    previous_record_hash: str
    payload: Mapping[str, Any]
    record_hash: str


@dataclass
class _MutableTaskState:
    task: TaskEnvelope
    current_snapshot: TaskControlSnapshot
    has_control_record: bool
    control_audit_events: list[AuditEvent]
    control_attempts: list[ControlAttemptEvidence]
    outcome: ClosedLoopOutcome | None
    worker_lease: WorkerLease | None
    dataset_outcome: Any | None
    watchlist_outcome: Any | None
    disease_r1_outcome: Any | None

    def freeze(self) -> ReplayedTaskState:
        return ReplayedTaskState(
            task=self.task,
            control_snapshot=self.current_snapshot if self.has_control_record else None,
            control_audit_events=tuple(self.control_audit_events),
            control_attempts=tuple(self.control_attempts),
            outcome=self.outcome,
            worker_lease=self.worker_lease,
            dataset_outcome=self.dataset_outcome,
            watchlist_outcome=self.watchlist_outcome,
            disease_r1_outcome=self.disease_r1_outcome,
        )


class _ReplayBuilder:
    def __init__(self) -> None:
        self.records: list[_LedgerRecord] = []
        self.idempotency_index: dict[str, _LedgerRecord] = {}
        self.tasks: dict[str, _MutableTaskState] = {}
        self.audit_event_ids: set[str] = set()
        self.last_record_hash = GENESIS_HASH
        self.monthly_usage: dict[str, int] = {}

    def add(self, record: _LedgerRecord) -> None:
        if record.idempotency_key in self.idempotency_index:
            raise LedgerError(
                "duplicate_idempotency_record",
                "ledger contains a duplicate idempotency key",
            )
        self._apply_semantics(record)
        self.records.append(record)
        self.idempotency_index[record.idempotency_key] = record
        self.last_record_hash = record.record_hash

    def _apply_semantics(self, record: _LedgerRecord) -> None:
        if record.record_type == "task_registered":
            _exact_keys(record.payload, {"task"}, "task registration payload")
            task = _task_from_mapping(record.payload["task"])
            if task.task_id != record.task_id:
                raise LedgerError("record_task_mismatch", "record task id does not match payload")
            if task.data_classification not in ALLOWED_DATA_CLASSIFICATIONS:
                raise LedgerError(
                    "data_classification_not_allowed",
                    "only synthetic or public D0 task metadata is allowed",
                )
            if task.task_id in self.tasks:
                raise LedgerError(
                    "duplicate_task_registration",
                    "task may be registered only once in an append-only ledger",
                )
            self.tasks[task.task_id] = _MutableTaskState(
                task=task,
                current_snapshot=TaskController.initial(task),
                has_control_record=False,
                control_audit_events=[],
                control_attempts=[],
                outcome=None,
                worker_lease=None,
                dataset_outcome=None,
                watchlist_outcome=None,
                disease_r1_outcome=None,
            )
            return

        state = self.tasks.get(record.task_id)
        if state is None:
            raise LedgerError(
                "task_registration_missing",
                "task registration must precede task records",
            )

        if record.record_type == "control_attempt_recorded":
            if (
                state.outcome is not None
                or state.dataset_outcome is not None
                or state.watchlist_outcome is not None
                or state.disease_r1_outcome is not None
            ):
                raise LedgerError(
                    "control_after_outcome",
                    "control attempt cannot be appended after a closed-loop outcome",
                )
            _exact_keys(
                record.payload,
                {"transition", "operator_authorization"},
                "control payload",
            )
            authorization = _authorization_from_mapping(
                record.payload["operator_authorization"]
            )
            transition_value = record.payload["transition"]
            transition = (
                None
                if transition_value is None
                else _transition_from_mapping(transition_value)
            )
            try:
                expected_authorization = authorize_control(
                    authorization.grant_snapshot,
                    operator_ref=authorization.operator_ref,
                    task_id=authorization.task_id,
                    action=authorization.action,
                    request_reason=authorization.request_reason,
                    checked_at=authorization.checked_at,
                    confirmed_action=authorization.confirmed_action,
                )
            except AuthorizationError as error:
                raise LedgerError(
                    "operator_authorization_invalid",
                    "operator authorization grant is not replayable",
                ) from error
            if authorization != expected_authorization:
                raise LedgerError(
                    "operator_authorization_invalid",
                    "operator authorization decision is not reproducible",
                )
            if authorization.task_id != record.task_id:
                raise LedgerError(
                    "operator_authorization_binding_mismatch",
                    "operator authorization is not bound to the record task",
                )
            if not authorization.allowed:
                if transition is not None:
                    raise LedgerError(
                        "denied_control_has_transition",
                        "a denied authorization cannot carry a control transition",
                    )
                state.control_attempts.append(
                    ControlAttemptEvidence(
                        idempotency_key=record.idempotency_key,
                        authorization=authorization,
                        transition=None,
                    )
                )
                return
            if transition is None:
                raise LedgerError(
                    "authorized_control_transition_missing",
                    "an allowed authorization must carry a control transition",
                )
            if (
                authorization.action != transition.action
                or authorization.operator_ref
                != transition.audit_event.subject_ref
            ):
                raise LedgerError(
                    "operator_authorization_binding_mismatch",
                    "operator authorization is not bound to the control transition",
                )
            if transition.before != state.current_snapshot:
                raise LedgerError(
                    "control_revision_mismatch",
                    "control transition does not continue the replayed snapshot",
                )
            if transition.audit_event.event_id in self.audit_event_ids:
                raise LedgerError(
                    "duplicate_control_audit",
                    "control audit event id is duplicated",
                )
            expected = TaskController().apply(
                state.current_snapshot,
                transition.action,
                actor_id=transition.audit_event.subject_ref,
            )
            if transition != expected:
                raise LedgerError(
                    "control_transition_invalid",
                    "control transition is not reproducible from deterministic policy",
                )
            state.current_snapshot = transition.after
            state.has_control_record = True
            state.control_audit_events.append(transition.audit_event)
            state.control_attempts.append(
                ControlAttemptEvidence(
                    idempotency_key=record.idempotency_key,
                    authorization=authorization,
                    transition=transition,
                )
            )
            self.audit_event_ids.add(transition.audit_event.event_id)
            return

        if record.record_type == "worker_lease_started":
            if (
                state.worker_lease is not None
                or state.outcome is not None
                or state.dataset_outcome is not None
                or state.watchlist_outcome is not None
                or state.disease_r1_outcome is not None
            ):
                raise LedgerError(
                    "worker_lease_already_started",
                    "a task may have only one D0 Worker Lease",
                )
            _exact_keys(record.payload, {"worker_lease"}, "Worker Lease payload")
            lease = _worker_lease_from_mapping(record.payload["worker_lease"])
            expected_id = deterministic_id(
                "lease", lease.task_id, lease.worker_id, lease.implementation_revision
            )
            if (
                lease.task_id != record.task_id
                or lease.lease_id != expected_id
                or lease.status != "active"
                or lease.revision != 0
                or lease.cancellation_requested
            ):
                raise LedgerError(
                    "worker_lease_start_invalid",
                    "Worker Lease start is not bound to the registered task",
                )
            state.worker_lease = lease
            return

        if record.record_type == "dataset_closed_loop_recorded":
            if state.worker_lease is None or state.worker_lease.status != "active":
                raise LedgerError(
                    "active_worker_lease_missing",
                    "Dataset outcome requires an active Worker Lease",
                )
            if state.dataset_outcome is not None or state.outcome is not None:
                raise LedgerError(
                    "outcome_already_recorded",
                    "closed-loop outcome may be appended only once",
                )
            _exact_keys(record.payload, {"outcome"}, "Dataset closed-loop payload")
            outcome = _dataset_outcome_from_mapping(record.payload["outcome"])
            if outcome.company_outcome.task != state.task:
                raise LedgerError(
                    "outcome_task_mismatch",
                    "Dataset outcome task does not match registration",
                )
            expected_snapshot = (
                state.current_snapshot if state.has_control_record else None
            )
            if outcome.company_outcome.control_snapshot != expected_snapshot:
                raise LedgerError(
                    "dataset_control_snapshot_mismatch",
                    "Dataset outcome does not include the latest Task control snapshot",
                )
            outcome_audit_ids = tuple(
                event.event_id for event in outcome.company_outcome.audit_events
            )
            if (
                len(set(outcome_audit_ids)) != len(outcome_audit_ids)
                or not set(event.event_id for event in state.control_audit_events).issubset(
                    outcome_audit_ids
                )
            ):
                raise LedgerError(
                    "dataset_control_audit_mismatch",
                    "Dataset outcome is missing unique Task control audit evidence",
                )
            evidence = outcome.adapter_evidence
            if evidence is not None and (
                evidence.implementation_revision
                != state.worker_lease.implementation_revision
            ):
                raise LedgerError(
                    "worker_lease_revision_mismatch",
                    "Dataset evidence does not match the Worker Lease revision",
                )
            if outcome.status == "pass":
                if (
                    outcome.company_outcome.result is None
                    or outcome.company_outcome.evaluation is None
                    or outcome.company_outcome.evaluation.verdict != "pass"
                    or evidence is None
                ):
                    raise LedgerError(
                        "dataset_outcome_invalid",
                        "passing Dataset outcome lacks result, evaluation, or evidence",
                    )
                from .dataset_agent_process import DATASET_AGENT_ID
                from .evaluator import CompanyEvaluator

                expected_evaluation = CompanyEvaluator().evaluate(
                    task=state.task,
                    route_decision=outcome.company_outcome.route_decision,
                    result=outcome.company_outcome.result,
                    audit_events=outcome.company_outcome.audit_events,
                    subject_agent_id=DATASET_AGENT_ID,
                )
                if outcome.company_outcome.evaluation != expected_evaluation:
                    raise LedgerError(
                        "dataset_company_evaluation_mismatch",
                        "Dataset Company Evaluation is not deterministically reproducible",
                    )
            elif outcome.status not in {"blocked", "fail"}:
                raise LedgerError(
                    "dataset_outcome_invalid",
                    "Dataset outcome status is unsupported",
                )
            state.dataset_outcome = outcome
            return

        if record.record_type == "watchlist_task_recorded":
            if state.worker_lease is None or state.worker_lease.status != "active":
                raise LedgerError(
                    "active_worker_lease_missing",
                    "Watchlist outcome requires an active Worker Lease",
                )
            if (
                state.watchlist_outcome is not None
                or state.dataset_outcome is not None
                or state.outcome is not None
            ):
                raise LedgerError(
                    "outcome_already_recorded",
                    "closed-loop outcome may be appended only once",
                )
            _exact_keys(record.payload, {"outcome"}, "Watchlist Task payload")
            outcome = _watchlist_outcome_from_mapping(record.payload["outcome"])
            if outcome.task != state.task or outcome.task.task_id != record.task_id:
                raise LedgerError(
                    "outcome_task_mismatch", "Watchlist outcome task does not match registration"
                )
            expected_snapshot = state.current_snapshot if state.has_control_record else None
            if outcome.control_snapshot != expected_snapshot:
                raise LedgerError(
                    "watchlist_control_snapshot_mismatch",
                    "Watchlist outcome does not include latest Task control",
                )
            from .evaluator import CompanyEvaluator
            from .watchlist_process import load_watchlist_implementation_lock

            lock = load_watchlist_implementation_lock()
            expected_evaluation = CompanyEvaluator().evaluate(
                task=outcome.task,
                route_decision=outcome.route_decision,
                result=outcome.result,
                audit_events=outcome.audit_events,
                subject_agent_id=lock.coordinator_target_id,
            )
            prior_monthly = self.monthly_usage.get(outcome.monthly_period, 0)
            if (
                outcome.schema_version != lock.task_schema_version
                or outcome.evaluation != expected_evaluation
                or outcome.evaluation.release_authorization
                or outcome.registry_implementation_revision
                != lock.registry.implementation_commit
                or outcome.scientific_implementation_revision
                != lock.scientific.implementation_commit
                or outcome.runtime_bundle_revision != lock.bundle_revision
                or state.worker_lease.implementation_revision != lock.bundle_revision
                or outcome.monthly_used_before_bytes != prior_monthly
                or outcome.monthly_budget_reserved_bytes < 0
                or outcome.monthly_budget_reserved_bytes > lock.task_limit_bytes
                or outcome.monthly_used_after_bytes
                != prior_monthly + outcome.monthly_budget_reserved_bytes
                or outcome.monthly_used_after_bytes > lock.month_limit_bytes
                or outcome.registry_write_performed
                or outcome.real_data_download_performed
                or outcome.release_authorization
            ):
                raise LedgerError(
                    "watchlist_outcome_invalid",
                    "Watchlist outcome violates locked budget, Revision, or authority",
                )
            if outcome.status == "pass":
                if (
                    outcome.evaluation.verdict != "pass"
                    or outcome.domain_status not in {"completed", "skipped"}
                ):
                    raise LedgerError(
                        "watchlist_outcome_invalid", "Passing Watchlist outcome is inconsistent"
                    )
            elif outcome.status != "blocked" or outcome.evaluation.verdict != "fail":
                raise LedgerError(
                    "watchlist_outcome_invalid", "Blocked Watchlist outcome is inconsistent"
                )
            if (
                outcome.model_invocation_count not in {0, 1}
                or outcome.worker_invocation_count not in {0, 1}
                or outcome.worker_invocation_count > outcome.model_invocation_count
                or (
                    outcome.domain_status == "skipped"
                    and (
                        outcome.model_invocation_count != 0
                        or outcome.worker_invocation_count != 0
                        or outcome.monthly_budget_reserved_bytes != 0
                    )
                )
            ):
                raise LedgerError(
                    "watchlist_outcome_invalid", "Watchlist invocation evidence is invalid"
                )
            outcome_audits = {event.event_id for event in outcome.audit_events}
            if not {event.event_id for event in state.control_audit_events}.issubset(
                outcome_audits
            ):
                raise LedgerError(
                    "watchlist_control_audit_mismatch",
                    "Watchlist outcome is missing control audit evidence",
                )
            self.monthly_usage[outcome.monthly_period] = outcome.monthly_used_after_bytes
            state.watchlist_outcome = outcome
            return

        if record.record_type == "disease_r1_attempt_recorded":
            if state.worker_lease is None or state.worker_lease.status != "active":
                raise LedgerError(
                    "active_worker_lease_missing",
                    "Disease R1 outcome requires an active Worker Lease",
                )
            if any(
                outcome is not None
                for outcome in (
                    state.outcome,
                    state.dataset_outcome,
                    state.watchlist_outcome,
                    state.disease_r1_outcome,
                )
            ):
                raise LedgerError(
                    "outcome_already_recorded",
                    "closed-loop outcome may be appended only once",
                )
            _exact_keys(record.payload, {"outcome"}, "Disease R1 attempt payload")
            outcome = _validate_disease_r1_outcome(record.payload["outcome"])
            if outcome["task_id"] != record.task_id:
                raise LedgerError(
                    "outcome_task_mismatch",
                    "Disease R1 outcome task does not match registration",
                )
            if (
                outcome["runtime_source_digest"]
                != state.worker_lease.implementation_revision
            ):
                raise LedgerError(
                    "worker_lease_revision_mismatch",
                    "Disease R1 outcome does not match the Worker Lease revision",
                )
            state.disease_r1_outcome = outcome
            return

        if record.record_type == "worker_lease_closed":
            if state.worker_lease is None or state.worker_lease.status != "active":
                raise LedgerError(
                    "active_worker_lease_missing",
                    "Worker Lease close requires an active lease",
                )
            recorded_outcome = (
                state.dataset_outcome
                or state.watchlist_outcome
                or state.disease_r1_outcome
            )
            if recorded_outcome is None:
                raise LedgerError(
                    "worker_outcome_missing",
                    "Worker Lease cannot close before outcome evidence",
                )
            _exact_keys(record.payload, {"worker_lease"}, "Worker Lease payload")
            closed = _worker_lease_from_mapping(record.payload["worker_lease"])
            opened = state.worker_lease
            if (
                closed.lease_id != opened.lease_id
                or closed.task_id != opened.task_id
                or closed.worker_id != opened.worker_id
                or closed.implementation_revision != opened.implementation_revision
                or closed.revision != opened.revision + 1
                or closed.status not in {"completed", "cancelled", "failed"}
                or (closed.status == "cancelled") != closed.cancellation_requested
            ):
                raise LedgerError(
                    "worker_lease_close_invalid",
                    "Worker Lease close does not continue the active lease",
                )
            if closed.status == "completed" and _outcome_status(recorded_outcome) != "pass":
                raise LedgerError(
                    "worker_lease_close_invalid",
                    "completed Worker Lease requires a passing Dataset outcome",
                )
            if closed.status == "cancelled" and (
                "dataset_agent_process_cancelled"
                not in _outcome_reason_codes(recorded_outcome)
                and "watchlist_task_cancelled"
                not in _outcome_reason_codes(recorded_outcome)
                and "disease_r1_cancelled"
                not in _outcome_reason_codes(recorded_outcome)
                and not _control_blocks_execution(state.current_snapshot)
            ):
                raise LedgerError(
                    "worker_lease_close_invalid",
                    "cancelled Worker Lease has no cancellation evidence",
                )
            state.worker_lease = closed
            return

        if record.record_type == "closed_loop_recorded":
            if state.outcome is not None:
                raise LedgerError(
                    "outcome_already_recorded",
                    "closed-loop outcome may be appended only once",
                )
            _exact_keys(record.payload, {"outcome"}, "closed-loop payload")
            outcome = _outcome_from_mapping(record.payload["outcome"])
            if outcome.task != state.task:
                raise LedgerError("outcome_task_mismatch", "outcome task does not match registration")
            from .loop import default_synthetic_loop

            expected = default_synthetic_loop().run(
                state.task,
                control_snapshot=(
                    state.current_snapshot if state.has_control_record else None
                ),
                control_audit_events=tuple(state.control_audit_events),
            )
            if outcome != expected:
                raise LedgerError(
                    "outcome_replay_mismatch",
                    "closed-loop outcome is not reproducible from prior records",
                )
            state.outcome = outcome
            return

        raise LedgerError("unsupported_record_type", "ledger record type is unsupported")

    def freeze(self) -> LedgerReplay:
        return LedgerReplay(
            records_checked=len(self.records),
            last_record_hash=self.last_record_hash,
            tasks=tuple(state.freeze() for state in self.tasks.values()),
        )


class SyntheticTaskLedger:
    """Append and replay local D0 synthetic task evidence."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def register_task(
        self,
        task: TaskEnvelope,
        *,
        idempotency_key: str,
    ) -> LedgerAppendResult:
        return self._append(
            record_type="task_registered",
            task_id=task.task_id,
            idempotency_key=idempotency_key,
            payload={"task": asdict(task)},
        )

    def record_control_attempt(
        self,
        operator_authorization: OperatorAuthorizationDecision,
        transition: ControlTransition | None,
        *,
        idempotency_key: str,
    ) -> LedgerAppendResult:
        return self._append(
            record_type="control_attempt_recorded",
            task_id=operator_authorization.task_id,
            idempotency_key=idempotency_key,
            payload={
                "transition": None if transition is None else asdict(transition),
                "operator_authorization": asdict(operator_authorization),
            },
        )

    def record_outcome(
        self,
        outcome: ClosedLoopOutcome,
        *,
        idempotency_key: str,
    ) -> LedgerAppendResult:
        return self._append(
            record_type="closed_loop_recorded",
            task_id=outcome.task.task_id,
            idempotency_key=idempotency_key,
            payload={"outcome": asdict(outcome)},
        )

    def start_worker_lease(
        self,
        lease: WorkerLease,
        *,
        idempotency_key: str,
    ) -> LedgerAppendResult:
        return self._append(
            record_type="worker_lease_started",
            task_id=lease.task_id,
            idempotency_key=idempotency_key,
            payload={"worker_lease": asdict(lease)},
        )

    def record_dataset_outcome(
        self,
        outcome: Any,
        *,
        idempotency_key: str,
    ) -> LedgerAppendResult:
        return self._append(
            record_type="dataset_closed_loop_recorded",
            task_id=outcome.company_outcome.task.task_id,
            idempotency_key=idempotency_key,
            payload={"outcome": asdict(outcome)},
        )

    def record_watchlist_outcome(
        self,
        outcome: Any,
        *,
        idempotency_key: str,
    ) -> LedgerAppendResult:
        return self._append(
            record_type="watchlist_task_recorded",
            task_id=outcome.task.task_id,
            idempotency_key=idempotency_key,
            payload={"outcome": asdict(outcome)},
        )

    def record_disease_r1_outcome(
        self,
        outcome: Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> LedgerAppendResult:
        return self._append(
            record_type="disease_r1_attempt_recorded",
            task_id=str(outcome.get("task_id", "")),
            idempotency_key=idempotency_key,
            payload={"outcome": outcome},
        )

    def close_worker_lease(
        self,
        lease: WorkerLease,
        *,
        idempotency_key: str,
    ) -> LedgerAppendResult:
        return self._append(
            record_type="worker_lease_closed",
            task_id=lease.task_id,
            idempotency_key=idempotency_key,
            payload={"worker_lease": asdict(lease)},
        )

    def replay(self) -> LedgerReplay:
        fd = self._open(create=False, exclusive=False)
        try:
            return self._read_builder(fd).freeze()
        finally:
            self._close(fd)

    def _append(
        self,
        *,
        record_type: str,
        task_id: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
    ) -> LedgerAppendResult:
        if record_type not in ALLOWED_RECORD_TYPES:
            raise LedgerError("unsupported_record_type", "record type is unsupported")
        if not isinstance(task_id, str) or not task_id:
            raise LedgerError("invalid_task_id", "task id must be a non-empty string")
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_PATTERN.fullmatch(
            idempotency_key
        ):
            raise LedgerError(
                "invalid_idempotency_key",
                "idempotency key does not match the local synthetic format",
            )

        normalized_payload = _normalize_json(payload)
        fd = self._open(create=True, exclusive=True)
        try:
            builder = self._read_builder(fd)
            existing = builder.idempotency_index.get(idempotency_key)
            if existing is not None:
                if (
                    existing.record_type == record_type
                    and existing.task_id == task_id
                    and _canonical_json(existing.payload)
                    == _canonical_json(normalized_payload)
                ):
                    return LedgerAppendResult(
                        record_id=existing.record_id,
                        sequence=existing.sequence,
                        record_hash=existing.record_hash,
                        appended=False,
                    )
                raise LedgerError(
                    "idempotency_conflict",
                    "idempotency key is already bound to different content",
                )

            payload_digest = _digest(_canonical_json(normalized_payload).encode("utf-8"))
            record_id = deterministic_id(
                "ledger",
                record_type,
                task_id,
                idempotency_key,
                payload_digest,
            )
            content = {
                "ledger_version": LEDGER_VERSION,
                "sequence": len(builder.records),
                "record_id": record_id,
                "record_type": record_type,
                "task_id": task_id,
                "idempotency_key": idempotency_key,
                "previous_record_hash": builder.last_record_hash,
                "payload": normalized_payload,
            }
            record_hash = _digest(_canonical_json(content).encode("utf-8"))
            document = {**content, "record_hash": record_hash}
            record = _record_from_document(document, len(builder.records), builder.last_record_hash)
            builder.add(record)

            encoded = (_canonical_json(document) + "\n").encode("utf-8")
            if len(encoded) > MAX_RECORD_BYTES:
                raise LedgerError("record_too_large", "ledger record exceeds the size limit")
            current_size = os.fstat(fd).st_size
            if current_size + len(encoded) > MAX_LEDGER_BYTES:
                raise LedgerError("ledger_too_large", "ledger exceeds the local size limit")
            written = os.write(fd, encoded)
            if written != len(encoded):
                raise LedgerError("ledger_short_write", "ledger append was incomplete")
            os.fsync(fd)
            return LedgerAppendResult(
                record_id=record.record_id,
                sequence=record.sequence,
                record_hash=record.record_hash,
                appended=True,
            )
        finally:
            self._close(fd)

    def _open(self, *, create: bool, exclusive: bool) -> int:
        if os.path.lexists(self.path):
            try:
                if stat.S_ISLNK(os.lstat(self.path).st_mode):
                    raise LedgerError(
                        "ledger_symlink_forbidden",
                        "ledger path may not be a symbolic link",
                    )
            except OSError as error:
                raise LedgerError("ledger_open_failed", "ledger metadata is unavailable") from error
        elif not create:
            raise LedgerError("ledger_not_found", "ledger file does not exist")

        parent = self.path.parent
        if not parent.exists() or not parent.is_dir():
            raise LedgerError("ledger_parent_missing", "ledger parent directory does not exist")

        flags = os.O_RDONLY
        if create:
            flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileNotFoundError as error:
            raise LedgerError("ledger_not_found", "ledger file does not exist") from error
        except OSError as error:
            raise LedgerError("ledger_open_failed", "ledger file could not be opened") from error
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise LedgerError("ledger_not_regular_file", "ledger must be a regular file")
            if metadata.st_uid != os.geteuid():
                raise LedgerError(
                    "ledger_owner_mismatch",
                    "ledger must be owned by the current local operator",
                )
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise LedgerError(
                    "ledger_permissions_too_broad",
                    "ledger permissions must be owner-only",
                )
            fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            return fd
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _close(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @staticmethod
    def _read_builder(fd: int) -> _ReplayBuilder:
        size = os.fstat(fd).st_size
        if size > MAX_LEDGER_BYTES:
            raise LedgerError("ledger_too_large", "ledger exceeds the local size limit")
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = size
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                raise LedgerError("ledger_read_incomplete", "ledger read ended unexpectedly")
            chunks.append(chunk)
            remaining -= len(chunk)
        source = b"".join(chunks)
        builder = _ReplayBuilder()
        if not source:
            return builder
        if not source.endswith(b"\n"):
            raise LedgerError("truncated_record", "ledger does not end with a complete record")

        for expected_sequence, line in enumerate(source.splitlines()):
            if not line:
                raise LedgerError("blank_record", "ledger contains an empty record")
            if len(line) + 1 > MAX_RECORD_BYTES:
                raise LedgerError("record_too_large", "ledger record exceeds the size limit")
            try:
                document = json.loads(
                    line.decode("utf-8"),
                    object_pairs_hook=_unique_object,
                    parse_constant=_reject_json_constant,
                )
            except LedgerError:
                raise
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise LedgerError("invalid_json", "ledger record is not valid JSON") from error
            record = _record_from_document(
                document,
                expected_sequence,
                builder.last_record_hash,
            )
            builder.add(record)
        return builder


def _record_from_document(
    document: Any,
    expected_sequence: int,
    expected_previous_hash: str,
) -> _LedgerRecord:
    _exact_keys(document, _RECORD_KEYS, "ledger record")
    if document["ledger_version"] != LEDGER_VERSION:
        raise LedgerError("unsupported_ledger_version", "ledger version is unsupported")
    sequence = _strict_int(document["sequence"], "record sequence")
    if sequence != expected_sequence:
        raise LedgerError("sequence_mismatch", "ledger sequence is not contiguous")
    record_type = _strict_string(document["record_type"], "record type")
    if record_type not in ALLOWED_RECORD_TYPES:
        raise LedgerError("unsupported_record_type", "ledger record type is unsupported")
    task_id = _strict_string(document["task_id"], "record task id")
    idempotency_key = _strict_string(document["idempotency_key"], "idempotency key")
    if not _IDEMPOTENCY_PATTERN.fullmatch(idempotency_key):
        raise LedgerError("invalid_idempotency_key", "idempotency key format is invalid")
    previous_hash = _strict_hash(document["previous_record_hash"], "previous hash")
    if previous_hash != expected_previous_hash:
        raise LedgerError("previous_hash_mismatch", "ledger hash chain is broken")
    record_hash = _strict_hash(document["record_hash"], "record hash")
    record_id = _strict_string(document["record_id"], "record id")
    payload = _strict_mapping(document["payload"], "record payload")

    content = {key: value for key, value in document.items() if key != "record_hash"}
    expected_hash = _digest(_canonical_json(content).encode("utf-8"))
    if record_hash != expected_hash:
        raise LedgerError("record_hash_mismatch", "ledger record hash does not match content")
    payload_digest = _digest(_canonical_json(payload).encode("utf-8"))
    expected_record_id = deterministic_id(
        "ledger", record_type, task_id, idempotency_key, payload_digest
    )
    if record_id != expected_record_id:
        raise LedgerError("record_id_mismatch", "ledger record id is not deterministic")
    return _LedgerRecord(
        sequence=sequence,
        record_id=record_id,
        record_type=record_type,
        task_id=task_id,
        idempotency_key=idempotency_key,
        previous_record_hash=previous_hash,
        payload=payload,
        record_hash=record_hash,
    )


def _task_from_mapping(value: Any) -> TaskEnvelope:
    mapping = _strict_mapping(value, "task")
    _exact_keys(
        mapping,
        {
            "task_id",
            "capability",
            "data_classification",
            "grant_id",
            "grant_active",
            "requested_target_id",
        },
        "task",
    )
    requested_target = mapping["requested_target_id"]
    if requested_target is not None:
        requested_target = _strict_string(requested_target, "requested target id")
    return TaskEnvelope(
        task_id=_strict_string(mapping["task_id"], "task id"),
        capability=_strict_string(mapping["capability"], "task capability"),
        data_classification=_strict_string(
            mapping["data_classification"], "task data classification"
        ),
        grant_id=_strict_string(mapping["grant_id"], "task grant id"),
        grant_active=_strict_bool(mapping["grant_active"], "task grant active"),
        requested_target_id=requested_target,
    )


def _snapshot_from_mapping(value: Any) -> TaskControlSnapshot:
    mapping = _strict_mapping(value, "control snapshot")
    _exact_keys(
        mapping,
        {
            "task_id",
            "grant_id",
            "task_status",
            "grant_status",
            "owner_kind",
            "revision",
            "last_control_event_ref",
        },
        "control snapshot",
    )
    last_ref = mapping["last_control_event_ref"]
    if last_ref is not None:
        last_ref = _strict_string(last_ref, "last control event ref")
    revision = _strict_int(mapping["revision"], "control revision")
    if revision < 0:
        raise LedgerError("invalid_record_payload", "control revision may not be negative")
    return TaskControlSnapshot(
        task_id=_strict_string(mapping["task_id"], "control task id"),
        grant_id=_strict_string(mapping["grant_id"], "control grant id"),
        task_status=_strict_string(mapping["task_status"], "task status"),
        grant_status=_strict_string(mapping["grant_status"], "grant status"),
        owner_kind=_strict_string(mapping["owner_kind"], "owner kind"),
        revision=revision,
        last_control_event_ref=last_ref,
    )


def _audit_from_mapping(value: Any) -> AuditEvent:
    mapping = _strict_mapping(value, "audit event")
    _exact_keys(mapping, {"event_id", "task_id", "event_type", "subject_ref"}, "audit event")
    return AuditEvent(
        event_id=_strict_string(mapping["event_id"], "audit event id"),
        task_id=_strict_string(mapping["task_id"], "audit task id"),
        event_type=_strict_string(mapping["event_type"], "audit event type"),
        subject_ref=_strict_string(mapping["subject_ref"], "audit subject ref"),
    )


def _authorization_from_mapping(value: Any) -> OperatorAuthorizationDecision:
    mapping = _strict_mapping(value, "operator authorization")
    _exact_keys(
        mapping,
        {
            "decision_id",
            "grant_snapshot",
            "operator_ref",
            "task_id",
            "action",
            "request_reason",
            "checked_at",
            "confirmed_action",
            "allowed",
            "reason_codes",
        },
        "operator authorization",
    )
    try:
        grant = grant_from_mapping(mapping["grant_snapshot"])
    except AuthorizationError as error:
        raise LedgerError(
            "operator_authorization_invalid",
            "operator authorization grant snapshot is invalid",
        ) from error
    return OperatorAuthorizationDecision(
        decision_id=_strict_string(
            mapping["decision_id"], "operator authorization decision id"
        ),
        grant_snapshot=grant,
        operator_ref=_strict_string(
            mapping["operator_ref"], "operator authorization operator ref"
        ),
        task_id=_strict_string(
            mapping["task_id"], "operator authorization task id"
        ),
        action=_strict_string(
            mapping["action"], "operator authorization action"
        ),
        request_reason=_strict_string(
            mapping["request_reason"], "operator authorization request reason"
        ),
        checked_at=_strict_string(
            mapping["checked_at"], "operator authorization checked at"
        ),
        confirmed_action=_strict_string(
            mapping["confirmed_action"], "operator authorization confirmation"
        ),
        allowed=_strict_bool(mapping["allowed"], "operator authorization allowed"),
        reason_codes=_string_tuple(
            mapping["reason_codes"], "operator authorization reason codes"
        ),
    )


def _transition_from_mapping(value: Any) -> ControlTransition:
    mapping = _strict_mapping(value, "control transition")
    _exact_keys(
        mapping,
        {"action", "applied", "reason_code", "before", "after", "audit_event"},
        "control transition",
    )
    return ControlTransition(
        action=_strict_string(mapping["action"], "control action"),
        applied=_strict_bool(mapping["applied"], "control applied"),
        reason_code=_strict_string(mapping["reason_code"], "control reason code"),
        before=_snapshot_from_mapping(mapping["before"]),
        after=_snapshot_from_mapping(mapping["after"]),
        audit_event=_audit_from_mapping(mapping["audit_event"]),
    )


def _route_from_mapping(value: Any) -> RouteDecision:
    mapping = _strict_mapping(value, "route decision")
    _exact_keys(
        mapping,
        {"decision_id", "task_id", "status", "target_id", "reason_codes"},
        "route decision",
    )
    target_id = mapping["target_id"]
    if target_id is not None:
        target_id = _strict_string(target_id, "route target id")
    return RouteDecision(
        decision_id=_strict_string(mapping["decision_id"], "route decision id"),
        task_id=_strict_string(mapping["task_id"], "route task id"),
        status=_strict_string(mapping["status"], "route status"),
        target_id=target_id,
        reason_codes=_string_tuple(mapping["reason_codes"], "route reason codes"),
    )


def _result_from_mapping(value: Any) -> TaskResult:
    mapping = _strict_mapping(value, "task result")
    _exact_keys(
        mapping,
        {
            "result_id",
            "task_id",
            "target_id",
            "status",
            "output_ref",
            "audit_event_refs",
            "side_effects",
        },
        "task result",
    )
    return TaskResult(
        result_id=_strict_string(mapping["result_id"], "result id"),
        task_id=_strict_string(mapping["task_id"], "result task id"),
        target_id=_strict_string(mapping["target_id"], "result target id"),
        status=_strict_string(mapping["status"], "result status"),
        output_ref=_strict_string(mapping["output_ref"], "result output ref"),
        audit_event_refs=_string_tuple(mapping["audit_event_refs"], "audit refs"),
        side_effects=_string_tuple(mapping["side_effects"], "side effects"),
    )


def _evaluation_from_mapping(value: Any) -> EvaluationReport:
    mapping = _strict_mapping(value, "evaluation report")
    _exact_keys(
        mapping,
        {
            "report_id",
            "evaluator_agent_id",
            "subject_result_id",
            "verdict",
            "reason_codes",
            "release_authorization",
        },
        "evaluation report",
    )
    return EvaluationReport(
        report_id=_strict_string(mapping["report_id"], "evaluation report id"),
        evaluator_agent_id=_strict_string(
            mapping["evaluator_agent_id"], "evaluator agent id"
        ),
        subject_result_id=_strict_string(
            mapping["subject_result_id"], "evaluation subject result id"
        ),
        verdict=_strict_string(mapping["verdict"], "evaluation verdict"),
        reason_codes=_string_tuple(mapping["reason_codes"], "evaluation reasons"),
        release_authorization=_strict_bool(
            mapping["release_authorization"], "release authorization"
        ),
    )


def _outcome_from_mapping(value: Any) -> ClosedLoopOutcome:
    mapping = _strict_mapping(value, "closed-loop outcome")
    _exact_keys(
        mapping,
        {
            "task",
            "route_decision",
            "result",
            "evaluation",
            "audit_events",
            "control_snapshot",
        },
        "closed-loop outcome",
    )
    result = None if mapping["result"] is None else _result_from_mapping(mapping["result"])
    evaluation = (
        None
        if mapping["evaluation"] is None
        else _evaluation_from_mapping(mapping["evaluation"])
    )
    control_snapshot = (
        None
        if mapping["control_snapshot"] is None
        else _snapshot_from_mapping(mapping["control_snapshot"])
    )
    audit_values = mapping["audit_events"]
    if not isinstance(audit_values, list):
        raise LedgerError("invalid_record_payload", "audit events must be a list")
    return ClosedLoopOutcome(
        task=_task_from_mapping(mapping["task"]),
        route_decision=_route_from_mapping(mapping["route_decision"]),
        result=result,
        evaluation=evaluation,
        audit_events=tuple(_audit_from_mapping(item) for item in audit_values),
        control_snapshot=control_snapshot,
    )


def _worker_lease_from_mapping(value: Any) -> WorkerLease:
    mapping = _strict_mapping(value, "Worker Lease")
    _exact_keys(
        mapping,
        {
            "lease_id",
            "task_id",
            "worker_id",
            "implementation_revision",
            "status",
            "revision",
            "cancellation_requested",
            "last_event_ref",
        },
        "Worker Lease",
    )
    revision = _strict_int(mapping["revision"], "Worker Lease revision")
    if revision < 0:
        raise LedgerError(
            "invalid_record_payload", "Worker Lease revision may not be negative"
        )
    implementation_revision = _strict_string(
        mapping["implementation_revision"], "Worker Lease implementation revision"
    )
    if not (
        re.fullmatch(r"[0-9a-f]{40}", implementation_revision)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", implementation_revision)
    ):
        raise LedgerError(
            "invalid_record_payload",
            "Worker Lease implementation revision must be a Git commit or bundle digest",
        )
    return WorkerLease(
        lease_id=_strict_string(mapping["lease_id"], "Worker Lease id"),
        task_id=_strict_string(mapping["task_id"], "Worker Lease task id"),
        worker_id=_strict_string(mapping["worker_id"], "Worker Lease worker id"),
        implementation_revision=implementation_revision,
        status=_strict_string(mapping["status"], "Worker Lease status"),
        revision=revision,
        cancellation_requested=_strict_bool(
            mapping["cancellation_requested"], "Worker Lease cancellation flag"
        ),
        last_event_ref=_strict_string(
            mapping["last_event_ref"], "Worker Lease event ref"
        ),
    )


def _dataset_outcome_from_mapping(value: Any) -> Any:
    from .dataset_agent_process import (
        DatasetAgentExecutionEvidence,
        DatasetCompanyLoopOutcome,
    )

    mapping = _strict_mapping(value, "Dataset closed-loop outcome")
    _exact_keys(
        mapping,
        {"status", "reason_codes", "company_outcome", "adapter_evidence"},
        "Dataset closed-loop outcome",
    )
    evidence_value = mapping["adapter_evidence"]
    evidence = None
    if evidence_value is not None:
        raw = _strict_mapping(evidence_value, "Dataset adapter evidence")
        _exact_keys(
            raw,
            {
                "implementation_revision",
                "domain_schema_version",
                "agent_id",
                "runtime_family",
                "receipt_id",
                "receipt_status",
                "actual_size_bytes",
                "actual_sha256",
                "domain_evaluation_report_id",
                "domain_evaluation_decision",
                "domain_audit_event_refs",
                "model_provider_id",
                "model_id",
                "input_tokens",
                "output_tokens",
                "cached_input_tokens",
                "model_cost_cny",
                "storage_write_performed",
                "data_use_approved",
                "registry_publish_performed",
                "approved_asset_release_created",
            },
            "Dataset adapter evidence",
        )
        nonnegative_fields = (
            "actual_size_bytes",
            "input_tokens",
            "output_tokens",
            "cached_input_tokens",
        )
        numbers = {key: _strict_int(raw[key], key) for key in nonnegative_fields}
        if any(number < 0 for number in numbers.values()):
            raise LedgerError(
                "invalid_record_payload", "Dataset evidence counts may not be negative"
            )
        evidence = DatasetAgentExecutionEvidence(
            implementation_revision=_strict_string(
                raw["implementation_revision"], "implementation revision"
            ),
            domain_schema_version=_strict_string(
                raw["domain_schema_version"], "domain schema version"
            ),
            agent_id=_strict_string(raw["agent_id"], "Dataset Agent id"),
            runtime_family=_strict_string(raw["runtime_family"], "runtime family"),
            receipt_id=_strict_string(raw["receipt_id"], "receipt id"),
            receipt_status=_strict_string(raw["receipt_status"], "receipt status"),
            actual_size_bytes=numbers["actual_size_bytes"],
            actual_sha256=_strict_string(raw["actual_sha256"], "actual SHA-256"),
            domain_evaluation_report_id=_strict_string(
                raw["domain_evaluation_report_id"], "domain evaluation report id"
            ),
            domain_evaluation_decision=_strict_string(
                raw["domain_evaluation_decision"], "domain evaluation decision"
            ),
            domain_audit_event_refs=_string_tuple(
                raw["domain_audit_event_refs"], "domain audit refs"
            ),
            model_provider_id=_strict_string(
                raw["model_provider_id"], "model provider id"
            ),
            model_id=_strict_string(raw["model_id"], "model id"),
            input_tokens=numbers["input_tokens"],
            output_tokens=numbers["output_tokens"],
            cached_input_tokens=numbers["cached_input_tokens"],
            model_cost_cny=_strict_string(raw["model_cost_cny"], "model cost"),
            storage_write_performed=_strict_bool(
                raw["storage_write_performed"], "storage write performed"
            ),
            data_use_approved=_strict_bool(
                raw["data_use_approved"], "data use approved"
            ),
            registry_publish_performed=_strict_bool(
                raw["registry_publish_performed"], "registry publish performed"
            ),
            approved_asset_release_created=_strict_bool(
                raw["approved_asset_release_created"], "approved release created"
            ),
        )
        try:
            model_cost = Decimal(evidence.model_cost_cny)
        except (InvalidOperation, ValueError) as error:
            raise LedgerError(
                "invalid_record_payload", "Dataset evidence model cost is invalid"
            ) from error
        if (
            not (
                re.fullmatch(r"[0-9a-f]{40}", evidence.implementation_revision)
                or (
                    evidence.runtime_family == "frozen_offline_python_worker"
                    and evidence.domain_schema_version == "orbit.offline-receipt/1"
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", evidence.implementation_revision)
                )
            )
            or not re.fullmatch(r"[0-9a-f]{64}", evidence.actual_sha256)
            or evidence.receipt_status != "verified"
            or evidence.domain_evaluation_decision != "pass"
            or len(set(evidence.domain_audit_event_refs))
            != len(evidence.domain_audit_event_refs)
            or len(evidence.domain_audit_event_refs) != 4
            or evidence.cached_input_tokens > evidence.input_tokens
            or not model_cost.is_finite()
            or model_cost != 0
            or evidence.model_provider_id != "synthetic-deterministic"
            or evidence.model_id != "structured-model-fixture-v1"
        ):
            raise LedgerError(
                "dataset_evidence_invalid",
                "Dataset evidence does not match the D0 fixture boundary",
            )
        if (
            evidence.storage_write_performed
            or evidence.data_use_approved
            or evidence.registry_publish_performed
            or evidence.approved_asset_release_created
        ):
            raise LedgerError(
                "dataset_evidence_authority_violated",
                "Dataset evidence claims an unauthorized side effect",
            )
    return DatasetCompanyLoopOutcome(
        status=_strict_string(mapping["status"], "Dataset outcome status"),
        reason_codes=_string_tuple(mapping["reason_codes"], "Dataset outcome reasons"),
        company_outcome=_outcome_from_mapping(mapping["company_outcome"]),
        adapter_evidence=evidence,
    )


def _watchlist_outcome_from_mapping(value: Any) -> Any:
    from .watchlist_execution import WatchlistTaskOutcome

    mapping = _strict_mapping(value, "Watchlist Task outcome")
    _exact_keys(
        mapping,
        {
            "schema_version",
            "status",
            "task",
            "route_decision",
            "result",
            "evaluation",
            "audit_events",
            "control_snapshot",
            "watchlist_event_ref",
            "watchlist_snapshot_digest",
            "change_state",
            "agent_eligible",
            "domain_status",
            "reason_codes",
            "model_invocation_count",
            "worker_invocation_count",
            "monthly_period",
            "monthly_used_before_bytes",
            "monthly_budget_reserved_bytes",
            "monthly_used_after_bytes",
            "registry_implementation_revision",
            "scientific_implementation_revision",
            "runtime_bundle_revision",
            "registry_write_performed",
            "real_data_download_performed",
            "release_authorization",
        },
        "Watchlist Task outcome",
    )
    audits = mapping["audit_events"]
    if not isinstance(audits, list):
        raise LedgerError("invalid_record_payload", "Watchlist audits must be a list")
    event_ref = mapping["watchlist_event_ref"]
    snapshot_digest = mapping["watchlist_snapshot_digest"]
    change_state = mapping["change_state"]
    agent_eligible = mapping["agent_eligible"]
    for value_item, label in (
        (event_ref, "Watchlist event ref"),
        (snapshot_digest, "Watchlist snapshot digest"),
        (change_state, "Watchlist change state"),
    ):
        if value_item is not None and not isinstance(value_item, str):
            raise LedgerError("invalid_record_payload", f"{label} must be a string or null")
    if agent_eligible is not None and type(agent_eligible) is not bool:
        raise LedgerError(
            "invalid_record_payload", "Watchlist eligibility must be a boolean or null"
        )
    counts = {
        key: _strict_int(mapping[key], key)
        for key in (
            "model_invocation_count",
            "worker_invocation_count",
            "monthly_used_before_bytes",
            "monthly_budget_reserved_bytes",
            "monthly_used_after_bytes",
        )
    }
    if any(number < 0 for number in counts.values()):
        raise LedgerError("invalid_record_payload", "Watchlist counts may not be negative")
    control_snapshot = (
        None
        if mapping["control_snapshot"] is None
        else _snapshot_from_mapping(mapping["control_snapshot"])
    )
    return WatchlistTaskOutcome(
        schema_version=_strict_string(mapping["schema_version"], "Watchlist schema"),
        status=_strict_string(mapping["status"], "Watchlist status"),
        task=_task_from_mapping(mapping["task"]),
        route_decision=_route_from_mapping(mapping["route_decision"]),
        result=_result_from_mapping(mapping["result"]),
        evaluation=_evaluation_from_mapping(mapping["evaluation"]),
        audit_events=tuple(_audit_from_mapping(item) for item in audits),
        control_snapshot=control_snapshot,
        watchlist_event_ref=event_ref,
        watchlist_snapshot_digest=snapshot_digest,
        change_state=change_state,
        agent_eligible=agent_eligible,
        domain_status=_strict_string(mapping["domain_status"], "Watchlist domain status"),
        reason_codes=_string_tuple(mapping["reason_codes"], "Watchlist reason codes"),
        model_invocation_count=counts["model_invocation_count"],
        worker_invocation_count=counts["worker_invocation_count"],
        monthly_period=_strict_string(mapping["monthly_period"], "Watchlist period"),
        monthly_used_before_bytes=counts["monthly_used_before_bytes"],
        monthly_budget_reserved_bytes=counts["monthly_budget_reserved_bytes"],
        monthly_used_after_bytes=counts["monthly_used_after_bytes"],
        registry_implementation_revision=_strict_string(
            mapping["registry_implementation_revision"], "Registry Revision"
        ),
        scientific_implementation_revision=_strict_string(
            mapping["scientific_implementation_revision"], "Scientific Revision"
        ),
        runtime_bundle_revision=_strict_string(
            mapping["runtime_bundle_revision"], "runtime bundle Revision"
        ),
        registry_write_performed=_strict_bool(
            mapping["registry_write_performed"], "Registry write"
        ),
        real_data_download_performed=_strict_bool(
            mapping["real_data_download_performed"], "real data download"
        ),
        release_authorization=_strict_bool(
            mapping["release_authorization"], "release authorization"
        ),
    )


def _control_blocks_execution(snapshot: TaskControlSnapshot) -> bool:
    return (
        snapshot.task_status != "active"
        or snapshot.grant_status != "active"
        or snapshot.owner_kind != "control_plane"
    )


def _validate_disease_r1_outcome(value: Any) -> dict[str, Any]:
    outcome = _strict_mapping(value, "Disease R1 outcome")
    _exact_keys(
        outcome,
        {
            "outcome_version",
            "attempt_id",
            "task_id",
            "status",
            "review_request_digest",
            "agent_release_digest",
            "package_digest",
            "runtime_source_digest",
            "control_source_digest",
            "grant_digest",
            "evidence_ref",
            "evidence_digest",
            "domain_evaluation",
            "company_evaluation",
            "reason_codes",
            "evidence_status",
            "synthetic_only",
            "release_authorization",
        },
        "Disease R1 outcome",
    )
    status = _strict_string(outcome["status"], "Disease R1 status")
    reason_codes = _string_tuple(
        outcome["reason_codes"], "Disease R1 reason codes"
    )
    for key in (
        "review_request_digest",
        "agent_release_digest",
        "package_digest",
        "runtime_source_digest",
        "control_source_digest",
        "grant_digest",
        "evidence_digest",
    ):
        _strict_hash(outcome[key], f"Disease R1 {key}")
    if (
        outcome["outcome_version"] != "orbit.synthetic-disease-r1-outcome/1"
        or not _strict_string(outcome["attempt_id"], "Disease R1 attempt").startswith(
            "attempt_"
        )
        or status not in {"pass", "fail", "cancelled"}
        or not _strict_string(outcome["evidence_ref"], "Disease R1 evidence ref").startswith(
            "evidence://synthetic/disease-r1/"
        )
        or outcome["evidence_status"] != "synthetic"
        or _strict_bool(outcome["synthetic_only"], "Disease R1 synthetic_only")
        is not True
        or _strict_bool(
            outcome["release_authorization"], "Disease R1 release authorization"
        )
        is not False
        or not reason_codes
    ):
        raise LedgerError(
            "disease_r1_outcome_invalid", "Disease R1 outcome boundary differs"
        )
    domain = outcome["domain_evaluation"]
    company = outcome["company_evaluation"]
    if status == "pass":
        if domain is None or company is None:
            raise LedgerError(
                "disease_r1_outcome_invalid",
                "Passing Disease R1 outcome requires both evaluations",
            )
        for evaluation in (
            _evaluation_from_mapping(domain),
            _evaluation_from_mapping(company),
        ):
            if evaluation.verdict != "pass" or evaluation.release_authorization:
                raise LedgerError(
                    "disease_r1_outcome_invalid",
                    "Disease R1 evaluation does not support pass",
                )
    elif domain is not None or company is not None:
        raise LedgerError(
            "disease_r1_outcome_invalid",
            "Failed Disease R1 outcome cannot claim completed evaluations",
        )
    return _normalize_json(outcome)


def _exact_keys(value: Any, expected: set[str] | frozenset[str], label: str) -> None:
    mapping = _strict_mapping(value, label)
    if set(mapping) != set(expected):
        raise LedgerError("invalid_record_payload", f"{label} fields do not match")


def _outcome_status(value: Any) -> str:
    if isinstance(value, dict):
        return _strict_string(value.get("status"), "outcome status")
    return _strict_string(getattr(value, "status", None), "outcome status")


def _outcome_reason_codes(value: Any) -> tuple[str, ...]:
    if isinstance(value, dict):
        return _string_tuple(value.get("reason_codes"), "outcome reason codes")
    reason_codes = getattr(value, "reason_codes", None)
    if not isinstance(reason_codes, tuple) or not all(
        isinstance(item, str) for item in reason_codes
    ):
        raise LedgerError(
            "invalid_record_payload", "outcome reason codes must be strings"
        )
    return reason_codes


def _strict_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise LedgerError("invalid_record_payload", f"{label} must be an object")
    return value


def _strict_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise LedgerError("invalid_record_payload", f"{label} must be a non-empty string")
    return value


def _strict_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise LedgerError("invalid_record_payload", f"{label} must be a boolean")
    return value


def _strict_int(value: Any, label: str) -> int:
    if type(value) is not int:
        raise LedgerError("invalid_record_payload", f"{label} must be an integer")
    return value


def _strict_hash(value: Any, label: str) -> str:
    text = _strict_string(value, label)
    if not _HASH_PATTERN.fullmatch(text):
        raise LedgerError("invalid_record_payload", f"{label} must be a SHA-256 digest")
    return text


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise LedgerError("invalid_record_payload", f"{label} must be a string list")
    return tuple(value)


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise LedgerError("invalid_record_payload", "value is not canonical JSON") from error


def _normalize_json(value: Any) -> dict[str, Any]:
    normalized = json.loads(_canonical_json(value))
    return _strict_mapping(normalized, "record payload")


def _digest(value: bytes) -> str:
    return "sha256:" + sha256(value).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LedgerError("duplicate_json_key", "ledger JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise LedgerError("invalid_json_constant", f"JSON constant {value} is forbidden")

