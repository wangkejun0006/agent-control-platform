"""Owner-only durable ledger and reconciler for Agent release qualification.

The JSONL adapter is a local synthetic implementation of the storage port.  A
PostgreSQL/Outbox adapter can replace it without changing checkpoint or receipt
semantics.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Protocol

from ..ids import deterministic_id
from ..lifecycle_ledger import (
    append_jsonl_document,
    close_ledger,
    open_owner_only_ledger,
    read_jsonl_documents,
)
from .automation import (
    AUTOMATION_POLICY_ACTIVATION_RECEIPT_SCHEMA_ID,
    EXECUTION_CLOSURE_RECEIPT_SCHEMA_ID,
    EXECUTION_STAGES,
    HUMAN_STAGES,
    POLICY_DECISION_RECEIPT_SCHEMA_ID,
    QUALIFICATION_RUN_SCHEMA_ID,
    QUALIFICATION_STAGES,
    REMEDIATION_RECEIPT_SCHEMA_ID,
    STAGE_RECEIPT_SCHEMA_ID,
    CheckpointPolicy,
    EvaluationGrant,
    PolicyEngine,
    QualificationAutomationError,
    QualificationCandidate,
    ReceiptArtifact,
    RemediationHandler,
    RemediationPlan,
    StageCheck,
    StageHandler,
    StageHandlerResult,
    StageObservation,
    StageSideEffects,
    _validate_approval_decision_shape,
    build_remediation_receipt,
    build_stage_receipt,
    canonical_digest,
    issue_evaluation_grant,
    receipt_artifact,
    validate_automation_policy,
    validate_execution_closure,
    validate_policy_activation_receipt,
)

LEDGER_VERSION = "orbit.qualification-ledger/1"
GENESIS_HASH = "sha256:" + ("0" * 64)
MAX_LEDGER_BYTES = 32 * 1024 * 1024
MAX_RECORD_BYTES = 512 * 1024
_RECORD_TYPES = frozenset(
    {
        "run_registered",
        "stage_receipt_recorded",
        "remediation_receipt_recorded",
        "policy_decision_recorded",
        "evaluation_grant_issued",
        "evaluation_grant_consumed",
        "execution_closure_recorded",
        "human_checkpoint_resolved",
        "run_quarantined",
        "run_cancelled",
    }
)
_RECORD_KEYS = {
    "ledger_version",
    "sequence",
    "record_id",
    "record_type",
    "run_id",
    "idempotency_key",
    "previous_record_hash",
    "payload",
    "record_hash",
}


class QualificationLedgerError(QualificationAutomationError):
    pass


class QualificationEventStore(Protocol):
    def append(
        self,
        *,
        record_type: str,
        run_id: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
    ) -> QualificationAppendResult: ...

    def replay(self) -> QualificationReplay: ...


@dataclass(frozen=True)
class QualificationAppendResult:
    sequence: int
    record_id: str
    record_hash: str
    appended: bool


@dataclass(frozen=True)
class EvaluationGrantState:
    grant: EvaluationGrant
    consumption_status: str
    consumed_at: str | None
    outcome: str | None


@dataclass(frozen=True)
class QualificationRunState:
    run_id: str
    revision: int
    status: str
    policy: Mapping[str, Any]
    policy_digest: str
    policy_activation: ReceiptArtifact
    policy_approval_decision: Mapping[str, Any]
    candidate: QualificationCandidate
    stage_plan: tuple[str, ...]
    stage_handlers: Mapping[str, Mapping[str, str]]
    current_stage_index: int
    stage_attempts: Mapping[str, int]
    total_attempts: int
    stage_receipts: tuple[ReceiptArtifact, ...]
    remediation_receipts: tuple[ReceiptArtifact, ...]
    policy_decisions: tuple[ReceiptArtifact, ...]
    evaluation_grants: tuple[EvaluationGrantState, ...]
    execution_closures: tuple[ReceiptArtifact, ...]
    human_checkpoint_decisions: tuple[Mapping[str, Any], ...]
    next_checkpoint_scope: str | None
    next_checkpoint_reason_codes: tuple[str, ...]
    registered_at: str

    @property
    def current_stage(self) -> str:
        return self.stage_plan[self.current_stage_index]

    @property
    def last_stage_receipt(self) -> ReceiptArtifact | None:
        return self.stage_receipts[-1] if self.stage_receipts else None

    def latest_policy_decision(
        self, stage: str | None = None
    ) -> ReceiptArtifact | None:
        selected_stage = self.current_stage if stage is None else stage
        matches = tuple(
            receipt
            for receipt in self.policy_decisions
            if receipt.document["metadata"]["attempt_id"] == self.candidate.attempt_id
            and receipt.document["metadata"]["stage"] == selected_stage
        )
        return matches[-1] if matches else None

    def grant_for_current_attempt(
        self, stage: str | None = None
    ) -> EvaluationGrantState | None:
        selected_stage = self.current_stage if stage is None else stage
        matches = tuple(
            state
            for state in self.evaluation_grants
            if state.grant.attempt_id == self.candidate.attempt_id
            and state.grant.stage == selected_stage
        )
        return matches[-1] if matches else None


@dataclass(frozen=True)
class QualificationReplay:
    records_checked: int
    last_record_hash: str
    runs: tuple[QualificationRunState, ...]

    def run(self, run_id: str) -> QualificationRunState:
        matches = tuple(run for run in self.runs if run.run_id == run_id)
        if len(matches) != 1:
            raise QualificationLedgerError(
                "qualification_run_not_found"
                if not matches
                else "qualification_run_ambiguous"
            )
        return matches[0]


class JsonlQualificationEventStore:
    """Tamper-evident local store; not a production database."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def append(
        self,
        *,
        record_type: str,
        run_id: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
    ) -> QualificationAppendResult:
        if record_type not in _RECORD_TYPES:
            raise QualificationLedgerError("qualification_record_type_invalid")
        if not isinstance(run_id, str) or not run_id.startswith("run_"):
            raise QualificationLedgerError("qualification_run_id_invalid")
        if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 192:
            raise QualificationLedgerError("qualification_idempotency_key_invalid")
        normalized = _normalize(payload)
        fd = open_owner_only_ledger(
            self.path,
            create=True,
            exclusive=True,
            error=QualificationLedgerError,
            label="Qualification ledger",
        )
        try:
            replay, records = _replay(fd, include_records=True)
            for record in records:
                if record["idempotency_key"] != idempotency_key:
                    continue
                if (
                    record["record_type"] == record_type
                    and record["run_id"] == run_id
                    and record["payload"] == normalized
                ):
                    return QualificationAppendResult(
                        record["sequence"],
                        record["record_id"],
                        record["record_hash"],
                        False,
                    )
                raise QualificationLedgerError("qualification_idempotency_conflict")
            _validate_new_record(replay, record_type, run_id, normalized)
            content = {
                "ledger_version": LEDGER_VERSION,
                "sequence": len(records),
                "record_id": deterministic_id(
                    "qualrec",
                    record_type,
                    run_id,
                    idempotency_key,
                    canonical_digest(normalized),
                ),
                "record_type": record_type,
                "run_id": run_id,
                "idempotency_key": idempotency_key,
                "previous_record_hash": replay.last_record_hash,
                "payload": normalized,
            }
            document = {**content, "record_hash": canonical_digest(content)}
            append_jsonl_document(
                fd,
                (_canonical(document) + "\n").encode("utf-8"),
                max_ledger_bytes=MAX_LEDGER_BYTES,
                max_record_bytes=MAX_RECORD_BYTES,
                error=QualificationLedgerError,
                label="Qualification ledger",
            )
            return QualificationAppendResult(
                content["sequence"],
                content["record_id"],
                document["record_hash"],
                True,
            )
        finally:
            close_ledger(fd)

    def replay(self) -> QualificationReplay:
        fd = open_owner_only_ledger(
            self.path,
            create=False,
            exclusive=False,
            error=QualificationLedgerError,
            label="Qualification ledger",
        )
        try:
            return _replay(fd)
        finally:
            close_ledger(fd)


class QualificationController:
    """Command boundary for the durable qualification state machine."""

    def __init__(self, store: QualificationEventStore) -> None:
        self.store = store

    def register_run(
        self,
        *,
        run_id: str,
        policy: Mapping[str, Any],
        policy_digest: str,
        policy_activation: ReceiptArtifact,
        policy_approval_decision: Mapping[str, Any],
        candidate: QualificationCandidate,
        stage_plan: tuple[str, ...],
        stage_handlers: Mapping[str, Mapping[str, str]],
        registered_at: str,
        idempotency_key: str,
    ) -> QualificationAppendResult:
        validate_automation_policy(policy)
        if canonical_digest(policy) != policy_digest:
            raise QualificationLedgerError("qualification_policy_digest_mismatch")
        validate_policy_activation_receipt(
            policy=policy,
            policy_digest=policy_digest,
            approval_decision=policy_approval_decision,
            receipt=policy_activation,
        )
        if tuple(policy["spec"]["stage_plan"]) != stage_plan:
            raise QualificationLedgerError("qualification_stage_plan_mismatch")
        normalized_handlers = _stage_handler_bindings(stage_plan, stage_handlers)
        _validate_evaluator_separation(stage_plan, normalized_handlers)
        allowed_handler_digests = set(candidate.stage_handler_digests)
        if any(
            binding["digest"] not in allowed_handler_digests
            for binding in normalized_handlers.values()
        ):
            raise QualificationLedgerError("qualification_stage_handler_not_bound")
        _time(registered_at)
        return self.store.append(
            record_type="run_registered",
            run_id=run_id,
            idempotency_key=idempotency_key,
            payload={
                "policy": policy,
                "policy_digest": policy_digest,
                "policy_activation": _receipt_mapping(policy_activation),
                "policy_approval_decision": policy_approval_decision,
                "candidate": candidate.to_mapping(),
                "stage_plan": list(stage_plan),
                "stage_handlers": normalized_handlers,
                "registered_at": registered_at,
            },
        )

    def record_stage_receipt(
        self,
        *,
        run_id: str,
        receipt: ReceiptArtifact,
        idempotency_key: str,
    ) -> QualificationAppendResult:
        return self.store.append(
            record_type="stage_receipt_recorded",
            run_id=run_id,
            payload={"receipt": _receipt_mapping(receipt)},
            idempotency_key=idempotency_key,
        )

    def record_remediation_receipt(
        self,
        *,
        run_id: str,
        receipt: ReceiptArtifact,
        successor: QualificationCandidate,
        idempotency_key: str,
    ) -> QualificationAppendResult:
        return self.store.append(
            record_type="remediation_receipt_recorded",
            run_id=run_id,
            payload={
                "receipt": _receipt_mapping(receipt),
                "successor": successor.to_mapping(),
            },
            idempotency_key=idempotency_key,
        )

    def record_policy_decision(
        self,
        *,
        run_id: str,
        receipt: ReceiptArtifact,
        idempotency_key: str,
    ) -> QualificationAppendResult:
        return self.store.append(
            record_type="policy_decision_recorded",
            run_id=run_id,
            payload={"receipt": _receipt_mapping(receipt)},
            idempotency_key=idempotency_key,
        )

    def issue_evaluation_grant(
        self,
        *,
        run_id: str,
        grant: EvaluationGrant,
        idempotency_key: str,
    ) -> QualificationAppendResult:
        return self.store.append(
            record_type="evaluation_grant_issued",
            run_id=run_id,
            payload={"grant": asdict(grant)},
            idempotency_key=idempotency_key,
        )

    def consume_evaluation_grant(
        self,
        *,
        run_id: str,
        grant_digest: str,
        consumed_at: str,
        outcome: str,
        idempotency_key: str,
    ) -> QualificationAppendResult:
        return self.store.append(
            record_type="evaluation_grant_consumed",
            run_id=run_id,
            payload={
                "grant_digest": grant_digest,
                "consumed_at": consumed_at,
                "outcome": outcome,
            },
            idempotency_key=idempotency_key,
        )

    def record_execution_closure(
        self,
        *,
        run_id: str,
        receipt: ReceiptArtifact,
        idempotency_key: str,
    ) -> QualificationAppendResult:
        return self.store.append(
            record_type="execution_closure_recorded",
            run_id=run_id,
            payload={"receipt": _receipt_mapping(receipt)},
            idempotency_key=idempotency_key,
        )

    def resolve_human_checkpoint(
        self,
        *,
        run_id: str,
        approval_decision: Mapping[str, Any],
        idempotency_key: str,
    ) -> QualificationAppendResult:
        return self.store.append(
            record_type="human_checkpoint_resolved",
            run_id=run_id,
            payload={"approval_decision": approval_decision},
            idempotency_key=idempotency_key,
        )

    def quarantine(
        self,
        *,
        run_id: str,
        reason_codes: tuple[str, ...],
        recorded_at: str,
        idempotency_key: str,
    ) -> QualificationAppendResult:
        return self.store.append(
            record_type="run_quarantined",
            run_id=run_id,
            payload={"reason_codes": list(reason_codes), "recorded_at": recorded_at},
            idempotency_key=idempotency_key,
        )

    def cancel(
        self,
        *,
        run_id: str,
        reason_codes: tuple[str, ...],
        recorded_at: str,
        idempotency_key: str,
    ) -> QualificationAppendResult:
        return self.store.append(
            record_type="run_cancelled",
            run_id=run_id,
            payload={"reason_codes": list(reason_codes), "recorded_at": recorded_at},
            idempotency_key=idempotency_key,
        )

    def replay(self) -> QualificationReplay:
        return self.store.replay()


class QualificationReconciler:
    """Advance a run until a human checkpoint or terminal state."""

    def __init__(
        self,
        controller: QualificationController,
        *,
        stage_handlers: Mapping[str, StageHandler],
        remediation_handlers: Mapping[str, RemediationHandler],
        handler_digests: Mapping[str, str],
        now: Callable[[], datetime] | None = None,
        max_transitions: int = 100,
    ) -> None:
        self.controller = controller
        self.stage_handlers = dict(stage_handlers)
        self.remediation_handlers = dict(remediation_handlers)
        self.handler_digests = dict(handler_digests)
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.max_transitions = max_transitions

    def run_until_checkpoint(self, run_id: str) -> QualificationRunState:
        for transition in range(self.max_transitions):
            state = self.controller.replay().run(run_id)
            if state.status in {
                "waiting_human",
                "completed",
                "failed",
                "cancelled",
                "quarantined",
            }:
                return state
            if state.status == "remediating":
                last = state.last_stage_receipt
                if (
                    last is not None
                    and last.document["spec"]["decision"]["next_action"]
                    == "automation_pause"
                ):
                    return state
                handler = self.remediation_handlers.get(state.current_stage)
                if handler is None:
                    return state
                if not self._handler_identity_matches(state):
                    self.controller.quarantine(
                        run_id=run_id,
                        reason_codes=("qualification_handler_digest_drift",),
                        recorded_at=_time_text(self.now()),
                        idempotency_key=(
                            f"reconcile:{run_id}:quarantine:handler:"
                            f"{state.current_stage}:{state.candidate.attempt_id}"
                        ),
                    )
                    return self.controller.replay().run(run_id)
                last = state.last_stage_receipt
                if last is None:
                    raise QualificationLedgerError("remediation_stage_receipt_missing")
                observation = _observation_from_stage_receipt(last)
                plan = handler(_handler_context(state), observation)
                remediation = build_remediation_receipt(
                    run_id=run_id,
                    policy=state.policy,
                    policy_digest=state.policy_digest,
                    predecessor=state.candidate,
                    failed_stage_receipt=last,
                    plan=plan,
                    created_at=_time_text(self.now()),
                )
                self.controller.record_remediation_receipt(
                    run_id=run_id,
                    receipt=remediation,
                    successor=plan.successor,
                    idempotency_key=(
                        f"reconcile:{run_id}:remediate:{plan.successor.attempt_id}"
                    ),
                )
                continue

            if state.current_stage in EXECUTION_STAGES:
                stage = state.current_stage
                grant_state = state.grant_for_current_attempt(stage)
                decision = state.latest_policy_decision(stage)
                if decision is None:
                    decision = PolicyEngine.evaluate(
                        policy=state.policy,
                        policy_digest=state.policy_digest,
                        policy_activation=state.policy_activation,
                        run_id=run_id,
                        stage=stage,
                        candidate=state.candidate,
                        decided_at=_time_text(self.now()),
                    )
                    self.controller.record_policy_decision(
                        run_id=run_id,
                        receipt=decision,
                        idempotency_key=(
                            f"reconcile:{run_id}:policy:{state.candidate.attempt_id}:"
                            f"{stage}"
                        ),
                    )
                    continue
                if decision.document["spec"]["decision"] != "allow":
                    observation = _policy_checkpoint_observation(
                        state,
                        tuple(decision.document["spec"]["reason_codes"]),
                        self.now,
                    )
                    checkpoint = CheckpointPolicy.classify(
                        policy=state.policy,
                        observation=observation,
                        stage_attempt=state.stage_attempts.get(state.current_stage, 0),
                        total_attempt=state.candidate.attempt_number - 1,
                    )
                    receipt = build_stage_receipt(
                        run_id=run_id,
                        candidate=state.candidate,
                        sequence=len(state.stage_receipts),
                        observation=observation,
                        decision=checkpoint,
                    )
                    self.controller.record_stage_receipt(
                        run_id=run_id,
                        receipt=receipt,
                        idempotency_key=(
                            f"reconcile:{run_id}:stage:{state.candidate.attempt_id}:"
                            f"{state.current_stage}:{len(state.stage_receipts)}"
                        ),
                    )
                    continue
                if grant_state is None:
                    issued = self.now().astimezone(timezone.utc).replace(microsecond=0)
                    expires = issued + timedelta(
                        seconds=state.candidate.max_runtime_seconds
                    )
                    grant = issue_evaluation_grant(
                        run_id=run_id,
                        candidate=state.candidate,
                        stage=stage,
                        policy_decision=decision,
                        issued_at=issued.isoformat(),
                        expires_at=expires.isoformat(),
                    )
                    self.controller.issue_evaluation_grant(
                        run_id=run_id,
                        grant=grant,
                        idempotency_key=(
                            f"reconcile:{run_id}:grant:{state.candidate.attempt_id}:"
                            f"{stage}"
                        ),
                    )
                    continue
                if grant_state.consumption_status != "active":
                    raise QualificationLedgerError(
                        "evaluation_stage_grant_already_consumed"
                    )

            handler = self.stage_handlers.get(state.current_stage)
            if handler is None:
                result = StageHandlerResult(
                    _engineering_failure_observation(
                        state, "qualification_stage_handler_missing", self.now()
                    )
                )
            elif not self._handler_identity_matches(state):
                result = StageHandlerResult(
                    _drift_observation(
                        state, "qualification_handler_digest_drift", self.now
                    )
                )
            else:
                result = handler(_handler_context(state))
                if not isinstance(result, StageHandlerResult):
                    raise QualificationLedgerError(
                        "qualification_stage_handler_invalid"
                    )
            observation = result.observation
            if observation.stage != state.current_stage:
                raise QualificationLedgerError("qualification_stage_handler_mismatch")
            if state.current_stage in EXECUTION_STAGES:
                grant_state = state.grant_for_current_attempt(state.current_stage)
                if grant_state is None:
                    raise QualificationLedgerError(
                        "evaluation_grant_missing_before_stage"
                    )
                closure = None
                closure_reason = None
                if result.execution_closure is None:
                    closure_reason = "execution_closure_missing"
                else:
                    try:
                        validate_execution_closure(result.execution_closure)
                        closure = receipt_artifact(
                            EXECUTION_CLOSURE_RECEIPT_SCHEMA_ID,
                            result.execution_closure,
                        )
                        if not _execution_closure_matches(
                            state,
                            grant_state,
                            closure,
                            outcome=observation.outcome,
                            require_consumed=False,
                        ):
                            closure_reason = "execution_closure_binding_invalid"
                    except (QualificationAutomationError, KeyError, TypeError):
                        closure_reason = "execution_closure_invalid"
                if closure_reason is not None:
                    self.controller.consume_evaluation_grant(
                        run_id=run_id,
                        grant_digest=grant_state.grant.grant_digest,
                        consumed_at=_time_text(self.now()),
                        outcome="fail",
                        idempotency_key=(
                            f"reconcile:{run_id}:consume-invalid:"
                            f"{state.candidate.attempt_id}:{state.current_stage}"
                        ),
                    )
                    failure = _execution_closure_failure_observation(
                        state, observation, closure_reason
                    )
                    checkpoint = CheckpointPolicy.classify(
                        policy=state.policy,
                        observation=failure,
                        stage_attempt=state.stage_attempts.get(state.current_stage, 0),
                        total_attempt=state.candidate.attempt_number - 1,
                    )
                    receipt = build_stage_receipt(
                        run_id=run_id,
                        candidate=state.candidate,
                        sequence=len(state.stage_receipts),
                        observation=failure,
                        decision=checkpoint,
                    )
                    self.controller.record_stage_receipt(
                        run_id=run_id,
                        receipt=receipt,
                        idempotency_key=(
                            f"reconcile:{run_id}:stage-invalid-closure:"
                            f"{state.candidate.attempt_id}:{state.current_stage}"
                        ),
                    )
                    return self.controller.replay().run(run_id)
            checkpoint = CheckpointPolicy.classify(
                policy=state.policy,
                observation=observation,
                stage_attempt=state.stage_attempts.get(state.current_stage, 0),
                total_attempt=state.candidate.attempt_number - 1,
            )
            stage_receipt = build_stage_receipt(
                run_id=run_id,
                candidate=state.candidate,
                sequence=len(state.stage_receipts),
                observation=observation,
                decision=checkpoint,
            )
            self.controller.record_stage_receipt(
                run_id=run_id,
                receipt=stage_receipt,
                idempotency_key=(
                    f"reconcile:{run_id}:stage:{state.candidate.attempt_id}:"
                    f"{state.current_stage}:{len(state.stage_receipts)}"
                ),
            )
            if state.current_stage in EXECUTION_STAGES:
                grant_state = (
                    self.controller.replay()
                    .run(run_id)
                    .grant_for_current_attempt(state.current_stage)
                )
                if grant_state is None:
                    raise QualificationLedgerError(
                        "evaluation_grant_missing_after_stage"
                    )
                self.controller.consume_evaluation_grant(
                    run_id=run_id,
                    grant_digest=grant_state.grant.grant_digest,
                    consumed_at=_time_text(self.now()),
                    outcome=observation.outcome,
                    idempotency_key=(
                        f"reconcile:{run_id}:consume:{state.candidate.attempt_id}:"
                        f"{state.current_stage}"
                    ),
                )
                if closure is None:
                    raise QualificationLedgerError(
                        "execution_closure_missing_after_stage"
                    )
                self.controller.record_execution_closure(
                    run_id=run_id,
                    receipt=closure,
                    idempotency_key=(
                        f"reconcile:{run_id}:closure:{state.candidate.attempt_id}:"
                        f"{state.current_stage}"
                    ),
                )

        state = self.controller.replay().run(run_id)
        self.controller.quarantine(
            run_id=run_id,
            reason_codes=("reconciler_transition_limit_exhausted",),
            recorded_at=_time_text(self.now()),
            idempotency_key=f"reconcile:{run_id}:quarantine:transition-limit",
        )
        return self.controller.replay().run(run_id)

    def _handler_identity_matches(self, state: QualificationRunState) -> bool:
        return (
            self.handler_digests.get(state.current_stage)
            == state.stage_handlers[state.current_stage]["digest"]
        )


def qualification_run_snapshot(
    state: QualificationRunState, *, updated_at: str
) -> ReceiptArtifact:
    """Build a formal, replay-derived QualificationRun snapshot."""
    _time(updated_at)
    metadata_status = "running" if state.status == "remediating" else state.status
    if metadata_status not in {
        "running",
        "waiting_human",
        "completed",
        "failed",
        "cancelled",
        "quarantined",
    }:
        raise QualificationLedgerError("qualification_snapshot_status_invalid")
    policy_metadata = state.policy["metadata"]
    predecessor_attempt_id = (
        None
        if not state.remediation_receipts
        else state.remediation_receipts[-1].document["spec"]["predecessor"][
            "attempt_id"
        ]
    )
    next_checkpoint = None
    if state.status == "waiting_human":
        if not state.next_checkpoint_scope or not state.next_checkpoint_reason_codes:
            raise QualificationLedgerError("qualification_snapshot_checkpoint_invalid")
        checkpoint_ref, checkpoint_digest = _checkpoint_subject(state)
        next_checkpoint = {
            "scope": state.next_checkpoint_scope,
            "subject_ref": checkpoint_ref,
            "subject_digest": checkpoint_digest,
            "reason_codes": list(state.next_checkpoint_reason_codes),
        }
    document = {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "QualificationRun",
        "metadata": {
            "run_id": state.run_id,
            "revision": state.revision,
            "status": metadata_status,
            "current_stage": state.current_stage,
            "evidence_status": policy_metadata["evidence_status"],
            "synthetic_only": policy_metadata["synthetic_only"],
            "created_at": state.registered_at,
            "updated_at": updated_at,
        },
        "spec": {
            "agent_id": state.candidate.agent_id,
            "agent_release": {
                "role": "agent_release",
                "ref": state.candidate.agent_release_ref,
                "digest": state.candidate.agent_release_digest,
            },
            "automation_policy": {
                "role": "automation_policy",
                "ref": (
                    f"policy://{policy_metadata['policy_id']}/"
                    f"{policy_metadata['version']}"
                ),
                "digest": state.policy_digest,
            },
            "automation_policy_activation": {
                "role": "automation_policy_activation_receipt",
                "ref": (
                    "receipt://"
                    + state.policy_activation.document["metadata"]["receipt_id"]
                ),
                "digest": state.policy_activation.digest,
            },
            "stage_plan": [
                {
                    "stage": stage,
                    "handler": state.stage_handlers[stage],
                    "required": True,
                    "max_attempts": state.policy["spec"]["execution_envelope"][
                        "max_attempts_per_stage"
                    ],
                }
                for stage in state.stage_plan
            ],
            "attempt": {
                "attempt_id": state.candidate.attempt_id,
                "number": state.candidate.attempt_number,
                "idempotency_key": (
                    f"qualification:{state.run_id}:{state.candidate.attempt_id}"
                ),
                "composition_ref": state.candidate.composition_ref,
                "composition_digest": state.candidate.composition_digest,
                "predecessor_attempt_id": predecessor_attempt_id,
            },
            "stage_receipt_refs": [
                {
                    "role": (
                        "passed_stage_receipt"
                        if receipt.document["metadata"]["outcome"] == "passed"
                        else "blocked_stage_receipt"
                    ),
                    "ref": "receipt://" + receipt.document["metadata"]["receipt_id"],
                    "digest": receipt.digest,
                }
                for receipt in state.stage_receipts
            ],
            "human_checkpoint_decision_refs": [
                {
                    "role": "human_checkpoint_approval",
                    "ref": "approval://" + decision["metadata"]["decision_id"],
                    "digest": canonical_digest(decision),
                }
                for decision in state.human_checkpoint_decisions
            ],
            "next_checkpoint": next_checkpoint,
            "execution_closure_refs": [
                {
                    "role": "execution_closure_receipt",
                    "ref": "receipt://" + receipt.document["metadata"]["receipt_id"],
                    "digest": receipt.digest,
                }
                for receipt in state.execution_closures
            ],
            "authority_boundary": {
                "company_authoritative_run_state": True,
                "approval_inferred": False,
                "agent_lifecycle_mutated": False,
                "release_authorization": False,
            },
        },
    }
    return receipt_artifact(QUALIFICATION_RUN_SCHEMA_ID, document)


def _validate_new_record(
    replay: QualificationReplay,
    record_type: str,
    run_id: str,
    payload: Mapping[str, Any],
) -> None:
    runs = {run.run_id: run for run in replay.runs}
    if record_type == "run_registered":
        if run_id in runs:
            raise QualificationLedgerError("qualification_run_already_registered")
        _state_from_registration(run_id, payload)
        return
    state = runs.get(run_id)
    if state is None:
        raise QualificationLedgerError("qualification_run_registration_missing")
    _apply_event(state, record_type, payload)


def _replay(
    fd: int, *, include_records: bool = False
) -> QualificationReplay | tuple[QualificationReplay, tuple[dict[str, Any], ...]]:
    records = read_jsonl_documents(
        fd,
        max_ledger_bytes=MAX_LEDGER_BYTES,
        max_record_bytes=MAX_RECORD_BYTES,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        error=QualificationLedgerError,
        label="Qualification ledger",
    )
    states: dict[str, QualificationRunState] = {}
    previous = GENESIS_HASH
    idempotency_keys: set[str] = set()
    for sequence, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
            raise QualificationLedgerError("qualification_record_fields_invalid")
        content = {key: value for key, value in record.items() if key != "record_hash"}
        if (
            record["ledger_version"] != LEDGER_VERSION
            or record["sequence"] != sequence
            or record["record_type"] not in _RECORD_TYPES
            or record["previous_record_hash"] != previous
            or record["record_hash"] != canonical_digest(content)
            or record["idempotency_key"] in idempotency_keys
        ):
            raise QualificationLedgerError("qualification_ledger_chain_invalid")
        run_id = record["run_id"]
        if record["record_type"] == "run_registered":
            if run_id in states:
                raise QualificationLedgerError("qualification_run_already_registered")
            states[run_id] = _state_from_registration(run_id, record["payload"])
        else:
            state = states.get(run_id)
            if state is None:
                raise QualificationLedgerError("qualification_run_registration_missing")
            states[run_id] = _apply_event(
                state, record["record_type"], record["payload"]
            )
        previous = record["record_hash"]
        idempotency_keys.add(record["idempotency_key"])
    replay = QualificationReplay(len(records), previous, tuple(states.values()))
    return (replay, records) if include_records else replay


def _state_from_registration(
    run_id: str, payload: Mapping[str, Any]
) -> QualificationRunState:
    if set(payload) != {
        "policy",
        "policy_digest",
        "policy_activation",
        "policy_approval_decision",
        "candidate",
        "stage_plan",
        "stage_handlers",
        "registered_at",
    }:
        raise QualificationLedgerError("qualification_registration_fields_invalid")
    validate_automation_policy(payload["policy"])
    if canonical_digest(payload["policy"]) != payload["policy_digest"]:
        raise QualificationLedgerError("qualification_policy_digest_mismatch")
    policy_activation = _receipt_from_mapping(
        payload["policy_activation"],
        AUTOMATION_POLICY_ACTIVATION_RECEIPT_SCHEMA_ID,
    )
    validate_policy_activation_receipt(
        policy=payload["policy"],
        policy_digest=payload["policy_digest"],
        approval_decision=payload["policy_approval_decision"],
        receipt=policy_activation,
    )
    candidate = QualificationCandidate.from_mapping(payload["candidate"])
    stage_plan = tuple(payload["stage_plan"])
    if (
        not stage_plan
        or stage_plan != tuple(payload["policy"]["spec"]["stage_plan"])
        or any(stage not in QUALIFICATION_STAGES for stage in stage_plan)
    ):
        raise QualificationLedgerError("qualification_stage_plan_mismatch")
    stage_handlers = _stage_handler_bindings(stage_plan, payload["stage_handlers"])
    _validate_evaluator_separation(stage_plan, stage_handlers)
    if any(
        binding["digest"] not in set(candidate.stage_handler_digests)
        for binding in stage_handlers.values()
    ):
        raise QualificationLedgerError("qualification_stage_handler_not_bound")
    _time(payload["registered_at"])
    return QualificationRunState(
        run_id=run_id,
        revision=0,
        status="running",
        policy=payload["policy"],
        policy_digest=payload["policy_digest"],
        policy_activation=policy_activation,
        policy_approval_decision=payload["policy_approval_decision"],
        candidate=candidate,
        stage_plan=stage_plan,
        stage_handlers=stage_handlers,
        current_stage_index=0,
        stage_attempts={},
        total_attempts=0,
        stage_receipts=(),
        remediation_receipts=(),
        policy_decisions=(),
        evaluation_grants=(),
        execution_closures=(),
        human_checkpoint_decisions=(),
        next_checkpoint_scope=None,
        next_checkpoint_reason_codes=(),
        registered_at=payload["registered_at"],
    )


def _apply_event(
    state: QualificationRunState, record_type: str, payload: Mapping[str, Any]
) -> QualificationRunState:
    if state.status in {"completed", "failed", "cancelled", "quarantined"}:
        raise QualificationLedgerError("qualification_run_already_terminal")
    revision = state.revision + 1
    if record_type == "stage_receipt_recorded":
        if state.status != "running" or set(payload) != {"receipt"}:
            raise QualificationLedgerError("qualification_stage_state_invalid")
        receipt = _receipt_from_mapping(payload["receipt"], STAGE_RECEIPT_SCHEMA_ID)
        document = receipt.document
        metadata = document["metadata"]
        if (
            metadata["run_id"] != state.run_id
            or metadata["attempt_id"] != state.candidate.attempt_id
            or metadata["attempt_number"] != state.candidate.attempt_number
            or metadata["stage"] != state.current_stage
            or metadata["sequence"] != len(state.stage_receipts)
        ):
            raise QualificationLedgerError(
                "qualification_stage_receipt_binding_invalid"
            )
        observation = _observation_from_stage_receipt(receipt)
        expected_decision = CheckpointPolicy.classify(
            policy=state.policy,
            observation=observation,
            stage_attempt=state.stage_attempts.get(state.current_stage, 0),
            total_attempt=state.candidate.attempt_number - 1,
        )
        expected_receipt = build_stage_receipt(
            run_id=state.run_id,
            candidate=state.candidate,
            sequence=len(state.stage_receipts),
            observation=observation,
            decision=expected_decision,
        )
        if receipt != expected_receipt:
            raise QualificationLedgerError("qualification_stage_receipt_invalid")
        decision = document["spec"]["decision"]
        attempts = dict(state.stage_attempts)
        attempts[state.current_stage] = attempts.get(state.current_stage, 0) + 1
        next_action = decision["next_action"]
        next_index = state.current_stage_index
        status = "running"
        checkpoint_scope = None
        checkpoint_reasons: tuple[str, ...] = ()
        if next_action == "auto_advance":
            if next_index + 1 < len(state.stage_plan):
                next_index += 1
            else:
                status = "completed"
        elif next_action in {"auto_remediate", "auto_retry", "automation_pause"}:
            status = "remediating"
        elif next_action == "human_checkpoint":
            status = "waiting_human"
            checkpoint_scope = decision["human_checkpoint_scope"]
            checkpoint_reasons = tuple(decision["reason_codes"])
        elif next_action == "quarantine":
            status = "quarantined"
            checkpoint_scope = decision["human_checkpoint_scope"]
            checkpoint_reasons = tuple(decision["reason_codes"])
        elif next_action == "complete":
            status = "completed"
        else:
            raise QualificationLedgerError("qualification_stage_next_action_invalid")
        return replace(
            state,
            revision=revision,
            status=status,
            current_stage_index=next_index,
            stage_attempts=attempts,
            total_attempts=state.total_attempts + 1,
            stage_receipts=state.stage_receipts + (receipt,),
            next_checkpoint_scope=checkpoint_scope,
            next_checkpoint_reason_codes=checkpoint_reasons,
        )
    if record_type == "remediation_receipt_recorded":
        if state.status != "remediating" or set(payload) != {"receipt", "successor"}:
            raise QualificationLedgerError("qualification_remediation_state_invalid")
        receipt = _receipt_from_mapping(
            payload["receipt"], REMEDIATION_RECEIPT_SCHEMA_ID
        )
        successor = QualificationCandidate.from_mapping(payload["successor"])
        document = receipt.document
        if (
            document["metadata"]["run_id"] != state.run_id
            or document["spec"]["predecessor"]["attempt_id"]
            != state.candidate.attempt_id
            or document["spec"]["successor"]["attempt_id"] != successor.attempt_id
            or successor.attempt_number != state.candidate.attempt_number + 1
            or any(
                state.candidate.boundary_digests[name]
                != successor.boundary_digests[name]
                for name in state.candidate.boundary_digests
            )
        ):
            raise QualificationLedgerError("qualification_remediation_binding_invalid")
        last_stage = state.last_stage_receipt
        if last_stage is None:
            raise QualificationLedgerError("qualification_remediation_binding_invalid")
        plan = RemediationPlan(
            successor=successor,
            changes=tuple(document["spec"]["changes"]),
            verification_receipt_refs=tuple(
                document["spec"]["verification_receipt_refs"]
            ),
        )
        expected_receipt = build_remediation_receipt(
            run_id=state.run_id,
            policy=state.policy,
            policy_digest=state.policy_digest,
            predecessor=state.candidate,
            failed_stage_receipt=last_stage,
            plan=plan,
            created_at=document["metadata"]["created_at"],
        )
        if receipt != expected_receipt:
            raise QualificationLedgerError("qualification_remediation_receipt_invalid")
        restart_index = state.current_stage_index
        runtime_stage = "runtime_realization"
        if runtime_stage in state.stage_plan:
            runtime_index = state.stage_plan.index(runtime_stage)
            if state.current_stage_index >= runtime_index:
                restart_index = runtime_index
        return replace(
            state,
            revision=revision,
            status="running",
            candidate=successor,
            current_stage_index=restart_index,
            remediation_receipts=state.remediation_receipts + (receipt,),
            next_checkpoint_scope=None,
            next_checkpoint_reason_codes=(),
        )
    if record_type == "policy_decision_recorded":
        if state.status != "running" or set(payload) != {"receipt"}:
            raise QualificationLedgerError("qualification_policy_state_invalid")
        receipt = _receipt_from_mapping(
            payload["receipt"], POLICY_DECISION_RECEIPT_SCHEMA_ID
        )
        expected = PolicyEngine.evaluate(
            policy=state.policy,
            policy_digest=state.policy_digest,
            policy_activation=state.policy_activation,
            run_id=state.run_id,
            stage=receipt.document["metadata"]["stage"],
            candidate=state.candidate,
            decided_at=receipt.document["metadata"]["decided_at"],
        )
        if receipt != expected:
            raise QualificationLedgerError("qualification_policy_receipt_invalid")
        stage = receipt.document["metadata"]["stage"]
        if (
            stage != state.current_stage
            or state.latest_policy_decision(stage) is not None
        ):
            raise QualificationLedgerError("qualification_policy_decision_duplicate")
        return replace(
            state,
            revision=revision,
            policy_decisions=state.policy_decisions + (receipt,),
        )
    if record_type == "evaluation_grant_issued":
        if state.status != "running" or set(payload) != {"grant"}:
            raise QualificationLedgerError("evaluation_grant_state_invalid")
        grant = _grant_from_mapping(payload["grant"])
        decision = state.latest_policy_decision(grant.stage)
        if (
            decision is None
            or decision.document["spec"]["decision"] != "allow"
            or grant.run_id != state.run_id
            or grant.attempt_id != state.candidate.attempt_id
            or grant.stage != state.current_stage
            or grant.policy_decision_receipt_digest != decision.digest
            or grant.composition_digest != state.candidate.composition_digest
            or state.grant_for_current_attempt(grant.stage) is not None
        ):
            raise QualificationLedgerError("evaluation_grant_binding_invalid")
        return replace(
            state,
            revision=revision,
            evaluation_grants=state.evaluation_grants
            + (EvaluationGrantState(grant, "active", None, None),),
        )
    if record_type == "evaluation_grant_consumed":
        if set(payload) != {"grant_digest", "consumed_at", "outcome"}:
            raise QualificationLedgerError("evaluation_grant_consumption_invalid")
        matching = tuple(
            item
            for item in state.evaluation_grants
            if item.grant.grant_digest == payload["grant_digest"]
        )
        current = matching[-1] if matching else None
        if (
            current is None
            or current.consumption_status != "active"
            or current.grant.grant_digest != payload["grant_digest"]
            or payload["outcome"] not in {"pass", "blocked", "fail", "cancelled"}
        ):
            raise QualificationLedgerError("evaluation_grant_consumption_invalid")
        _time(payload["consumed_at"])
        grants = tuple(
            replace(
                item,
                consumption_status="consumed",
                consumed_at=payload["consumed_at"],
                outcome=payload["outcome"],
            )
            if item is current
            else item
            for item in state.evaluation_grants
        )
        return replace(state, revision=revision, evaluation_grants=grants)
    if record_type == "execution_closure_recorded":
        if set(payload) != {"receipt"}:
            raise QualificationLedgerError("execution_closure_record_invalid")
        receipt = _receipt_from_mapping(
            payload["receipt"], EXECUTION_CLOSURE_RECEIPT_SCHEMA_ID
        )
        validate_execution_closure(receipt.document)
        stage = receipt.document["metadata"].get("stage")
        grant = state.grant_for_current_attempt(stage)
        if (
            receipt.document["metadata"]["run_id"] != state.run_id
            or receipt.document["metadata"]["attempt_id"] != state.candidate.attempt_id
            or stage not in EXECUTION_STAGES
            or grant is None
            or grant.consumption_status != "consumed"
            or not _execution_closure_matches(
                state,
                grant,
                receipt,
                outcome=grant.outcome,
                require_consumed=True,
            )
            or any(
                item.document["metadata"]["attempt_id"] == state.candidate.attempt_id
                and item.document["metadata"]["stage"] == stage
                for item in state.execution_closures
            )
        ):
            raise QualificationLedgerError("execution_closure_binding_invalid")
        return replace(
            state,
            revision=revision,
            execution_closures=state.execution_closures + (receipt,),
        )
    if record_type == "human_checkpoint_resolved":
        if state.status != "waiting_human" or set(payload) != {"approval_decision"}:
            raise QualificationLedgerError("human_checkpoint_state_invalid")
        approval = _validate_human_checkpoint_decision(
            state, payload["approval_decision"]
        )
        decision = approval["spec"]["decision"]
        if decision not in {"approve", "reject"}:
            raise QualificationLedgerError("human_checkpoint_binding_invalid")
        decisions = state.human_checkpoint_decisions + (approval,)
        if decision == "reject":
            return replace(
                state,
                revision=revision,
                status="failed",
                human_checkpoint_decisions=decisions,
                next_checkpoint_scope=None,
                next_checkpoint_reason_codes=(),
            )
        if state.current_stage in HUMAN_STAGES or (
            state.current_stage_index == len(state.stage_plan) - 1
            and state.next_checkpoint_scope == "agent_activation"
        ):
            next_index = state.current_stage_index + 1
            if next_index >= len(state.stage_plan):
                required_execution_stages = {
                    stage for stage in state.stage_plan if stage in EXECUTION_STAGES
                }
                closed_execution_stages = {
                    receipt.document["metadata"]["stage"]
                    for receipt in state.execution_closures
                }
                if not required_execution_stages.issubset(closed_execution_stages):
                    raise QualificationLedgerError(
                        "qualification_execution_closure_missing"
                    )
                return replace(
                    state,
                    revision=revision,
                    status="completed",
                    human_checkpoint_decisions=decisions,
                    next_checkpoint_scope=None,
                    next_checkpoint_reason_codes=(),
                )
            return replace(
                state,
                revision=revision,
                status="running",
                human_checkpoint_decisions=decisions,
                current_stage_index=next_index,
                next_checkpoint_scope=None,
                next_checkpoint_reason_codes=(),
            )
        return replace(
            state,
            revision=revision,
            status="running",
            human_checkpoint_decisions=decisions,
            next_checkpoint_scope=None,
            next_checkpoint_reason_codes=(),
        )
    if record_type == "run_quarantined":
        if set(payload) != {"reason_codes", "recorded_at"}:
            raise QualificationLedgerError("qualification_quarantine_invalid")
        _time(payload["recorded_at"])
        reasons = tuple(payload["reason_codes"])
        if not reasons:
            raise QualificationLedgerError("qualification_quarantine_invalid")
        return replace(
            state,
            revision=revision,
            status="quarantined",
            next_checkpoint_scope="risk_waiver",
            next_checkpoint_reason_codes=reasons,
        )
    if record_type == "run_cancelled":
        if set(payload) != {"reason_codes", "recorded_at"}:
            raise QualificationLedgerError("qualification_cancellation_invalid")
        reasons = tuple(payload["reason_codes"])
        if not reasons or not all(
            isinstance(reason, str) and reason for reason in reasons
        ):
            raise QualificationLedgerError("qualification_cancellation_invalid")
        _time(payload["recorded_at"])
        return replace(
            state,
            revision=revision,
            status="cancelled",
            next_checkpoint_scope=None,
            next_checkpoint_reason_codes=(),
        )
    raise QualificationLedgerError("qualification_record_type_invalid")


def _receipt_mapping(receipt: ReceiptArtifact) -> dict[str, Any]:
    if canonical_digest(receipt.document) != receipt.digest:
        raise QualificationLedgerError("qualification_receipt_digest_invalid")
    return {
        "schema_id": receipt.schema_id,
        "digest": receipt.digest,
        "document": receipt.document,
    }


def _receipt_from_mapping(value: Mapping[str, Any], schema_id: str) -> ReceiptArtifact:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_id",
        "digest",
        "document",
    }:
        raise QualificationLedgerError("qualification_receipt_fields_invalid")
    if (
        value["schema_id"] != schema_id
        or canonical_digest(value["document"]) != value["digest"]
    ):
        raise QualificationLedgerError("qualification_receipt_digest_invalid")
    return ReceiptArtifact(value["schema_id"], value["document"], value["digest"])


def _grant_from_mapping(value: Mapping[str, Any]) -> EvaluationGrant:
    if not isinstance(value, Mapping):
        raise QualificationLedgerError("evaluation_grant_invalid")
    try:
        grant = EvaluationGrant(**value)
    except TypeError as cause:
        raise QualificationLedgerError("evaluation_grant_invalid") from cause
    content = asdict(grant)
    digest = content.pop("grant_digest")
    if (
        canonical_digest(content) != digest
        or grant.single_use is not True
        or grant.status != "active"
        or type(grant.synthetic_only) is not bool
        or grant.production_authorization is not False
        or grant.release_authorization is not False
    ):
        raise QualificationLedgerError("evaluation_grant_invalid")
    return grant


def _checkpoint_subject(state: QualificationRunState) -> tuple[str, str]:
    if not state.next_checkpoint_scope or not state.next_checkpoint_reason_codes:
        raise QualificationLedgerError("human_checkpoint_state_invalid")
    reference = f"checkpoint://{state.next_checkpoint_scope}/{state.run_id}"
    content = {
        "scope": state.next_checkpoint_scope,
        "run_id": state.run_id,
        "composition_ref": state.candidate.composition_ref,
        "composition_digest": state.candidate.composition_digest,
        "reason_codes": list(state.next_checkpoint_reason_codes),
    }
    return reference, canonical_digest(content)


def _validate_human_checkpoint_decision(
    state: QualificationRunState, value: Mapping[str, Any]
) -> Mapping[str, Any]:
    try:
        metadata, spec = _validate_approval_decision_shape(
            value,
            reason_code="human_checkpoint_approval_invalid",
        )
    except QualificationAutomationError as cause:
        raise QualificationLedgerError("human_checkpoint_approval_invalid") from cause
    checkpoint_ref, checkpoint_digest = _checkpoint_subject(state)
    if (
        not metadata["decision_id"].startswith("decision_")
        or spec["decision"] not in {"approve", "reject"}
        or spec.get("scope_ref") != checkpoint_ref
        or spec.get("scope_digest") != checkpoint_digest
    ):
        raise QualificationLedgerError("human_checkpoint_approval_invalid")
    decided_at = _time(metadata.get("decided_at"))
    if decided_at < _time(state.registered_at):
        raise QualificationLedgerError("human_checkpoint_approval_invalid")
    expires_at = spec.get("expires_at")
    if expires_at is not None and _time(expires_at) <= decided_at:
        raise QualificationLedgerError("human_checkpoint_approval_invalid")
    return value


def _model_route_closed(state: QualificationRunState, receipt: ReceiptArtifact) -> bool:
    terminal = receipt.document["spec"]["model_route"]
    if state.candidate.model_route_digest is None:
        return terminal is None
    return (
        isinstance(terminal, Mapping)
        and terminal.get("digest") == state.candidate.model_route_digest
    )


def _execution_closure_matches(
    state: QualificationRunState,
    grant: EvaluationGrantState,
    receipt: ReceiptArtifact,
    *,
    outcome: str | None,
    require_consumed: bool,
) -> bool:
    document = receipt.document
    return (
        (not require_consumed or grant.consumption_status == "consumed")
        and document["metadata"]["run_id"] == state.run_id
        and document["metadata"]["attempt_id"] == state.candidate.attempt_id
        and document["metadata"]["stage"] == grant.grant.stage
        and document["spec"]["composition"]["digest"]
        == state.candidate.composition_digest
        and document["spec"]["task"]["digest"] == state.candidate.task_digest
        and document["spec"]["grant"]["digest"] == grant.grant.grant_digest
        and document["spec"]["policy_decision"]["digest"]
        == grant.grant.policy_decision_receipt_digest
        and _model_route_closed(state, receipt)
        and _closure_outcome_matches(outcome, receipt)
        and _execution_usage_within_candidate(state, receipt)
    )


def _closure_outcome_matches(outcome: str | None, receipt: ReceiptArtifact) -> bool:
    expected = {
        "pass": "completed",
        "blocked": "blocked",
        "fail": "failed",
        "cancelled": "cancelled",
    }
    return receipt.document["metadata"]["status"] == expected.get(outcome)


def _execution_usage_within_candidate(
    state: QualificationRunState, receipt: ReceiptArtifact
) -> bool:
    usage = receipt.document["spec"]["usage"]
    envelope = state.policy["spec"]["execution_envelope"]
    return (
        usage["model_calls"] <= state.candidate.max_model_requests
        and usage["request_attempts"] <= envelope["max_model_requests"]
        and usage["input_tokens"] <= state.candidate.max_input_tokens
        and usage["output_tokens"] <= state.candidate.max_output_tokens
        and Decimal(usage["cost_usd"]) <= Decimal(state.candidate.max_cost_usd)
        and Decimal(usage["cost_cny"]) <= Decimal(state.candidate.max_cost_cny)
        and usage["runtime_seconds"] <= state.candidate.max_runtime_seconds
    )


def _handler_context(state: QualificationRunState) -> Mapping[str, Any]:
    grant = state.grant_for_current_attempt()
    return {
        "run_id": state.run_id,
        "revision": state.revision,
        "stage": state.current_stage,
        "policy": state.policy,
        "policy_digest": state.policy_digest,
        "candidate": state.candidate.to_mapping(),
        "stage_attempt": state.stage_attempts.get(state.current_stage, 0),
        "total_attempt": state.total_attempts,
        "evaluation_grant": None if grant is None else asdict(grant.grant),
    }


def _stage_handler_bindings(
    stage_plan: tuple[str, ...], value: Mapping[str, Mapping[str, str]]
) -> dict[str, dict[str, str]]:
    if not isinstance(value, Mapping) or set(value) != set(stage_plan):
        raise QualificationLedgerError("qualification_stage_handler_set_invalid")
    normalized: dict[str, dict[str, str]] = {}
    for stage in stage_plan:
        binding = value[stage]
        if not isinstance(binding, Mapping) or set(binding) != {
            "id",
            "version",
            "digest",
        }:
            raise QualificationLedgerError("qualification_stage_handler_invalid")
        component_id = binding["id"]
        version = binding["version"]
        if (
            not isinstance(component_id, str)
            or not component_id.startswith("component_")
            or not isinstance(version, str)
            or version.count(".") != 2
            or not _is_digest(binding["digest"])
        ):
            raise QualificationLedgerError("qualification_stage_handler_invalid")
        normalized[stage] = {
            "id": component_id,
            "version": version,
            "digest": binding["digest"],
        }
    return normalized


def _validate_evaluator_separation(
    stage_plan: tuple[str, ...],
    bindings: Mapping[str, Mapping[str, str]],
) -> None:
    evaluator_stages = tuple(
        stage
        for stage in ("domain_evaluation", "company_evaluation")
        if stage in stage_plan
    )
    evaluator_digests = [bindings[stage]["digest"] for stage in evaluator_stages]
    if len(evaluator_digests) != len(set(evaluator_digests)):
        raise QualificationLedgerError("qualification_evaluator_not_independent")
    execution_digests = {
        bindings[stage]["digest"] for stage in stage_plan if stage in EXECUTION_STAGES
    }
    if any(digest in execution_digests for digest in evaluator_digests):
        raise QualificationLedgerError("qualification_evaluator_not_independent")


def _engineering_failure_observation(
    state: QualificationRunState,
    reason_code: str,
    now: Callable[[], datetime],
) -> StageObservation:
    at = _time_text(now())
    return StageObservation(
        stage=state.current_stage,
        outcome="blocked",
        failure_class="engineering_compatibility",
        reason_codes=(reason_code,),
        checks=(StageCheck("stage_handler_available", "blocked", reason_code),),
        inputs=(
            {
                "role": "runtime_composition",
                "ref": state.candidate.composition_ref,
                "digest": state.candidate.composition_digest,
            },
        ),
        executor={
            "component": {
                "id": "component_qualification_reconciler",
                "version": "0.1.0",
                "digest": canonical_digest("qualification_reconciler/0.1.0"),
            },
            "deterministic": True,
            "environment_profile_digest": state.candidate.isolation_profile_digest,
        },
        side_effects=StageSideEffects(),
        started_at=at,
        completed_at=at,
    )


def _drift_observation(
    state: QualificationRunState,
    reason_code: str,
    now: Callable[[], datetime],
) -> StageObservation:
    at = _time_text(now())
    return StageObservation(
        stage=state.current_stage,
        outcome="blocked",
        failure_class="unexplained_drift",
        reason_codes=(reason_code,),
        checks=(StageCheck("stage_handler_digest", "blocked", reason_code),),
        inputs=(
            {
                "role": "runtime_composition",
                "ref": state.candidate.composition_ref,
                "digest": state.candidate.composition_digest,
            },
        ),
        executor={
            "component": state.stage_handlers[state.current_stage],
            "deterministic": True,
            "environment_profile_digest": state.candidate.isolation_profile_digest,
        },
        side_effects=StageSideEffects(),
        started_at=at,
        completed_at=at,
    )


def _execution_closure_failure_observation(
    state: QualificationRunState,
    original: StageObservation,
    reason_code: str,
) -> StageObservation:
    return StageObservation(
        stage=state.current_stage,
        outcome="fail",
        failure_class="unexplained_drift",
        reason_codes=(reason_code,),
        checks=(StageCheck("execution_terminal_closure", "blocked", reason_code),),
        inputs=original.inputs,
        executor=original.executor,
        side_effects=original.side_effects,
        started_at=original.started_at,
        completed_at=original.completed_at,
    )


def _policy_checkpoint_observation(
    state: QualificationRunState,
    reason_codes: tuple[str, ...],
    now: Callable[[], datetime],
) -> StageObservation:
    at = _time_text(now())
    return StageObservation(
        stage=state.current_stage,
        outcome="blocked",
        failure_class="policy_boundary",
        reason_codes=reason_codes,
        checks=(StageCheck("automation_policy_subset", "blocked", reason_codes[0]),),
        inputs=(
            {
                "role": "runtime_composition",
                "ref": state.candidate.composition_ref,
                "digest": state.candidate.composition_digest,
            },
        ),
        executor={
            "component": {
                "id": "component_qualification_policy_engine",
                "version": "0.1.0",
                "digest": canonical_digest("qualification_policy_engine/0.1.0"),
            },
            "deterministic": True,
            "environment_profile_digest": state.candidate.isolation_profile_digest,
        },
        side_effects=StageSideEffects(),
        started_at=at,
        completed_at=at,
    )


def _observation_from_stage_receipt(receipt: ReceiptArtifact) -> StageObservation:
    document = receipt.document
    return StageObservation(
        stage=document["metadata"]["stage"],
        outcome={"passed": "pass", "failed": "fail"}.get(
            document["metadata"]["outcome"], document["metadata"]["outcome"]
        ),
        failure_class=document["spec"]["decision"]["failure_class"],
        reason_codes=tuple(document["spec"]["decision"]["reason_codes"]),
        checks=tuple(
            StageCheck(
                item["name"],
                item["status"],
                item["reason_code"],
                tuple(item["evidence_refs"]),
            )
            for item in document["spec"]["checks"]
        ),
        inputs=tuple(document["spec"]["inputs"]),
        executor=document["spec"]["executor"],
        side_effects=StageSideEffects(**document["spec"]["side_effects"]),
        started_at=document["metadata"]["started_at"],
        completed_at=document["metadata"]["completed_at"],
    )


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize(item) for key, item in sorted(value.items())}
    if isinstance(value, tuple):
        return [_normalize(item) for item in value]
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise QualificationLedgerError("qualification_payload_type_invalid")


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise QualificationLedgerError("qualification_duplicate_json_key")
        value[key] = item
    return value


def _reject_constant(value: str) -> Any:
    raise QualificationLedgerError("qualification_non_finite_number")


def _is_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise QualificationLedgerError("qualification_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as cause:
        raise QualificationLedgerError("qualification_time_invalid") from cause
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QualificationLedgerError("qualification_time_invalid")
    return parsed.astimezone(timezone.utc)


def _time_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise QualificationLedgerError("qualification_time_invalid")
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()

