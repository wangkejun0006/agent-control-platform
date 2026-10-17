"""Independent, tamper-evident lifecycle for synthetic Tool releases.

Agent and Tool identities never share lifecycle state.  This ledger mirrors the
strict approval/evaluation/hash-chain gates of the Agent lifecycle while keying
state by immutable ``(tool_id, release_digest)``.  It is local D0 evidence, not
a Company Registry, production audit system, or source of effective Grants.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .ids import deterministic_id
from .lifecycle_ledger import (
    append_jsonl_document,
    close_ledger,
    open_owner_only_ledger,
    read_jsonl_documents,
)
from .tool_registry import ToolRegistryCandidate


TOOL_LIFECYCLE_LEDGER_VERSION = "orbit.synthetic-tool-lifecycle-ledger/1"
TOOL_LIFECYCLE_GENESIS_HASH = "sha256:" + ("0" * 64)
MAX_TOOL_LIFECYCLE_LEDGER_BYTES = 16 * 1024 * 1024
MAX_TOOL_LIFECYCLE_RECORD_BYTES = 256 * 1024
TOOL_LIFECYCLE_STATUSES = frozenset(
    {"draft", "evaluation", "active", "suspended", "retired"}
)
TOOL_LIFECYCLE_RECORD_TYPES = frozenset(
    {
        "tool_candidate_registered",
        "tool_evaluation_recorded",
        "tool_approval_recorded",
        "tool_lifecycle_transitioned",
    }
)
_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,95}$")
_RELEASE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9._-]{2,127}$")
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")
_RECORD_KEYS = frozenset(
    {
        "ledger_version",
        "sequence",
        "record_id",
        "record_type",
        "tool_id",
        "release_digest",
        "idempotency_key",
        "previous_record_hash",
        "payload",
        "record_hash",
    }
)


class ToolLifecycleError(ValueError):
    """Fail-closed Tool lifecycle error with a stable reason code."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class ToolLifecycleEvaluation:
    report_id: str
    subject_tool_id: str
    subject_release_digest: str
    evaluator_ref: str
    verdict: str
    release_recommendation: str
    allowed_operation_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    risk_flags: tuple[str, ...]
    release_authorization: bool = False


@dataclass(frozen=True)
class SyntheticToolApprovalDecision:
    decision_id: str
    action: str
    subject_tool_id: str
    subject_release_digest: str
    decided_by_human_ref: str
    decision: str
    reason: str
    evidence_status: str = "synthetic"
    synthetic_only: bool = True


@dataclass(frozen=True)
class ToolLifecycleTransition:
    transition_id: str
    audit_event_ref: str
    tool_id: str
    release_digest: str
    before: str
    after: str
    reason_code: str
    actor_kind: str
    actor_ref: str
    approval_decision_ref: str | None
    automatic: bool
    revision: int


@dataclass(frozen=True)
class ToolLifecycleAppendResult:
    record_id: str
    sequence: int
    record_hash: str
    appended: bool


@dataclass(frozen=True)
class ReplayedToolLifecycle:
    candidate: ToolRegistryCandidate
    status: str
    revision: int
    evaluation: ToolLifecycleEvaluation | None
    approvals: tuple[SyntheticToolApprovalDecision, ...]
    transitions: tuple[ToolLifecycleTransition, ...]


@dataclass(frozen=True)
class ToolLifecycleReplay:
    records_checked: int
    last_record_hash: str
    tools: tuple[ReplayedToolLifecycle, ...]

    def tool(
        self, tool_id: str, release_digest: str | None = None
    ) -> ReplayedToolLifecycle:
        matches = tuple(
            item
            for item in self.tools
            if item.candidate.tool_id == tool_id
            and (
                release_digest is None
                or item.candidate.release_digest == release_digest
            )
        )
        if not matches:
            raise ToolLifecycleError(
                "tool_release_not_found", "Tool release is absent from the lifecycle ledger"
            )
        if len(matches) > 1:
            raise ToolLifecycleError(
                "tool_release_ambiguous", "Tool release must be selected by digest"
            )
        return matches[0]

    def active_for_capability(self, capability: str) -> tuple[ReplayedToolLifecycle, ...]:
        return tuple(
            item
            for item in self.tools
            if item.status == "active"
            and capability in item.candidate.capabilities
        )


@dataclass(frozen=True)
class _ToolLifecycleRecord:
    sequence: int
    record_id: str
    record_type: str
    tool_id: str
    release_digest: str
    idempotency_key: str
    previous_record_hash: str
    payload: Mapping[str, Any]
    record_hash: str


@dataclass
class _MutableToolState:
    candidate: ToolRegistryCandidate
    status: str
    revision: int
    evaluation: ToolLifecycleEvaluation | None
    approvals: list[SyntheticToolApprovalDecision]
    transitions: list[ToolLifecycleTransition]

    def freeze(self) -> ReplayedToolLifecycle:
        return ReplayedToolLifecycle(
            candidate=self.candidate,
            status=self.status,
            revision=self.revision,
            evaluation=self.evaluation,
            approvals=tuple(self.approvals),
            transitions=tuple(self.transitions),
        )


class _ReplayBuilder:
    def __init__(self) -> None:
        self.records: list[_ToolLifecycleRecord] = []
        self.idempotency_index: dict[str, _ToolLifecycleRecord] = {}
        self.tools: dict[tuple[str, str], _MutableToolState] = {}
        self.last_record_hash = TOOL_LIFECYCLE_GENESIS_HASH

    def add(self, record: _ToolLifecycleRecord) -> None:
        if record.idempotency_key in self.idempotency_index:
            raise ToolLifecycleError(
                "duplicate_idempotency_record",
                "Tool lifecycle contains a duplicate idempotency key",
            )
        self._apply(record)
        self.records.append(record)
        self.idempotency_index[record.idempotency_key] = record
        self.last_record_hash = record.record_hash

    def _apply(self, record: _ToolLifecycleRecord) -> None:
        key = (record.tool_id, record.release_digest)
        if record.record_type == "tool_candidate_registered":
            _exact_keys(record.payload, {"candidate"}, "Tool candidate payload")
            candidate = _candidate_from_mapping(record.payload["candidate"])
            if key != (candidate.tool_id, candidate.release_digest):
                raise ToolLifecycleError(
                    "record_subject_mismatch", "Tool candidate record subject differs"
                )
            if key in self.tools:
                raise ToolLifecycleError(
                    "tool_release_already_registered", "Tool release already exists"
                )
            self.tools[key] = _MutableToolState(
                candidate=candidate,
                status="draft",
                revision=0,
                evaluation=None,
                approvals=[],
                transitions=[],
            )
            return

        state = self.tools.get(key)
        if state is None:
            raise ToolLifecycleError(
                "tool_candidate_missing", "Tool candidate must be registered first"
            )
        if record.record_type == "tool_evaluation_recorded":
            _exact_keys(
                record.payload,
                {"evaluation", "transition"},
                "Tool evaluation payload",
            )
            evaluation = _evaluation_from_mapping(record.payload["evaluation"])
            transition = _transition_from_mapping(record.payload["transition"])
            _validate_evaluation_binding(state.candidate, evaluation)
            if state.status != "draft" or state.evaluation is not None:
                raise ToolLifecycleError(
                    "tool_evaluation_state_invalid",
                    "Tool release is not ready for initial evaluation",
                )
            expected = _transition(
                state.candidate,
                before="draft",
                after="evaluation",
                reason_code="submitted_for_evaluation",
                actor_kind="system",
                actor_ref="system_tool_lifecycle_policy_syn",
                approval_decision_ref=None,
                automatic=True,
                revision=1,
            )
            if transition != expected:
                raise ToolLifecycleError(
                    "tool_evaluation_transition_invalid",
                    "Tool evaluation transition is not reproducible",
                )
            state.evaluation = evaluation
            state.status = "evaluation"
            state.revision = 1
            state.transitions.append(transition)
            return

        if record.record_type == "tool_approval_recorded":
            _exact_keys(record.payload, {"approval"}, "Tool approval payload")
            approval = _approval_from_mapping(record.payload["approval"])
            _validate_approval_binding(state.candidate, approval)
            if any(item.decision_id == approval.decision_id for item in state.approvals):
                raise ToolLifecycleError(
                    "tool_approval_duplicated", "Tool ApprovalDecision is duplicated"
                )
            state.approvals.append(approval)
            return

        if record.record_type == "tool_lifecycle_transitioned":
            _exact_keys(record.payload, {"transition"}, "Tool transition payload")
            transition = _transition_from_mapping(record.payload["transition"])
            if transition.before != state.status or transition.revision != state.revision + 1:
                raise ToolLifecycleError(
                    "tool_lifecycle_revision_mismatch",
                    "Tool transition does not continue the current revision",
                )
            expected = _expected_transition(state, transition)
            if transition != expected:
                raise ToolLifecycleError(
                    "tool_lifecycle_transition_invalid",
                    "Tool lifecycle transition is not reproducible",
                )
            state.status = transition.after
            state.revision = transition.revision
            state.transitions.append(transition)
            return
        raise ToolLifecycleError(
            "unsupported_record_type", "Tool lifecycle record type is unsupported"
        )

    def freeze(self) -> ToolLifecycleReplay:
        return ToolLifecycleReplay(
            records_checked=len(self.records),
            last_record_hash=self.last_record_hash,
            tools=tuple(item.freeze() for item in self.tools.values()),
        )


class SyntheticToolLifecycleLedger:
    """Owner-only append ledger for local synthetic Tool lifecycle evidence."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def register_candidate(
        self, candidate: ToolRegistryCandidate, *, idempotency_key: str
    ) -> ToolLifecycleAppendResult:
        _validate_candidate(candidate)
        return self._append(
            "tool_candidate_registered",
            candidate.tool_id,
            candidate.release_digest,
            idempotency_key,
            {"candidate": asdict(candidate)},
        )

    def record_evaluation(
        self, evaluation: ToolLifecycleEvaluation, *, idempotency_key: str
    ) -> ToolLifecycleAppendResult:
        state = self.replay().tool(
            evaluation.subject_tool_id, evaluation.subject_release_digest
        )
        _validate_evaluation_binding(state.candidate, evaluation)
        transition = _transition(
            state.candidate,
            before="draft",
            after="evaluation",
            reason_code="submitted_for_evaluation",
            actor_kind="system",
            actor_ref="system_tool_lifecycle_policy_syn",
            approval_decision_ref=None,
            automatic=True,
            revision=1,
        )
        return self._append(
            "tool_evaluation_recorded",
            evaluation.subject_tool_id,
            evaluation.subject_release_digest,
            idempotency_key,
            {"evaluation": asdict(evaluation), "transition": asdict(transition)},
        )

    def record_approval(
        self, approval: SyntheticToolApprovalDecision, *, idempotency_key: str
    ) -> ToolLifecycleAppendResult:
        state = self.replay().tool(
            approval.subject_tool_id, approval.subject_release_digest
        )
        _validate_approval_binding(state.candidate, approval)
        return self._append(
            "tool_approval_recorded",
            approval.subject_tool_id,
            approval.subject_release_digest,
            idempotency_key,
            {"approval": asdict(approval)},
        )

    def activate(
        self,
        tool_id: str,
        release_digest: str,
        *,
        approval_decision_ref: str,
        idempotency_key: str,
    ) -> ToolLifecycleAppendResult:
        state = self.replay().tool(tool_id, release_digest)
        transition = _build_human_transition(
            state, "active", approval_decision_ref
        )
        return self._append(
            "tool_lifecycle_transitioned",
            tool_id,
            release_digest,
            idempotency_key,
            {"transition": asdict(transition)},
        )

    def suspend(
        self,
        tool_id: str,
        release_digest: str,
        *,
        actor_ref: str,
        reason_code: str,
        idempotency_key: str,
    ) -> ToolLifecycleAppendResult:
        state = self.replay().tool(tool_id, release_digest)
        if state.status != "active":
            raise ToolLifecycleError(
                "tool_suspension_state_invalid", "Only an active Tool may be suspended"
            )
        transition = _transition(
            state.candidate,
            before="active",
            after="suspended",
            reason_code=reason_code,
            actor_kind="system",
            actor_ref=actor_ref,
            approval_decision_ref=None,
            automatic=True,
            revision=state.revision + 1,
        )
        return self._append(
            "tool_lifecycle_transitioned",
            tool_id,
            release_digest,
            idempotency_key,
            {"transition": asdict(transition)},
        )

    def retire(
        self,
        tool_id: str,
        release_digest: str,
        *,
        approval_decision_ref: str,
        idempotency_key: str,
    ) -> ToolLifecycleAppendResult:
        state = self.replay().tool(tool_id, release_digest)
        transition = _build_human_transition(
            state, "retired", approval_decision_ref
        )
        return self._append(
            "tool_lifecycle_transitioned",
            tool_id,
            release_digest,
            idempotency_key,
            {"transition": asdict(transition)},
        )

    def replay(self) -> ToolLifecycleReplay:
        fd = self._open(create=False, exclusive=False)
        try:
            return self._read_builder(fd).freeze()
        finally:
            self._close(fd)

    def _append(
        self,
        record_type: str,
        tool_id: str,
        release_digest: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
    ) -> ToolLifecycleAppendResult:
        if record_type not in TOOL_LIFECYCLE_RECORD_TYPES:
            raise ToolLifecycleError(
                "unsupported_record_type", "Tool lifecycle record type is unsupported"
            )
        _validate_id(tool_id, "Tool id")
        _validate_hash(release_digest, "Tool release digest")
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_PATTERN.fullmatch(
            idempotency_key
        ):
            raise ToolLifecycleError(
                "invalid_idempotency_key", "Tool lifecycle idempotency key is invalid"
            )
        normalized = _normalize_json(payload)
        fd = self._open(create=True, exclusive=True)
        try:
            builder = self._read_builder(fd)
            existing = builder.idempotency_index.get(idempotency_key)
            if existing is not None:
                if (
                    existing.record_type == record_type
                    and existing.tool_id == tool_id
                    and existing.release_digest == release_digest
                    and _canonical_json(existing.payload)
                    == _canonical_json(normalized)
                ):
                    return ToolLifecycleAppendResult(
                        existing.record_id,
                        existing.sequence,
                        existing.record_hash,
                        False,
                    )
                raise ToolLifecycleError(
                    "idempotency_conflict",
                    "Tool lifecycle idempotency key is bound to other content",
                )
            payload_digest = _digest(
                _canonical_json(normalized).encode("utf-8")
            )
            record_id = deterministic_id(
                "tool_lifecycle",
                record_type,
                tool_id,
                release_digest,
                idempotency_key,
                payload_digest,
            )
            content = {
                "ledger_version": TOOL_LIFECYCLE_LEDGER_VERSION,
                "sequence": len(builder.records),
                "record_id": record_id,
                "record_type": record_type,
                "tool_id": tool_id,
                "release_digest": release_digest,
                "idempotency_key": idempotency_key,
                "previous_record_hash": builder.last_record_hash,
                "payload": normalized,
            }
            record_hash = _digest(_canonical_json(content).encode("utf-8"))
            document = {**content, "record_hash": record_hash}
            record = _record_from_document(
                document, len(builder.records), builder.last_record_hash
            )
            builder.add(record)
            encoded = (_canonical_json(document) + "\n").encode("utf-8")
            append_jsonl_document(
                fd,
                encoded,
                max_ledger_bytes=MAX_TOOL_LIFECYCLE_LEDGER_BYTES,
                max_record_bytes=MAX_TOOL_LIFECYCLE_RECORD_BYTES,
                error=ToolLifecycleError,
                label="Tool lifecycle ledger",
            )
            return ToolLifecycleAppendResult(
                record.record_id, record.sequence, record.record_hash, True
            )
        finally:
            self._close(fd)

    def _open(self, *, create: bool, exclusive: bool) -> int:
        return open_owner_only_ledger(
            self.path,
            create=create,
            exclusive=exclusive,
            error=ToolLifecycleError,
            label="Tool lifecycle ledger",
        )

    @staticmethod
    def _close(fd: int) -> None:
        close_ledger(fd)

    @staticmethod
    def _read_builder(fd: int) -> _ReplayBuilder:
        builder = _ReplayBuilder()
        documents = read_jsonl_documents(
            fd,
            max_ledger_bytes=MAX_TOOL_LIFECYCLE_LEDGER_BYTES,
            max_record_bytes=MAX_TOOL_LIFECYCLE_RECORD_BYTES,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
            error=ToolLifecycleError,
            label="Tool lifecycle ledger",
        )
        for sequence, document in enumerate(documents):
            builder.add(
                _record_from_document(
                    document, sequence, builder.last_record_hash
                )
            )
        return builder


def _build_human_transition(
    state: ReplayedToolLifecycle, after: str, approval_ref: str
) -> ToolLifecycleTransition:
    approvals = tuple(
        item for item in state.approvals if item.decision_id == approval_ref
    )
    if len(approvals) != 1:
        raise ToolLifecycleError(
            "approval_decision_missing", "Exact Tool ApprovalDecision is unavailable"
        )
    approval = approvals[0]
    expected_action = "activate" if after == "active" else "retire"
    if approval.decision != "approve" or approval.action != expected_action:
        raise ToolLifecycleError(
            "approval_decision_scope_mismatch",
            "Tool ApprovalDecision does not approve the transition",
        )
    if after == "active":
        evaluation = state.evaluation
        if state.status != "evaluation" or evaluation is None:
            raise ToolLifecycleError(
                "tool_activation_state_invalid", "Tool release is not in evaluation"
            )
        if (
            evaluation.verdict != "pass"
            or evaluation.release_recommendation != "recommend"
            or not evaluation.allowed_operation_ids
            or not set(evaluation.allowed_operation_ids).issubset(
                state.candidate.d0_allowed_operation_ids
            )
        ):
            raise ToolLifecycleError(
                "tool_evaluation_not_passed",
                "Tool evaluation did not pass within the reviewed D0 scope",
            )
        reason_code = "human_approved_synthetic_tool_release"
    elif after == "retired":
        if state.status not in {"active", "suspended"}:
            raise ToolLifecycleError(
                "tool_retirement_state_invalid",
                "Tool release cannot retire from its current state",
            )
        reason_code = "human_approved_tool_retirement"
    else:
        raise ToolLifecycleError(
            "unsupported_transition", "Tool human transition is unsupported"
        )
    return _transition(
        state.candidate,
        before=state.status,
        after=after,
        reason_code=reason_code,
        actor_kind="human",
        actor_ref=approval.decided_by_human_ref,
        approval_decision_ref=approval.decision_id,
        automatic=False,
        revision=state.revision + 1,
    )


def _expected_transition(
    state: _MutableToolState, transition: ToolLifecycleTransition
) -> ToolLifecycleTransition:
    if transition.after == "suspended":
        if (
            state.status != "active"
            or transition.approval_decision_ref is not None
            or not transition.automatic
        ):
            raise ToolLifecycleError(
                "tool_suspension_invalid", "Tool suspension boundary is invalid"
            )
        return _transition(
            state.candidate,
            before="active",
            after="suspended",
            reason_code=transition.reason_code,
            actor_kind=transition.actor_kind,
            actor_ref=transition.actor_ref,
            approval_decision_ref=None,
            automatic=True,
            revision=state.revision + 1,
        )
    if transition.after in {"active", "retired"}:
        return _build_human_transition(
            state.freeze(), transition.after, transition.approval_decision_ref or ""
        )
    raise ToolLifecycleError(
        "unsupported_transition", "Tool lifecycle transition is unsupported"
    )


def _transition(
    candidate: ToolRegistryCandidate,
    *,
    before: str,
    after: str,
    reason_code: str,
    actor_kind: str,
    actor_ref: str,
    approval_decision_ref: str | None,
    automatic: bool,
    revision: int,
) -> ToolLifecycleTransition:
    if before not in TOOL_LIFECYCLE_STATUSES or after not in TOOL_LIFECYCLE_STATUSES:
        raise ToolLifecycleError(
            "invalid_lifecycle_status", "Tool lifecycle status is invalid"
        )
    if actor_kind not in {"human", "system"}:
        raise ToolLifecycleError("invalid_actor_kind", "Tool actor kind is invalid")
    _validate_id(actor_ref, "Tool lifecycle actor")
    transition_id = deterministic_id(
        "tool_transition",
        candidate.tool_id,
        candidate.release_digest,
        before,
        after,
        reason_code,
        actor_kind,
        actor_ref,
        approval_decision_ref or "none",
        str(automatic),
        str(revision),
    )
    return ToolLifecycleTransition(
        transition_id=transition_id,
        audit_event_ref=deterministic_id(
            "audit", transition_id, candidate.tool_id, candidate.release_digest
        ),
        tool_id=candidate.tool_id,
        release_digest=candidate.release_digest,
        before=before,
        after=after,
        reason_code=reason_code,
        actor_kind=actor_kind,
        actor_ref=actor_ref,
        approval_decision_ref=approval_decision_ref,
        automatic=automatic,
        revision=revision,
    )


def _validate_candidate(candidate: ToolRegistryCandidate) -> None:
    _validate_id(candidate.tool_id, "Tool id")
    _validate_hash(candidate.release_digest, "Tool release digest")
    _validate_hash(candidate.manifest_digest, "Tool manifest digest")
    _validate_hash(
        candidate.source_release_manifest_digest, "Tool source release digest"
    )
    if not _RELEASE_ID_PATTERN.fullmatch(candidate.source_release_id):
        raise ToolLifecycleError(
            "invalid_identifier", "Tool source release id is invalid"
        )
    _validate_id(candidate.owner_human_ref, "Tool owner")
    for values, label, allow_empty in (
        (candidate.capabilities, "Tool capabilities", False),
        (candidate.operation_ids, "Tool operations", False),
        (candidate.d0_allowed_operation_ids, "D0 Tool operations", False),
        (candidate.allowed_data_classifications, "Tool classifications", False),
        (candidate.risk_classes, "Tool risks", False),
    ):
        _validate_string_tuple(values, label, allow_empty=allow_empty)
    if not set(candidate.d0_allowed_operation_ids).issubset(candidate.operation_ids):
        raise ToolLifecycleError(
            "tool_operation_scope_invalid", "D0 Tool operations exceed the manifest"
        )
    if (
        candidate.release_digest != candidate.manifest_digest
        or candidate.source_manifest_status != "evaluation"
        or candidate.registry_status != "draft"
        or candidate.evidence_status != "synthetic"
        or not candidate.synthetic_only
        or candidate.company_authoritative
    ):
        raise ToolLifecycleError(
            "tool_candidate_boundary_invalid",
            "Tool candidate exceeds the local synthetic Registry boundary",
        )


def _validate_evaluation_binding(
    candidate: ToolRegistryCandidate, evaluation: ToolLifecycleEvaluation
) -> None:
    for value, label in (
        (evaluation.report_id, "Tool evaluation report"),
        (evaluation.subject_tool_id, "Tool evaluation subject"),
        (evaluation.evaluator_ref, "Tool evaluator"),
    ):
        _validate_id(value, label)
    _validate_hash(evaluation.subject_release_digest, "Tool evaluation digest")
    if (
        evaluation.subject_tool_id != candidate.tool_id
        or evaluation.subject_release_digest != candidate.release_digest
    ):
        raise ToolLifecycleError(
            "tool_evaluation_subject_mismatch",
            "Tool evaluation is not bound to the candidate",
        )
    if evaluation.evaluator_ref in {candidate.tool_id, candidate.owner_human_ref}:
        raise ToolLifecycleError(
            "tool_self_evaluation_forbidden",
            "Tool release and owner cannot evaluate their own candidate",
        )
    if evaluation.verdict not in {"pass", "fail", "needs_review"}:
        raise ToolLifecycleError(
            "tool_evaluation_verdict_invalid", "Tool evaluation verdict is invalid"
        )
    if evaluation.release_recommendation not in {
        "recommend",
        "do_not_recommend",
        "insufficient_evidence",
    }:
        raise ToolLifecycleError(
            "tool_release_recommendation_invalid",
            "Tool release recommendation is invalid",
        )
    if evaluation.release_authorization:
        raise ToolLifecycleError(
            "tool_evaluation_release_authority_forbidden",
            "Tool evaluation cannot authorize release",
        )
    _validate_string_tuple(
        evaluation.allowed_operation_ids,
        "Tool evaluated operations",
        allow_empty=evaluation.verdict != "pass",
    )
    if not set(evaluation.allowed_operation_ids).issubset(
        candidate.d0_allowed_operation_ids
    ):
        raise ToolLifecycleError(
            "tool_evaluation_operation_scope_invalid",
            "Tool evaluation operations exceed the reviewed D0 scope",
        )
    _validate_string_tuple(
        evaluation.evidence_refs, "Tool evaluation evidence", allow_empty=False
    )
    _validate_string_tuple(evaluation.risk_flags, "Tool evaluation risks")


def _validate_approval_binding(
    candidate: ToolRegistryCandidate, approval: SyntheticToolApprovalDecision
) -> None:
    for value, label in (
        (approval.decision_id, "Tool approval id"),
        (approval.subject_tool_id, "Tool approval subject"),
        (approval.decided_by_human_ref, "Tool approval human"),
    ):
        _validate_id(value, label)
    _validate_hash(approval.subject_release_digest, "Tool approval digest")
    if (
        approval.subject_tool_id != candidate.tool_id
        or approval.subject_release_digest != candidate.release_digest
    ):
        raise ToolLifecycleError(
            "tool_approval_subject_mismatch",
            "Tool ApprovalDecision is not bound to the candidate",
        )
    if approval.action not in {"activate", "retire"}:
        raise ToolLifecycleError(
            "tool_approval_action_invalid", "Tool approval action is invalid"
        )
    if approval.decision not in {"approve", "deny"}:
        raise ToolLifecycleError(
            "tool_approval_decision_invalid", "Tool approval decision is invalid"
        )
    if not approval.reason:
        raise ToolLifecycleError(
            "tool_approval_reason_missing", "Tool approval reason is required"
        )
    if approval.evidence_status != "synthetic" or not approval.synthetic_only:
        raise ToolLifecycleError(
            "tool_approval_boundary_invalid", "Only synthetic Tool approval is allowed"
        )


def _record_from_document(
    value: Any, sequence: int, previous_hash: str
) -> _ToolLifecycleRecord:
    mapping = _strict_mapping(value, "Tool lifecycle record")
    _exact_keys(mapping, _RECORD_KEYS, "Tool lifecycle record")
    if mapping["ledger_version"] != TOOL_LIFECYCLE_LEDGER_VERSION:
        raise ToolLifecycleError(
            "ledger_version_invalid", "Tool lifecycle ledger version differs"
        )
    if mapping["sequence"] != sequence or mapping["previous_record_hash"] != previous_hash:
        raise ToolLifecycleError(
            "ledger_chain_invalid", "Tool lifecycle sequence or previous hash differs"
        )
    _validate_id(mapping["record_id"], "Tool lifecycle record id")
    _validate_id(mapping["tool_id"], "Tool lifecycle subject")
    _validate_hash(mapping["release_digest"], "Tool lifecycle release digest")
    _validate_hash(mapping["record_hash"], "Tool lifecycle record hash")
    if mapping["record_type"] not in TOOL_LIFECYCLE_RECORD_TYPES:
        raise ToolLifecycleError(
            "unsupported_record_type", "Tool lifecycle record type is unsupported"
        )
    if not isinstance(mapping["idempotency_key"], str) or not _IDEMPOTENCY_PATTERN.fullmatch(
        mapping["idempotency_key"]
    ):
        raise ToolLifecycleError(
            "invalid_idempotency_key", "Tool lifecycle idempotency key is invalid"
        )
    payload = _strict_mapping(mapping["payload"], "Tool lifecycle payload")
    expected_hash = _digest(
        _canonical_json(
            {key: mapping[key] for key in _RECORD_KEYS if key != "record_hash"}
        ).encode("utf-8")
    )
    if mapping["record_hash"] != expected_hash:
        raise ToolLifecycleError(
            "record_hash_mismatch", "Tool lifecycle record hash differs"
        )
    return _ToolLifecycleRecord(
        sequence=mapping["sequence"],
        record_id=mapping["record_id"],
        record_type=mapping["record_type"],
        tool_id=mapping["tool_id"],
        release_digest=mapping["release_digest"],
        idempotency_key=mapping["idempotency_key"],
        previous_record_hash=mapping["previous_record_hash"],
        payload=payload,
        record_hash=mapping["record_hash"],
    )


def _candidate_from_mapping(value: Any) -> ToolRegistryCandidate:
    mapping = _strict_mapping(value, "Tool candidate")
    _exact_keys(mapping, set(ToolRegistryCandidate.__dataclass_fields__), "Tool candidate")
    candidate = ToolRegistryCandidate(
        tool_id=_strict_string(mapping["tool_id"], "Tool id"),
        version=_strict_string(mapping["version"], "Tool version"),
        release_digest=_strict_string(mapping["release_digest"], "release digest"),
        manifest_digest=_strict_string(mapping["manifest_digest"], "manifest digest"),
        source_release_id=_strict_string(
            mapping["source_release_id"], "source release"
        ),
        source_release_manifest_digest=_strict_string(
            mapping["source_release_manifest_digest"], "source release digest"
        ),
        owner_human_ref=_strict_string(mapping["owner_human_ref"], "Tool owner"),
        capabilities=_string_tuple(mapping["capabilities"], "Tool capabilities"),
        operation_ids=_string_tuple(mapping["operation_ids"], "Tool operations"),
        d0_allowed_operation_ids=_string_tuple(
            mapping["d0_allowed_operation_ids"], "D0 Tool operations"
        ),
        allowed_data_classifications=_string_tuple(
            mapping["allowed_data_classifications"], "Tool classifications"
        ),
        risk_classes=_string_tuple(mapping["risk_classes"], "Tool risks"),
        source_manifest_status=_strict_string(
            mapping["source_manifest_status"], "source manifest status"
        ),
        registry_status=_strict_string(mapping["registry_status"], "registry status"),
        evidence_status=_strict_string(mapping["evidence_status"], "evidence status"),
        synthetic_only=_strict_bool(mapping["synthetic_only"], "synthetic only"),
        company_authoritative=_strict_bool(
            mapping["company_authoritative"], "company authoritative"
        ),
    )
    _validate_candidate(candidate)
    return candidate


def _evaluation_from_mapping(value: Any) -> ToolLifecycleEvaluation:
    mapping = _strict_mapping(value, "Tool evaluation")
    _exact_keys(
        mapping, set(ToolLifecycleEvaluation.__dataclass_fields__), "Tool evaluation"
    )
    return ToolLifecycleEvaluation(
        report_id=_strict_string(mapping["report_id"], "evaluation report"),
        subject_tool_id=_strict_string(mapping["subject_tool_id"], "evaluation subject"),
        subject_release_digest=_strict_string(
            mapping["subject_release_digest"], "evaluation digest"
        ),
        evaluator_ref=_strict_string(mapping["evaluator_ref"], "evaluator"),
        verdict=_strict_string(mapping["verdict"], "verdict"),
        release_recommendation=_strict_string(
            mapping["release_recommendation"], "release recommendation"
        ),
        allowed_operation_ids=_string_tuple(
            mapping["allowed_operation_ids"], "evaluated operations"
        ),
        evidence_refs=_string_tuple(mapping["evidence_refs"], "evidence refs"),
        risk_flags=_string_tuple(mapping["risk_flags"], "risk flags"),
        release_authorization=_strict_bool(
            mapping["release_authorization"], "release authorization"
        ),
    )


def _approval_from_mapping(value: Any) -> SyntheticToolApprovalDecision:
    mapping = _strict_mapping(value, "Tool approval")
    _exact_keys(
        mapping, set(SyntheticToolApprovalDecision.__dataclass_fields__), "Tool approval"
    )
    return SyntheticToolApprovalDecision(
        decision_id=_strict_string(mapping["decision_id"], "approval id"),
        action=_strict_string(mapping["action"], "approval action"),
        subject_tool_id=_strict_string(mapping["subject_tool_id"], "approval subject"),
        subject_release_digest=_strict_string(
            mapping["subject_release_digest"], "approval digest"
        ),
        decided_by_human_ref=_strict_string(
            mapping["decided_by_human_ref"], "approval human"
        ),
        decision=_strict_string(mapping["decision"], "approval decision"),
        reason=_strict_string(mapping["reason"], "approval reason"),
        evidence_status=_strict_string(mapping["evidence_status"], "evidence status"),
        synthetic_only=_strict_bool(mapping["synthetic_only"], "synthetic only"),
    )


def _transition_from_mapping(value: Any) -> ToolLifecycleTransition:
    mapping = _strict_mapping(value, "Tool transition")
    _exact_keys(
        mapping, set(ToolLifecycleTransition.__dataclass_fields__), "Tool transition"
    )
    return ToolLifecycleTransition(
        transition_id=_strict_string(mapping["transition_id"], "transition id"),
        audit_event_ref=_strict_string(mapping["audit_event_ref"], "audit ref"),
        tool_id=_strict_string(mapping["tool_id"], "Tool id"),
        release_digest=_strict_string(mapping["release_digest"], "release digest"),
        before=_strict_string(mapping["before"], "before status"),
        after=_strict_string(mapping["after"], "after status"),
        reason_code=_strict_string(mapping["reason_code"], "reason code"),
        actor_kind=_strict_string(mapping["actor_kind"], "actor kind"),
        actor_ref=_strict_string(mapping["actor_ref"], "actor ref"),
        approval_decision_ref=(
            None
            if mapping["approval_decision_ref"] is None
            else _strict_string(mapping["approval_decision_ref"], "approval ref")
        ),
        automatic=_strict_bool(mapping["automatic"], "automatic"),
        revision=_strict_int(mapping["revision"], "revision"),
    )


def _validate_id(value: Any, label: str) -> None:
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
        raise ToolLifecycleError("invalid_identifier", f"{label} is invalid")


def _validate_hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or not _HASH_PATTERN.fullmatch(value):
        raise ToolLifecycleError("invalid_digest", f"{label} is invalid")


def _validate_string_tuple(
    value: Any, label: str, *, allow_empty: bool = True
) -> None:
    if (
        not isinstance(value, tuple)
        or (not allow_empty and not value)
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ToolLifecycleError(
            "invalid_sequence", f"{label} must contain unique strings"
        )


def _exact_keys(
    value: Any, expected: set[str] | frozenset[str], label: str
) -> None:
    mapping = _strict_mapping(value, label)
    if set(mapping) != set(expected):
        raise ToolLifecycleError(
            "invalid_record_payload", f"{label} fields do not match"
        )


def _strict_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ToolLifecycleError(
            "invalid_record_payload", f"{label} must be an object"
        )
    return value


def _strict_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ToolLifecycleError(
            "invalid_record_payload", f"{label} must be a non-empty string"
        )
    return value


def _strict_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolLifecycleError(
            "invalid_record_payload", f"{label} must be an integer"
        )
    return value


def _strict_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ToolLifecycleError(
            "invalid_record_payload", f"{label} must be boolean"
        )
    return value


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ToolLifecycleError(
            "invalid_record_payload", f"{label} must be unique strings"
        )
    return tuple(value)


def _normalize_json(value: Any) -> Any:
    try:
        return json.loads(_canonical_json(value))
    except (TypeError, ValueError) as error:
        raise ToolLifecycleError(
            "payload_not_json", "Tool lifecycle payload is not strict JSON"
        ) from error


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _digest(source: bytes) -> str:
    return "sha256:" + sha256(source).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ToolLifecycleError(
                "duplicate_json_key", "Tool lifecycle record has a duplicate JSON key"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ToolLifecycleError(
        "invalid_json_constant", f"Tool lifecycle JSON constant {value} is forbidden"
    )

