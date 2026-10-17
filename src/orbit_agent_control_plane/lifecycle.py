"""Tamper-evident D0 Agent lifecycle evidence and template instantiation.

The local ledger is deliberately synthetic and non-authoritative.  It proves
that stable Agent activation requires an exact human decision while a bounded
Task Agent may be instantiated automatically from an approved template.
"""

from __future__ import annotations

import json
import os
import re
import stat
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


LIFECYCLE_LEDGER_VERSION = "orbit.synthetic-agent-lifecycle-ledger/1"
LIFECYCLE_GENESIS_HASH = "sha256:" + ("0" * 64)
MAX_LIFECYCLE_LEDGER_BYTES = 16 * 1024 * 1024
MAX_LIFECYCLE_RECORD_BYTES = 256 * 1024
LIFECYCLE_STATUSES = frozenset(
    {"draft", "evaluation", "active", "suspended", "retired"}
)
STRUCTURAL_CHANGE_FIELDS = frozenset(
    {
        "new_stable_agent",
        "new_agent_template",
        "purpose",
        "agent_system",
        "owner",
        "autonomy",
        "data_scope",
        "tool_scope",
        "model_scope",
        "runtime",
        "budget_ceiling",
        "evaluation_threshold",
    }
)
ALLOWED_D0_CLASSIFICATIONS = frozenset({"synthetic", "public"})
ALLOWED_RECORD_TYPES = frozenset(
    {
        "candidate_registered",
        "evaluation_recorded",
        "approval_recorded",
        "lifecycle_transitioned",
        "task_agent_instantiated",
        "task_agent_retired",
    }
)
_HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{2,95}$")
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RECORD_KEYS = frozenset(
    {
        "ledger_version",
        "sequence",
        "record_id",
        "record_type",
        "agent_id",
        "idempotency_key",
        "previous_record_hash",
        "payload",
        "record_hash",
    }
)


class LifecycleError(ValueError):
    """Fail-closed lifecycle error with a stable reason code."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class AgentCandidate:
    agent_id: str
    release_digest: str
    definition_ref: str
    binding_ref: str
    owner_role_ref: str
    agent_system_ref: str
    change_fields: tuple[str, ...]
    structural_change: bool
    evidence_status: str = "synthetic"
    synthetic_only: bool = True


@dataclass(frozen=True)
class LifecycleEvaluation:
    report_id: str
    subject_agent_id: str
    subject_release_digest: str
    evaluator_agent_id: str
    verdict: str
    release_recommendation: str
    evidence_refs: tuple[str, ...]
    risk_flags: tuple[str, ...]
    release_authorization: bool = False


@dataclass(frozen=True)
class SyntheticApprovalDecision:
    decision_id: str
    action: str
    subject_agent_id: str
    subject_release_digest: str
    decided_by_human_ref: str
    decision: str
    reason: str
    evidence_status: str = "synthetic"
    synthetic_only: bool = True


@dataclass(frozen=True)
class LifecycleTransition:
    transition_id: str
    agent_id: str
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
class ApprovedAgentTemplate:
    template_id: str
    version: str
    template_digest: str
    child_definition_ref: str
    agent_system_ref: str
    capabilities: tuple[str, ...]
    tool_operations: tuple[str, ...]
    data_operations: tuple[str, ...]
    data_classifications: tuple[str, ...]
    budget_units: int
    max_lifetime_seconds: int
    max_delegation_depth: int
    approved_by_human_ref: str
    approved: bool = True
    synthetic_only: bool = True


@dataclass(frozen=True)
class ParentTaskScope:
    task_id: str
    agent_system_ref: str
    capabilities: tuple[str, ...]
    tool_operations: tuple[str, ...]
    data_operations: tuple[str, ...]
    data_classifications: tuple[str, ...]
    budget_units: int
    remaining_lifetime_seconds: int
    max_delegation_depth: int
    active: bool = True
    synthetic_only: bool = True


@dataclass(frozen=True)
class TaskAgentRequest:
    agent_id: str
    parent_task_id: str
    template_id: str
    template_version: str
    template_digest: str
    child_definition_ref: str
    agent_system_ref: str
    capabilities: tuple[str, ...]
    tool_operations: tuple[str, ...]
    data_operations: tuple[str, ...]
    data_classifications: tuple[str, ...]
    budget_units: int
    lifetime_seconds: int
    delegation_depth: int
    approval_obligations_preserved: bool
    synthetic_only: bool = True


@dataclass(frozen=True)
class TaskAgentInstantiation:
    creation_id: str
    agent_id: str
    release_digest: str
    parent_task_id: str
    template_ref: str
    policy_decision: str
    reason_codes: tuple[str, ...]
    cleanup_required: tuple[str, ...]


@dataclass(frozen=True)
class TaskAgentCleanup:
    runtime_destroyed: bool
    grants_revoked: bool
    identity_soft_retired: bool
    working_memory_deleted: bool
    audit_retained: bool


@dataclass(frozen=True)
class LifecycleAppendResult:
    record_id: str
    sequence: int
    record_hash: str
    appended: bool


@dataclass(frozen=True)
class ReplayedAgentLifecycle:
    candidate: AgentCandidate
    status: str
    revision: int
    evaluation: LifecycleEvaluation | None
    approvals: tuple[SyntheticApprovalDecision, ...]
    transitions: tuple[LifecycleTransition, ...]
    task_instantiation: TaskAgentInstantiation | None
    cleanup: TaskAgentCleanup | None


@dataclass(frozen=True)
class LifecycleReplay:
    records_checked: int
    last_record_hash: str
    agents: tuple[ReplayedAgentLifecycle, ...]

    def agent(self, agent_id: str) -> ReplayedAgentLifecycle:
        matches = tuple(item for item in self.agents if item.candidate.agent_id == agent_id)
        if not matches:
            raise LifecycleError("agent_not_found", "agent is not present in lifecycle ledger")
        if len(matches) > 1:
            raise LifecycleError("agent_ambiguous", "agent has ambiguous lifecycle state")
        return matches[0]


@dataclass(frozen=True)
class _LifecycleRecord:
    sequence: int
    record_id: str
    record_type: str
    agent_id: str
    idempotency_key: str
    previous_record_hash: str
    payload: Mapping[str, Any]
    record_hash: str


@dataclass
class _MutableAgentState:
    candidate: AgentCandidate
    status: str
    revision: int
    evaluation: LifecycleEvaluation | None
    approvals: list[SyntheticApprovalDecision]
    transitions: list[LifecycleTransition]
    task_instantiation: TaskAgentInstantiation | None
    cleanup: TaskAgentCleanup | None

    def freeze(self) -> ReplayedAgentLifecycle:
        return ReplayedAgentLifecycle(
            candidate=self.candidate,
            status=self.status,
            revision=self.revision,
            evaluation=self.evaluation,
            approvals=tuple(self.approvals),
            transitions=tuple(self.transitions),
            task_instantiation=self.task_instantiation,
            cleanup=self.cleanup,
        )


def classify_structural_change(change_fields: tuple[str, ...]) -> bool:
    _validate_string_tuple(change_fields, "change fields")
    return bool(STRUCTURAL_CHANGE_FIELDS.intersection(change_fields))


def instantiate_task_agent(
    template: ApprovedAgentTemplate,
    parent: ParentTaskScope,
    request: TaskAgentRequest,
) -> TaskAgentInstantiation:
    _validate_template(template)
    _validate_parent_scope(parent)
    _validate_task_agent_request(request)
    failures: list[str] = []
    checks = (
        (not template.approved, "template_not_approved"),
        (not parent.active, "parent_task_inactive"),
        (request.parent_task_id != parent.task_id, "parent_task_mismatch"),
        (request.template_id != template.template_id, "template_id_mismatch"),
        (request.template_version != template.version, "template_version_mismatch"),
        (request.template_digest != template.template_digest, "template_digest_mismatch"),
        (
            request.child_definition_ref != template.child_definition_ref,
            "child_definition_mismatch",
        ),
        (
            request.agent_system_ref != template.agent_system_ref
            or request.agent_system_ref != parent.agent_system_ref,
            "agent_system_mismatch",
        ),
        (
            not set(request.capabilities).issubset(template.capabilities)
            or not set(request.capabilities).issubset(parent.capabilities),
            "capability_not_parent_subset",
        ),
        (
            not set(request.tool_operations).issubset(template.tool_operations)
            or not set(request.tool_operations).issubset(parent.tool_operations),
            "tool_scope_not_parent_subset",
        ),
        (
            not set(request.data_operations).issubset(template.data_operations)
            or not set(request.data_operations).issubset(parent.data_operations),
            "data_scope_not_parent_subset",
        ),
        (
            not set(request.data_classifications).issubset(
                template.data_classifications
            )
            or not set(request.data_classifications).issubset(
                parent.data_classifications
            )
            or not set(request.data_classifications).issubset(
                ALLOWED_D0_CLASSIFICATIONS
            ),
            "classification_not_parent_subset",
        ),
        (
            request.budget_units > template.budget_units
            or request.budget_units > parent.budget_units,
            "budget_not_parent_subset",
        ),
        (
            request.lifetime_seconds > template.max_lifetime_seconds
            or request.lifetime_seconds > parent.remaining_lifetime_seconds,
            "lifetime_not_parent_subset",
        ),
        (
            request.delegation_depth > template.max_delegation_depth
            or request.delegation_depth > parent.max_delegation_depth,
            "delegation_depth_not_parent_subset",
        ),
        (
            not request.approval_obligations_preserved,
            "approval_obligations_weakened",
        ),
    )
    failures.extend(code for failed, code in checks if failed)
    if failures:
        raise LifecycleError(failures[0], "Task Agent request exceeds its parent or template")

    release_digest = _digest(
        _canonical_json(
            {
                "template_digest": template.template_digest,
                "parent_task_id": parent.task_id,
                "request": asdict(request),
            }
        ).encode("utf-8")
    )
    creation_id = deterministic_id(
        "creation",
        request.agent_id,
        parent.task_id,
        template.template_digest,
        release_digest,
    )
    return TaskAgentInstantiation(
        creation_id=creation_id,
        agent_id=request.agent_id,
        release_digest=release_digest,
        parent_task_id=parent.task_id,
        template_ref=f"{template.template_id}@{template.version}",
        policy_decision="allow",
        reason_codes=("approved_template_parent_subset",),
        cleanup_required=(
            "destroy_runtime",
            "revoke_grants",
            "soft_retire_identity",
            "delete_working_memory",
            "retain_audit",
        ),
    )


def load_synthetic_approval_decision(
    path: Path | str,
) -> SyntheticApprovalDecision:
    """Load one owner-only synthetic ApprovalDecision without following links."""

    approval_path = Path(path)
    if not os.path.lexists(approval_path):
        raise LifecycleError("approval_file_not_found", "approval file does not exist")
    if stat.S_ISLNK(os.lstat(approval_path).st_mode):
        raise LifecycleError("approval_symlink_forbidden", "approval file may not be a symlink")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(approval_path, flags)
    except OSError as error:
        raise LifecycleError("approval_file_unavailable", "approval file cannot be opened") from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise LifecycleError("approval_not_regular_file", "approval must be a regular file")
        if metadata.st_uid != os.geteuid():
            raise LifecycleError("approval_owner_mismatch", "approval owner differs")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise LifecycleError("approval_permissions_too_broad", "approval must be owner-only")
        if metadata.st_size > 64 * 1024:
            raise LifecycleError("approval_file_too_large", "approval file exceeds limit")
        source = os.read(fd, metadata.st_size + 1)
    finally:
        os.close(fd)
    try:
        document = json.loads(
            source.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except LifecycleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LifecycleError("approval_invalid_json", "approval is invalid JSON") from error
    return _approval_from_mapping(document)


class _ReplayBuilder:
    def __init__(self) -> None:
        self.records: list[_LifecycleRecord] = []
        self.idempotency_index: dict[str, _LifecycleRecord] = {}
        self.agents: dict[str, _MutableAgentState] = {}
        self.last_record_hash = LIFECYCLE_GENESIS_HASH

    def add(self, record: _LifecycleRecord) -> None:
        if record.idempotency_key in self.idempotency_index:
            raise LifecycleError(
                "duplicate_idempotency_record",
                "lifecycle ledger contains a duplicate idempotency key",
            )
        self._apply(record)
        self.records.append(record)
        self.idempotency_index[record.idempotency_key] = record
        self.last_record_hash = record.record_hash

    def _apply(self, record: _LifecycleRecord) -> None:
        if record.record_type == "candidate_registered":
            _exact_keys(record.payload, {"candidate"}, "candidate payload")
            candidate = _candidate_from_mapping(record.payload["candidate"])
            if candidate.agent_id != record.agent_id:
                raise LifecycleError("record_agent_mismatch", "candidate agent id differs")
            if candidate.agent_id in self.agents:
                raise LifecycleError("candidate_already_registered", "candidate exists")
            self.agents[candidate.agent_id] = _MutableAgentState(
                candidate=candidate,
                status="draft",
                revision=0,
                evaluation=None,
                approvals=[],
                transitions=[],
                task_instantiation=None,
                cleanup=None,
            )
            return

        if record.record_type == "task_agent_instantiated":
            _exact_keys(
                record.payload,
                {"template", "parent", "request", "instantiation", "candidate", "transition"},
                "Task Agent instantiation payload",
            )
            template = _template_from_mapping(record.payload["template"])
            parent = _parent_from_mapping(record.payload["parent"])
            request = _task_request_from_mapping(record.payload["request"])
            expected = instantiate_task_agent(template, parent, request)
            instantiation = _instantiation_from_mapping(record.payload["instantiation"])
            candidate = _candidate_from_mapping(record.payload["candidate"])
            transition = _transition_from_mapping(record.payload["transition"])
            if expected != instantiation:
                raise LifecycleError("task_agent_instantiation_invalid", "instantiation is not reproducible")
            expected_candidate = _task_agent_candidate(template, request, expected)
            if candidate != expected_candidate:
                raise LifecycleError("task_agent_candidate_invalid", "Task Agent candidate is not reproducible")
            expected_transition = _transition(
                candidate,
                before="draft",
                after="active",
                reason_code="approved_template_parent_subset",
                actor_kind="system",
                actor_ref="system_agent_lifecycle_policy_syn",
                approval_decision_ref=None,
                automatic=True,
                revision=1,
            )
            if transition != expected_transition:
                raise LifecycleError("task_agent_transition_invalid", "Task Agent transition is not reproducible")
            if record.agent_id != request.agent_id or record.agent_id in self.agents:
                raise LifecycleError("task_agent_identity_conflict", "Task Agent identity conflicts")
            self.agents[record.agent_id] = _MutableAgentState(
                candidate=candidate,
                status="active",
                revision=1,
                evaluation=None,
                approvals=[],
                transitions=[transition],
                task_instantiation=instantiation,
                cleanup=None,
            )
            return

        state = self.agents.get(record.agent_id)
        if state is None:
            raise LifecycleError("candidate_missing", "candidate must be registered first")

        if record.record_type == "evaluation_recorded":
            _exact_keys(record.payload, {"evaluation", "transition"}, "evaluation payload")
            evaluation = _evaluation_from_mapping(record.payload["evaluation"])
            transition = _transition_from_mapping(record.payload["transition"])
            _validate_evaluation_binding(state.candidate, evaluation)
            if state.task_instantiation is not None:
                raise LifecycleError("task_agent_evaluation_not_supported", "temporary Task Agent uses template evidence")
            if state.status != "draft" or state.evaluation is not None:
                raise LifecycleError("evaluation_state_invalid", "candidate is not ready for initial evaluation")
            expected = _transition(
                state.candidate,
                before="draft",
                after="evaluation",
                reason_code="submitted_for_evaluation",
                actor_kind="system",
                actor_ref="system_agent_lifecycle_policy_syn",
                approval_decision_ref=None,
                automatic=True,
                revision=1,
            )
            if transition != expected:
                raise LifecycleError("evaluation_transition_invalid", "evaluation transition is not reproducible")
            state.evaluation = evaluation
            state.status = "evaluation"
            state.revision = transition.revision
            state.transitions.append(transition)
            return

        if record.record_type == "approval_recorded":
            _exact_keys(record.payload, {"approval"}, "approval payload")
            approval = _approval_from_mapping(record.payload["approval"])
            _validate_approval_binding(state.candidate, approval)
            if any(item.decision_id == approval.decision_id for item in state.approvals):
                raise LifecycleError("approval_duplicated", "approval decision is duplicated")
            state.approvals.append(approval)
            return

        if record.record_type == "lifecycle_transitioned":
            _exact_keys(record.payload, {"transition"}, "transition payload")
            transition = _transition_from_mapping(record.payload["transition"])
            if transition.before != state.status or transition.revision != state.revision + 1:
                raise LifecycleError("lifecycle_revision_mismatch", "transition does not continue current state")
            expected = _expected_stable_transition(state, transition)
            if transition != expected:
                raise LifecycleError("lifecycle_transition_invalid", "transition is not reproducible")
            state.status = transition.after
            state.revision = transition.revision
            state.transitions.append(transition)
            return

        if record.record_type == "task_agent_retired":
            _exact_keys(record.payload, {"cleanup", "transition"}, "Task Agent retirement payload")
            if state.task_instantiation is None:
                raise LifecycleError("not_task_agent", "only template Task Agent can use automatic cleanup")
            cleanup = _cleanup_from_mapping(record.payload["cleanup"])
            if cleanup != _complete_cleanup():
                raise LifecycleError("task_agent_cleanup_incomplete", "Task Agent cleanup is incomplete")
            transition = _transition_from_mapping(record.payload["transition"])
            if state.status not in {"active", "suspended"}:
                raise LifecycleError("task_agent_retirement_state_invalid", "Task Agent cannot retire from current state")
            expected = _transition(
                state.candidate,
                before=state.status,
                after="retired",
                reason_code="parent_task_ended",
                actor_kind="system",
                actor_ref="system_agent_lifecycle_policy_syn",
                approval_decision_ref=None,
                automatic=True,
                revision=state.revision + 1,
            )
            if transition != expected:
                raise LifecycleError("task_agent_retirement_invalid", "Task Agent retirement is not reproducible")
            state.cleanup = cleanup
            state.status = "retired"
            state.revision = transition.revision
            state.transitions.append(transition)
            return

        raise LifecycleError("unsupported_record_type", "lifecycle record type is unsupported")

    def freeze(self) -> LifecycleReplay:
        return LifecycleReplay(
            records_checked=len(self.records),
            last_record_hash=self.last_record_hash,
            agents=tuple(item.freeze() for item in self.agents.values()),
        )


class SyntheticAgentLifecycleLedger:
    """Owner-only append ledger for local synthetic Agent lifecycle evidence."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def register_candidate(self, candidate: AgentCandidate, *, idempotency_key: str) -> LifecycleAppendResult:
        _validate_candidate(candidate)
        return self._append("candidate_registered", candidate.agent_id, idempotency_key, {"candidate": asdict(candidate)})

    def record_evaluation(self, evaluation: LifecycleEvaluation, *, idempotency_key: str) -> LifecycleAppendResult:
        replay = self.replay()
        state = replay.agent(evaluation.subject_agent_id)
        _validate_evaluation_binding(state.candidate, evaluation)
        transition = _transition(
            state.candidate,
            before="draft",
            after="evaluation",
            reason_code="submitted_for_evaluation",
            actor_kind="system",
            actor_ref="system_agent_lifecycle_policy_syn",
            approval_decision_ref=None,
            automatic=True,
            revision=1,
        )
        return self._append("evaluation_recorded", evaluation.subject_agent_id, idempotency_key, {"evaluation": asdict(evaluation), "transition": asdict(transition)})

    def record_approval(self, approval: SyntheticApprovalDecision, *, idempotency_key: str) -> LifecycleAppendResult:
        replay = self.replay()
        state = replay.agent(approval.subject_agent_id)
        _validate_approval_binding(state.candidate, approval)
        return self._append("approval_recorded", approval.subject_agent_id, idempotency_key, {"approval": asdict(approval)})

    def activate_stable(self, agent_id: str, *, approval_decision_ref: str, idempotency_key: str) -> LifecycleAppendResult:
        state = self.replay().agent(agent_id)
        transition = _build_stable_transition(state, "active", approval_decision_ref)
        return self._append("lifecycle_transitioned", agent_id, idempotency_key, {"transition": asdict(transition)})

    def suspend(self, agent_id: str, *, actor_kind: str, actor_ref: str, reason_code: str, idempotency_key: str) -> LifecycleAppendResult:
        state = self.replay().agent(agent_id)
        if state.status != "active":
            raise LifecycleError("suspension_state_invalid", "only active Agent may be suspended")
        transition = _transition(
            state.candidate,
            before="active",
            after="suspended",
            reason_code=reason_code,
            actor_kind=actor_kind,
            actor_ref=actor_ref,
            approval_decision_ref=None,
            automatic=True,
            revision=state.revision + 1,
        )
        return self._append("lifecycle_transitioned", agent_id, idempotency_key, {"transition": asdict(transition)})

    def retire_stable(self, agent_id: str, *, approval_decision_ref: str, idempotency_key: str) -> LifecycleAppendResult:
        state = self.replay().agent(agent_id)
        transition = _build_stable_transition(state, "retired", approval_decision_ref)
        return self._append("lifecycle_transitioned", agent_id, idempotency_key, {"transition": asdict(transition)})

    def spawn_task_agent(self, template: ApprovedAgentTemplate, parent: ParentTaskScope, request: TaskAgentRequest, *, idempotency_key: str) -> LifecycleAppendResult:
        instantiation = instantiate_task_agent(template, parent, request)
        candidate = _task_agent_candidate(template, request, instantiation)
        transition = _transition(
            candidate,
            before="draft",
            after="active",
            reason_code="approved_template_parent_subset",
            actor_kind="system",
            actor_ref="system_agent_lifecycle_policy_syn",
            approval_decision_ref=None,
            automatic=True,
            revision=1,
        )
        return self._append(
            "task_agent_instantiated",
            request.agent_id,
            idempotency_key,
            {
                "template": asdict(template),
                "parent": asdict(parent),
                "request": asdict(request),
                "instantiation": asdict(instantiation),
                "candidate": asdict(candidate),
                "transition": asdict(transition),
            },
        )

    def retire_task_agent(self, agent_id: str, *, idempotency_key: str) -> LifecycleAppendResult:
        state = self.replay().agent(agent_id)
        if state.task_instantiation is None:
            raise LifecycleError("not_task_agent", "stable Agent cannot use automatic Task Agent retirement")
        transition = _transition(
            state.candidate,
            before=state.status,
            after="retired",
            reason_code="parent_task_ended",
            actor_kind="system",
            actor_ref="system_agent_lifecycle_policy_syn",
            approval_decision_ref=None,
            automatic=True,
            revision=state.revision + 1,
        )
        return self._append("task_agent_retired", agent_id, idempotency_key, {"cleanup": asdict(_complete_cleanup()), "transition": asdict(transition)})

    def replay(self) -> LifecycleReplay:
        fd = self._open(create=False, exclusive=False)
        try:
            return self._read_builder(fd).freeze()
        finally:
            self._close(fd)

    def _append(self, record_type: str, agent_id: str, idempotency_key: str, payload: Mapping[str, Any]) -> LifecycleAppendResult:
        if record_type not in ALLOWED_RECORD_TYPES:
            raise LifecycleError("unsupported_record_type", "record type is unsupported")
        _validate_id(agent_id, "agent id")
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_PATTERN.fullmatch(idempotency_key):
            raise LifecycleError("invalid_idempotency_key", "idempotency key format is invalid")
        normalized = _normalize_json(payload)
        fd = self._open(create=True, exclusive=True)
        try:
            builder = self._read_builder(fd)
            existing = builder.idempotency_index.get(idempotency_key)
            if existing is not None:
                if existing.record_type == record_type and existing.agent_id == agent_id and _canonical_json(existing.payload) == _canonical_json(normalized):
                    return LifecycleAppendResult(existing.record_id, existing.sequence, existing.record_hash, False)
                raise LifecycleError("idempotency_conflict", "idempotency key is bound to different content")
            payload_digest = _digest(_canonical_json(normalized).encode("utf-8"))
            record_id = deterministic_id("lifecycle", record_type, agent_id, idempotency_key, payload_digest)
            content = {
                "ledger_version": LIFECYCLE_LEDGER_VERSION,
                "sequence": len(builder.records),
                "record_id": record_id,
                "record_type": record_type,
                "agent_id": agent_id,
                "idempotency_key": idempotency_key,
                "previous_record_hash": builder.last_record_hash,
                "payload": normalized,
            }
            record_hash = _digest(_canonical_json(content).encode("utf-8"))
            document = {**content, "record_hash": record_hash}
            record = _record_from_document(document, len(builder.records), builder.last_record_hash)
            builder.add(record)
            encoded = (_canonical_json(document) + "\n").encode("utf-8")
            append_jsonl_document(
                fd,
                encoded,
                max_ledger_bytes=MAX_LIFECYCLE_LEDGER_BYTES,
                max_record_bytes=MAX_LIFECYCLE_RECORD_BYTES,
                error=LifecycleError,
                label="Agent lifecycle ledger",
            )
            return LifecycleAppendResult(record.record_id, record.sequence, record.record_hash, True)
        finally:
            self._close(fd)

    def _open(self, *, create: bool, exclusive: bool) -> int:
        return open_owner_only_ledger(
            self.path,
            create=create,
            exclusive=exclusive,
            error=LifecycleError,
            label="Agent lifecycle ledger",
        )

    @staticmethod
    def _close(fd: int) -> None:
        close_ledger(fd)

    @staticmethod
    def _read_builder(fd: int) -> _ReplayBuilder:
        builder = _ReplayBuilder()
        documents = read_jsonl_documents(
            fd,
            max_ledger_bytes=MAX_LIFECYCLE_LEDGER_BYTES,
            max_record_bytes=MAX_LIFECYCLE_RECORD_BYTES,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
            error=LifecycleError,
            label="Agent lifecycle ledger",
        )
        for sequence, document in enumerate(documents):
            builder.add(_record_from_document(document, sequence, builder.last_record_hash))
        return builder


def _build_stable_transition(state: ReplayedAgentLifecycle, after: str, approval_ref: str) -> LifecycleTransition:
    if state.task_instantiation is not None:
        raise LifecycleError("task_agent_stable_transition_forbidden", "Task Agent uses automatic lifecycle")
    approvals = tuple(item for item in state.approvals if item.decision_id == approval_ref)
    if len(approvals) != 1:
        raise LifecycleError("approval_decision_missing", "exact ApprovalDecision is unavailable")
    approval = approvals[0]
    if approval.decision != "approve" or approval.action != ("activate" if after == "active" else "retire"):
        raise LifecycleError("approval_decision_scope_mismatch", "ApprovalDecision does not approve transition")
    if after == "active":
        if state.status != "evaluation" or state.evaluation is None:
            raise LifecycleError("activation_state_invalid", "stable Agent is not in evaluation")
        if state.evaluation.verdict != "pass" or state.evaluation.release_recommendation != "recommend":
            raise LifecycleError("evaluation_not_passed", "stable Agent evaluation did not pass")
        reason = "human_approved_release"
    elif after == "retired":
        if state.status not in {"active", "suspended"}:
            raise LifecycleError("retirement_state_invalid", "stable Agent cannot retire from current state")
        reason = "human_approved_retirement"
    else:
        raise LifecycleError("unsupported_transition", "stable transition is unsupported")
    return _transition(
        state.candidate,
        before=state.status,
        after=after,
        reason_code=reason,
        actor_kind="human",
        actor_ref=approval.decided_by_human_ref,
        approval_decision_ref=approval.decision_id,
        automatic=False,
        revision=state.revision + 1,
    )


def _expected_stable_transition(state: _MutableAgentState, transition: LifecycleTransition) -> LifecycleTransition:
    if state.task_instantiation is not None:
        if transition.after != "suspended":
            raise LifecycleError("task_agent_transition_forbidden", "Task Agent transition is unsupported")
    if transition.after == "suspended":
        if state.status != "active" or transition.approval_decision_ref is not None or not transition.automatic:
            raise LifecycleError("suspension_invalid", "suspension boundary is invalid")
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
        frozen = state.freeze()
        return _build_stable_transition(frozen, transition.after, transition.approval_decision_ref or "")
    raise LifecycleError("unsupported_transition", "lifecycle transition is unsupported")


def _transition(candidate: AgentCandidate, *, before: str, after: str, reason_code: str, actor_kind: str, actor_ref: str, approval_decision_ref: str | None, automatic: bool, revision: int) -> LifecycleTransition:
    if before not in LIFECYCLE_STATUSES or after not in LIFECYCLE_STATUSES:
        raise LifecycleError("invalid_lifecycle_status", "lifecycle status is invalid")
    if actor_kind not in {"human", "system"}:
        raise LifecycleError("invalid_actor_kind", "lifecycle actor kind is invalid")
    _validate_id(actor_ref, "actor ref")
    transition_id = deterministic_id(
        "transition",
        candidate.agent_id,
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
    return LifecycleTransition(transition_id, candidate.agent_id, candidate.release_digest, before, after, reason_code, actor_kind, actor_ref, approval_decision_ref, automatic, revision)


def _task_agent_candidate(template: ApprovedAgentTemplate, request: TaskAgentRequest, instantiation: TaskAgentInstantiation) -> AgentCandidate:
    return AgentCandidate(
        agent_id=request.agent_id,
        release_digest=instantiation.release_digest,
        definition_ref=request.child_definition_ref,
        binding_ref=f"binding_{request.agent_id}_ephemeral_syn",
        owner_role_ref="role_parent_task_accountable_human_syn",
        agent_system_ref=request.agent_system_ref,
        change_fields=("template_instance",),
        structural_change=False,
    )


def _complete_cleanup() -> TaskAgentCleanup:
    return TaskAgentCleanup(True, True, True, True, True)


def _validate_candidate(candidate: AgentCandidate) -> None:
    _validate_id(candidate.agent_id, "candidate agent id")
    _validate_hash(candidate.release_digest, "candidate release digest")
    for value, label in ((candidate.definition_ref, "definition ref"), (candidate.binding_ref, "binding ref"), (candidate.owner_role_ref, "owner role ref"), (candidate.agent_system_ref, "agent system ref")):
        _validate_id(value, label)
    _validate_string_tuple(candidate.change_fields, "change fields")
    if candidate.structural_change != classify_structural_change(candidate.change_fields):
        raise LifecycleError("structural_classification_mismatch", "structural change classification is not deterministic")
    if candidate.evidence_status != "synthetic" or not candidate.synthetic_only:
        raise LifecycleError("candidate_not_synthetic", "only synthetic candidate evidence is allowed")


def _validate_evaluation_binding(candidate: AgentCandidate, evaluation: LifecycleEvaluation) -> None:
    _validate_evaluation(evaluation)
    if evaluation.subject_agent_id != candidate.agent_id or evaluation.subject_release_digest != candidate.release_digest:
        raise LifecycleError("evaluation_subject_mismatch", "evaluation is not bound to candidate")
    if evaluation.evaluator_agent_id == candidate.agent_id:
        raise LifecycleError("self_evaluation_forbidden", "Agent cannot evaluate itself")


def _validate_evaluation(value: LifecycleEvaluation) -> None:
    for item, label in ((value.report_id, "evaluation report id"), (value.subject_agent_id, "evaluation subject"), (value.evaluator_agent_id, "evaluator agent")):
        _validate_id(item, label)
    _validate_hash(value.subject_release_digest, "evaluation release digest")
    if value.verdict not in {"pass", "fail", "needs_review"}:
        raise LifecycleError("evaluation_verdict_invalid", "evaluation verdict is invalid")
    if value.release_recommendation not in {"recommend", "do_not_recommend", "insufficient_evidence"}:
        raise LifecycleError("release_recommendation_invalid", "release recommendation is invalid")
    if value.release_authorization:
        raise LifecycleError("evaluation_release_authority_forbidden", "evaluation cannot authorize release")
    _validate_string_tuple(value.evidence_refs, "evaluation evidence refs", allow_empty=False)
    _validate_string_tuple(value.risk_flags, "evaluation risk flags")


def _validate_approval_binding(candidate: AgentCandidate, approval: SyntheticApprovalDecision) -> None:
    _validate_approval(approval)
    if approval.subject_agent_id != candidate.agent_id or approval.subject_release_digest != candidate.release_digest:
        raise LifecycleError("approval_subject_mismatch", "ApprovalDecision is not bound to candidate")


def _validate_approval(value: SyntheticApprovalDecision) -> None:
    for item, label in ((value.decision_id, "approval decision id"), (value.subject_agent_id, "approval subject"), (value.decided_by_human_ref, "approval human")):
        _validate_id(item, label)
    _validate_hash(value.subject_release_digest, "approval release digest")
    if value.action not in {"activate", "retire"} or value.decision not in {"approve", "reject", "revoke"}:
        raise LifecycleError("approval_decision_invalid", "approval action or decision is invalid")
    if not isinstance(value.reason, str) or len(value.reason.strip()) < 3:
        raise LifecycleError("approval_reason_invalid", "approval reason is required")
    if value.evidence_status != "synthetic" or not value.synthetic_only:
        raise LifecycleError("approval_not_synthetic", "only synthetic ApprovalDecision is allowed")


def _validate_template(value: ApprovedAgentTemplate) -> None:
    for item, label in ((value.template_id, "template id"), (value.child_definition_ref, "child definition ref"), (value.agent_system_ref, "agent system ref"), (value.approved_by_human_ref, "template approver")):
        _validate_id(item, label)
    if not isinstance(value.version, str) or not value.version:
        raise LifecycleError("template_version_invalid", "template version is required")
    _validate_hash(value.template_digest, "template digest")
    for items, label in ((value.capabilities, "template capabilities"), (value.tool_operations, "template tools"), (value.data_operations, "template data operations"), (value.data_classifications, "template classifications")):
        _validate_string_tuple(items, label)
    if not set(value.data_classifications).issubset(ALLOWED_D0_CLASSIFICATIONS):
        raise LifecycleError("template_classification_not_allowed", "template is outside D0")
    if min(value.budget_units, value.max_lifetime_seconds) < 1 or value.max_delegation_depth < 0:
        raise LifecycleError("template_limit_invalid", "template limits are invalid")
    if not value.synthetic_only:
        raise LifecycleError("template_not_synthetic", "only synthetic template is allowed")


def _validate_parent_scope(value: ParentTaskScope) -> None:
    _validate_id(value.task_id, "parent task id")
    _validate_id(value.agent_system_ref, "parent agent system")
    for items, label in ((value.capabilities, "parent capabilities"), (value.tool_operations, "parent tools"), (value.data_operations, "parent data operations"), (value.data_classifications, "parent classifications")):
        _validate_string_tuple(items, label)
    if not set(value.data_classifications).issubset(ALLOWED_D0_CLASSIFICATIONS):
        raise LifecycleError("parent_classification_not_allowed", "parent task is outside D0")
    if min(value.budget_units, value.remaining_lifetime_seconds) < 1 or value.max_delegation_depth < 0 or not value.synthetic_only:
        raise LifecycleError("parent_scope_invalid", "parent task scope is invalid")


def _validate_task_agent_request(value: TaskAgentRequest) -> None:
    for item, label in ((value.agent_id, "Task Agent id"), (value.parent_task_id, "parent task id"), (value.template_id, "template id"), (value.child_definition_ref, "child definition ref"), (value.agent_system_ref, "agent system ref")):
        _validate_id(item, label)
    _validate_hash(value.template_digest, "template digest")
    if not isinstance(value.template_version, str) or not value.template_version:
        raise LifecycleError("template_version_invalid", "template version is required")
    for items, label in ((value.capabilities, "request capabilities"), (value.tool_operations, "request tools"), (value.data_operations, "request data operations"), (value.data_classifications, "request classifications")):
        _validate_string_tuple(items, label)
    if min(value.budget_units, value.lifetime_seconds) < 1 or value.delegation_depth < 0 or not value.synthetic_only:
        raise LifecycleError("task_agent_request_invalid", "Task Agent request is invalid")


def _record_from_document(document: Any, expected_sequence: int, previous_hash: str) -> _LifecycleRecord:
    _exact_keys(document, _RECORD_KEYS, "lifecycle record")
    if document["ledger_version"] != LIFECYCLE_LEDGER_VERSION:
        raise LifecycleError("unsupported_ledger_version", "lifecycle ledger version is unsupported")
    sequence = _strict_int(document["sequence"], "record sequence")
    if sequence != expected_sequence:
        raise LifecycleError("sequence_mismatch", "lifecycle sequence is not contiguous")
    record_type = _strict_string(document["record_type"], "record type")
    if record_type not in ALLOWED_RECORD_TYPES:
        raise LifecycleError("unsupported_record_type", "lifecycle record type is unsupported")
    agent_id = _strict_string(document["agent_id"], "record agent id")
    _validate_id(agent_id, "record agent id")
    idempotency_key = _strict_string(document["idempotency_key"], "idempotency key")
    if not _IDEMPOTENCY_PATTERN.fullmatch(idempotency_key):
        raise LifecycleError("invalid_idempotency_key", "idempotency key format is invalid")
    if document["previous_record_hash"] != previous_hash:
        raise LifecycleError("previous_hash_mismatch", "lifecycle hash chain is broken")
    _validate_hash(document["previous_record_hash"], "previous record hash")
    record_hash = _strict_string(document["record_hash"], "record hash")
    _validate_hash(record_hash, "record hash")
    payload = _strict_mapping(document["payload"], "record payload")
    content = {key: value for key, value in document.items() if key != "record_hash"}
    if record_hash != _digest(_canonical_json(content).encode("utf-8")):
        raise LifecycleError("record_hash_mismatch", "lifecycle record hash differs")
    payload_digest = _digest(_canonical_json(payload).encode("utf-8"))
    expected_id = deterministic_id("lifecycle", record_type, agent_id, idempotency_key, payload_digest)
    if document["record_id"] != expected_id:
        raise LifecycleError("record_id_mismatch", "lifecycle record id is not deterministic")
    return _LifecycleRecord(sequence, expected_id, record_type, agent_id, idempotency_key, previous_hash, payload, record_hash)


def _candidate_from_mapping(value: Any) -> AgentCandidate:
    mapping = _strict_mapping(value, "candidate")
    _exact_keys(mapping, set(AgentCandidate.__dataclass_fields__), "candidate")
    candidate = AgentCandidate(
        agent_id=_strict_string(mapping["agent_id"], "candidate id"),
        release_digest=_strict_string(mapping["release_digest"], "release digest"),
        definition_ref=_strict_string(mapping["definition_ref"], "definition ref"),
        binding_ref=_strict_string(mapping["binding_ref"], "binding ref"),
        owner_role_ref=_strict_string(mapping["owner_role_ref"], "owner role"),
        agent_system_ref=_strict_string(mapping["agent_system_ref"], "agent system"),
        change_fields=_string_tuple(mapping["change_fields"], "change fields"),
        structural_change=_strict_bool(mapping["structural_change"], "structural change"),
        evidence_status=_strict_string(mapping["evidence_status"], "evidence status"),
        synthetic_only=_strict_bool(mapping["synthetic_only"], "synthetic only"),
    )
    _validate_candidate(candidate)
    return candidate


def _evaluation_from_mapping(value: Any) -> LifecycleEvaluation:
    mapping = _strict_mapping(value, "evaluation")
    _exact_keys(mapping, set(LifecycleEvaluation.__dataclass_fields__), "evaluation")
    result = LifecycleEvaluation(
        report_id=_strict_string(mapping["report_id"], "report id"),
        subject_agent_id=_strict_string(mapping["subject_agent_id"], "subject agent"),
        subject_release_digest=_strict_string(mapping["subject_release_digest"], "subject digest"),
        evaluator_agent_id=_strict_string(mapping["evaluator_agent_id"], "evaluator agent"),
        verdict=_strict_string(mapping["verdict"], "verdict"),
        release_recommendation=_strict_string(mapping["release_recommendation"], "release recommendation"),
        evidence_refs=_string_tuple(mapping["evidence_refs"], "evidence refs"),
        risk_flags=_string_tuple(mapping["risk_flags"], "risk flags"),
        release_authorization=_strict_bool(mapping["release_authorization"], "release authorization"),
    )
    _validate_evaluation(result)
    return result


def _approval_from_mapping(value: Any) -> SyntheticApprovalDecision:
    mapping = _strict_mapping(value, "approval")
    _exact_keys(mapping, set(SyntheticApprovalDecision.__dataclass_fields__), "approval")
    result = SyntheticApprovalDecision(
        decision_id=_strict_string(mapping["decision_id"], "decision id"),
        action=_strict_string(mapping["action"], "approval action"),
        subject_agent_id=_strict_string(mapping["subject_agent_id"], "approval subject"),
        subject_release_digest=_strict_string(mapping["subject_release_digest"], "approval digest"),
        decided_by_human_ref=_strict_string(mapping["decided_by_human_ref"], "approval human"),
        decision=_strict_string(mapping["decision"], "approval decision"),
        reason=_strict_string(mapping["reason"], "approval reason"),
        evidence_status=_strict_string(mapping["evidence_status"], "approval evidence"),
        synthetic_only=_strict_bool(mapping["synthetic_only"], "approval synthetic only"),
    )
    _validate_approval(result)
    return result


def _transition_from_mapping(value: Any) -> LifecycleTransition:
    mapping = _strict_mapping(value, "transition")
    _exact_keys(mapping, set(LifecycleTransition.__dataclass_fields__), "transition")
    approval = mapping["approval_decision_ref"]
    if approval is not None:
        approval = _strict_string(approval, "approval decision ref")
    transition = LifecycleTransition(
        transition_id=_strict_string(mapping["transition_id"], "transition id"),
        agent_id=_strict_string(mapping["agent_id"], "transition agent"),
        release_digest=_strict_string(mapping["release_digest"], "transition digest"),
        before=_strict_string(mapping["before"], "transition before"),
        after=_strict_string(mapping["after"], "transition after"),
        reason_code=_strict_string(mapping["reason_code"], "transition reason"),
        actor_kind=_strict_string(mapping["actor_kind"], "actor kind"),
        actor_ref=_strict_string(mapping["actor_ref"], "actor ref"),
        approval_decision_ref=approval,
        automatic=_strict_bool(mapping["automatic"], "automatic"),
        revision=_strict_int(mapping["revision"], "transition revision"),
    )
    return transition


def _template_from_mapping(value: Any) -> ApprovedAgentTemplate:
    mapping = _strict_mapping(value, "template")
    _exact_keys(mapping, set(ApprovedAgentTemplate.__dataclass_fields__), "template")
    result = ApprovedAgentTemplate(
        template_id=_strict_string(mapping["template_id"], "template id"),
        version=_strict_string(mapping["version"], "template version"),
        template_digest=_strict_string(mapping["template_digest"], "template digest"),
        child_definition_ref=_strict_string(mapping["child_definition_ref"], "child definition"),
        agent_system_ref=_strict_string(mapping["agent_system_ref"], "agent system"),
        capabilities=_string_tuple(mapping["capabilities"], "template capabilities"),
        tool_operations=_string_tuple(mapping["tool_operations"], "template tools"),
        data_operations=_string_tuple(mapping["data_operations"], "template data"),
        data_classifications=_string_tuple(mapping["data_classifications"], "template classifications"),
        budget_units=_strict_int(mapping["budget_units"], "template budget"),
        max_lifetime_seconds=_strict_int(mapping["max_lifetime_seconds"], "template lifetime"),
        max_delegation_depth=_strict_int(mapping["max_delegation_depth"], "template depth"),
        approved_by_human_ref=_strict_string(mapping["approved_by_human_ref"], "template approver"),
        approved=_strict_bool(mapping["approved"], "template approved"),
        synthetic_only=_strict_bool(mapping["synthetic_only"], "template synthetic"),
    )
    _validate_template(result)
    return result


def _parent_from_mapping(value: Any) -> ParentTaskScope:
    mapping = _strict_mapping(value, "parent task")
    _exact_keys(mapping, set(ParentTaskScope.__dataclass_fields__), "parent task")
    result = ParentTaskScope(
        task_id=_strict_string(mapping["task_id"], "parent task id"),
        agent_system_ref=_strict_string(mapping["agent_system_ref"], "parent agent system"),
        capabilities=_string_tuple(mapping["capabilities"], "parent capabilities"),
        tool_operations=_string_tuple(mapping["tool_operations"], "parent tools"),
        data_operations=_string_tuple(mapping["data_operations"], "parent data"),
        data_classifications=_string_tuple(mapping["data_classifications"], "parent classifications"),
        budget_units=_strict_int(mapping["budget_units"], "parent budget"),
        remaining_lifetime_seconds=_strict_int(mapping["remaining_lifetime_seconds"], "parent lifetime"),
        max_delegation_depth=_strict_int(mapping["max_delegation_depth"], "parent depth"),
        active=_strict_bool(mapping["active"], "parent active"),
        synthetic_only=_strict_bool(mapping["synthetic_only"], "parent synthetic"),
    )
    _validate_parent_scope(result)
    return result


def _task_request_from_mapping(value: Any) -> TaskAgentRequest:
    mapping = _strict_mapping(value, "Task Agent request")
    _exact_keys(mapping, set(TaskAgentRequest.__dataclass_fields__), "Task Agent request")
    result = TaskAgentRequest(
        agent_id=_strict_string(mapping["agent_id"], "Task Agent id"),
        parent_task_id=_strict_string(mapping["parent_task_id"], "parent task id"),
        template_id=_strict_string(mapping["template_id"], "template id"),
        template_version=_strict_string(mapping["template_version"], "template version"),
        template_digest=_strict_string(mapping["template_digest"], "template digest"),
        child_definition_ref=_strict_string(mapping["child_definition_ref"], "child definition"),
        agent_system_ref=_strict_string(mapping["agent_system_ref"], "agent system"),
        capabilities=_string_tuple(mapping["capabilities"], "request capabilities"),
        tool_operations=_string_tuple(mapping["tool_operations"], "request tools"),
        data_operations=_string_tuple(mapping["data_operations"], "request data"),
        data_classifications=_string_tuple(mapping["data_classifications"], "request classifications"),
        budget_units=_strict_int(mapping["budget_units"], "request budget"),
        lifetime_seconds=_strict_int(mapping["lifetime_seconds"], "request lifetime"),
        delegation_depth=_strict_int(mapping["delegation_depth"], "request depth"),
        approval_obligations_preserved=_strict_bool(mapping["approval_obligations_preserved"], "approval obligations"),
        synthetic_only=_strict_bool(mapping["synthetic_only"], "request synthetic"),
    )
    _validate_task_agent_request(result)
    return result


def _instantiation_from_mapping(value: Any) -> TaskAgentInstantiation:
    mapping = _strict_mapping(value, "instantiation")
    _exact_keys(mapping, set(TaskAgentInstantiation.__dataclass_fields__), "instantiation")
    return TaskAgentInstantiation(
        creation_id=_strict_string(mapping["creation_id"], "creation id"),
        agent_id=_strict_string(mapping["agent_id"], "instantiation agent"),
        release_digest=_strict_string(mapping["release_digest"], "instantiation digest"),
        parent_task_id=_strict_string(mapping["parent_task_id"], "instantiation parent"),
        template_ref=_strict_string(mapping["template_ref"], "template ref"),
        policy_decision=_strict_string(mapping["policy_decision"], "policy decision"),
        reason_codes=_string_tuple(mapping["reason_codes"], "instantiation reasons"),
        cleanup_required=_string_tuple(mapping["cleanup_required"], "cleanup required"),
    )


def _cleanup_from_mapping(value: Any) -> TaskAgentCleanup:
    mapping = _strict_mapping(value, "cleanup")
    _exact_keys(mapping, set(TaskAgentCleanup.__dataclass_fields__), "cleanup")
    return TaskAgentCleanup(*(_strict_bool(mapping[name], name) for name in TaskAgentCleanup.__dataclass_fields__))


def _validate_id(value: Any, label: str) -> None:
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
        raise LifecycleError("invalid_identifier", f"{label} is invalid")


def _validate_hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or not _HASH_PATTERN.fullmatch(value):
        raise LifecycleError("invalid_digest", f"{label} is invalid")


def _validate_string_tuple(value: Any, label: str, *, allow_empty: bool = True) -> None:
    if not isinstance(value, tuple) or (not allow_empty and not value) or any(not isinstance(item, str) or not item for item in value) or len(set(value)) != len(value):
        raise LifecycleError("invalid_sequence", f"{label} must contain unique strings")


def _exact_keys(value: Any, expected: set[str] | frozenset[str], label: str) -> None:
    mapping = _strict_mapping(value, label)
    if set(mapping) != set(expected):
        raise LifecycleError("invalid_record_payload", f"{label} fields do not match")


def _strict_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise LifecycleError("invalid_record_payload", f"{label} must be an object")
    return value


def _strict_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise LifecycleError("invalid_record_payload", f"{label} must be a non-empty string")
    return value


def _strict_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LifecycleError("invalid_record_payload", f"{label} must be an integer")
    return value


def _strict_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise LifecycleError("invalid_record_payload", f"{label} must be boolean")
    return value


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value) or len(set(value)) != len(value):
        raise LifecycleError("invalid_record_payload", f"{label} must be unique strings")
    return tuple(value)


def _normalize_json(value: Any) -> Any:
    try:
        return json.loads(_canonical_json(value))
    except (TypeError, ValueError) as error:
        raise LifecycleError("payload_not_json", "lifecycle payload is not strict JSON") from error


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(source: bytes) -> str:
    return "sha256:" + sha256(source).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LifecycleError("duplicate_json_key", "lifecycle record has duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise LifecycleError("invalid_json_constant", f"unsupported JSON constant {value}")

