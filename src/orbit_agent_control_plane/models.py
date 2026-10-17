"""Immutable objects for the D0 synthetic Router/Evaluator loop."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TaskEnvelope:
    task_id: str
    capability: str
    data_classification: str
    grant_id: str
    grant_active: bool
    requested_target_id: str | None = None


@dataclass(frozen=True)
class RoutingTarget:
    target_id: str
    capabilities: frozenset[str]
    allowed_data_classifications: frozenset[str]
    active: bool = True


@dataclass(frozen=True)
class RouteDecision:
    decision_id: str
    task_id: str
    status: str
    target_id: str | None
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    task_id: str
    event_type: str
    subject_ref: str


@dataclass(frozen=True)
class TaskControlSnapshot:
    task_id: str
    grant_id: str
    task_status: str
    grant_status: str
    owner_kind: str
    revision: int
    last_control_event_ref: str | None = None


@dataclass(frozen=True)
class ControlTransition:
    action: str
    applied: bool
    reason_code: str
    before: TaskControlSnapshot
    after: TaskControlSnapshot
    audit_event: AuditEvent


@dataclass(frozen=True)
class TaskResult:
    result_id: str
    task_id: str
    target_id: str
    status: str
    output_ref: str
    audit_event_refs: tuple[str, ...]
    side_effects: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvaluationReport:
    report_id: str
    evaluator_agent_id: str
    subject_result_id: str
    verdict: str
    reason_codes: tuple[str, ...]
    release_authorization: bool = False


@dataclass(frozen=True)
class WorkerLease:
    lease_id: str
    task_id: str
    worker_id: str
    implementation_revision: str
    status: str
    revision: int
    cancellation_requested: bool
    last_event_ref: str


@dataclass(frozen=True)
class ClosedLoopOutcome:
    task: TaskEnvelope
    route_decision: RouteDecision
    result: TaskResult | None
    evaluation: EvaluationReport | None
    audit_events: tuple[AuditEvent, ...]
    control_snapshot: TaskControlSnapshot | None = None


@dataclass(frozen=True)
class AgentReleaseSelection:
    agent_id: str
    release_digest: str
    capabilities: frozenset[str]
    requested_tool_capabilities: frozenset[str]
    allowed_data_classifications: frozenset[str]
    active: bool


@dataclass(frozen=True)
class ToolCapabilityRequirement:
    request_name: str
    capability: str
    operation_id: str


@dataclass(frozen=True)
class RuntimeCompositionRequest:
    task_id: str
    data_classification: str
    agent: AgentReleaseSelection
    tool_requirements: tuple[ToolCapabilityRequirement, ...]
    model_route_ref: str
    model_route_digest: str
    policy_ref: str
    policy_digest: str
    execution_grant_ref: str
    execution_grant_digest: str
    input_registry_revision: str
    budget_units: int
    synthetic_only: bool = True


@dataclass(frozen=True)
class ComposedToolRelease:
    request_name: str
    tool_id: str
    version: str
    release_digest: str
    capability: str
    operation_id: str


@dataclass(frozen=True)
class RuntimeComposition:
    composition_id: str
    task_id: str
    agent_id: str
    agent_release_digest: str
    tool_releases: tuple[ComposedToolRelease, ...]
    model_route_ref: str
    model_route_digest: str
    policy_ref: str
    policy_digest: str
    execution_grant_ref: str
    execution_grant_digest: str
    input_registry_revision: str
    budget_units: int
    evidence_status: str = "synthetic"
    production_authorized: bool = False

