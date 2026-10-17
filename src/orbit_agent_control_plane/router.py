"""Deterministic Company Task Router with fail-closed decisions."""

from __future__ import annotations

from collections.abc import Iterable
import re

from .control import execution_block_reasons
from .ids import COMPANY_TASK_ROUTER_AGENT_ID, deterministic_id
from .models import (
    AuditEvent,
    ComposedToolRelease,
    RuntimeComposition,
    RuntimeCompositionRequest,
    RouteDecision,
    RoutingTarget,
    TaskControlSnapshot,
    TaskEnvelope,
)
from .tool_lifecycle import ReplayedToolLifecycle


_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_LOGICAL_REF_PATTERN = re.compile(r"^[a-z][A-Za-z0-9._:/-]{2,239}$")
_LEAK_PATTERN = re.compile(
    r"/Users/|/Volumes/|(?:file|smb)://|secretref_|\bsk-[A-Za-z0-9_-]+",
    re.IGNORECASE,
)


class RuntimeCompositionError(ValueError):
    """Fail-closed immutable runtime composition error."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


class RuntimeComposer:
    """Select one active immutable Tool release per Agent-requested capability."""

    allowed_data_classifications = frozenset({"synthetic", "public"})

    def compose(
        self,
        request: RuntimeCompositionRequest,
        tool_releases: Iterable[ReplayedToolLifecycle],
    ) -> RuntimeComposition:
        self._validate_request(request)
        available = tuple(tool_releases)
        selections: list[ComposedToolRelease] = []
        seen_names: set[str] = set()
        seen_capabilities: set[str] = set()
        for requirement in request.tool_requirements:
            if requirement.request_name in seen_names:
                raise RuntimeCompositionError(
                    "tool_request_name_duplicated",
                    "Tool request names must be unique",
                )
            if requirement.capability in seen_capabilities:
                raise RuntimeCompositionError(
                    "tool_capability_duplicated",
                    "Each Tool capability must be composed once",
                )
            seen_names.add(requirement.request_name)
            seen_capabilities.add(requirement.capability)
            if requirement.capability not in request.agent.requested_tool_capabilities:
                raise RuntimeCompositionError(
                    "tool_capability_not_requested_by_agent",
                    "Runtime composition exceeds the Agent Release permission request",
                )
            matches = tuple(
                state
                for state in available
                if state.status == "active"
                and requirement.capability in state.candidate.capabilities
                and requirement.operation_id
                in state.candidate.d0_allowed_operation_ids
                and state.evaluation is not None
                and requirement.operation_id
                in state.evaluation.allowed_operation_ids
                and request.data_classification
                in state.candidate.allowed_data_classifications
            )
            if not matches:
                raise RuntimeCompositionError(
                    "active_tool_release_not_found",
                    "No active Tool release satisfies the capability and operation",
                )
            if len(matches) > 1:
                raise RuntimeCompositionError(
                    "active_tool_release_ambiguous",
                    "Multiple active Tool releases satisfy one capability",
                )
            selected = matches[0].candidate
            selections.append(
                ComposedToolRelease(
                    request_name=requirement.request_name,
                    tool_id=selected.tool_id,
                    version=selected.version,
                    release_digest=selected.release_digest,
                    capability=requirement.capability,
                    operation_id=requirement.operation_id,
                )
            )
        if not selections and request.agent.requested_tool_capabilities:
            raise RuntimeCompositionError(
                "tool_composition_incomplete",
                "Agent-requested Tool capabilities were not composed",
            )
        composition_id = deterministic_id(
            "composition",
            request.task_id,
            request.agent.agent_id,
            request.agent.release_digest,
            *(item.release_digest for item in selections),
            request.model_route_digest,
            request.policy_digest,
            request.execution_grant_digest,
            request.input_registry_revision,
            str(request.budget_units),
        )
        return RuntimeComposition(
            composition_id=composition_id,
            task_id=request.task_id,
            agent_id=request.agent.agent_id,
            agent_release_digest=request.agent.release_digest,
            tool_releases=tuple(selections),
            model_route_ref=request.model_route_ref,
            model_route_digest=request.model_route_digest,
            policy_ref=request.policy_ref,
            policy_digest=request.policy_digest,
            execution_grant_ref=request.execution_grant_ref,
            execution_grant_digest=request.execution_grant_digest,
            input_registry_revision=request.input_registry_revision,
            budget_units=request.budget_units,
        )

    def _validate_request(self, request: RuntimeCompositionRequest) -> None:
        if not request.synthetic_only:
            raise RuntimeCompositionError(
                "composition_not_synthetic", "Only synthetic D0 composition is allowed"
            )
        if request.data_classification not in self.allowed_data_classifications:
            raise RuntimeCompositionError(
                "composition_classification_not_allowed",
                "Runtime composition classification is outside D0",
            )
        if not request.agent.active:
            raise RuntimeCompositionError(
                "agent_release_inactive", "Agent Release must be active for composition"
            )
        if request.data_classification not in request.agent.allowed_data_classifications:
            raise RuntimeCompositionError(
                "agent_classification_not_allowed",
                "Agent Release does not allow the Task classification",
            )
        if request.budget_units <= 0 or isinstance(request.budget_units, bool):
            raise RuntimeCompositionError(
                "composition_budget_invalid", "Composition budget must be positive"
            )
        if not request.tool_requirements and request.agent.requested_tool_capabilities:
            raise RuntimeCompositionError(
                "tool_composition_incomplete",
                "Agent-requested Tool capabilities require explicit composition",
            )
        for digest in (
            request.agent.release_digest,
            request.model_route_digest,
            request.policy_digest,
            request.execution_grant_digest,
        ):
            if not _DIGEST_PATTERN.fullmatch(digest):
                raise RuntimeCompositionError(
                    "composition_digest_invalid",
                    "Runtime composition contains an invalid immutable digest",
                )
        logical_refs = (
            request.task_id,
            request.agent.agent_id,
            request.model_route_ref,
            request.policy_ref,
            request.execution_grant_ref,
            request.input_registry_revision,
        )
        if any(
            not _LOGICAL_REF_PATTERN.fullmatch(value) or _LEAK_PATTERN.search(value)
            for value in logical_refs
        ):
            raise RuntimeCompositionError(
                "composition_logical_ref_invalid",
                "Runtime composition must contain logical, path-free references",
            )


class CompanyTaskRouter:
    agent_id = COMPANY_TASK_ROUTER_AGENT_ID
    allowed_data_classifications = frozenset({"synthetic", "public"})

    def route(
        self,
        task: TaskEnvelope,
        targets: Iterable[RoutingTarget],
        control_snapshot: TaskControlSnapshot | None = None,
        control_audit_events: Iterable[AuditEvent] = (),
    ) -> RouteDecision:
        target_list = tuple(targets)
        control_audits = tuple(control_audit_events)
        reason_codes: list[str] = []

        if task.data_classification not in self.allowed_data_classifications:
            reason_codes.append("data_classification_not_allowed")
        if not task.grant_active:
            reason_codes.append("grant_inactive_or_expired")
        if control_snapshot is not None:
            if control_snapshot.task_id != task.task_id:
                reason_codes.append("control_task_mismatch")
            if control_snapshot.grant_id != task.grant_id:
                reason_codes.append("control_grant_mismatch")
            if control_snapshot.revision > 0:
                control_ref = control_snapshot.last_control_event_ref
                if control_ref is None:
                    reason_codes.append("control_audit_reference_missing")
                else:
                    matches = tuple(
                        event for event in control_audits if event.event_id == control_ref
                    )
                    if not matches:
                        reason_codes.append("control_audit_reference_unresolved")
                    elif len(matches) > 1:
                        reason_codes.append("control_audit_reference_ambiguous")
                    else:
                        control_event = matches[0]
                        if control_event.task_id != task.task_id:
                            reason_codes.append("control_audit_task_mismatch")
                        if not control_event.event_type.startswith("task_control_") or not (
                            control_event.event_type.endswith("_applied")
                        ):
                            reason_codes.append("control_audit_event_invalid")
            for reason in execution_block_reasons(control_snapshot):
                if reason not in reason_codes:
                    reason_codes.append(reason)

        selected: RoutingTarget | None = None
        if not reason_codes and task.requested_target_id is not None:
            matches = tuple(
                target for target in target_list if target.target_id == task.requested_target_id
            )
            if not matches:
                reason_codes.append("requested_target_unknown")
            elif len(matches) > 1:
                reason_codes.append("requested_target_ambiguous")
            else:
                selected = matches[0]
                if not selected.active:
                    reason_codes.append("requested_target_inactive")
                if task.capability not in selected.capabilities:
                    reason_codes.append("capability_not_supported")
                if task.data_classification not in selected.allowed_data_classifications:
                    reason_codes.append("target_data_classification_not_allowed")
        elif not reason_codes:
            eligible = tuple(
                target
                for target in target_list
                if target.active
                and task.capability in target.capabilities
                and task.data_classification in target.allowed_data_classifications
            )
            if not eligible:
                reason_codes.append("routing_target_not_found")
            elif len(eligible) > 1:
                reason_codes.append("routing_target_ambiguous")
            else:
                selected = eligible[0]

        if reason_codes:
            selected = None
            status = "blocked"
        else:
            status = "routed"
            reason_codes.append("deterministic_policy_match")

        target_id = selected.target_id if selected is not None else None
        return RouteDecision(
            decision_id=deterministic_id(
                "route",
                task.task_id,
                status,
                target_id or "none",
                *reason_codes,
            ),
            task_id=task.task_id,
            status=status,
            target_id=target_id,
            reason_codes=tuple(reason_codes),
        )

