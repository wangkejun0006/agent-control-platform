"""Independent fixed-suite evaluator; no model controls PASS/FAIL."""

from __future__ import annotations

from collections.abc import Iterable

from .ids import (
    COMPANY_EVALUATOR_AGENT_ID,
    COMPANY_TASK_ROUTER_AGENT_ID,
    deterministic_id,
)
from .models import AuditEvent, EvaluationReport, RouteDecision, TaskEnvelope, TaskResult


COMPLETION_EVENT_TYPES = frozenset(
    {
        "synthetic_worker_completed",
        "dataset_agent_process_completed",
        "watchlist_task_completed",
    }
)


class CompanyEvaluator:
    agent_id = COMPANY_EVALUATOR_AGENT_ID

    def evaluate(
        self,
        *,
        task: TaskEnvelope,
        route_decision: RouteDecision,
        result: TaskResult,
        audit_events: Iterable[AuditEvent],
        subject_agent_id: str,
    ) -> EvaluationReport:
        reason_codes: list[str] = []
        audit_list = tuple(audit_events)

        if subject_agent_id == self.agent_id:
            reason_codes.append("self_evaluation_forbidden")
        if route_decision.status != "routed" or route_decision.target_id is None:
            reason_codes.append("route_not_routed")
        if route_decision.task_id != task.task_id:
            reason_codes.append("route_task_mismatch")
        if result.task_id != task.task_id:
            reason_codes.append("result_task_mismatch")
        if result.target_id != route_decision.target_id:
            reason_codes.append("result_target_mismatch")
        if result.status != "completed":
            reason_codes.append("result_not_completed")
        if not result.output_ref.startswith("artifact://synthetic/"):
            reason_codes.append("output_not_synthetic_artifact")
        elif not result.output_ref.startswith(
            f"artifact://synthetic/{task.task_id}/"
        ):
            reason_codes.append("output_task_mismatch")
        if result.side_effects:
            reason_codes.append("external_side_effect_forbidden")

        expected_route_audit_id = f"audit_{route_decision.decision_id}"
        route_events = tuple(
            event for event in audit_list if event.event_id == expected_route_audit_id
        )
        if not route_events:
            reason_codes.append("route_audit_missing")
        elif len(route_events) > 1:
            reason_codes.append("route_audit_ambiguous")
        else:
            route_event = route_events[0]
            if route_event.event_type != "route_decision_recorded":
                reason_codes.append("route_audit_type_mismatch")
            if route_event.task_id != task.task_id:
                reason_codes.append("route_audit_task_mismatch")
            if route_event.subject_ref != COMPANY_TASK_ROUTER_AGENT_ID:
                reason_codes.append("route_audit_subject_mismatch")

        if not result.audit_event_refs:
            reason_codes.append("audit_reference_missing")
        else:
            if len(set(result.audit_event_refs)) != len(result.audit_event_refs):
                reason_codes.append("audit_reference_duplicated")
            for audit_ref in dict.fromkeys(result.audit_event_refs):
                referenced_events = tuple(
                    event for event in audit_list if event.event_id == audit_ref
                )
                if not referenced_events:
                    reason_codes.append("audit_reference_unresolved")
                    continue
                if len(referenced_events) > 1:
                    reason_codes.append("audit_reference_ambiguous")
                    continue
                event = referenced_events[0]
                if event.event_type not in COMPLETION_EVENT_TYPES:
                    reason_codes.append("audit_event_type_mismatch")
                if event.task_id != task.task_id:
                    reason_codes.append("audit_task_mismatch")
                if event.subject_ref != subject_agent_id:
                    reason_codes.append("audit_subject_mismatch")

        verdict = "pass" if not reason_codes else "fail"
        if not reason_codes:
            reason_codes.append("fixed_suite_pass")
        return EvaluationReport(
            report_id=deterministic_id(
                "evaluation",
                self.agent_id,
                result.result_id,
                verdict,
                *reason_codes,
            ),
            evaluator_agent_id=self.agent_id,
            subject_result_id=result.result_id,
            verdict=verdict,
            reason_codes=tuple(reason_codes),
            release_authorization=False,
        )

