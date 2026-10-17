"""No-network synthetic worker used only to close the initial D0 loop."""

from __future__ import annotations

from .ids import SYNTHETIC_WORKER_ID, deterministic_id
from .models import AuditEvent, RouteDecision, TaskEnvelope, TaskResult


class DeterministicSyntheticWorker:
    agent_id = SYNTHETIC_WORKER_ID

    def execute(
        self,
        task: TaskEnvelope,
        route_decision: RouteDecision,
    ) -> tuple[TaskResult, AuditEvent]:
        if route_decision.status != "routed" or route_decision.target_id is None:
            raise ValueError("worker_requires_routed_decision")
        if route_decision.task_id != task.task_id:
            raise ValueError("worker_route_task_mismatch")

        audit_event = AuditEvent(
            event_id=deterministic_id(
                "audit",
                task.task_id,
                route_decision.decision_id,
                "synthetic_worker_completed",
            ),
            task_id=task.task_id,
            event_type="synthetic_worker_completed",
            subject_ref=self.agent_id,
        )
        result = TaskResult(
            result_id=deterministic_id(
                "result",
                task.task_id,
                route_decision.target_id,
                audit_event.event_id,
            ),
            task_id=task.task_id,
            target_id=route_decision.target_id,
            status="completed",
            output_ref=f"artifact://synthetic/{task.task_id}/result",
            audit_event_refs=(audit_event.event_id,),
            side_effects=(),
        )
        return result, audit_event

