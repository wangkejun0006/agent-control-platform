"""Minimal Router -> synthetic Worker -> Evaluator orchestration."""

from __future__ import annotations

from dataclasses import dataclass

from .evaluator import CompanyEvaluator
from .models import (
    AuditEvent,
    ClosedLoopOutcome,
    RoutingTarget,
    TaskControlSnapshot,
    TaskEnvelope,
)
from .router import CompanyTaskRouter
from .worker import DeterministicSyntheticWorker


@dataclass(frozen=True)
class SyntheticClosedLoop:
    router: CompanyTaskRouter
    evaluator: CompanyEvaluator
    worker: DeterministicSyntheticWorker
    targets: tuple[RoutingTarget, ...]

    def run(
        self,
        task: TaskEnvelope,
        *,
        control_snapshot: TaskControlSnapshot | None = None,
        control_audit_events: tuple[AuditEvent, ...] = (),
    ) -> ClosedLoopOutcome:
        route_decision = self.router.route(
            task,
            self.targets,
            control_snapshot,
            control_audit_events,
        )
        route_audit = AuditEvent(
            event_id=f"audit_{route_decision.decision_id}",
            task_id=task.task_id,
            event_type="route_decision_recorded",
            subject_ref=self.router.agent_id,
        )
        if route_decision.status != "routed":
            return ClosedLoopOutcome(
                task=task,
                route_decision=route_decision,
                result=None,
                evaluation=None,
                audit_events=control_audit_events + (route_audit,),
                control_snapshot=control_snapshot,
            )

        result, worker_audit = self.worker.execute(task, route_decision)
        audits = control_audit_events + (route_audit, worker_audit)
        evaluation = self.evaluator.evaluate(
            task=task,
            route_decision=route_decision,
            result=result,
            audit_events=audits,
            subject_agent_id=self.worker.agent_id,
        )
        return ClosedLoopOutcome(
            task=task,
            route_decision=route_decision,
            result=result,
            evaluation=evaluation,
            audit_events=audits,
            control_snapshot=control_snapshot,
        )


def default_synthetic_loop() -> SyntheticClosedLoop:
    target = RoutingTarget(
        target_id="agent_system_company_d0_echo_syn",
        capabilities=frozenset({"company.synthetic.echo"}),
        allowed_data_classifications=frozenset({"synthetic", "public"}),
    )
    return SyntheticClosedLoop(
        router=CompanyTaskRouter(),
        evaluator=CompanyEvaluator(),
        worker=DeterministicSyntheticWorker(),
        targets=(target,),
    )

