import unittest

from orbit_agent_control_plane.evaluator import CompanyEvaluator
from orbit_agent_control_plane.models import (
    AuditEvent,
    RouteDecision,
    TaskEnvelope,
    TaskResult,
)


class CompanyEvaluatorTest(unittest.TestCase):
    DATASET_AGENT_ID = "agt_orbit_research_dataset_scout_acquisition_syn"

    def setUp(self) -> None:
        self.evaluator = CompanyEvaluator()
        self.task = TaskEnvelope(
            task_id="task_d0_eval_001",
            capability="dataset_acquisition.request_create",
            data_classification="public",
            grant_id="grant_d0_eval_001",
            grant_active=True,
        )
        self.decision = RouteDecision(
            decision_id="route_decision_001",
            task_id=self.task.task_id,
            status="routed",
            target_id=self.DATASET_AGENT_ID,
            reason_codes=("deterministic_policy_match",),
        )
        self.audit = AuditEvent(
            event_id="audit_worker_001",
            task_id=self.task.task_id,
            event_type="synthetic_worker_completed",
            subject_ref=self.DATASET_AGENT_ID,
        )
        self.route_audit = AuditEvent(
            event_id=f"audit_{self.decision.decision_id}",
            task_id=self.task.task_id,
            event_type="route_decision_recorded",
            subject_ref="agt_company_task_router_syn",
        )
        self.result = TaskResult(
            result_id="result_d0_eval_001",
            task_id=self.task.task_id,
            target_id=self.DATASET_AGENT_ID,
            status="completed",
            output_ref="artifact://synthetic/task_d0_eval_001/result",
            audit_event_refs=(self.audit.event_id,),
            side_effects=(),
        )

    def evaluate(self, result: TaskResult, audits: tuple[AuditEvent, ...]):
        return self.evaluator.evaluate(
            task=self.task,
            route_decision=self.decision,
            result=result,
            audit_events=audits,
            subject_agent_id=self.DATASET_AGENT_ID,
        )

    def test_passes_complete_synthetic_result(self) -> None:
        report = self.evaluate(self.result, (self.route_audit, self.audit))

        self.assertEqual("pass", report.verdict)
        self.assertEqual(("fixed_suite_pass",), report.reason_codes)
        self.assertFalse(report.release_authorization)

    def test_rejects_self_evaluation(self) -> None:
        report = self.evaluator.evaluate(
            task=self.task,
            route_decision=self.decision,
            result=self.result,
            audit_events=(self.route_audit, self.audit),
            subject_agent_id=self.evaluator.agent_id,
        )

        self.assertEqual("fail", report.verdict)
        self.assertIn("self_evaluation_forbidden", report.reason_codes)

    def test_rejects_mismatched_result_and_side_effects(self) -> None:
        invalid = TaskResult(
            result_id="result_invalid",
            task_id="task_other",
            target_id="agent_system_other_syn",
            status="completed",
            output_ref=self.result.output_ref,
            audit_event_refs=self.result.audit_event_refs,
            side_effects=("network_write",),
        )

        report = self.evaluate(invalid, (self.route_audit, self.audit))

        self.assertEqual("fail", report.verdict)
        self.assertIn("result_task_mismatch", report.reason_codes)
        self.assertIn("result_target_mismatch", report.reason_codes)
        self.assertIn("external_side_effect_forbidden", report.reason_codes)

    def test_rejects_unresolved_audit_reference(self) -> None:
        report = self.evaluate(self.result, (self.route_audit,))

        self.assertEqual("fail", report.verdict)
        self.assertIn("audit_reference_unresolved", report.reason_codes)

    def test_rejects_audit_from_wrong_task_or_subject(self) -> None:
        invalid_audit = AuditEvent(
            event_id=self.audit.event_id,
            task_id="task_other",
            event_type=self.audit.event_type,
            subject_ref="worker_other_syn",
        )

        report = self.evaluate(self.result, (self.route_audit, invalid_audit))

        self.assertEqual("fail", report.verdict)
        self.assertIn("audit_task_mismatch", report.reason_codes)
        self.assertIn("audit_subject_mismatch", report.reason_codes)

    def test_rejects_missing_or_invalid_route_audit(self) -> None:
        missing = self.evaluate(self.result, (self.audit,))
        self.assertIn("route_audit_missing", missing.reason_codes)

        invalid = AuditEvent(
            event_id=self.route_audit.event_id,
            task_id=self.task.task_id,
            event_type="synthetic_worker_completed",
            subject_ref="worker_other_syn",
        )
        report = self.evaluate(self.result, (invalid, self.audit))
        self.assertIn("route_audit_type_mismatch", report.reason_codes)
        self.assertIn("route_audit_subject_mismatch", report.reason_codes)

    def test_rejects_ambiguous_worker_audit_reference(self) -> None:
        report = self.evaluate(
            self.result,
            (self.route_audit, self.audit, self.audit),
        )
        self.assertEqual("fail", report.verdict)
        self.assertIn("audit_reference_ambiguous", report.reason_codes)


if __name__ == "__main__":
    unittest.main()

