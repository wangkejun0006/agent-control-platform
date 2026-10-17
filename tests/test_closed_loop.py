import unittest

from orbit_agent_control_plane.control import TaskController
from orbit_agent_control_plane.loop import default_synthetic_loop
from orbit_agent_control_plane.models import TaskEnvelope


class SyntheticClosedLoopTest(unittest.TestCase):
    def setUp(self) -> None:
        self.loop = default_synthetic_loop()
        self.task = TaskEnvelope(
            task_id="task_d0_loop_001",
            capability="company.synthetic.echo",
            data_classification="synthetic",
            grant_id="grant_d0_loop_001",
            grant_active=True,
        )

    def test_completes_d0_loop_without_release_authority(self) -> None:
        outcome = self.loop.run(self.task)

        self.assertEqual("routed", outcome.route_decision.status)
        self.assertIsNotNone(outcome.result)
        self.assertIsNotNone(outcome.evaluation)
        assert outcome.result is not None
        assert outcome.evaluation is not None
        self.assertEqual((), outcome.result.side_effects)
        self.assertEqual("pass", outcome.evaluation.verdict)
        self.assertFalse(outcome.evaluation.release_authorization)

    def test_same_input_produces_identical_outcome(self) -> None:
        first = self.loop.run(self.task)
        second = self.loop.run(self.task)

        self.assertEqual(first, second)

    def test_blocked_route_stops_before_worker_and_evaluator(self) -> None:
        blocked_task = TaskEnvelope(
            task_id=self.task.task_id,
            capability=self.task.capability,
            data_classification=self.task.data_classification,
            grant_id=self.task.grant_id,
            grant_active=False,
        )
        outcome = self.loop.run(blocked_task)

        self.assertEqual("blocked", outcome.route_decision.status)
        self.assertEqual(
            ("grant_inactive_or_expired",), outcome.route_decision.reason_codes
        )
        self.assertIsNone(outcome.result)
        self.assertIsNone(outcome.evaluation)

    def test_control_event_is_reconciled_before_blocked_route_audit(self) -> None:
        controller = TaskController()
        transition = controller.apply(
            controller.initial(self.task),
            "takeover",
            actor_id="human_operator_test_syn",
        )

        outcome = self.loop.run(
            self.task,
            control_snapshot=transition.after,
            control_audit_events=(transition.audit_event,),
        )

        self.assertEqual("blocked", outcome.route_decision.status)
        self.assertEqual(transition.after, outcome.control_snapshot)
        self.assertEqual(transition.audit_event, outcome.audit_events[0])
        self.assertEqual("route_decision_recorded", outcome.audit_events[1].event_type)
        self.assertIsNone(outcome.result)
        self.assertIsNone(outcome.evaluation)


if __name__ == "__main__":
    unittest.main()

