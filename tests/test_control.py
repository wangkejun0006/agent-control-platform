import unittest

from orbit_agent_control_plane.control import TaskController, execution_block_reasons
from orbit_agent_control_plane.models import TaskEnvelope


class TaskControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = TaskController()
        self.task = TaskEnvelope(
            task_id="task_d0_control_001",
            capability="company.synthetic.echo",
            data_classification="synthetic",
            grant_id="grant_d0_control_001",
            grant_active=True,
        )

    def apply(self, action: str):
        return self.controller.apply(
            self.controller.initial(self.task),
            action,
            actor_id="human_operator_test_syn",
        )

    def test_pause_blocks_execution_without_revoking_grant(self) -> None:
        transition = self.apply("pause")

        self.assertTrue(transition.applied)
        self.assertEqual("task_paused", transition.reason_code)
        self.assertEqual("paused", transition.after.task_status)
        self.assertEqual("active", transition.after.grant_status)
        self.assertEqual(("task_paused",), execution_block_reasons(transition.after))

    def test_revoke_blocks_execution_without_ending_task(self) -> None:
        transition = self.apply("revoke")

        self.assertTrue(transition.applied)
        self.assertEqual("active", transition.after.task_status)
        self.assertEqual("revoked", transition.after.grant_status)
        self.assertEqual(("grant_revoked",), execution_block_reasons(transition.after))

    def test_cancel_is_terminal_and_revokes_task_grant(self) -> None:
        transition = self.apply("cancel")

        self.assertEqual("cancelled", transition.after.task_status)
        self.assertEqual("revoked", transition.after.grant_status)
        self.assertEqual(
            ("task_cancelled", "grant_revoked"),
            execution_block_reasons(transition.after),
        )

    def test_takeover_transfers_owner_and_revokes_agent_execution(self) -> None:
        transition = self.apply("takeover")

        self.assertEqual("human_taken_over", transition.after.task_status)
        self.assertEqual("human_operator", transition.after.owner_kind)
        self.assertEqual("revoked", transition.after.grant_status)
        self.assertEqual(
            ("human_takeover_active", "grant_revoked"),
            execution_block_reasons(transition.after),
        )

    def test_repeated_control_is_rejected_without_revision_change(self) -> None:
        first = self.apply("pause")
        second = self.controller.apply(
            first.after,
            "pause",
            actor_id="human_operator_test_syn",
        )

        self.assertFalse(second.applied)
        self.assertEqual("already_paused", second.reason_code)
        self.assertEqual(first.after, second.after)
        self.assertEqual("task_control_pause_rejected", second.audit_event.event_type)

    def test_terminal_task_rejects_later_control(self) -> None:
        cancelled = self.apply("cancel")
        later = self.controller.apply(
            cancelled.after,
            "takeover",
            actor_id="human_operator_test_syn",
        )

        self.assertFalse(later.applied)
        self.assertEqual("terminal_task_state", later.reason_code)

    def test_unknown_action_and_missing_actor_fail_closed(self) -> None:
        snapshot = self.controller.initial(self.task)
        with self.assertRaisesRegex(ValueError, "unsupported_control_action"):
            self.controller.apply(snapshot, "resume", actor_id="operator")
        with self.assertRaisesRegex(ValueError, "control_actor_required"):
            self.controller.apply(snapshot, "pause", actor_id="")


if __name__ == "__main__":
    unittest.main()

