import unittest

from orbit_agent_control_plane.control import TaskController
from orbit_agent_control_plane.models import RoutingTarget, TaskEnvelope
from orbit_agent_control_plane.router import CompanyTaskRouter


class CompanyTaskRouterTest(unittest.TestCase):
    DATASET_AGENT_ID = "agt_orbit_research_dataset_scout_acquisition_syn"

    def setUp(self) -> None:
        self.router = CompanyTaskRouter()
        self.target = RoutingTarget(
            target_id=self.DATASET_AGENT_ID,
            capabilities=frozenset({"dataset_acquisition.request_create"}),
            allowed_data_classifications=frozenset({"public"}),
            active=True,
        )

    @staticmethod
    def task(**overrides: object) -> TaskEnvelope:
        values: dict[str, object] = {
            "task_id": "task_d0_router_001",
            "capability": "dataset_acquisition.request_create",
            "data_classification": "public",
            "grant_id": "grant_d0_router_001",
            "grant_active": True,
            "requested_target_id": None,
        }
        values.update(overrides)
        return TaskEnvelope(**values)

    def test_routes_exactly_one_eligible_target(self) -> None:
        decision = self.router.route(self.task(), (self.target,))

        self.assertEqual("routed", decision.status)
        self.assertEqual(self.target.target_id, decision.target_id)
        self.assertEqual(("deterministic_policy_match",), decision.reason_codes)

    def test_rejects_inactive_or_expired_grant(self) -> None:
        decision = self.router.route(
            self.task(grant_active=False), (self.target,)
        )

        self.assertEqual("blocked", decision.status)
        self.assertEqual(("grant_inactive_or_expired",), decision.reason_codes)

    def test_rejects_unknown_requested_target(self) -> None:
        decision = self.router.route(
            self.task(requested_target_id="agt_orbit_missing_syn"),
            (self.target,),
        )

        self.assertEqual("blocked", decision.status)
        self.assertEqual(("requested_target_unknown",), decision.reason_codes)

    def test_rejects_unsupported_capability(self) -> None:
        decision = self.router.route(
            self.task(capability="unsupported_capability"), (self.target,)
        )

        self.assertEqual("blocked", decision.status)
        self.assertEqual(("routing_target_not_found",), decision.reason_codes)

    def test_rejects_ambiguous_targets(self) -> None:
        second_target = RoutingTarget(
            target_id="agt_orbit_research_dataset_scout_second_syn",
            capabilities=self.target.capabilities,
            allowed_data_classifications=self.target.allowed_data_classifications,
            active=True,
        )
        decision = self.router.route(self.task(), (self.target, second_target))

        self.assertEqual("blocked", decision.status)
        self.assertEqual(("routing_target_ambiguous",), decision.reason_codes)

    def test_fails_closed_for_non_d0_classification(self) -> None:
        decision = self.router.route(
            self.task(data_classification="medical_private"), (self.target,)
        )

        self.assertEqual("blocked", decision.status)
        self.assertEqual(
            ("data_classification_not_allowed",), decision.reason_codes
        )

    def test_control_snapshot_blocks_paused_task(self) -> None:
        task = self.task()
        controller = TaskController()
        paused = controller.apply(
            controller.initial(task),
            "pause",
            actor_id="human_operator_test_syn",
        )

        decision = self.router.route(
            task,
            (self.target,),
            paused.after,
            (paused.audit_event,),
        )

        self.assertEqual("blocked", decision.status)
        self.assertEqual(("task_paused",), decision.reason_codes)

    def test_mismatched_control_snapshot_fails_closed(self) -> None:
        task = self.task()
        other_task = self.task(
            task_id="task_other",
            grant_id="grant_other",
        )
        snapshot = TaskController().initial(other_task)

        decision = self.router.route(task, (self.target,), snapshot)

        self.assertEqual("blocked", decision.status)
        self.assertEqual(
            ("control_task_mismatch", "control_grant_mismatch"),
            decision.reason_codes,
        )

    def test_missing_control_audit_fails_closed(self) -> None:
        task = self.task()
        controller = TaskController()
        paused = controller.apply(
            controller.initial(task),
            "pause",
            actor_id="human_operator_test_syn",
        )

        decision = self.router.route(task, (self.target,), paused.after)

        self.assertEqual("blocked", decision.status)
        self.assertEqual(
            ("control_audit_reference_unresolved", "task_paused"),
            decision.reason_codes,
        )


if __name__ == "__main__":
    unittest.main()

