from __future__ import annotations

import copy
import importlib
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

from orbit_agent_control_plane.control import TaskController
from orbit_agent_control_plane.disease_r1 import (
    DISEASE_AGENT_ID,
    DiseaseR1Error,
    evaluate_worker_response,
    grant_from_mapping,
    plan_disease_r1,
    validate_task_input,
)
from orbit_agent_control_plane.router import CompanyTaskRouter


ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_ROOT = ROOT.parent / "orbit-health-system" / "scientific-research-platform"
sys.path.insert(0, str(SCIENTIFIC_ROOT / "src"))

_ipc = importlib.import_module(
    "orbit_scientific_research_platform.disease_research.ipc"
)
_r1_worker = importlib.import_module(
    "orbit_scientific_research_platform.disease_research.r1_worker"
)


TASK_INPUT = (
    SCIENTIFIC_ROOT
    / "contracts"
    / "disease-research"
    / "fixtures"
    / "synthetic"
    / "fictional-stationery.task-input.synthetic.json"
)
RELEASE_DIGEST = (
    "sha256:629d8d9b6997baf694b5856a526721ccd69bf71348c481c5c4dc6d909f62a0cb"
)
RUNTIME_DIGEST = "sha256:" + ("b" * 64)


class DiseaseR1Test(unittest.TestCase):
    def grant_mapping(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "version": "orbit.synthetic-disease-r1-execution-grant/1",
            "grant_id": "grant_orbit_disease_stationery_r1_retry4_syn",
            "task_id": "tsk_orbit_disease_stationery_r1_retry4_syn",
            "agent_id": DISEASE_AGENT_ID,
            "agent_release_digest": RELEASE_DIGEST,
            "package": {
                "package_id": "drpkg-smb-01-fictional-stationery",
                "version": "0.1.0",
                "digest": "sha256:b7a5ba899283e57a7d4b9d0ad47725d7d0310537f69814bafdaab8c96dc5e5f1",
                "artifact_ref": "urn:orbit:artifact:disease-research/packages/drpkg-smb-01-fictional-stationery/0.1.0",
            },
            "runtime_source_digest": RUNTIME_DIGEST,
            "policy_ref": "pol_orbit_disease_stationery_r1_syn",
            "policy_digest": "sha256:" + ("c" * 64),
            "allowed_operations": ["disease_research_task.execute_synthetic"],
            "budget_units": 10,
            "issued_at": "2026-08-26T00:00:00Z",
            "expires_at": "2026-08-26T00:10:00Z",
            "revoked": False,
            "model_allowed": False,
            "network_allowed": False,
            "host_filesystem_allowed": False,
            "nas_allowed": False,
            "real_registry_allowed": False,
            "agent_to_agent_allowed": False,
            "publish_allowed": False,
            "evidence_status": "synthetic",
            "synthetic_only": True,
        }
        value.update(overrides)
        return value

    def plan(self, **grant_overrides: object):
        return plan_disease_r1(
            grant_from_mapping(self.grant_mapping(**grant_overrides)),
            checked_at="2026-08-26T00:05:00Z",
            lifecycle_status="active",
            lifecycle_release_digest=RELEASE_DIGEST,
        )

    def task_input(self, plan):
        value = json.loads(TASK_INPUT.read_text(encoding="utf-8"))
        value["parent_task_ref"] = f"company-task://synthetic/{plan.task.task_id}"
        value["agent_binding_ref"] = (
            "agent-binding://synthetic/"
            "bind_orbit_disease_research_task_d0_syn/0.1.0/sha256/"
            "a9edd1b1648650631cfeade592430e494e624a220b22fc528748adcb3cdd1334"
        )
        value["execution_grant_ref"] = plan.grant.grant_id
        value["route_decision_ref"] = plan.route.decision_id
        return value

    def response(self, plan, task_input):
        event = _ipc.build_task_event(
            task_input,
            event_id="drevent_orbit_disease_r1_syn",
            company_task_id=plan.task.task_id,
            invocation_id="inv_orbit_disease_r1_syn",
            runtime_adapter_ref={
                "id": "runtime_adapter_orbit_disease_r1_syn",
                "version": "0.1.0",
                "digest": plan.grant.runtime_source_digest,
            },
        )
        request = _ipc.build_ipc_request(event, request_id=plan.request_id)
        return _r1_worker._process(
            json.dumps(request, separators=(",", ":")).encode("utf-8"),
            enforce_process_boundary=False,
        )

    def assert_reason(self, reason: str, callback) -> None:
        with self.assertRaises(DiseaseR1Error) as raised:
            callback()
        self.assertEqual(reason, raised.exception.reason_code)

    def test_complete_path_is_deterministic_and_double_evaluated(self) -> None:
        plan = self.plan()
        retry = self.plan()
        self.assertEqual(plan, retry)
        self.assertEqual((), plan.composition.tool_releases)
        self.assertEqual("model_route_none_disease_r1_syn", plan.composition.model_route_ref)
        self.assertFalse(plan.composition.production_authorized)
        task_input = self.task_input(plan)
        validate_task_input(task_input, plan)
        outcome = evaluate_worker_response(plan, self.response(plan, task_input))
        self.assertEqual("pass", outcome.domain_evaluation.verdict)
        self.assertFalse(outcome.domain_evaluation.release_authorization)
        self.assertEqual("pass", outcome.company_outcome.evaluation.verdict)
        self.assertFalse(outcome.company_outcome.evaluation.release_authorization)

    def test_running_cancellation_blocks_route_before_worker_execution(self) -> None:
        plan = self.plan()
        controller = TaskController()
        transition = controller.apply(
            controller.initial(plan.task),
            "cancel",
            actor_id="human_operator_orbit_disease_r1_syn",
        )
        route = CompanyTaskRouter().route(
            plan.task,
            (),
            transition.after,
            (transition.audit_event,),
        )
        self.assertEqual("blocked", route.status)
        self.assertIn("task_cancelled", route.reason_codes)

    def test_expired_revoked_and_release_or_package_drift_fail(self) -> None:
        self.assert_reason("grant_revoked", lambda: self.plan(revoked=True))
        expired = grant_from_mapping(
            self.grant_mapping(
                issued_at="2026-08-26T00:00:00Z",
                expires_at="2026-08-26T00:01:00Z",
            )
        )
        self.assert_reason(
            "grant_expired",
            lambda: plan_disease_r1(
                expired,
                checked_at="2026-08-26T00:05:00Z",
                lifecycle_status="active",
                lifecycle_release_digest=RELEASE_DIGEST,
            ),
        )
        self.assert_reason(
            "agent_release_drift",
            lambda: plan_disease_r1(
                grant_from_mapping(self.grant_mapping()),
                checked_at="2026-08-26T00:05:00Z",
                lifecycle_status="active",
                lifecycle_release_digest="sha256:" + ("d" * 64),
            ),
        )
        changed_package = copy.deepcopy(self.grant_mapping()["package"])
        changed_package["digest"] = "sha256:" + ("e" * 64)
        self.assert_reason(
            "grant_scope_invalid",
            lambda: grant_from_mapping(self.grant_mapping(package=changed_package)),
        )

    def test_path_storage_secret_and_extra_permission_injection_fail(self) -> None:
        plan = self.plan()
        base = self.task_input(plan)
        cases = (
            ("debug_ref", "/Users/example/forbidden", "task_input_fields_invalid"),
            ("opaque_storage_ref", "opaque://forbidden", "task_input_fields_invalid"),
            ("secret_ref", "secret-forbidden", "task_input_fields_invalid"),
        )
        for key, value, reason in cases:
            with self.subTest(key=key):
                injected = copy.deepcopy(base)
                injected[key] = value
                self.assert_reason(reason, lambda injected=injected: validate_task_input(injected, plan))
        widened = copy.deepcopy(base)
        widened["authority_boundary"]["may_write_storage"] = True
        self.assert_reason(
            "task_input_scope_invalid", lambda: validate_task_input(widened, plan)
        )
        network_grant = self.grant_mapping(network_allowed=True)
        self.assert_reason(
            "grant_scope_invalid", lambda: grant_from_mapping(network_grant)
        )

    def test_worker_package_or_release_digest_drift_fails(self) -> None:
        plan = self.plan()
        task_input = self.task_input(plan)
        response = self.response(plan, task_input)
        response["result_package"]["package"]["digest"] = "f" * 64
        self.assert_reason(
            "worker_response_scope_invalid",
            lambda: evaluate_worker_response(plan, response),
        )
        drifted = replace(plan.grant, runtime_source_digest="sha256:" + ("d" * 64))
        self.assertNotEqual(plan.grant.runtime_source_digest, drifted.runtime_source_digest)


if __name__ == "__main__":
    unittest.main()

