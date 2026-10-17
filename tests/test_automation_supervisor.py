from __future__ import annotations

import unittest

from orbit_agent_control_plane.service_runtime.automation_supervisor import (
    AutomationSupervisor,
    AutomationSupervisorStore,
    FailureContext,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.models import Base
from orbit_agent_control_plane.service_runtime.repositories import (
    ServiceRepositoryError,
)


class AutomationSupervisorTests(unittest.TestCase):
    def classify(self, reason_code: str, **changes):
        values = {
            "reason_code": reason_code,
            "failure_class": "deterministic_test_failure",
            "identical_failures": 1,
            "verified_remediation_cycles": 0,
            "total_attempts": 1,
            "max_total_attempts": 5,
            "budget_remaining": True,
        }
        values.update(changes)
        return AutomationSupervisor.classify(FailureContext(**values))

    def test_disease_query_failure_is_machine_remediation_not_human_checkpoint(
        self,
    ) -> None:
        decision = self.classify("r2_literature_query_invalid")
        self.assertEqual("auto_remediate", decision.action)
        self.assertFalse(decision.human_checkpoint_required)
        self.assertTrue(decision.stop_current_attempt)

    def test_dataset_grant_gap_is_fail_closed_authority_strengthening(self) -> None:
        decision = self.classify("dataset_signed_execution_grant_missing")
        self.assertEqual("auto_remediate_authority_strengthening", decision.action)
        self.assertFalse(decision.human_checkpoint_required)
        self.assertIn(
            "signed_grant_persisted_before_network",
            decision.required_evidence,
        )

    def test_identical_failures_pause_for_verified_machine_repair(self) -> None:
        decision = self.classify(
            "r2_literature_query_invalid",
            identical_failures=2,
        )
        self.assertEqual("automation_pause_for_verified_remediation", decision.action)
        self.assertFalse(decision.human_checkpoint_required)

    def test_two_verified_repairs_or_scope_drift_require_human_decision(self) -> None:
        repeated = self.classify(
            "r2_literature_query_invalid",
            identical_failures=2,
            verified_remediation_cycles=2,
        )
        drift = self.classify(
            "r2_literature_query_invalid",
            boundary_drift=True,
        )
        self.assertTrue(repeated.human_checkpoint_required)
        self.assertEqual("risk_waiver", repeated.human_checkpoint_scope)
        self.assertTrue(drift.human_checkpoint_required)
        self.assertEqual("execution_approval", drift.human_checkpoint_scope)

    def test_transient_failure_retries_while_budget_remains(self) -> None:
        decision = self.classify(
            "provider_http_503",
            failure_class="transient_runtime",
        )
        self.assertEqual("auto_retry", decision.action)
        self.assertFalse(decision.human_checkpoint_required)

    def test_total_budget_ceiling_is_a_human_scope_change(self) -> None:
        decision = self.classify(
            "r2_literature_query_invalid",
            total_attempts=5,
            budget_remaining=False,
        )
        self.assertTrue(decision.human_checkpoint_required)
        self.assertEqual("risk_waiver", decision.human_checkpoint_scope)

    def test_cross_run_history_stops_after_two_verified_repairs(self) -> None:
        database = Database("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(database.engine)
        supervisor = AutomationSupervisor(AutomationSupervisorStore(database))
        scope_ref = "pilot://full-chain/execution-intent-test"
        fingerprint = "sha256:" + ("a" * 64)
        for cycle in (1, 2):
            supervisor.record_verified_remediation(
                scope_ref=scope_ref,
                remediation_digest="sha256:" + (str(cycle) * 64),
                runtime_source_digest="sha256:" + (str(cycle + 2) * 64),
                regression_evidence_digest="sha256:" + (str(cycle + 4) * 64),
                idempotency_key=f"supervisor:repair:{cycle}",
            )
            status = supervisor.observe_failure(
                scope_ref=scope_ref,
                attempt_ref=f"attempt://disease/{cycle}",
                failure_fingerprint=fingerprint,
                reason_code="r2_literature_query_invalid",
                failure_class="deterministic_test_failure",
                failure_evidence_digest="sha256:" + (str(cycle + 6) * 64),
                total_attempts=cycle,
                max_total_attempts=5,
                budget_remaining=True,
                idempotency_key=f"supervisor:failure:{cycle}",
            )
        self.assertEqual("human_checkpoint", status["status"])
        self.assertEqual(2, status["verified_remediation_cycles"])
        self.assertEqual(2, status["last_failure"]["identical_failures"])
        self.assertEqual("risk_waiver", status["next_human_checkpoint"])
        with self.assertRaisesRegex(
            ServiceRepositoryError,
            "automation_supervisor_scope_terminal",
        ):
            supervisor.record_verified_remediation(
                scope_ref=scope_ref,
                remediation_digest="sha256:" + ("9" * 64),
                runtime_source_digest="sha256:" + ("8" * 64),
                regression_evidence_digest="sha256:" + ("7" * 64),
                idempotency_key="supervisor:repair:after-checkpoint",
            )
        database.dispose()

    def test_supervision_events_are_idempotent_and_success_is_terminal(self) -> None:
        database = Database("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(database.engine)
        supervisor = AutomationSupervisor(AutomationSupervisorStore(database))
        values = {
            "scope_ref": "pilot://full-chain/idempotent-test",
            "remediation_digest": "sha256:" + ("1" * 64),
            "runtime_source_digest": "sha256:" + ("2" * 64),
            "regression_evidence_digest": "sha256:" + ("3" * 64),
            "idempotency_key": "supervisor:repair:idempotent",
        }
        first = supervisor.record_verified_remediation(**values)
        duplicate = supervisor.record_verified_remediation(**values)
        self.assertEqual(1, first["revision"])
        self.assertEqual(1, duplicate["revision"])
        completed = supervisor.record_success(
            scope_ref=values["scope_ref"],
            attempt_ref="attempt://disease/pass",
            result_evidence_digest="sha256:" + ("4" * 64),
            idempotency_key="supervisor:success:idempotent",
        )
        self.assertEqual("completed", completed["status"])
        self.assertFalse(completed["release_authorization"])
        database.dispose()


if __name__ == "__main__":
    unittest.main()

