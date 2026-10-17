from __future__ import annotations

import unittest

from candidate_support.disease_r2_qualification_adapter import (
    DiseaseR2QualificationAdapterError,
    runtime_observation_from_stage_hook,
)
from candidate_support.disease_r2_stage_hooks import run_pre_approval_hooks
from tests.test_disease_r2_stage_hooks import ATTEMPT_002, ATTEMPT_004, SCOPE_LEDGER

ISOLATION_DIGEST = "sha256:" + "e" * 64


class DiseaseR2QualificationAdapterTest(unittest.TestCase):
    def convert(self, receipt: dict):
        return runtime_observation_from_stage_hook(
            receipt=receipt,
            started_at="2026-08-27T01:00:00+00:00",
            completed_at="2026-08-27T01:00:01+00:00",
            environment_profile_digest=ISOLATION_DIGEST,
        )

    def test_attempt_002_becomes_machine_remediable_runtime_observation(self) -> None:
        receipt = run_pre_approval_hooks(
            review_package=ATTEMPT_002 / "execution-review-package.json",
            scope_ledger_path=SCOPE_LEDGER,
        )
        observation = self.convert(receipt)
        self.assertEqual(observation.stage, "runtime_realization")
        self.assertEqual(observation.outcome, "blocked")
        self.assertEqual(observation.failure_class, "engineering_compatibility")
        self.assertIn("r2_stage_runtime_compatibility_failed", observation.reason_codes)
        self.assertFalse(observation.side_effects.docker_started)

    def test_attempt_004_becomes_runtime_pass_without_inheriting_old_human_gate(
        self,
    ) -> None:
        receipt = run_pre_approval_hooks(
            review_package=ATTEMPT_004 / "execution-review-package.json",
            scope_ledger_path=SCOPE_LEDGER,
        )
        observation = self.convert(receipt)
        self.assertEqual(observation.outcome, "pass")
        self.assertEqual(observation.failure_class, "none")
        self.assertEqual(
            observation.reason_codes,
            ("runtime_realization_static_checks_passed",),
        )
        self.assertTrue(all(check.status == "pass" for check in observation.checks))

    def test_digest_tampering_is_rejected(self) -> None:
        receipt = run_pre_approval_hooks(
            review_package=ATTEMPT_004 / "execution-review-package.json",
            scope_ledger_path=SCOPE_LEDGER,
        )
        receipt["runtime_source_lock_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            DiseaseR2QualificationAdapterError, "disease_r2_hook_receipt_invalid"
        ):
            self.convert(receipt)


if __name__ == "__main__":
    unittest.main()

