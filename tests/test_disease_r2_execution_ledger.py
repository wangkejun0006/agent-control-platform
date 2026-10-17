from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from candidate_support.disease_r2_execution_ledger import (
    DiseaseR2ExecutionLedgerError,
    SyntheticDiseaseR2ExecutionLedger,
)


class DiseaseR2ExecutionLedgerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "execution.jsonl"
        self.ledger = SyntheticDiseaseR2ExecutionLedger(self.path)
        self.task_id = "tsk_orbit_disease_r2_execution_syn"
        self.started = {
            "task_id": self.task_id,
            "task_digest": "sha256:" + ("a" * 64),
            "grant_id": "grant_orbit_disease_r2_execution_syn",
            "grant_digest": "sha256:" + ("b" * 64),
            "composition_digest": "sha256:" + ("c" * 64),
            "runtime_source_digest": "sha256:" + ("d" * 64),
            "execution_approval_digest": "sha256:" + ("1" * 64),
            "issued_at": "2026-08-27T00:00:00Z",
            "expires_at": "2026-08-27T00:15:00Z",
            "worker_lease": {
                "lease_id": "lease_orbit_disease_r2_execution_syn",
                "status": "active",
                "revision": 0,
            },
            "synthetic_only": True,
            "release_authorization": False,
        }
        self.outcome = {
            "status": "pass",
            "evidence_digest": "sha256:" + ("e" * 64),
            "result_digest": "sha256:" + ("f" * 64),
            "reason_codes": ["disease_r2_fixed_suite_pass"],
            "usage": {
                "calls": 4,
                "attempts": 4,
                "input_tokens": 8000,
                "output_tokens": 800,
                "cost_usd": "0.064000",
                "cost_cny": "0.480000",
            },
            "release_authorization": False,
        }
        self.terminal = {
            "task": {"task_id": self.task_id, "status": "completed", "revision": 1},
            "grant": {
                "grant_id": self.started["grant_id"],
                "status": "consumed",
                "effective": False,
                "revision": 1,
            },
            "execution_approval": {
                "digest": self.started["execution_approval_digest"],
                "status": "consumed",
                "single_use": True,
            },
            "model_route": {
                "digest": "sha256:" + ("2" * 64),
                "status": "consumed",
            },
            "release_authorization": False,
        }

    def test_task_grant_outcome_and_lease_close_replay(self) -> None:
        self.ledger.start(
            self.task_id, self.started, idempotency_key="r2:start:one"
        )
        self.ledger.record_outcome(
            self.task_id, self.outcome, idempotency_key="r2:outcome:one"
        )
        self.ledger.close_lease(
            self.task_id,
            {
                "lease_id": self.started["worker_lease"]["lease_id"],
                "status": "completed",
                "revision": 1,
            },
            idempotency_key="r2:lease:close",
        )
        self.ledger.close_authority(
            self.task_id,
            self.terminal,
            idempotency_key="r2:authority:close",
        )
        replay = self.ledger.replay()
        self.assertEqual(4, replay.records_checked)
        self.assertEqual("pass", replay.state.outcome["status"])
        self.assertEqual("completed", replay.state.lease["status"])
        self.assertEqual("consumed", replay.state.terminal["grant"]["status"])
        self.assertEqual(0o600, self.path.stat().st_mode & 0o777)

    def test_lifetime_budget_and_terminal_mismatch_fail_closed(self) -> None:
        too_long = {**self.started, "expires_at": "2026-08-27T00:15:01Z"}
        with self.assertRaises(DiseaseR2ExecutionLedgerError) as caught:
            self.ledger.start(
                self.task_id, too_long, idempotency_key="r2:start:too-long"
            )
        self.assertEqual("r2_execution_lifetime_invalid", caught.exception.reason_code)

        self.ledger.start(
            self.task_id, self.started, idempotency_key="r2:start:one"
        )
        over = {
            **self.outcome,
            "usage": {**self.outcome["usage"], "calls": 5},
        }
        with self.assertRaises(DiseaseR2ExecutionLedgerError) as caught:
            self.ledger.record_outcome(
                self.task_id, over, idempotency_key="r2:outcome:over"
            )
        self.assertEqual("r2_execution_outcome_invalid", caught.exception.reason_code)

    def test_authority_cannot_close_before_lease_or_with_active_grant(self) -> None:
        self.ledger.start(self.task_id, self.started, idempotency_key="r2:start:one")
        self.ledger.record_outcome(
            self.task_id, self.outcome, idempotency_key="r2:outcome:one"
        )
        with self.assertRaises(DiseaseR2ExecutionLedgerError):
            self.ledger.close_authority(
                self.task_id,
                self.terminal,
                idempotency_key="r2:authority:early",
            )


if __name__ == "__main__":
    unittest.main()

