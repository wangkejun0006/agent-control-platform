from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.ledger import SyntheticTaskLedger


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (
    ROOT / "evidence/disease-agent-r1/2026-08-26/retry-004/result.json"
)
FAILURE_EVIDENCE = EVIDENCE.with_name("result.failure.json")
LEDGER = (
    ROOT
    / "evidence/publication-baseline/2026-08-26/"
    "disease-r1-retry-004-task.snapshot.synthetic.jsonl"
)
TASK_ID = "tsk_orbit_disease_stationery_r1_retry4_syn"
REVIEW_DIGEST = (
    "sha256:210b4435a4a99ecbdbe0200384ee92070a4d7359a845b7b0ee6c60a832684b83"
)
GRANT_DIGEST = (
    "sha256:31ffd99e88dc94c18eb914ddd030139624c3635a149ed20a15f49dbd0df326ce"
)
RUNTIME_DIGEST = (
    "sha256:293d6bffaf2e22f6bb6eaf7031f430b24f15bdfb386183a65417d5d59bbf4de3"
)
CONTROL_DIGEST = (
    "sha256:88221d292b72365a9c13003bcc34ee97a6c03565b2890901732fad954efa47dd"
)
APPROVAL_DIGEST = (
    "sha256:964a51bae8120b5b77259a62601509812e23f3cee3c5fb908eb6ae1aed9d7119"
)
FORBIDDEN = re.compile(
    r"/Users/|/Volumes/|(?:file|smb|opaque)://|opaque_storage_ref|"
    r"secret|credential|endpoint|docker\.sock",
    re.IGNORECASE,
)


class DiseaseR1ExecutionEvidenceTest(unittest.TestCase):
    def test_result_is_exact_double_evaluated_synthetic_pass(self) -> None:
        result = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual("R1 synthetic pass", result["status"])
        self.assertTrue(result["synthetic_only"])
        self.assertEqual(REVIEW_DIGEST, result["review_request_digest"])
        self.assertEqual(GRANT_DIGEST, result["grant_digest"])
        self.assertEqual(RUNTIME_DIGEST, result["runtime_source_digest"])
        self.assertEqual(CONTROL_DIGEST, result["control_source_digest"])
        self.assertEqual("pass", result["domain_evaluation"]["verdict"])
        self.assertFalse(result["domain_evaluation"]["release_authorization"])
        self.assertEqual("pass", result["company_evaluation"]["verdict"])
        self.assertFalse(result["company_evaluation"]["release_authorization"])
        self.assertFalse(result["release_authorization"])
        self.assertFalse(result["preproduction_authorized"])
        self.assertFalse(result["production_authorized"])
        self.assertFalse(FAILURE_EVIDENCE.exists())

    def test_ledger_closes_pass_outcome_before_completed_lease(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            replay_path = Path(temporary) / "task-ledger.synthetic.jsonl"
            replay_path.write_bytes(LEDGER.read_bytes())
            os.chmod(replay_path, 0o600)
            replay = SyntheticTaskLedger(replay_path).replay()
            state = replay.task(TASK_ID)
        evidence_digest = "sha256:" + hashlib.sha256(EVIDENCE.read_bytes()).hexdigest()
        with LEDGER.open(encoding="utf-8") as records:
            self.assertEqual(4, sum(1 for _ in records))
        self.assertEqual("pass", state.disease_r1_outcome["status"])
        self.assertEqual(evidence_digest, state.disease_r1_outcome["evidence_digest"])
        self.assertEqual("completed", state.worker_lease.status)
        self.assertEqual(1, state.worker_lease.revision)
        self.assertFalse(state.worker_lease.cancellation_requested)

    def test_published_evidence_contains_no_forbidden_reference(self) -> None:
        for path in (EVIDENCE, LEDGER):
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
                self.assertIsNone(FORBIDDEN.search(path.read_text(encoding="utf-8")))
        result = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        approval = (
            json.dumps(
                result["execution_approval"],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        self.assertEqual(
            APPROVAL_DIGEST,
            "sha256:" + hashlib.sha256(approval).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()

