from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.disease_r1_review import (
    DiseaseR1ReviewError,
    load_disease_r1_execution_approval,
    prepare_disease_r1_review,
    verify_disease_r1_review,
)

ROOT = Path(__file__).resolve().parents[1]
REVIEW = Path(
    "evidence/disease-agent-r1/2026-08-26/retry-004/execution-review-request.json"
)
LIFECYCLE_SNAPSHOT = (
    ROOT
    / "evidence/publication-baseline/2026-08-26/"
    "disease-lifecycle.snapshot.synthetic.jsonl"
)
PRIOR_TASK_SNAPSHOT = (
    ROOT
    / "evidence/publication-baseline/2026-08-26/"
    "disease-r1-retry-003-task.snapshot.synthetic.jsonl"
)


class DiseaseR1ReviewTest(unittest.TestCase):
    def test_historical_review_is_exact_but_current_source_fails_closed(self) -> None:
        historical = verify_disease_r1_review(ROOT, REVIEW)
        self.assertEqual(
            "sha256:88221d292b72365a9c13003bcc34ee97a6c03565b2890901732fad954efa47dd",
            historical.control_source_digest,
        )
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            lifecycle_ledger = temporary_root / "lifecycle.synthetic.jsonl"
            prior_task_ledger = temporary_root / "prior-task.synthetic.jsonl"
            lifecycle_ledger.write_bytes(LIFECYCLE_SNAPSHOT.read_bytes())
            prior_task_ledger.write_bytes(PRIOR_TASK_SNAPSHOT.read_bytes())
            os.chmod(lifecycle_ledger, 0o600)
            os.chmod(prior_task_ledger, 0o600)
            ledger_before = hashlib.sha256(lifecycle_ledger.read_bytes()).hexdigest()
            with self.assertRaises(DiseaseR1ReviewError) as raised:
                prepare_disease_r1_review(
                    ROOT,
                    REVIEW,
                    lifecycle_ledger=lifecycle_ledger,
                    prior_task_ledger=prior_task_ledger,
                )
            self.assertEqual("r1_control_source_drift", raised.exception.reason_code)
            self.assertEqual(
                ledger_before,
                hashlib.sha256(lifecycle_ledger.read_bytes()).hexdigest(),
            )

    def test_artifact_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "evidence" / "disease-agent-r1" / "2026-08-26"
            target.parent.mkdir(parents=True)
            shutil.copytree(ROOT / REVIEW.parent.parent, target)
            candidate = target / "retry-004" / "policy-candidate.synthetic.json"
            candidate.write_text(candidate.read_text() + " ", encoding="utf-8")
            with self.assertRaises(DiseaseR1ReviewError) as raised:
                verify_disease_r1_review(root, REVIEW)
            self.assertEqual(
                "r1_review_artifact_digest_mismatch", raised.exception.reason_code
            )

    def test_execution_approval_must_be_owner_only_and_exact(self) -> None:
        review = verify_disease_r1_review(ROOT, REVIEW)
        approval = {
            "decision_id": "decision_orbit_disease_r1_once_syn",
            "action": "run_disease_r1_once",
            "review_request_digest": review.review_request_digest,
            "task_candidate_digest": review.task_candidate_digest,
            "grant_candidate_digest": review.grant_candidate_digest,
            "composition_candidate_digest": review.composition_candidate_digest,
            "runtime_source_digest": review.runtime_source_digest,
            "control_source_digest": review.control_source_digest,
            "agent_release_digest": (
                "sha256:629d8d9b6997baf694b5856a526721ccd69bf71348c481c5c4dc6d909f62a0cb"
            ),
            "decided_by_human_ref": "human_orbit_disease_r1_owner_syn",
            "decided_at": "2026-08-26T00:00:00Z",
            "expires_at": "2026-08-26T00:10:00Z",
            "decision": "approve",
            "reason": "Approve exactly one bounded local synthetic R1 execution only.",
            "evidence_status": "synthetic",
            "synthetic_only": True,
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "approval.json"
            path.write_text(
                json.dumps(approval, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
            loaded = load_disease_r1_execution_approval(
                path, review, checked_at="2026-08-26T00:05:00Z"
            )
            self.assertEqual(approval["decision_id"], loaded.decision_id)
            os.chmod(path, 0o644)
            with self.assertRaises(DiseaseR1ReviewError) as raised:
                load_disease_r1_execution_approval(
                    path, review, checked_at="2026-08-26T00:05:00Z"
                )
            self.assertEqual("r1_approval_file_invalid", raised.exception.reason_code)


if __name__ == "__main__":
    unittest.main()

