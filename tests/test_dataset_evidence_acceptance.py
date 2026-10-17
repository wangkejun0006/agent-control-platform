from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.dataset_evidence_acceptance import (
    APPROVAL_VERSION,
    DatasetEvidenceAcceptanceError,
    SyntheticDatasetEvidenceAcceptanceLedger,
    load_dataset_evidence_approval,
    verify_dataset_evidence_review,
)


ROOT = Path(__file__).resolve().parents[1]


class DatasetEvidenceAcceptanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.review = verify_dataset_evidence_review()
        self.approval_path = self.root / "approval.json"
        self.ledger_path = self.root / "acceptance.synthetic.jsonl"
        self.write_approval()

    def write_approval(self, **overrides: object) -> None:
        document = {
            "approval_version": APPROVAL_VERSION,
            "decision_id": "decision_dataset_d0_evidence_acceptance_syn",
            "decision": "approve",
            "decided_by_human_ref": "human_dataset_d0_final_reviewer_syn",
            "approved_at": "2026-08-26T12:00:00+08:00",
            "scope": "dataset-agent-tools/d0-synthetic-evidence-acceptance",
            "evidence_bundle_digest": self.review.evidence_bundle_digest,
            "approval_semantics": self.review.approval_semantics,
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "release_authorization": False,
            **overrides,
        }
        self.approval_path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        self.approval_path.chmod(0o600)

    def assert_reason(self, reason: str, callback) -> None:
        with self.assertRaises(DatasetEvidenceAcceptanceError) as raised:
            callback()
        self.assertEqual(reason, raised.exception.reason_code)

    def test_review_closes_exact_frozen_evidence_and_hold(self) -> None:
        self.assertEqual(
            "sha256:e8771854170c42ca8b24b31e91737f6cda488b6944ea86d159c874b264dc087b",
            self.review.evidence_bundle_digest,
        )
        self.assertEqual("D0 synthetic active", self.review.accepted_status_ceiling)
        self.assertEqual(4, len(self.review.evidence))

    def test_exact_approval_appends_acceptance_and_linked_audit_idempotently(self) -> None:
        approval = load_dataset_evidence_approval(self.approval_path, self.review)
        ledger = SyntheticDatasetEvidenceAcceptanceLedger(self.ledger_path)
        first = ledger.accept(self.review, approval)
        retry = ledger.accept(self.review, approval)
        replay = ledger.replay()
        self.assertTrue(first.appended)
        self.assertFalse(retry.appended)
        self.assertEqual(first.record_hash, retry.record_hash)
        self.assertEqual(1, replay.records_checked)
        acceptance = replay.acceptances[0]
        self.assertEqual("hold", acceptance["lifecycle_assurance_recommendation"])
        self.assertFalse(acceptance["release_authorization"])
        self.assertFalse(acceptance["agent_lifecycle_mutated"])
        self.assertFalse(acceptance["tool_lifecycle_mutated"])
        self.assertEqual(
            "dataset.d0.evidence.accept", acceptance["audit"]["action"]
        )
        self.assertEqual(0o600, os.stat(self.ledger_path).st_mode & 0o777)

    def test_approval_digest_scope_or_authorization_drift_fails(self) -> None:
        cases = (
            ({"evidence_bundle_digest": "sha256:" + ("0" * 64)},),
            ({"scope": "dataset-agent-tools/production"},),
            ({"release_authorization": True},),
        )
        for index, (overrides,) in enumerate(cases):
            with self.subTest(index=index):
                self.write_approval(**overrides)
                self.assert_reason(
                    "approval_scope_invalid",
                    lambda: load_dataset_evidence_approval(
                        self.approval_path, self.review
                    ),
                )

    def test_ledger_tamper_fails_closed(self) -> None:
        approval = load_dataset_evidence_approval(self.approval_path, self.review)
        ledger = SyntheticDatasetEvidenceAcceptanceLedger(self.ledger_path)
        ledger.accept(self.review, approval)
        source = self.ledger_path.read_bytes()
        self.ledger_path.write_bytes(
            source.replace(b'"release_authorization":false', b'"release_authorization":true')
        )
        os.chmod(self.ledger_path, 0o600)
        self.assert_reason("ledger_integrity_invalid", ledger.replay)

    def test_approval_requires_owner_only_regular_file(self) -> None:
        self.approval_path.chmod(0o644)
        self.assert_reason(
            "input_permissions_too_broad",
            lambda: load_dataset_evidence_approval(
                self.approval_path, self.review
            ),
        )


if __name__ == "__main__":
    unittest.main()

