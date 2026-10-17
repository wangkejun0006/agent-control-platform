from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.qualification import (
    LocalPolicyActivationLedger,
    PolicyActivationLedgerError,
    build_policy_activation_receipt,
    canonical_digest,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = (
    ROOT
    / "evidence/disease-agent-r2/2026-08-27-automation-policy-alpha2/automation-policy.disease-r2.synthetic.json"
)


def approval(policy: dict, policy_digest: str) -> dict:
    return {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "ApprovalDecision",
        "metadata": {
            "decision_id": "decision_disease_r2_policy_activation_test_syn",
            "approval_id": "approval_disease_r2_policy_activation_test_syn",
            "task_id": "task_disease_r2_policy_activation_test_syn",
            "status": "immutable",
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "decided_at": "2026-08-28T00:00:00Z",
        },
        "spec": {
            "decision": "approve",
            "decided_by_human_ref": "human_orbit_platform_owner",
            "decided_by_role_ref": "role_orbit_platform_owner",
            "scope_ref": f"policy://{policy['metadata']['policy_id']}/0.1.0",
            "scope_digest": policy_digest,
            "reason": "approve exact local synthetic qualification policy",
            "expires_at": policy["metadata"]["expires_at"],
            "separation_of_duties_check_ref": "audit://policy-activation/sod",
            "audit_event_refs": ["audit_policy_activation_test_syn"],
        },
    }


class PolicyActivationLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        cls.policy_digest = canonical_digest(cls.policy)
        cls.approval = approval(cls.policy, cls.policy_digest)
        cls.receipt = build_policy_activation_receipt(
            policy=cls.policy,
            policy_digest=cls.policy_digest,
            approval_decision=cls.approval,
            activated_at="2026-08-28T00:00:01Z",
        )

    def test_apply_is_owner_only_idempotent_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "activation.jsonl"
            ledger = LocalPolicyActivationLedger(path)
            first = ledger.apply(
                policy=self.policy,
                policy_digest=self.policy_digest,
                approval_decision=self.approval,
                receipt=self.receipt,
                recorded_at="2026-08-28T00:00:01Z",
            )
            second = ledger.apply(
                policy=self.policy,
                policy_digest=self.policy_digest,
                approval_decision=self.approval,
                receipt=self.receipt,
                recorded_at="2026-08-28T00:00:01Z",
            )
            self.assertEqual(first, second)
            self.assertEqual(first, ledger.replay())
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertFalse(first.release_authorization)

    def test_tamper_and_broad_permissions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "activation.jsonl"
            ledger = LocalPolicyActivationLedger(path)
            ledger.apply(
                policy=self.policy,
                policy_digest=self.policy_digest,
                approval_decision=self.approval,
                receipt=self.receipt,
                recorded_at="2026-08-28T00:00:01Z",
            )
            document = json.loads(path.read_text(encoding="utf-8"))
            document["status"] = "production"
            path.write_text(json.dumps(document) + "\n", encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaises(PolicyActivationLedgerError):
                ledger.replay()
            os.chmod(path, 0o644)
            with self.assertRaises(PolicyActivationLedgerError):
                ledger.replay()


if __name__ == "__main__":
    unittest.main()

