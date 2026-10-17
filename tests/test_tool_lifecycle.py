from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from orbit_agent_control_plane.registration import (
    HISTORICAL_ALPHA1_COMPANY_LOCK,
    HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
)
from orbit_agent_control_plane.tool_lifecycle import (
    SyntheticToolApprovalDecision,
    SyntheticToolLifecycleLedger,
    ToolLifecycleError,
    ToolLifecycleEvaluation,
)
from orbit_agent_control_plane.tool_registry import load_tool_candidate_bundle

ROOT = Path(__file__).resolve().parents[1]
DATASET_REGISTRY_ROOT = (
    ROOT / "showcase/vendor-fixtures/dataset-registry"
)
RELEASE_MANIFEST = Path("contracts/tools/0.1.0/release-manifest.json")


class ToolLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        parent = Path(self.temporary.name) / "ledger"
        parent.mkdir(mode=0o700)
        self.ledger_path = parent / "tool-lifecycle.synthetic.jsonl"
        self.ledger = SyntheticToolLifecycleLedger(self.ledger_path)
        self.bundle = load_tool_candidate_bundle(
            DATASET_REGISTRY_ROOT,
            RELEASE_MANIFEST,
            company_lock_path=HISTORICAL_ALPHA1_COMPANY_LOCK,
            contract_bundle_root=HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
        )
        self.candidate = self.bundle.candidate(
            "tool_orbit_dataset_acquisition_worker"
        )

    def assert_reason(self, reason: str, callback) -> None:
        with self.assertRaises(ToolLifecycleError) as raised:
            callback()
        self.assertEqual(reason, raised.exception.reason_code)

    def evaluation(self, **overrides: object) -> ToolLifecycleEvaluation:
        values: dict[str, object] = {
            "report_id": "eval_dataset_acquisition_tool_syn",
            "subject_tool_id": self.candidate.tool_id,
            "subject_release_digest": self.candidate.release_digest,
            "evaluator_ref": "agt_orbit_company_evaluator_syn",
            "verdict": "pass",
            "release_recommendation": "recommend",
            "allowed_operation_ids": self.candidate.d0_allowed_operation_ids,
            "evidence_refs": (
                "evidence_tool_schema_syn",
                "evidence_tool_negative_permissions_syn",
            ),
            "risk_flags": ("real_transfer_operation_not_d0_allowed",),
            "release_authorization": False,
        }
        values.update(overrides)
        return ToolLifecycleEvaluation(**values)

    def approval(self, **overrides: object) -> SyntheticToolApprovalDecision:
        values: dict[str, object] = {
            "decision_id": "approval_dataset_acquisition_tool_activate_syn",
            "action": "activate",
            "subject_tool_id": self.candidate.tool_id,
            "subject_release_digest": self.candidate.release_digest,
            "decided_by_human_ref": "hum_orbit_platform_owner_syn",
            "decision": "approve",
            "reason": "D0 synthetic operation only",
        }
        values.update(overrides)
        return SyntheticToolApprovalDecision(**values)

    def activate_candidate(self) -> None:
        self.ledger.register_candidate(
            self.candidate, idempotency_key="tool:register:acquisition"
        )
        self.ledger.record_evaluation(
            self.evaluation(), idempotency_key="tool:evaluate:acquisition"
        )
        self.ledger.record_approval(
            self.approval(), idempotency_key="tool:approve:acquisition"
        )
        self.ledger.activate(
            self.candidate.tool_id,
            self.candidate.release_digest,
            approval_decision_ref=self.approval().decision_id,
            idempotency_key="tool:activate:acquisition",
        )

    def test_register_evaluate_approve_activate_and_replay(self) -> None:
        first = self.ledger.register_candidate(
            self.candidate, idempotency_key="tool:register:acquisition"
        )
        retry = self.ledger.register_candidate(
            self.candidate, idempotency_key="tool:register:acquisition"
        )
        self.assertTrue(first.appended)
        self.assertFalse(retry.appended)
        self.ledger.record_evaluation(
            self.evaluation(), idempotency_key="tool:evaluate:acquisition"
        )
        self.ledger.record_approval(
            self.approval(), idempotency_key="tool:approve:acquisition"
        )
        self.ledger.activate(
            self.candidate.tool_id,
            self.candidate.release_digest,
            approval_decision_ref=self.approval().decision_id,
            idempotency_key="tool:activate:acquisition",
        )

        replay = self.ledger.replay()
        state = replay.tool(self.candidate.tool_id, self.candidate.release_digest)
        self.assertEqual(4, replay.records_checked)
        self.assertEqual("active", state.status)
        self.assertEqual(2, state.revision)
        self.assertFalse(state.evaluation.release_authorization)
        self.assertEqual(2, len(state.transitions))
        self.assertTrue(state.transitions[-1].audit_event_ref.startswith("audit_"))
        self.assertEqual(0o600, self.ledger_path.stat().st_mode & 0o777)

    def test_activation_requires_evaluation_and_exact_human_approval(self) -> None:
        self.ledger.register_candidate(
            self.candidate, idempotency_key="tool:register:acquisition"
        )
        self.assert_reason(
            "approval_decision_missing",
            lambda: self.ledger.activate(
                self.candidate.tool_id,
                self.candidate.release_digest,
                approval_decision_ref="approval_missing_syn",
                idempotency_key="tool:activate:missing",
            ),
        )
        self.ledger.record_evaluation(
            self.evaluation(verdict="fail", release_recommendation="do_not_recommend"),
            idempotency_key="tool:evaluate:fail",
        )
        self.ledger.record_approval(
            self.approval(), idempotency_key="tool:approve:acquisition"
        )
        self.assert_reason(
            "tool_evaluation_not_passed",
            lambda: self.ledger.activate(
                self.candidate.tool_id,
                self.candidate.release_digest,
                approval_decision_ref=self.approval().decision_id,
                idempotency_key="tool:activate:failed-eval",
            ),
        )

    def test_evaluator_cannot_self_authorize_or_widen_operations(self) -> None:
        self.ledger.register_candidate(
            self.candidate, idempotency_key="tool:register:acquisition"
        )
        for expected, evaluation in (
            (
                "tool_self_evaluation_forbidden",
                self.evaluation(evaluator_ref=self.candidate.owner_human_ref),
            ),
            (
                "tool_evaluation_release_authority_forbidden",
                self.evaluation(release_authorization=True),
            ),
            (
                "tool_evaluation_operation_scope_invalid",
                self.evaluation(
                    allowed_operation_ids=("acquire_authorized_artifact",)
                ),
            ),
        ):
            with self.subTest(reason=expected):
                self.assert_reason(
                    expected,
                    lambda evaluation=evaluation: self.ledger.record_evaluation(
                        evaluation, idempotency_key="tool:evaluate:rejected"
                    ),
                )

    def test_suspend_and_retire_are_independent_per_release(self) -> None:
        self.activate_candidate()
        self.ledger.suspend(
            self.candidate.tool_id,
            self.candidate.release_digest,
            actor_ref="system_security_monitor_syn",
            reason_code="synthetic_kill_switch",
            idempotency_key="tool:suspend:acquisition",
        )
        retirement = self.approval(
            decision_id="approval_dataset_acquisition_tool_retire_syn",
            action="retire",
            reason="Synthetic D0 retirement",
        )
        self.ledger.record_approval(
            retirement, idempotency_key="tool:approve:retirement"
        )
        self.ledger.retire(
            self.candidate.tool_id,
            self.candidate.release_digest,
            approval_decision_ref=retirement.decision_id,
            idempotency_key="tool:retire:acquisition",
        )
        state = self.ledger.replay().tool(
            self.candidate.tool_id, self.candidate.release_digest
        )
        self.assertEqual("retired", state.status)
        self.assertEqual(4, state.revision)

    def test_multiple_releases_require_digest_selection(self) -> None:
        self.ledger.register_candidate(
            self.candidate, idempotency_key="tool:register:release-1"
        )
        other_digest = "sha256:" + ("1" * 64)
        other = replace(
            self.candidate,
            version="0.1.1-synthetic",
            release_digest=other_digest,
            manifest_digest=other_digest,
        )
        self.ledger.register_candidate(other, idempotency_key="tool:register:release-2")
        self.assert_reason(
            "tool_release_ambiguous",
            lambda: self.ledger.replay().tool(self.candidate.tool_id),
        )

    def test_truncated_hash_drift_permissions_and_symlink_fail(self) -> None:
        self.ledger.register_candidate(
            self.candidate, idempotency_key="tool:register:acquisition"
        )
        source = self.ledger_path.read_bytes()
        self.ledger_path.write_bytes(source[:-1])
        self.assert_reason("truncated_record", self.ledger.replay)

        self.ledger_path.write_bytes(source)
        document = json.loads(source)
        document["record_hash"] = "sha256:" + ("2" * 64)
        self.ledger_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
        self.assert_reason("record_hash_mismatch", self.ledger.replay)

        self.ledger_path.write_bytes(source)
        os.chmod(self.ledger_path, 0o644)
        self.assert_reason("ledger_permissions_too_broad", self.ledger.replay)

        os.chmod(self.ledger_path, 0o600)
        self.ledger_path.unlink()
        self.ledger_path.symlink_to(Path(self.temporary.name) / "missing")
        self.assert_reason("ledger_symlink_forbidden", self.ledger.replay)


if __name__ == "__main__":
    unittest.main()

