from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from candidate_support.disease_r2_stage_hooks import (
    run_pre_approval_hooks,
    write_receipt_once,
)
from candidate_support.disease_r2_v4_preflight import verify_candidate
from tests.disease_r2_fixture import SCOPE_LEDGER

ROOT = Path(__file__).resolve().parents[1]
ATTEMPT_002 = (
    ROOT
    / "evidence/disease-agent-r2/2026-08-27-execution-remediation-v4-attempt-002"
)
ATTEMPT_003 = (
    ROOT
    / "evidence/disease-agent-r2/2026-08-27-execution-remediation-v4-attempt-003"
)
ATTEMPT_004 = (
    ROOT
    / "evidence/disease-agent-r2/2026-08-27-execution-remediation-v4-attempt-004"
)


def load(root: Path, name: str) -> dict:
    return json.loads((root / name).read_text(encoding="utf-8"))


class DiseaseR2StageHooksTest(unittest.TestCase):
    def test_attempt_002_is_blocked_before_authority_or_external_io(self) -> None:
        receipt = run_pre_approval_hooks(
            review_package=ATTEMPT_002 / "execution-review-package.json",
            scope_ledger_path=SCOPE_LEDGER,
        )
        self.assertEqual("blocked", receipt["status"])
        self.assertEqual("candidate_remediation_required", receipt["next_stage"])
        self.assertFalse(receipt["human_intervention_required"])
        self.assertEqual(
            "r2_stage_runtime_compatibility_failed",
            receipt["checks"][-1]["reason_code"],
        )
        self.assertTrue(
            all(value is False for value in receipt["authority_boundary"].values())
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preflight-attempt-002.synthetic.json"
            file_digest = write_receipt_once(path, receipt)
            self.assertEqual(
                "sha256:c71607ce63ab1abb66f8397bd328335fc89c5d55a46bcf456fa4a4f996835407",
                file_digest,
            )
            self.assertEqual(receipt, json.loads(path.read_text(encoding="utf-8")))
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_attempt_003_is_blocked_by_terminal_closure_hook(self) -> None:
        receipt = run_pre_approval_hooks(
            review_package=ATTEMPT_003 / "execution-review-package.json",
            scope_ledger_path=SCOPE_LEDGER,
        )
        self.assertEqual("blocked", receipt["status"])
        self.assertEqual(
            "r2_stage_runtime_compatibility_invalid",
            receipt["checks"][-1]["reason_code"],
        )
        self.assertTrue(
            all(value is False for value in receipt["authority_boundary"].values())
        )

    def test_attempt_004_advances_only_to_human_execution_gate(self) -> None:
        receipt = run_pre_approval_hooks(
            review_package=ATTEMPT_004 / "execution-review-package.json",
            scope_ledger_path=SCOPE_LEDGER,
        )
        self.assertEqual("ready_for_human_gate", receipt["status"])
        self.assertEqual(
            "human_execution_approval_required", receipt["next_stage"]
        )
        self.assertTrue(receipt["human_intervention_required"])
        self.assertEqual(
            ["pass", "pass"], [item["status"] for item in receipt["checks"]]
        )
        self.assertTrue(
            all(value is False for value in receipt["authority_boundary"].values())
        )

    def test_attempt_004_exact_owner_only_execution_receipt_is_accepted(self) -> None:
        review = load(ATTEMPT_004, "execution-review-package.json")
        intent = load(ATTEMPT_004, "execution-intent.synthetic.json")
        task = load(ATTEMPT_004, "task-candidate.synthetic.json")
        grant = load(ATTEMPT_004, "execution-grant-candidate.synthetic.json")
        source = load(ATTEMPT_004, "runtime-source-lock.json")
        realization = load(
            ATTEMPT_004, "runtime-realization-candidate.synthetic.json"
        )
        composition = load(
            ATTEMPT_004, "runtime-composition-candidate.synthetic.json"
        )
        approval = {
            "approval_version": "orbit.synthetic-disease-r2-execution-approval/4",
            "decision_id": "approval_orbit_disease_r2_v4_004_syn",
            "scope": "r2_execution",
            "subject_digest": intent["execution_intent_digest"],
            "review_package_digest": review["review_package_digest"],
            "runtime_source_lock_digest": source["runtime_source_lock_digest"],
            "runtime_realization_digest": realization["runtime_realization_digest"],
            "task_candidate_digest": task["task_candidate_digest"],
            "grant_candidate_digest": review["grant_candidate_digest"],
            "grant_canonical_digest": grant["grant_canonical_digest"],
            "composition_digest": composition["composition_digest"],
            "image_id": review["image_id"],
            "decided_by_human_ref": "hum_orbit_platform_owner_syn",
            "decision": "approve",
            "synthetic_only": True,
            "single_use": True,
            "release_authorization": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            path.write_text(json.dumps(approval), encoding="utf-8")
            os.chmod(path, 0o600)
            result = verify_candidate(
                ATTEMPT_004 / "execution-review-package.json",
                runtime_root=ATTEMPT_004,
                scope_ledger_path=SCOPE_LEDGER,
                execution_approval_path=path,
                require_execution_approval=True,
            )
        self.assertEqual("approved_unconsumed", result["execution_scope_status"])

    def test_receipt_writer_is_owner_only_and_write_once(self) -> None:
        receipt = run_pre_approval_hooks(
            review_package=ATTEMPT_004 / "execution-review-package.json",
            scope_ledger_path=SCOPE_LEDGER,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            digest = write_receipt_once(path, receipt)
            self.assertTrue(digest.startswith("sha256:"))
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                write_receipt_once(path, receipt)


if __name__ == "__main__":
    unittest.main()

