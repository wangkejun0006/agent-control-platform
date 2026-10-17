from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from candidate_support.disease_r2_governance import (
    AGENT_ID,
    AGENT_RELEASE_DIGEST,
    APPROVAL_VERSION,
    MODEL_ROUTE_DIGEST,
    REVIEW_PACKAGE_DIGEST,
    TOOL_ID,
    TOOL_RELEASE_DIGEST,
    DiseaseR2GovernanceError,
    SyntheticR2ScopeLedger,
    apply_approved_scopes,
)

ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC = (
    ROOT.parent / "orbit-health-system" / "scientific-research-platform"
)


class DiseaseR2GovernanceTest(unittest.TestCase):
    def approval(self, root: Path) -> Path:
        path = root / "approval.synthetic.json"
        path.write_text(
            json.dumps(
                {
                    "approval_version": APPROVAL_VERSION,
                    "review_package_digest": REVIEW_PACKAGE_DIGEST,
                    "decided_by_human_ref": "hum_orbit_platform_owner_syn",
                    "decision": "approve",
                    "reason": (
                        "Approve four independent local synthetic R2 scopes; "
                        "no production or release authorization."
                    ),
                    "scopes": [
                        {
                            "decision_id": "approval_disease_r2_agent_activate_syn",
                            "scope": "agent_activation",
                            "subject_id": AGENT_ID,
                            "subject_digest": AGENT_RELEASE_DIGEST,
                        },
                        {
                            "decision_id": "approval_disease_r2_tool_activate_syn",
                            "scope": "tool_activation",
                            "subject_id": TOOL_ID,
                            "subject_digest": TOOL_RELEASE_DIGEST,
                        },
                        {
                            "decision_id": "approval_disease_r2_model_route_syn",
                            "scope": "model_route_approval",
                            "subject_id": (
                                "model_route_orbit_disease_r2_fixture_gpt56sol_syn"
                            ),
                            "subject_digest": MODEL_ROUTE_DIGEST,
                        },
                        {
                            "decision_id": "approval_disease_r2_execution_syn",
                            "scope": "r2_execution",
                            "subject_id": "review_orbit_disease_r2_20260826",
                            "subject_digest": REVIEW_PACKAGE_DIGEST,
                        },
                    ],
                    "authority_boundary": {
                        "formal_registry_authorized": False,
                        "preproduction_authorized": False,
                        "production_authorized": False,
                        "release_authorization": False,
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        return path

    def test_applies_three_scopes_and_blocks_execution_without_consuming_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            approval = self.approval(parent)
            scope_ledger = parent / "scope.jsonl"
            result = apply_approved_scopes(
                control=ROOT,
                scientific=SCIENTIFIC,
                approval_path=approval,
                scope_ledger_path=scope_ledger,
            )
            replayed = apply_approved_scopes(
                control=ROOT,
                scientific=SCIENTIFIC,
                approval_path=approval,
                scope_ledger_path=scope_ledger,
            )

            self.assertEqual(result, replayed)
            self.assertEqual("active", result["agent"]["lifecycle_status"])
            self.assertEqual("active", result["tool"]["lifecycle_status"])
            scopes = SyntheticR2ScopeLedger(scope_ledger).replay()
            self.assertEqual(8, scopes.records_checked)
            self.assertEqual(
                "approved_unconsumed", scopes.status("model_route_approval").status
            )
            self.assertEqual(
                "blocked_unconsumed", scopes.status("r2_execution").status
            )
            self.assertFalse(result["execution"]["model_called"])
            self.assertFalse(result["release_authorization"])
            self.assertEqual(0o600, scope_ledger.stat().st_mode & 0o777)

    def test_broad_approval_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            approval = self.approval(parent)
            os.chmod(approval, 0o644)
            with self.assertRaises(DiseaseR2GovernanceError) as caught:
                apply_approved_scopes(
                    control=ROOT,
                    scientific=SCIENTIFIC,
                    approval_path=approval,
                    scope_ledger_path=parent / "scope.jsonl",
                )
            self.assertEqual("scope_approval_insecure", caught.exception.reason_code)


if __name__ == "__main__":
    unittest.main()

