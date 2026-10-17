from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from orbit_agent_control_plane.cli import main
from orbit_agent_control_plane.dataset_evidence_acceptance import APPROVAL_VERSION


class DatasetEvidenceAcceptanceCliTest(unittest.TestCase):
    @staticmethod
    def invoke(*args: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(list(args))
        return code, json.loads(output.getvalue())

    def test_prepare_is_read_only_and_apply_requires_human_approval(self) -> None:
        code, prepared = self.invoke("dataset-d0-evidence-review", "prepare")
        self.assertEqual(0, code)
        self.assertEqual("awaiting-human-review", prepared["status"])
        self.assertFalse(prepared["release_authorization"])

        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "acceptance.synthetic.jsonl"
            blocked_code, blocked = self.invoke(
                "dataset-d0-evidence-review",
                "apply",
                "--ledger",
                str(ledger),
            )
            self.assertEqual(1, blocked_code)
            self.assertEqual("approval_file_required", blocked["reason_code"])
            self.assertFalse(ledger.exists())

    def test_apply_status_and_replay_preserve_evidence_only_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = root / "acceptance.synthetic.jsonl"
            approval = root / "approval.json"
            prepared_code, prepared = self.invoke(
                "dataset-d0-evidence-review", "prepare"
            )
            self.assertEqual(0, prepared_code)
            approval.write_text(
                json.dumps(
                    {
                        "approval_version": APPROVAL_VERSION,
                        "decision_id": "decision_dataset_d0_evidence_cli_syn",
                        "decision": "approve",
                        "decided_by_human_ref": "human_dataset_d0_cli_reviewer_syn",
                        "approved_at": "2026-08-26T12:00:00+08:00",
                        "scope": "dataset-agent-tools/d0-synthetic-evidence-acceptance",
                        "evidence_bundle_digest": prepared["evidence_bundle_digest"],
                        "approval_semantics": prepared["approval_semantics"],
                        "evidence_status": "synthetic",
                        "synthetic_only": True,
                        "release_authorization": False,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            approval.chmod(0o600)
            apply_code, applied = self.invoke(
                "dataset-d0-evidence-review",
                "apply",
                "--approval",
                str(approval),
                "--ledger",
                str(ledger),
            )
            status_code, status = self.invoke(
                "dataset-d0-evidence-review", "status", "--ledger", str(ledger)
            )
            replay_code, replay = self.invoke(
                "dataset-d0-evidence-review", "replay", "--ledger", str(ledger)
            )
            self.assertEqual(0, apply_code)
            self.assertEqual(0, status_code)
            self.assertEqual(0, replay_code)
            for document in (applied, status, replay):
                self.assertFalse(document["company_authoritative"])
                self.assertFalse(document["release_authorization"])
                self.assertFalse(document["agent_lifecycle_mutated"])
                self.assertFalse(document["tool_lifecycle_mutated"])


if __name__ == "__main__":
    unittest.main()

