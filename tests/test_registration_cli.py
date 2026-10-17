from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from orbit_agent_control_plane.cli import main

ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_ROOT = ROOT.parent / "orbit-health-system" / "scientific-research-platform"
HANDOFF = "contracts/agents/disease-research-task-agent/registration/0.1.0/registration-handoff-manifest.json"


def write_test_approval(path: Path) -> None:
    source = json.loads(
        (ROOT / "references" / "agent-registration-approved-inputs.json").read_text(
            encoding="utf-8"
        )
    )
    entries = source["approved_handoffs"] or source["review_requests"]
    approved = copy.deepcopy(entries[0])
    source["status"] = "local-synthetic-registration-only"
    source["review_requests"] = []
    source["approved_handoffs"] = [approved]
    path.write_text(json.dumps(source, ensure_ascii=False, indent=2) + "\n")


class AgentRegistrationCliTest(unittest.TestCase):
    @staticmethod
    def invoke(*args: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(list(args))
        return code, json.loads(output.getvalue())

    def test_apply_status_replay_and_idempotent_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "owner-only" / "registration.synthetic.jsonl"
            approval_lock = Path(temporary) / "approved-inputs.json"
            write_test_approval(approval_lock)
            arguments = (
                "agent-registration",
                "apply",
                "--source-root",
                str(SCIENTIFIC_ROOT),
                "--handoff-manifest",
                HANDOFF,
                "--approval-lock",
                str(approval_lock),
                "--contract-baseline",
                "alpha1-history",
                "--ledger",
                str(ledger),
            )
            first_code, first = self.invoke(*arguments)
            retry_code, retry = self.invoke(*arguments)
            status_code, status = self.invoke(
                "agent-registration", "status", "--ledger", str(ledger)
            )
            replay_code, replay = self.invoke(
                "agent-registration", "replay", "--ledger", str(ledger)
            )
            self.assertEqual(0, first_code)
            self.assertEqual(0, retry_code)
            self.assertTrue(first["ledger_appended"])
            self.assertFalse(retry["ledger_appended"])
            self.assertEqual(first["local_ledger_record_hash"], retry["local_ledger_record_hash"])
            self.assertEqual(0, status_code)
            self.assertEqual(1, status["records_checked"])
            self.assertEqual(0, replay_code)
            self.assertEqual(1, len(replay["registrations"]))
            serialized = json.dumps([first, retry, status, replay])
            self.assertNotIn("/Users/", serialized)
            self.assertFalse(first["company_authoritative"])
            self.assertFalse(first["company_registry_write_applied"])
            self.assertFalse(first["formal_registry_record_exists"])
            self.assertFalse(first["activation_authorized"])
            self.assertFalse(first["active"])
            self.assertFalse(first["task_execution_authorized"])

    def test_fixture_only_lifecycle_register_remains_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "lifecycle.synthetic.jsonl"
            code, document = self.invoke(
                "agent-lifecycle", "register", "--ledger", str(ledger)
            )
            self.assertEqual(0, code)
            self.assertEqual(
                "agt_orbit_agent_lifecycle_assurance_syn",
                document["agents"][0]["agent_id"],
            )

    def test_blocked_output_does_not_echo_physical_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "registration.synthetic.jsonl"
            code, document = self.invoke(
                "agent-registration",
                "apply",
                "--source-root",
                str(SCIENTIFIC_ROOT),
                "--handoff-manifest",
                "/Users/private/absolute.json",
                "--ledger",
                str(ledger),
            )
            self.assertEqual(1, code)
            self.assertEqual("unsafe_source_path", document["reason_code"])
            self.assertNotIn("/Users/", json.dumps(document))
            self.assertFalse(document["synthetic_registration_evidence_written"])


if __name__ == "__main__":
    unittest.main()

