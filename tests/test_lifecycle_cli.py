from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from orbit_agent_control_plane.cli import main


OBSERVATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "references"
    / "fixture-fixture-structured-v1-lifecycle-assurance-d0.json"
)


class AgentLifecycleCliTest(unittest.TestCase):
    @staticmethod
    def invoke(*args: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(list(args))
        return exit_code, json.loads(output.getvalue())

    def test_stable_candidate_needs_exact_approval_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "lifecycle.synthetic.jsonl"
            register_code, _ = self.invoke(
                "agent-lifecycle", "register", "--ledger", str(ledger)
            )
            evaluate_code, _ = self.invoke(
                "agent-lifecycle", "evaluate", "--ledger", str(ledger)
            )
            missing_code, missing = self.invoke(
                "agent-lifecycle", "activate", "--ledger", str(ledger)
            )
            self.assertEqual(0, register_code)
            self.assertEqual(0, evaluate_code)
            self.assertEqual(1, missing_code)
            self.assertEqual("approval_file_required", missing["reason_code"])

            approval = Path(temporary) / "approval.synthetic.json"
            approval.write_text(
                json.dumps(
                    {
                        "decision_id": "approval_lifecycle_assurance_syn",
                        "action": "activate",
                        "subject_agent_id": "agt_orbit_agent_lifecycle_assurance_syn",
                        "subject_release_digest": "sha256:" + ("c" * 64),
                        "decided_by_human_ref": "human_platform_owner_syn",
                        "decision": "approve",
                        "reason": "D0 synthetic lifecycle activation proof",
                        "evidence_status": "synthetic",
                        "synthetic_only": True,
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(approval, 0o600)
            activate_code, activated = self.invoke(
                "agent-lifecycle",
                "activate",
                "--ledger",
                str(ledger),
                "--approval",
                str(approval),
            )
            self.assertEqual(0, activate_code)
            self.assertEqual("active", activated["agents"][0]["lifecycle_status"])
            self.assertFalse(activated["agents"][0]["release_authorization"])

    def test_template_task_agent_auto_cleanup_and_assurance_cli(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "task-agent.synthetic.jsonl"
            spawn_code, spawned = self.invoke(
                "agent-lifecycle", "spawn-task-agent", "--ledger", str(ledger)
            )
            retire_code, retired = self.invoke(
                "agent-lifecycle", "retire-task-agent", "--ledger", str(ledger)
            )
            self.assertEqual(0, spawn_code)
            self.assertTrue(spawned["agents"][0]["temporary_task_agent"])
            self.assertEqual(0, retire_code)
            self.assertEqual("retired", retired["agents"][0]["lifecycle_status"])
            self.assertTrue(retired["agents"][0]["cleanup_complete"])

        assurance_code, assurance = self.invoke("synthetic-lifecycle-assurance")
        self.assertEqual(0, assurance_code)
        self.assertEqual("capable-structured-fixture", assurance["selected_model"]["model_id"])
        self.assertEqual("0.000000", assurance["usage"]["cost_cny"])
        self.assertFalse(assurance["release_authorization"])

    def test_provider_cli_requires_exact_charge_confirmation_before_configuration(self) -> None:
        code, document = self.invoke(
            "provider-lifecycle-assurance",
            "--capability-observation",
            str(OBSERVATION_PATH),
            "--max-cost-cny",
            "0.50",
        )
        self.assertEqual(1, code)
        self.assertEqual(
            "provider_charge_confirmation_required", document["reason_code"]
        )
        self.assertFalse(document["release_authorization"])

        confirmed_code, confirmed = self.invoke(
            "provider-lifecycle-assurance",
            "--capability-observation",
            str(OBSERVATION_PATH),
            "--max-cost-cny",
            "0.50",
            "--confirm-provider-charge",
            "D0_SYNTHETIC_PAID_CALL",
        )
        self.assertEqual(1, confirmed_code)
        self.assertEqual(
            "provider_environment_file_required", confirmed["reason_code"]
        )


if __name__ == "__main__":
    unittest.main()

