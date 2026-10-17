from __future__ import annotations

import copy
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from orbit_agent_control_plane.cli import main
from orbit_agent_control_plane.lifecycle import LifecycleError
from orbit_agent_control_plane.lifecycle_intake import import_lifecycle_candidate
from orbit_agent_control_plane.registration import (
    DEFAULT_APPROVAL_LOCK,
    HISTORICAL_ALPHA1_COMPANY_LOCK,
    HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
)

ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_ROOT = ROOT.parent / "orbit-health-system" / "scientific-research-platform"
HANDOFF = Path(
    "contracts/agents/disease-research-task-agent/registration/0.1.0/registration-handoff-manifest.json"
)
RELEASE = Path("lifecycle-input/disease-agent-release.e4.synthetic.yaml")
EVALUATION = Path("lifecycle-input/disease-agent-e4-evaluation.synthetic.yaml")
AGENT_ID = "agt_orbit_disease_research_task_syn"
RELEASE_DIGEST = (
    "sha256:0117c98dd0609932e5c04bd47d44bf7e7c4138aa4fa7dc8edf94bb60f128a95d"
)
HISTORICAL_ALPHA1_ARGS = {
    "company_lock_path": HISTORICAL_ALPHA1_COMPANY_LOCK,
    "contract_bundle_root": HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
}


class LifecycleIntakeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.source_root = root / "scientific"
        shutil.copytree(SCIENTIFIC_ROOT / "contracts", self.source_root / "contracts")
        (self.source_root / RELEASE.parent).mkdir()
        shutil.copyfile(
            ROOT / "tests" / "fixtures" / RELEASE.name,
            self.source_root / RELEASE,
        )
        shutil.copyfile(
            ROOT / "tests" / "fixtures" / EVALUATION.name,
            self.source_root / EVALUATION,
        )
        self.approval_lock = root / "registration-approved-inputs.json"
        self.registration_ledger = root / "registration.synthetic.jsonl"
        self.lifecycle_ledger = root / "lifecycle.synthetic.jsonl"
        self.activation_approval = root / "activation-approval.json"
        self.company_root = root / "control-plane"
        self.company_release = Path(
            "company-evidence/disease-agent-release.e4.synthetic.yaml"
        )
        self.company_evaluation = Path(
            "company-evidence/disease-agent-e4-evaluation.synthetic.yaml"
        )
        (self.company_root / self.company_release.parent).mkdir(parents=True)
        shutil.copyfile(
            ROOT / "tests" / "fixtures" / RELEASE.name,
            self.company_root / self.company_release,
        )
        shutil.copyfile(
            ROOT / "tests" / "fixtures" / EVALUATION.name,
            self.company_root / self.company_evaluation,
        )
        self.write_approved_registration_lock()
        self.activation_approval.write_text(
            json.dumps(
                {
                    "decision_id": "decision_orbit_disease_e4_activate_syn",
                    "action": "activate",
                    "subject_agent_id": AGENT_ID,
                    "subject_release_digest": RELEASE_DIGEST,
                    "decided_by_human_ref": "human_orbit_disease_activation_owner_syn",
                    "decision": "approve",
                    "reason": "批准精确 Disease E4 synthetic release 的本地 D0 激活；不批准预产或生产。",
                    "evidence_status": "synthetic",
                    "synthetic_only": True,
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self.activation_approval.chmod(0o600)

    def write_approved_registration_lock(self) -> None:
        lock = json.loads(DEFAULT_APPROVAL_LOCK.read_text(encoding="utf-8"))
        entries = lock["approved_handoffs"] or lock["review_requests"]
        approved = copy.deepcopy(entries[0])
        lock["status"] = "local-synthetic-registration-only"
        lock["review_requests"] = []
        lock["approved_handoffs"] = [approved]
        self.approval_lock.write_text(
            json.dumps(lock, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def invoke(*args: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(list(args))
        return code, json.loads(output.getvalue())

    def register(self) -> None:
        code, document = self.invoke(
            "agent-registration",
            "apply",
            "--source-root",
            str(self.source_root),
            "--handoff-manifest",
            str(HANDOFF),
            "--approval-lock",
            str(self.approval_lock),
            "--contract-baseline",
            "alpha1-history",
            "--ledger",
            str(self.registration_ledger),
        )
        self.assertEqual(0, code, document)

    def test_import_requires_exact_record_and_selected_release(self) -> None:
        with self.assertRaises(LifecycleError) as raised:
            import_lifecycle_candidate(
                self.source_root,
                HANDOFF,
                self.registration_ledger,
                RELEASE,
                approval_lock_path=self.approval_lock,
                **HISTORICAL_ALPHA1_ARGS,
            )
        self.assertEqual("ledger_not_found", raised.exception.reason_code)

        self.register()
        imported = import_lifecycle_candidate(
            self.source_root,
            HANDOFF,
            self.registration_ledger,
            RELEASE,
            approval_lock_path=self.approval_lock,
            **HISTORICAL_ALPHA1_ARGS,
        )
        self.assertEqual(AGENT_ID, imported.candidate.agent_id)
        self.assertEqual(RELEASE_DIGEST, imported.candidate.release_digest)
        self.assertEqual(
            "agent_system_orbit_research_syn",
            imported.candidate.agent_system_ref,
        )

    def test_cli_import_evaluation_and_activation_use_separate_scopes(self) -> None:
        self.register()
        import_code, imported = self.invoke(
            "agent-lifecycle",
            "import-registration",
            "--ledger",
            str(self.lifecycle_ledger),
            "--source-root",
            str(self.source_root),
            "--handoff-manifest",
            str(HANDOFF),
            "--registration-ledger",
            str(self.registration_ledger),
            "--registration-approval-lock",
            str(self.approval_lock),
            "--release-manifest",
            str(RELEASE),
            "--contract-baseline",
            "alpha1-history",
        )
        self.assertEqual(0, import_code, imported)
        self.assertEqual("draft", imported["agents"][0]["lifecycle_status"])

        premature_code, premature = self.invoke(
            "agent-lifecycle",
            "activate",
            "--ledger",
            str(self.lifecycle_ledger),
            "--approval",
            str(self.activation_approval),
        )
        self.assertEqual(1, premature_code)
        self.assertEqual("activation_state_invalid", premature["reason_code"])

        evaluation_code, evaluated = self.invoke(
            "agent-lifecycle",
            "record-evaluation",
            "--ledger",
            str(self.lifecycle_ledger),
            "--agent-id",
            AGENT_ID,
            "--source-root",
            str(self.source_root),
            "--release-manifest",
            str(RELEASE),
            "--evaluation-report",
            str(EVALUATION),
            "--contract-baseline",
            "alpha1-history",
        )
        self.assertEqual(0, evaluation_code, evaluated)
        self.assertEqual("evaluation", evaluated["agents"][0]["lifecycle_status"])
        self.assertFalse(evaluated["agents"][0]["release_authorization"])

        activation_code, activated = self.invoke(
            "agent-lifecycle",
            "activate",
            "--ledger",
            str(self.lifecycle_ledger),
            "--approval",
            str(self.activation_approval),
        )
        self.assertEqual(0, activation_code, activated)
        self.assertEqual("active", activated["agents"][0]["lifecycle_status"])
        self.assertFalse(activated["company_authoritative"])

    def test_cli_accepts_separate_domain_and_company_evidence_roots(self) -> None:
        self.register()
        import_code, imported = self.invoke(
            "agent-lifecycle",
            "import-registration",
            "--ledger",
            str(self.lifecycle_ledger),
            "--source-root",
            str(self.source_root),
            "--release-root",
            str(self.company_root),
            "--handoff-manifest",
            str(HANDOFF),
            "--registration-ledger",
            str(self.registration_ledger),
            "--registration-approval-lock",
            str(self.approval_lock),
            "--release-manifest",
            str(self.company_release),
            "--contract-baseline",
            "alpha1-history",
        )
        self.assertEqual(0, import_code, imported)
        self.assertEqual("draft", imported["agents"][0]["lifecycle_status"])

        evaluation_code, evaluated = self.invoke(
            "agent-lifecycle",
            "record-evaluation",
            "--ledger",
            str(self.lifecycle_ledger),
            "--agent-id",
            AGENT_ID,
            "--release-root",
            str(self.company_root),
            "--evaluation-root",
            str(self.company_root),
            "--release-manifest",
            str(self.company_release),
            "--evaluation-report",
            str(self.company_evaluation),
            "--contract-baseline",
            "alpha1-history",
        )
        self.assertEqual(0, evaluation_code, evaluated)
        self.assertEqual("evaluation", evaluated["agents"][0]["lifecycle_status"])
        self.assertFalse(evaluated["agents"][0]["release_authorization"])


if __name__ == "__main__":
    unittest.main()

