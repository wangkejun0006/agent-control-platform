from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from orbit_agent_control_plane.qualification.service import REQUIRED_ADAPTER_ROLES

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (
    ROOT / "evidence/qualification-service/2026-08-28-security-hardening-publication"
)
HISTORY = ROOT / "evidence/qualification-service/2026-08-28"
POLICY_DIGEST = (
    "sha256:0785ff86017656a0668715413f7908802380847da6750bc0a422fb4c9f3d58bd"
)
ACTIVATION_RECEIPT_DIGEST = (
    "sha256:d32467203f4d259bff7270e4c0cbf12366bebc4058910dad21d767bd2b205f85"
)


class QualificationServiceEvidenceTests(unittest.TestCase):
    def test_skill_manifest_closes_final_runtime_and_deployment(self) -> None:
        verifier = (
            ROOT
            / ".agents/skills/orbit-agent-lifecycle-review/scripts/verify_artifact_set.py"
        )
        completed = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "--root",
                str(EVIDENCE),
                "--manifest",
                "skill-artifact-set.json",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual("PASS", result["status"])
        checked = {item["path"] for item in result["artifacts_checked"]}
        self.assertIn("runtime-result.attempt-012.synthetic.json", checked)
        self.assertIn("deployment-observation.attempt-006.synthetic.json", checked)
        self.assertIn("qualification-service-security-profile.candidate.json", checked)
        self.assertIn("compose.preproduction.yaml", checked)
        self.assertIn("secret-bindings.preproduction.json", checked)
        self.assertFalse(result["release_authorization"])
        self.assertFalse(result["runtime_started"])

    def test_runtime_and_deployment_are_synthetic_and_fail_closed(self) -> None:
        runtime = _read("runtime-result.attempt-012.synthetic.json")
        deployment = _read("deployment-observation.attempt-006.synthetic.json")
        activation = _read("policy-activation.snapshot.synthetic.json")
        readiness = _read("readiness-assessment.synthetic.json")
        self.assertEqual("PASS", runtime["status"])
        self.assertEqual(14, len(runtime["checks"]))
        self.assertEqual(POLICY_DIGEST, runtime["policy_digest"])
        self.assertEqual(
            ACTIVATION_RECEIPT_DIGEST,
            runtime["activation_receipt_digest"],
        )
        self.assertFalse(runtime["runtime_worker_started"])
        self.assertFalse(runtime["release_authorization"])
        self.assertEqual("PASS", deployment["status"])
        self.assertTrue(deployment["internal_network_only"])
        self.assertFalse(deployment["host_ports_published"])
        self.assertFalse(deployment["mutations_enabled"])
        self.assertFalse(deployment["policy_activation_in_service_database"])
        self.assertEqual("active", activation["status"])
        self.assertFalse(activation["service_database_intake_completed"])
        self.assertEqual("not_ready", readiness["status"])
        self.assertFalse(readiness["ready"])
        self.assertFalse(readiness["release_authorization"])

    def test_published_adapter_and_deployment_snapshot_remains_self_closed(self) -> None:
        recorded_manifest = _read("adapter-manifest.synthetic.json")
        self.assertEqual(
            set(REQUIRED_ADAPTER_ROLES),
            {item["role"] for item in recorded_manifest["adapters"]},
        )
        self.assertTrue(
            all(
                item["runtime_verified"]
                and item["synthetic_only"]
                and item["evidence_status"] == "synthetic"
                and item["digest"].startswith("sha256:")
                for item in recorded_manifest["adapters"]
            )
        )
        deployment = _read("deployment-observation.attempt-006.synthetic.json")
        self.assertEqual(
            {"compose", "dockerfile", "uv_lock"},
            set(deployment["source_digests"]),
        )
        self.assertTrue(
            all(
                value.startswith("sha256:") and len(value) == 71
                for value in deployment["source_digests"].values()
            )
        )
        self.assertTrue(deployment["runtime_adapter_digest"].startswith("sha256:"))
        self.assertEqual(
            (
                ROOT
                / "references/qualification-service-security-profile.candidate.json"
            ).read_bytes(),
            (
                EVIDENCE / "qualification-service-security-profile.candidate.json"
            ).read_bytes(),
        )
        self.assertEqual(
            (ROOT / "deploy/service/compose.preproduction.yaml").read_bytes(),
            (EVIDENCE / "compose.preproduction.yaml").read_bytes(),
        )
        self.assertEqual(
            (
                ROOT / "deploy/service/secret-bindings.preproduction.json"
            ).read_bytes(),
            (EVIDENCE / "secret-bindings.preproduction.json").read_bytes(),
        )

    def test_failed_attempts_are_preserved_without_overwriting_final_pass(self) -> None:
        statuses = {
            path.name: _read_path(path)["status"]
            for path in HISTORY.glob("runtime-result*.synthetic.json")
        }
        self.assertEqual("PASS", statuses["runtime-result.attempt-009.synthetic.json"])
        self.assertEqual("PASS", statuses["runtime-result.attempt-010.synthetic.json"])
        self.assertEqual("PASS", statuses["runtime-result.attempt-011.synthetic.json"])
        self.assertEqual("PASS", statuses["runtime-result.attempt-012.synthetic.json"])
        self.assertEqual("FAIL", statuses["runtime-result.synthetic.json"])
        self.assertEqual("FAIL", statuses["runtime-result.attempt-006.synthetic.json"])
        self.assertEqual("PASS", statuses["runtime-result.attempt-007.synthetic.json"])


def _read(name: str) -> dict:
    return _read_path(EVIDENCE / name)


def _read_path(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("qualification_service_evidence_invalid")
    return value


if __name__ == "__main__":
    unittest.main()

