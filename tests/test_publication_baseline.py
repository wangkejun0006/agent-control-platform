from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.dataset_evidence_acceptance import (
    SyntheticDatasetEvidenceAcceptanceLedger,
)
from orbit_agent_control_plane.ledger import SyntheticTaskLedger
from orbit_agent_control_plane.lifecycle import SyntheticAgentLifecycleLedger
from orbit_agent_control_plane.registration import SyntheticAgentRegistrationLedger


ROOT = Path(__file__).resolve().parents[1]
BASELINE_ROOT = ROOT / "evidence/publication-baseline/2026-08-26"
MANIFEST = BASELINE_ROOT / "publication-baseline.synthetic.json"
DISEASE_AGENT_ID = "agt_orbit_disease_research_task_syn"
RETRY_003_TASK_ID = "tsk_orbit_disease_stationery_r1_retry3_syn"
RETRY_004_TASK_ID = "tsk_orbit_disease_stationery_r1_retry4_syn"
FORBIDDEN = re.compile(
    r"/Users/|/Volumes/|(?:file|smb|opaque)://|docker\.sock|"
    r"(?:api[ _-]?key|credential|secret)",
    re.IGNORECASE,
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _owner_only_copy(source: Path, destination: Path) -> Path:
    destination.write_bytes(source.read_bytes())
    os.chmod(destination, 0o600)
    return destination


class PublicationBaselineTest(unittest.TestCase):
    def test_manifest_binds_exact_safe_artifact_bytes(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            "orbit.synthetic-publication-baseline/1",
            manifest["baseline_version"],
        )
        self.assertTrue(manifest["synthetic_only"])
        self.assertEqual("synthetic", manifest["evidence_status"])
        self.assertFalse(manifest["authority_boundary"]["company_authoritative"])
        self.assertFalse(manifest["authority_boundary"]["release_authorization"])
        self.assertFalse(manifest["authority_boundary"]["preproduction_authorized"])
        self.assertFalse(manifest["authority_boundary"]["production_authorized"])
        roles: set[str] = set()
        for artifact in manifest["artifacts"]:
            relative = Path(artifact["path"])
            with self.subTest(role=artifact["role"]):
                self.assertFalse(relative.is_absolute())
                self.assertNotIn("..", relative.parts)
                self.assertNotIn(artifact["role"], roles)
                roles.add(artifact["role"])
                path = ROOT / relative
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
                self.assertEqual(artifact["sha256"], _digest(path))

    def test_published_snapshots_replay_to_exact_terminal_states(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            dataset = SyntheticDatasetEvidenceAcceptanceLedger(
                _owner_only_copy(
                    BASELINE_ROOT
                    / "dataset-d0-evidence-acceptance.snapshot.synthetic.jsonl",
                    destination / "dataset-acceptance.jsonl",
                )
            ).replay()
            self.assertEqual(1, dataset.records_checked)
            self.assertEqual(
                "D0 synthetic active",
                dataset.acceptances[0]["accepted_status_ceiling"],
            )
            self.assertEqual(
                "hold",
                dataset.acceptances[0]["lifecycle_assurance_recommendation"],
            )
            self.assertFalse(dataset.acceptances[0]["release_authorization"])

            registration = SyntheticAgentRegistrationLedger(
                _owner_only_copy(
                    BASELINE_ROOT / "disease-registration.snapshot.synthetic.jsonl",
                    destination / "registration.jsonl",
                )
            ).replay()
            latest = registration.registrations[-1]
            self.assertEqual(2, registration.records_checked)
            self.assertEqual("draft", latest["registration_status"])
            self.assertFalse(latest["company_authoritative"])
            self.assertFalse(latest["formal_registry_record_exists"])
            self.assertFalse(latest["activation_authorized"])

            lifecycle = SyntheticAgentLifecycleLedger(
                _owner_only_copy(
                    BASELINE_ROOT / "disease-lifecycle.snapshot.synthetic.jsonl",
                    destination / "lifecycle.jsonl",
                )
            ).replay()
            disease = lifecycle.agent(DISEASE_AGENT_ID)
            self.assertEqual("active", disease.status)
            self.assertEqual(2, disease.revision)
            self.assertIsNotNone(disease.evaluation)
            self.assertFalse(disease.evaluation.release_authorization)

            retry_003 = SyntheticTaskLedger(
                _owner_only_copy(
                    BASELINE_ROOT
                    / "disease-r1-retry-003-task.snapshot.synthetic.jsonl",
                    destination / "retry-003.jsonl",
                )
            ).replay().task(RETRY_003_TASK_ID)
            self.assertEqual("fail", retry_003.disease_r1_outcome["status"])
            self.assertEqual("failed", retry_003.worker_lease.status)
            self.assertEqual(1, retry_003.worker_lease.revision)

            retry_004 = SyntheticTaskLedger(
                _owner_only_copy(
                    BASELINE_ROOT
                    / "disease-r1-retry-004-task.snapshot.synthetic.jsonl",
                    destination / "retry-004.jsonl",
                )
            ).replay().task(RETRY_004_TASK_ID)
            self.assertEqual("pass", retry_004.disease_r1_outcome["status"])
            self.assertEqual("completed", retry_004.worker_lease.status)
            self.assertEqual(1, retry_004.worker_lease.revision)
            self.assertFalse(
                retry_004.disease_r1_outcome["release_authorization"]
            )

    def test_snapshots_are_sanitized_publication_copies(self) -> None:
        for path in BASELINE_ROOT.glob("*.jsonl"):
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
                self.assertIsNone(FORBIDDEN.search(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()

