from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from orbit_agent_control_plane.qualification.automation import (
    QualificationCandidate,
    canonical_digest,
    validate_automation_policy,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.models import Base
from orbit_agent_control_plane.service_runtime.public_pilot_execution import (
    preflight_public_pilot,
)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/full-chain-pilot/2026-08-29"
SUCCESSOR = ROOT / "evidence/full-chain-pilot/2026-08-29-successor"
DATASET_SUCCESSOR = ROOT / "evidence/full-chain-pilot/2026-08-29-dataset-successor"
GOVERNED_SUCCESSOR = (
    ROOT / "evidence/full-chain-pilot/2026-08-29-governed-successor"
)
REPOSITORIES = {
    "orbit-agent-control-plane": ROOT,
    "dataset-acquisition-registry": ROOT.parent
    / (
        "orbit-health-system/capabilities/data-asset-foundation/"
        "dataset-acquisition-registry"
    ),
    "scientific-research-platform": ROOT.parent
    / "orbit-health-system/scientific-research-platform",
}


def _read(name: str) -> dict:
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


def _raw(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class FullChainPilotReviewTests(unittest.TestCase):
    def test_review_and_runtime_sources_close_without_effective_authority(self) -> None:
        review_path = EVIDENCE / "full-chain-pilot-review-package.json"
        review = _read(review_path.name)
        content = {
            key: value for key, value in review.items() if key != "review_package_digest"
        }
        self.assertEqual(review["review_package_digest"], canonical_digest(content))
        self.assertFalse(review["runtime_started"])
        self.assertFalse(review["provider_called"])
        self.assertFalse(review["physionet_called"])
        self.assertFalse(review["release_authorization"])
        self.assertEqual("hold", review["lifecycle_assurance"])
        self.assertEqual(5, review["disease"]["attempt_budget"]["max_attempts"])
        self.assertEqual(
            "fixture-structured-v1-2026-07-09",
            review["disease"]["required_resolved_model_id"],
        )
        self.assertEqual(2, len(review["dataset"]["resources"]))
        self.assertFalse(review["dataset"]["raw_psg_edf_download_authorized"])
        self.assertFalse(review["cross_chain"]["disease_can_call_dataset_tools"])
        self.assertFalse(review["cross_chain"]["dataset_can_call_model_or_literature"])
        prompt = (EVIDENCE / "approval-prompt.zh-CN.md").read_text(encoding="utf-8")
        self.assertIn(_raw(review_path), prompt)
        self.assertIn(review["review_package_digest"], prompt)

        remediation = _read("disease-run-002-failure.public.json")
        source_changes = {
            item["path"]: item
            for item in remediation["engineering_remediation"]["source_changes"]
        }
        for name in (
            "disease-runtime-source-lock.public.json",
            "dataset-runtime-source-lock.public.json",
        ):
            lock = _read(name)
            source_content = {
                key: value for key, value in lock.items() if key != "source_set_digest"
            }
            self.assertEqual(lock["source_set_digest"], canonical_digest(source_content))
            for entry in lock["entries"]:
                self.assertIn(entry["repository"], REPOSITORIES)
                self.assertFalse(Path(entry["path"]).is_absolute())
                change = source_changes.get(entry["path"])
                if name == "disease-runtime-source-lock.public.json" and change:
                    self.assertEqual(entry["sha256"], change["predecessor_sha256"])
        self.assertFalse(
            remediation["engineering_remediation"]["permission_boundary_changed"]
        )
        self.assertEqual(
            "R2 provider-backed public-corpus blocked", remediation["status"]
        )
        self.assertFalse(remediation["dataset_execution_started"])

        attempt_2 = json.loads(
            (DATASET_SUCCESSOR / "attempt-002/remediation-manifest.json").read_text()
        )
        attempt_3 = json.loads(
            (DATASET_SUCCESSOR / "attempt-003/remediation-manifest.json").read_text()
        )
        attempt_4 = json.loads(
            (DATASET_SUCCESSOR / "attempt-004/remediation-manifest.json").read_text()
        )
        dataset_lock = _read("dataset-runtime-source-lock.public.json")
        self.assertEqual(
            dataset_lock["source_set_digest"],
            attempt_2["predecessor_runtime_source_digest"],
        )
        self.assertEqual(
            attempt_2["successor_runtime_source_digest"],
            attempt_3["predecessor_runtime_source_digest"],
        )
        self.assertEqual(
            attempt_3["successor_runtime_source_digest"],
            attempt_4["predecessor_runtime_source_digest"],
        )
        current_lock = json.loads(
            (
                DATASET_SUCCESSOR
                / "attempt-004/dataset-runtime-source-lock.public.json"
            ).read_text()
        )
        current_content = {
            key: value
            for key, value in current_lock.items()
            if key != "source_set_digest"
        }
        self.assertEqual(
            current_lock["source_set_digest"], canonical_digest(current_content)
        )

    def test_successor_binds_two_exact_ids_and_current_runtime_bytes(self) -> None:
        review_path = SUCCESSOR / "full-chain-pilot-review-package.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        content = {
            key: value for key, value in review.items() if key != "review_package_digest"
        }
        self.assertEqual(review["review_package_digest"], canonical_digest(content))
        self.assertEqual(
            ["fixture-structured-v1-2026-07-09", "fixture-structured-v1"],
            review["disease"]["allowed_resolved_model_ids"],
        )
        prompt = (SUCCESSOR / "approval-prompt.zh-CN.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(_raw(review_path), prompt)
        self.assertIn(review["review_package_digest"], prompt)
        policy = json.loads(
            (SUCCESSOR / "automation-policy.disease-r2.public.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            1, policy["spec"]["execution_envelope"]["max_attempts_per_stage"]
        )
        self.assertEqual(
            5, policy["spec"]["execution_envelope"]["max_total_attempts"]
        )
        expected_operations = {
            (
                "sha256:775e2996c5302a28e24d2b8b7b104788e0a782688ba847ae63c8a8b729b48f0d"
                "#search_public_corpus"
            ),
            (
                "sha256:775e2996c5302a28e24d2b8b7b104788e0a782688ba847ae63c8a8b729b48f0d"
                "#fetch_public_record"
            ),
        }
        for number in range(1, 6):
            candidate = json.loads(
                (
                    SUCCESSOR
                    / f"disease-qualification-candidate.attempt-{number:03d}.public.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(expected_operations, set(candidate["tool_operations"]))
        lock = json.loads(
            (SUCCESSOR / "disease-runtime-source-lock.public.json").read_text(
                encoding="utf-8"
            )
        )
        lock_content = {
            key: value for key, value in lock.items() if key != "source_set_digest"
        }
        self.assertEqual(lock["source_set_digest"], canonical_digest(lock_content))
        self.assertFalse(review["runtime_started"])
        self.assertFalse(review["release_authorization"])

    def test_governed_successor_binds_current_runtime_and_signed_dataset_grant(self) -> None:
        review_path = GOVERNED_SUCCESSOR / "full-chain-pilot-review-package.json"
        review = json.loads(review_path.read_text(encoding="utf-8"))
        content = {
            key: value for key, value in review.items() if key != "review_package_digest"
        }
        self.assertEqual(review["review_package_digest"], canonical_digest(content))
        self.assertEqual(
            ["fixture-structured-v1-2026-07-09", "fixture-structured-v1"],
            review["disease"]["allowed_resolved_model_ids"],
        )
        self.assertEqual(
            "control_plane_signed_before_network_and_verified_by_acquisition_adapter",
            review["dataset"]["execution_grant_enforcement"],
        )
        self.assertEqual(
            "control_plane_persisted_and_terminally_closed",
            review["dataset"]["worker_lease_enforcement"],
        )
        self.assertFalse(
            review["automation_checkpoint_semantics"][
                "execution_stop_is_human_approval"
            ]
        )
        self.assertEqual(
            "pause_for_verified_machine_remediation",
            review["automation_checkpoint_semantics"][
                "same_unrepaired_failure_twice"
            ],
        )
        for name in (
            "disease-runtime-source-lock.public.json",
            "dataset-runtime-source-lock.public.json",
        ):
            lock = json.loads((GOVERNED_SUCCESSOR / name).read_text())
            source_content = {
                key: value for key, value in lock.items() if key != "source_set_digest"
            }
            self.assertEqual(lock["source_set_digest"], canonical_digest(source_content))
            for entry in lock["entries"]:
                self.assertIn(entry["repository"], REPOSITORIES)
                self.assertFalse(Path(entry["path"]).is_absolute())
                self.assertRegex(entry["sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertFalse(review["runtime_started"])
        self.assertFalse(review["release_authorization"])

    def test_five_disease_candidates_are_policy_bounded_and_preflight_only(self) -> None:
        policy = _read("automation-policy.disease-r2.public.json")
        review = _read("full-chain-pilot-review-package.json")
        validate_automation_policy(policy)
        candidates = tuple(
            QualificationCandidate.from_mapping(
                _read(f"disease-qualification-candidate.attempt-{number:03d}.public.json")
            )
            for number in range(1, 6)
        )
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        now = datetime.now(timezone.utc).replace(microsecond=0)
        receipt = {
            "review_package_digest": review["review_package_digest"],
            "automation_policy_digest": canonical_digest(policy),
            "activated_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=15))
            .isoformat()
            .replace("+00:00", "Z"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            database_url = f"sqlite+pysqlite:///{Path(temporary) / 'state.sqlite3'}"
            database = Database(database_url)
            Base.metadata.create_all(database.engine)
            database.dispose()
            result = preflight_public_pilot(
                database_url=database_url,
                policy=policy,
                review={
                    "automation_policy_digest": canonical_digest(policy),
                    "review_package_digest": review["review_package_digest"],
                },
                enablement_receipt=receipt,
                candidates=candidates,
                private_key_pem=private_pem,
                public_key_pem=public_pem,
                runtime_adapter_digest="sha256:" + "a" * 64,
            )
        self.assertEqual("ready", result["status"])
        self.assertEqual(5, len(result["attempts"]))
        self.assertFalse(result["effective_task_created"])
        self.assertFalse(result["effective_grant_created"])
        self.assertEqual(0, result["provider_calls"])

    def test_lifecycle_review_v2_has_one_pending_human_checkpoint(self) -> None:
        manifest = _read("skill-artifact-set.json")
        self.assertEqual(
            "orbit.lifecycle-review-artifact-set/2", manifest["manifest_version"]
        )
        scopes = manifest["digest_bindings"]["pending_approval_scopes"]
        self.assertEqual(5, len(scopes))
        self.assertEqual([], manifest["digest_bindings"]["approval_receipts"])
        self.assertFalse(manifest["activation_authorized"])
        self.assertFalse(manifest["runtime_started"])
        for artifact in manifest["artifacts"]:
            self.assertEqual(artifact["sha256"], _raw(ROOT / artifact["path"]))


if __name__ == "__main__":
    unittest.main()

