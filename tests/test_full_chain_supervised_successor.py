from __future__ import annotations

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
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.models import Base
from orbit_agent_control_plane.service_runtime.public_pilot_execution import (
    preflight_public_pilot,
)

ROOT = Path(__file__).resolve().parents[1]
ALPHA2_SEMANTIC_AUTHORITY_LOCK_DIGEST = (
    "sha256:d055402d59b4feaea241dc36d23d255e35d39ca5661d72dea704433b7f6681af"
)
ALPHA2_CONCEPT_CATALOG_DIGEST = (
    "sha256:0d32597d5c1b4da6cfc511bb01da5c8f4a2266aa895edba2b7af3dc474119e0a"
)
ALPHA2_TERM_REGISTRY_DIGEST = (
    "sha256:c573c88b407145e07c7506402d744700703155fa2e5dd33ec6779be7a4fcf9ac"
)
EVIDENCE = ROOT / (
    "evidence/full-chain-pilot/"
    "2026-08-31-supervised-successor-semantic-alpha2"
)
def _read(name: str) -> dict:
    value = json.loads((EVIDENCE / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value

class FullChainSupervisedSuccessorTests(unittest.TestCase):
    def test_package_maps_existing_terms_and_preserves_historical_locks(self) -> None:
        review = _read("full-chain-pilot-review-package.json")
        content = {
            key: value
            for key, value in review.items()
            if key != "review_package_digest"
        }
        self.assertEqual(review["review_package_digest"], canonical_digest(content))
        self.assertEqual("awaiting_human_checkpoint", review["status"])
        self.assertEqual(
            "orbit.term/governed-release-pipeline",
            review["architecture_mapping"]["term_ref"],
        )
        self.assertEqual(
            ALPHA2_SEMANTIC_AUTHORITY_LOCK_DIGEST,
            review["architecture_mapping"]["semantic_authority_lock_digest"],
        )
        self.assertEqual(
            ALPHA2_CONCEPT_CATALOG_DIGEST,
            review["architecture_mapping"]["concept_catalog_digest"],
        )
        self.assertEqual(
            ALPHA2_TERM_REGISTRY_DIGEST,
            review["architecture_mapping"]["term_registry_digest"],
        )
        self.assertFalse(
            review["architecture_mapping"]["automation_supervisor_is_new_concept"]
        )
        self.assertTrue(
            review["architecture_mapping"][
                "execution_grant_is_only_task_authority"
            ]
        )
        self.assertEqual(4, review["disease"]["attempts_consumed_before"])
        self.assertEqual(1, review["disease"]["remaining_provider_backed_attempts"])
        self.assertTrue(review["human_checkpoint"]["required"])
        self.assertFalse(review["runtime_started"])
        self.assertFalse(review["release_authorization"])
        for name in (
            "disease-runtime-source-lock.public.json",
            "dataset-runtime-source-lock.public.json",
        ):
            lock = _read(name)
            lock_content = {
                key: value
                for key, value in lock.items()
                if key != "source_set_digest"
            }
            self.assertEqual(
                lock["source_set_digest"], canonical_digest(lock_content)
            )
            self.assertEqual(
                "orbit.full-chain-runtime-source-lock/1", lock["lock_version"]
            )
            self.assertFalse(lock["production_authorization"])
            self.assertFalse(lock["release_authorization"])
            self.assertTrue(lock["entries"])
            for entry in lock["entries"]:
                self.assertEqual({"repository", "path", "sha256"}, set(entry))
                self.assertTrue(entry["repository"])
                self.assertFalse(Path(entry["path"]).is_absolute())
                self.assertNotIn("..", Path(entry["path"]).parts)
                self.assertRegex(entry["sha256"], r"^sha256:[0-9a-f]{64}$")
        component = _read("managed-component.governed-release-pipeline.public.json")
        component_content = {
            key: value
            for key, value in component.items()
            if key != "descriptor_digest"
        }
        self.assertEqual(
            component["descriptor_digest"], canonical_digest(component_content)
        )
        self.assertEqual(
            "none", component["authority_boundary"]["authority_claim"]
        )

    def test_attempt_five_preflight_is_ready_but_non_effective(self) -> None:
        policy = _read("automation-policy.disease-r2.public.json")
        review = _read("full-chain-pilot-review-package.json")
        candidate = QualificationCandidate.from_mapping(
            _read("disease-qualification-candidate.attempt-005.public.json")
        )
        remediation = _read("runtime-remediation-manifest.json")
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
                review=review,
                enablement_receipt=receipt,
                candidates=(candidate,),
                private_key_pem=private_pem,
                public_key_pem=public_pem,
                runtime_adapter_digest="sha256:" + ("a" * 64),
                supervision_scope_ref=(
                    "execution-intent://" + review["execution_intent_digest"]
                ),
                verified_remediation={
                    "remediation_digest": remediation["manifest_digest"],
                    "runtime_source_digest": remediation[
                        "successor_runtime_source_base_digest"
                    ],
                    "regression_evidence_digest": canonical_digest(
                        remediation["offline_verification"]
                    ),
                },
                pilot_max_attempts=5,
                attempts_consumed_before=4,
            )
        self.assertEqual("ready", result["status"])
        self.assertEqual(4, result["attempts_consumed_before"])
        self.assertEqual(5, result["pilot_max_attempts"])
        self.assertEqual([candidate.attempt_id], result["attempts"])
        self.assertFalse(result["effective_task_created"])
        self.assertFalse(result["effective_grant_created"])
        self.assertEqual(0, result["provider_calls"])


if __name__ == "__main__":
    unittest.main()

