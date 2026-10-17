from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from candidate_support.disease_r2_automation_policy import (
    AGENT_RELEASE,
    ARCHITECTURE_COMMIT,
    ARCHITECTURE_RELEASE_MANIFEST_DIGEST,
    ARCHITECTURE_TAG,
    CORPUS_REVISION,
    ENDPOINT,
    MODEL_ROUTE,
    TOOL_RELEASE,
    build_artifacts,
)
from orbit_agent_control_plane.qualification.automation import (
    QualificationCandidate,
    canonical_digest,
    validate_automation_policy,
)
from orbit_agent_control_plane.registration import _SchemaValidator

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (
    ROOT
    / "evidence"
    / "disease-agent-r2"
    / "2026-08-27-execution-remediation-v4-attempt-004"
)
PROFILE = ROOT / "references" / "qualification-service-profile.candidate.json"
BUNDLE = (
    ROOT
    / "packages"
    / "agent-authoring-toolkit"
    / "contract-bundles"
    / "contract-v0.1.0-alpha.2"
)


class DiseaseR2AutomationPolicyTests(unittest.TestCase):
    def test_policy_binds_real_r2_artifacts_and_stays_non_effective(self) -> None:
        built = build_artifacts(
            repository_root=ROOT,
            evidence_root=EVIDENCE,
            service_profile_path=PROFILE,
        )
        policy = built["policy"]
        validate_automation_policy(policy)
        candidate = QualificationCandidate.from_mapping(built["candidate"])
        self.assertEqual(AGENT_RELEASE, candidate.agent_release_digest)
        self.assertEqual(MODEL_ROUTE, candidate.model_route_digest)
        self.assertIn(CORPUS_REVISION, candidate.input_artifact_digests)
        self.assertEqual((ENDPOINT,), candidate.endpoint_origins)
        self.assertEqual(
            {
                f"{TOOL_RELEASE}#fetch_public_record",
                f"{TOOL_RELEASE}#search_public_corpus",
            },
            set(candidate.tool_operations),
        )
        self.assertFalse(policy["spec"]["authority_boundary"]["release_authorization"])
        self.assertFalse(built["service_readiness"]["ready"])
        self.assertEqual("not_ready", built["service_readiness"]["status"])

    def test_policy_validates_against_published_alpha2_schema(self) -> None:
        built = build_artifacts(
            repository_root=ROOT,
            evidence_root=EVIDENCE,
            service_profile_path=PROFILE,
        )
        lock = json.loads((BUNDLE / "bundle-lock.json").read_text(encoding="utf-8"))
        authority = lock["authority"]
        self.assertEqual(ARCHITECTURE_TAG, authority["contract_release_id"])
        self.assertEqual(ARCHITECTURE_TAG, authority["contract_git_tag"])
        self.assertEqual(ARCHITECTURE_COMMIT, authority["contract_git_commit"])
        self.assertEqual(
            ARCHITECTURE_RELEASE_MANIFEST_DIGEST,
            authority["release_manifest_sha256"],
        )
        schemas = {}
        for item in lock["released_schemas"]:
            schema = json.loads(
                (BUNDLE / item["bundle_path"]).read_text(encoding="utf-8")
            )
            schemas[schema["$id"]] = schema
        _SchemaValidator(schemas).validate(
            built["policy"], "urn:company-ai-os:schema:automation-policy:0.1"
        )

    def test_builder_generates_review_only_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "build_disease_r2_automation_policy.py"),
                    "--output",
                    directory,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual("PASS", result["status"])
            self.assertFalse(result["effective"])
            self.assertFalse(result["release_authorization"])
            review = json.loads(
                (Path(directory) / "automation-policy-review-package.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(review["authority_boundary"]["runtime_started"])
            manifest = json.loads(
                (Path(directory) / "skill-artifact-set.json").read_text(encoding="utf-8")
            )
            summary = json.loads(
                (Path(directory) / "skill-review-summary.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual("PASS", summary["status"])
            self.assertFalse(summary["effective"])
            self.assertEqual(
                ["automation_policy_activation"],
                manifest["digest_bindings"]["pending_approval_scopes"],
            )
            self.assertEqual(
                canonical_digest(
                    json.loads(
                        (Path(directory) / "automation-policy.disease-r2.synthetic.json").read_text(
                            encoding="utf-8"
                        )
                    )
                ),
                result["policy_digest"],
            )


if __name__ == "__main__":
    unittest.main()

