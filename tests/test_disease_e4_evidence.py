from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from orbit_agent_control_plane.lifecycle import (
    AgentCandidate,
    SyntheticAgentLifecycleLedger,
)
from orbit_agent_control_plane.lifecycle_intake import (
    load_company_lifecycle_evaluation,
    load_verified_agent_release,
)
from orbit_agent_control_plane.registration import (
    _COMMON_SCHEMA_ID,
    HISTORICAL_ALPHA1_COMPANY_LOCK,
    HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
    _canonical_digest_without,
    _load_strict_yaml_bytes,
    _load_verified_company_schemas,
    _SchemaValidator,
    verify_registration_handoff,
)

ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_ROOT = ROOT.parent / "orbit-health-system" / "scientific-research-platform"
EVIDENCE = ROOT / "evidence" / "disease-agent-e4" / "2026-08-26"
HANDOFF = Path(
    "contracts/agents/disease-research-task-agent/registration/0.1.0/registration-handoff-manifest.json"
)
RELEASE = Path("evidence/disease-agent-e4/2026-08-26/agent-release.synthetic.yaml")
EVALUATION = Path(
    "evidence/disease-agent-e4/2026-08-26/company-evaluation.synthetic.yaml"
)
RELEASE_DIGEST = (
    "sha256:629d8d9b6997baf694b5856a526721ccd69bf71348c481c5c4dc6d909f62a0cb"
)
RESULT_DIGEST = (
    "sha256:580bdebdbf8b91362edc49785fc0255a8809fb781cc9003d25807e9e5f3ae11f"
)

VERIFY_SCRIPT = (
    ROOT
    / ".agents"
    / "skills"
    / "orbit-agent-lifecycle-review"
    / "scripts"
    / "verify_artifact_set.py"
)
SPEC = importlib.util.spec_from_file_location("disease_e4_artifact_review", VERIFY_SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFY_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY_MODULE)


def _digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


class DiseaseE4EvidenceTest(unittest.TestCase):
    def test_fixed_suite_matches_exact_runtime_evidence(self) -> None:
        result_path = EVIDENCE / "result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        suite = json.loads(
            (EVIDENCE / "disease-e4-suite.synthetic.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(RESULT_DIGEST, _digest(result_path))
        self.assertEqual("E4 synthetic pass", result["status"])
        self.assertEqual([], result["failed_checks"])
        self.assertEqual(set(suite["required_checks"]), set(result["checks"]))
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(suite["required_image_id"], result["image"]["id"])
        self.assertEqual(
            suite["required_runtime_source_digest"],
            result["runtime_source_digest"],
        )
        for field, expected in suite["required_authority_boundary"].items():
            self.assertEqual(expected, result[field])

    def test_release_and_evaluation_bind_exact_e4_bytes(self) -> None:
        registration = verify_registration_handoff(
            SCIENTIFIC_ROOT,
            HANDOFF,
            company_lock_path=HISTORICAL_ALPHA1_COMPANY_LOCK,
            contract_bundle_root=HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
        )
        release = load_verified_agent_release(
            ROOT,
            RELEASE,
            registration,
            required_evidence_refs=("evidence://synthetic/disease-agent/e4",),
            company_lock_path=HISTORICAL_ALPHA1_COMPANY_LOCK,
            contract_bundle_root=HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
        )
        self.assertEqual(RELEASE_DIGEST, release.release_digest)
        candidate = AgentCandidate(
            agent_id=registration.agent_id,
            release_digest=release.release_digest,
            definition_ref=registration.definition_ref,
            binding_ref=registration.binding_ref,
            owner_role_ref=registration.owner_role_ref,
            agent_system_ref="agent_system_orbit_research_syn",
            change_fields=("new_stable_agent", "purpose", "runtime"),
            structural_change=True,
        )
        evaluation = load_company_lifecycle_evaluation(
            ROOT,
            EVALUATION,
            RELEASE,
            candidate,
            release_root=ROOT,
            company_lock_path=HISTORICAL_ALPHA1_COMPANY_LOCK,
            contract_bundle_root=HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
        )
        self.assertEqual("pass", evaluation.verdict)
        self.assertEqual("recommend", evaluation.release_recommendation)
        self.assertFalse(evaluation.release_authorization)
        self.assertEqual(len(evaluation.evidence_refs), len(set(evaluation.evidence_refs)))
        with tempfile.TemporaryDirectory() as directory:
            ledger = SyntheticAgentLifecycleLedger(Path(directory) / "lifecycle.jsonl")
            ledger.register_candidate(candidate, idempotency_key="candidate:exact-e4")
            ledger.record_evaluation(
                evaluation, idempotency_key="evaluation:exact-e4"
            )
            self.assertEqual("evaluation", ledger.replay().agent(candidate.agent_id).status)

    def test_skill_review_closes_artifacts_without_authority(self) -> None:
        manifest = PurePosixPath(
            "evidence/disease-agent-e4/2026-08-26/activation-review-request.json"
        )
        reviewed = VERIFY_MODULE.verify(ROOT, manifest)
        self.assertEqual("PASS", reviewed["status"])
        self.assertEqual(7, len(reviewed["artifacts_checked"]))
        self.assertFalse(reviewed["release_authorization"])
        self.assertFalse(reviewed["activation_authorized"])

    def test_evaluation_audit_schema_and_integrity_close(self) -> None:
        audit_path = EVIDENCE / "company-evaluation-audit.synthetic.yaml"
        audit = _load_strict_yaml_bytes(audit_path.read_bytes())
        schema_id = "urn:company-ai-os:schema:audit-event:0.1"
        schemas, _, _ = _load_verified_company_schemas(
            HISTORICAL_ALPHA1_COMPANY_LOCK,
            HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
            {_COMMON_SCHEMA_ID, schema_id},
        )
        _SchemaValidator(schemas).validate(audit, schema_id)
        expected = "sha256:" + _canonical_digest_without(
            audit, ("spec", "integrity", "event_digest")
        )
        self.assertEqual(expected, audit["spec"]["integrity"]["event_digest"])


if __name__ == "__main__":
    unittest.main()

