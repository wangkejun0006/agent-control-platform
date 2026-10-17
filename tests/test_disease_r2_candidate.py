import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "candidate_support"))

from disease_r2_candidate import (
    AGENT_RELEASE_DIGEST,
    ALLOWED_RETURNED_MODEL_IDS,
    CORPUS_REVISION,
    EXCHANGE_RATE_CNY_PER_USD,
    HARD_CAP_CNY,
    IMAGE_ID,
    LITERATURE_COLLECTOR_DIGEST,
    LITERATURE_TOOL_RELEASE_DIGEST,
    MODEL_GATEWAY_ORIGIN,
    MODEL_ROUTE_DIGEST,
    PUBLIC_CORPUS_FAILED_ATTEMPT_DIGEST,
    PUBLIC_CORPUS_MANIFEST_DIGEST,
    PUBLIC_CORPUS_RECEIPT_DIGEST,
    PUBLIC_CORPUS_REVIEW_DIGEST,
    DiseaseR2CandidateError,
    build_docker_command,
    build_minimal_bundle,
    company_evaluate_offline_result,
    digest_file,
    verify_cross_repo_sources,
)
from disease_r2_harness import describe_harness

from orbit_agent_control_plane.registration import (
    DEFAULT_COMPANY_LOCK,
    DEFAULT_CONTRACT_BUNDLE,
    _load_strict_yaml_bytes,
    _load_verified_company_schemas,
    _SchemaValidator,
)

SCIENTIFIC_ROOT = (
    ROOT.parent / "orbit-health-system" / "scientific-research-platform"
)
EVIDENCE_ROOT = ROOT / "evidence" / "disease-agent-r2" / "2026-08-26"


def load_json(name: str):
    return json.loads((EVIDENCE_ROOT / name).read_text())


def load_builder():
    source = ROOT / "scripts" / "build_disease_r2_candidate.py"
    spec = importlib.util.spec_from_file_location("disease_r2_builder_test", source)
    if spec is None or spec.loader is None:
        raise AssertionError("builder import unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DiseaseR2ControlCandidateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_json("review-package-manifest.json")
        cls.task = load_json("task-candidate.synthetic.json")
        cls.grant = load_json("execution-grant-candidate.synthetic.json")
        cls.composition = load_json(
            "runtime-composition-candidate.synthetic.json"
        )
        cls.runtime_source = load_json("runtime-source.lock.json")
        cls.offline = load_json("offline-result.synthetic.json")
        cls.public_request = load_json(
            "public-corpus-acquisition-review-request.json"
        )
        cls.builder = load_builder()
        cls.schemas, _, _ = _load_verified_company_schemas(
            DEFAULT_COMPANY_LOCK,
            DEFAULT_CONTRACT_BUNDLE,
            {
                "urn:company-ai-os:schema:agent-common:0.1",
                "urn:company-ai-os:schema:task:0.3",
                "urn:company-ai-os:schema:execution-grant:0.1",
                "urn:company-ai-os:schema:model-route:0.1",
            },
        )
        cls.validator = _SchemaValidator(cls.schemas)

    def validate(self, value, schema_id: str) -> None:
        self.validator.validate(value, schema_id)

    def test_materialized_package_is_exactly_reproducible(self) -> None:
        generated = self.builder.build(SCIENTIFIC_ROOT)
        for name, value in generated.items():
            with self.subTest(name=name):
                self.assertEqual(
                    (EVIDENCE_ROOT / name).read_bytes(),
                    self.builder.render_json(value),
                )
        self.assertEqual(
            (EVIDENCE_ROOT / "acceptance-report.zh-CN.md").read_text(),
            self.builder.acceptance_report(generated),
        )

    def test_manifest_file_digests_and_self_digest_close(self) -> None:
        for name, expected in self.manifest["artifacts"].items():
            with self.subTest(name=name):
                self.assertEqual(expected, digest_file(EVIDENCE_ROOT / name))
        canonical = copy.deepcopy(self.manifest)
        supplied = canonical.pop("review_package_digest")
        self.assertEqual(
            supplied,
            self.builder.digest_mapping(canonical),
        )
        self.assertEqual(
            self.manifest["status"],
            "R2 candidate prepared / awaiting human approval",
        )
        self.assertFalse(any(self.manifest["authority_boundary"].values()))

    def test_company_task_grant_and_model_route_validate(self) -> None:
        self.validate(
            self.task["company_task"],
            "urn:company-ai-os:schema:task:0.3",
        )
        self.validate(
            self.grant["company_contract_projection"],
            "urn:company-ai-os:schema:execution-grant:0.1",
        )
        route = _load_strict_yaml_bytes(
            (
                ROOT
                / "references"
                / "disease-r2"
                / "model-route.candidate.synthetic.yaml"
            ).read_bytes()
        )
        self.validate(route, "urn:company-ai-os:schema:model-route:0.1")
        self.assertEqual(route["metadata"]["status"], "draft")
        self.assertEqual(route["spec"]["fallback_route_refs"], [])
        self.assertEqual(route["spec"]["request_limits"]["max_retries"], 1)
        self.assertEqual(route["spec"]["request_limits"]["max_concurrency"], 1)
        self.assertEqual(route["spec"]["request_limits"]["timeout_seconds"], 30)
        gateway = json.loads(
            (
                ROOT
                / "references"
                / "disease-r2"
                / "model-gateway-boundary.candidate.synthetic.json"
            ).read_text()
        )
        profile = json.loads(
            (
                ROOT
                / "references"
                / "disease-r2"
                / "model-profile.fixture-fixture-structured-v1.synthetic.json"
            ).read_text()
        )
        self.assertEqual(gateway["origin"], MODEL_GATEWAY_ORIGIN)
        self.assertEqual(
            gateway["allowed_returned_model_ids"],
            list(ALLOWED_RETURNED_MODEL_IDS),
        )
        self.assertEqual(
            route["spec"]["endpoint_ref"]["digest"],
            digest_file(
                ROOT
                / "references"
                / "disease-r2"
                / "model-gateway-boundary.candidate.synthetic.json"
            ),
        )
        self.assertEqual(
            route["spec"]["model_refs"][0]["digest"],
            digest_file(
                ROOT
                / "references"
                / "disease-r2"
                / "model-profile.fixture-fixture-structured-v1.synthetic.json"
            ),
        )
        self.assertEqual(
            profile["cny_budget"]["exchange_rate_cny_per_usd"],
            EXCHANGE_RATE_CNY_PER_USD,
        )
        self.assertEqual(
            profile["cny_budget"]["hard_cap_cny"], HARD_CAP_CNY
        )

    def test_composition_pins_every_required_immutable_input(self) -> None:
        bindings = self.manifest["immutable_bindings"]
        self.assertEqual(bindings["agent_release_digest"], AGENT_RELEASE_DIGEST)
        self.assertEqual(bindings["model_route_digest"], MODEL_ROUTE_DIGEST)
        self.assertEqual(
            bindings["literature_tool_release_digest"],
            LITERATURE_TOOL_RELEASE_DIGEST,
        )
        self.assertEqual(bindings["public_corpus_revision"], CORPUS_REVISION)
        self.assertEqual(
            bindings["public_corpus_manifest_digest"],
            PUBLIC_CORPUS_MANIFEST_DIGEST,
        )
        self.assertEqual(
            bindings["public_corpus_receipt_digest"],
            PUBLIC_CORPUS_RECEIPT_DIGEST,
        )
        self.assertEqual(bindings["image_id"], IMAGE_ID)
        self.assertEqual(
            bindings["task_candidate_digest"],
            digest_file(EVIDENCE_ROOT / "task-candidate.synthetic.json"),
        )
        self.assertEqual(
            bindings["grant_candidate_digest"],
            digest_file(
                EVIDENCE_ROOT / "execution-grant-candidate.synthetic.json"
            ),
        )
        self.assertEqual(
            self.composition["composition_digest"],
            bindings["composition_digest"],
        )
        self.assertEqual(
            self.composition["grant"]["canonical_digest"],
            bindings["grant_canonical_digest"],
        )
        self.assertEqual(
            self.composition["runtime"]["max_lifetime_seconds"],
            900,
        )
        self.assertFalse(
            any(self.composition["authority_boundary"].values())
        )

    def test_cross_repo_release_and_runtime_hashes_are_exact(self) -> None:
        actual = verify_cross_repo_sources(ROOT, SCIENTIFIC_ROOT)
        self.assertEqual(actual["agent_release"], AGENT_RELEASE_DIGEST)
        self.assertEqual(
            actual["literature_tool_release"],
            LITERATURE_TOOL_RELEASE_DIGEST,
        )
        self.assertEqual(actual["model_route"], MODEL_ROUTE_DIGEST)
        self.assertEqual(
            actual["literature_collector"], LITERATURE_COLLECTOR_DIGEST
        )
        self.assertEqual(
            actual["public_corpus_manifest"],
            PUBLIC_CORPUS_MANIFEST_DIGEST,
        )
        self.assertEqual(actual["public_corpus_normalized"], CORPUS_REVISION)
        self.assertEqual(
            actual["public_corpus_receipt"],
            PUBLIC_CORPUS_RECEIPT_DIGEST,
        )
        self.assertEqual(
            actual["public_corpus_failed_attempt"],
            PUBLIC_CORPUS_FAILED_ATTEMPT_DIGEST,
        )
        entries = {
            item["role"]: item["digest"]
            for item in self.runtime_source["entries"]
        }
        self.assertEqual(
            entries["scientific_runtime"],
            actual["scientific_runtime"],
        )
        self.assertEqual(
            entries["scientific_worker"],
            actual["scientific_worker"],
        )
        self.assertEqual(
            entries["literature_collector"],
            actual["literature_collector"],
        )
        self.assertEqual(
            entries["control_candidate"],
            digest_file(
                ROOT
                / "candidate_support"
                / "disease_r2_candidate.py"
            ),
        )
        self.assertEqual(
            entries["docker_harness"],
            digest_file(
                ROOT
                / "candidate_support"
                / "disease_r2_harness.py"
            ),
        )
        self.assertFalse(
            any(self.runtime_source["authority_boundary"].values())
        )

    def test_docker_harness_only_constructs_restricted_command(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="orbit-r2-bundle-", dir="/private/tmp"
        ) as temporary:
            description = describe_harness(Path(temporary))
        command = description["command"]
        for pair in (
            ["--network", "none"],
            ["--read-only"],
            ["--user", "65532:65532"],
            ["--cap-drop", "ALL"],
            ["--security-opt", "no-new-privileges:true"],
            ["--pull", "never"],
        ):
            joined = " ".join(command)
            self.assertIn(" ".join(pair), joined)
        self.assertNotIn("--env-file", command)
        self.assertNotIn("/var/run/docker.sock", " ".join(command))
        self.assertEqual(description["status"], "command-construction-only")
        self.assertFalse(description["container_started"])
        with self.assertRaisesRegex(
            DiseaseR2CandidateError, "^bundle_not_ephemeral$"
        ):
            build_docker_command(Path("/var/empty/orbit-r2-bundle-test"))

    def test_minimal_bundle_has_no_endpoint_secret_path_or_authority(self) -> None:
        bindings = self.manifest["immutable_bindings"]
        bundle = build_minimal_bundle(
            task_digest=bindings["task_candidate_digest"],
            grant_digest=bindings["grant_canonical_digest"],
            composition_digest=bindings["composition_digest"],
            runtime_source_digest=bindings["runtime_source_digest"],
        )
        self.assertEqual(set(bundle), {"task-event.json"})
        serialized = bundle["task-event.json"].decode()
        for forbidden in (
            "credential",
            "secret",
            "endpoint",
            "/Users/",
            "/Volumes/",
            "opaque://",
            "smb://",
        ):
            self.assertNotIn(forbidden, serialized.lower())

    def test_independent_company_evaluation_and_drift_fail_closed(self) -> None:
        report = company_evaluate_offline_result(self.offline)
        self.assertEqual(report, load_json("company-evaluation.synthetic.json"))
        self.assertEqual(report["verdict"], "pass")
        self.assertFalse(report["release_authorization"])
        drift = copy.deepcopy(self.offline)
        drift["corpus_revision"] = "sha256:" + ("0" * 64)
        self.assertEqual(
            company_evaluate_offline_result(drift)["verdict"],
            "fail",
        )
        fabricated = copy.deepcopy(self.offline)
        fabricated["claims"][0]["evidence_refs"] = [
            "artifact://synthetic/literature/fabricated"
        ]
        self.assertEqual(
            company_evaluate_offline_result(fabricated)["verdict"],
            "fail",
        )

    def test_public_corpus_request_and_completed_freeze_are_exact(self) -> None:
        allowlist = self.public_request["network_allowlist"]
        self.assertEqual(
            allowlist["origin"], "https://eutils.ncbi.nlm.nih.gov"
        )
        self.assertEqual(
            allowlist["paths"],
            [
                "/entrez/eutils/esearch.fcgi",
                "/entrez/eutils/efetch.fcgi",
            ],
        )
        self.assertEqual(len(self.public_request["queries"]), 2)
        self.assertTrue(
            all(
                query["max_records"] == 4
                for query in self.public_request["queries"]
            )
        )
        limits = self.public_request["collection_limits"]
        self.assertEqual(limits["max_records_after_deduplication"], 8)
        self.assertEqual(limits["fulltext"], "forbidden")
        self.assertEqual(limits["nas"], "forbidden")
        self.assertEqual(limits["personal_medical_data"], "forbidden")
        self.assertFalse(
            any(self.public_request["authority_boundary"].values())
        )
        self.assertEqual(
            digest_file(
                EVIDENCE_ROOT
                / "public-corpus-acquisition-review-request.json"
            ),
            PUBLIC_CORPUS_REVIEW_DIGEST,
        )
        summary = load_json("skill-review-summary.json")
        collection = summary["public_corpus_collection"]
        self.assertEqual(collection["status"], "completed-read-only")
        self.assertEqual(collection["record_count"], 8)
        self.assertEqual(collection["total_approved_network_calls"], 6)
        self.assertFalse(collection["fulltext_collected"])
        self.assertFalse(collection["nas_accessed"])
        self.assertFalse(collection["external_model_called"])

    def test_approval_scopes_are_separate_and_configuration_is_closed(self) -> None:
        summary = load_json("skill-review-summary.json")
        self.assertEqual(
            summary["approval_scopes"],
            [
                "agent_activation",
                "tool_activation",
                "model_route_approval",
                "one_time_r2_execution",
            ],
        )
        self.assertFalse(summary["scope_conversion_allowed"])
        self.assertEqual(summary["missing_human_inputs"], [])
        self.assertIn(
            "Model Route is not approved",
            summary["execution_review_blockers"],
        )
        self.assertFalse(any(summary["authority_boundary"].values()))

    def test_r1_and_dataset_frozen_evidence_remain_published_bytes(self) -> None:
        expected = {
            "evidence/dataset-tools-d0/2026-08-25/acceptance-report.zh-CN.md":
                "0b038b53b530c8f12e8eb53a1cee894f6d1015c1507becda400b1dcc59af7f55",
            "evidence/dataset-tools-d0/2026-08-25/result.json":
                "0dfe9af3244c22ab3727c7a3786ddc2d2c3b862ad701f702db236215efd08e4b",
            "references/dataset-tool-d0-composition-lock.json":
                "1d4de535e82d6082ab957e8f03ba4af8c2822fa48875a37792f053f3cd071143",
            "evidence/dataset-tools-d0/2026-08-25/skill-review-summary.json":
                "72064a19b11937675cafc9bcf80c43a83445da141a73857af283c1328d183ade",
            "evidence/disease-agent-r1/2026-08-26/retry-004/result.json":
                "daafed4d9efca259a533c78573b2da9f54e0f65296c1131843dfd11c09ad0e0c",
        }
        for relative, expected_digest in expected.items():
            with self.subTest(relative=relative):
                actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(actual, expected_digest)


if __name__ == "__main__":
    unittest.main()

