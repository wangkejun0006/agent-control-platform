"""Build an exact, non-effective AutomationPolicy for Disease R2 qualification."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from orbit_agent_control_plane.qualification.automation import (
    BOUNDARY_NAMES,
    QualificationCandidate,
    canonical_digest,
    validate_automation_policy,
)
from orbit_agent_control_plane.qualification.service import (
    assess_production_readiness,
    validate_service_profile,
)

POLICY_CREATED_AT = "2026-08-27T13:00:00Z"
POLICY_EXPIRES_AT = "2026-09-03T13:00:00Z"
ARCHITECTURE_COMMIT = "bc7f21e67dbadd6aa618954fea4656b3387382f9"
ARCHITECTURE_TAG = "contract-v0.1.0-alpha.2"
ARCHITECTURE_RELEASE_MANIFEST_DIGEST = (
    "sha256:ffc9b78cda101e263dcbc0a60060cc48c5c11dec0eb1aba5aca50a74b489521a"
)
AGENT_ID = "agt_orbit_disease_research_task_syn"
AGENT_RELEASE = "sha256:e41c15f412b87c39654978a628ac7704b5cbbb2915f41b3b9d4426cf7aa4b04a"
TOOL_RELEASE = "sha256:775e2996c5302a28e24d2b8b7b104788e0a782688ba847ae63c8a8b729b48f0d"
MODEL_ROUTE = "sha256:8bc631ae8cf7fc7f2d07ac187eb5ca0d313de00818d77abfa7b2b4a04a5c74e7"
CORPUS_REVISION = "sha256:bb796b5aa76f930566e78c599eb197282595b26f2523f7b062374b7c261d6b30"
CORPUS_MANIFEST = "sha256:2af4bd9254b888670f6bf9b4932d6ac2ffd23d8874e5d44ea112485555135f08"
CORPUS_REVIEW = "sha256:aa1ead1dfa83cd93edbae0f995308ba90f1cfba3bb58ff5591fa80b1a3bd60e1"
CORPUS_RECEIPT = "sha256:4ed7fe1ebb52f586b87275f0127dc1df42f62e62fbb4fa8435c3eed356d35ec3"
IMAGE_ID = "sha256:f8f548d87d16634d1ad9e3777280f3f577ba2358703f04e18e74007ffd3621bf"
ENDPOINT = "https://models.paper-orbit.invalid/v1/chat/completions"
DOMAIN_SUITE_DIGEST = (
    "sha256:b472675c9990434510ec520d7c48a22a542ed23961e64e33b3074cba016d1c5b"
)
COMPANY_SUITE_DIGEST = (
    "sha256:044f954d8b4b2a2566cde5b4e82f4601ed5b3d85c2e776994f82b4842e3c562a"
)
ISOLATION_PROFILE_DIGEST = (
    "sha256:be699762f051fbf8e8d459027e2fef77dc033e7bb116014700f40d3d3f451b39"
)
EXPECTED_RAW_ARTIFACTS = {
    "approval-scope-bindings.synthetic.json": "sha256:3e368f0f187b82c00372238cfad4f8dba555250f15d44e5cdd60e8717c4933ac",
    "execution-intent.synthetic.json": "sha256:d77b373f94f41b80b1d005c84d167979f3819181ab4c447d099deac44260ac0c",
    "execution-review-package.json": "sha256:4f84f4a1fa2e63c09dbf325fd21a9cf847d9b5670c7118213745feebf25c0d54",
    "isolation-profile.synthetic.json": "sha256:c1a8c955c839da8d2842c76dc07b3981e1befc54a9dc17a4bfab0901a8c66a88",
    "price-observation.snapshot.synthetic.json": "sha256:86ceea4bd3829d2f885d2e37395c01b6919fa8676ed89389cfad05cd4809ee40",
    "runtime-composition-candidate.synthetic.json": "sha256:16f6bfd258f222308e713b36d9952754ab70f38c0621c269b4a3523808466377",
    "runtime-realization-candidate.synthetic.json": "sha256:3d575a5000046395e8209060f0f20838d24098c070f4b27683b3bd6839a927a2",
    "runtime-source-lock.json": "sha256:097f3b05350b6aee32457850479471b9a0bd50accfc54942f0f5dfbfff3de9ef",
    "task-candidate.synthetic.json": "sha256:9412e7c80353fbc0a8ad9ae41635d48eaab4e8d74543a392223c3ee95abb847d",
    "execution-grant-candidate.synthetic.json": "sha256:68ff97bff90fb05d94c8ae894d775463acda03d3bb96080013c88715fd0d0c47",
}
HANDLER_SOURCES = (
    ("component_qualification_policy_engine", "src/orbit_agent_control_plane/qualification/automation.py"),
    ("component_qualification_reconciler", "src/orbit_agent_control_plane/qualification/ledger.py"),
    ("component_qualification_service_gate", "src/orbit_agent_control_plane/qualification/service.py"),
    ("component_disease_r2_qualification_adapter", "candidate_support/disease_r2_qualification_adapter.py"),
    ("component_disease_r2_stage_hooks", "candidate_support/disease_r2_stage_hooks.py"),
    ("component_disease_r2_execution_worker", "candidate_support/disease_r2_execution_worker.py"),
    ("component_disease_r2_orchestrator", "candidate_support/disease_r2_orchestrator.py"),
)


class DiseaseR2AutomationPolicyError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def build_artifacts(
    *, repository_root: Path, evidence_root: Path, service_profile_path: Path
) -> dict[str, Any]:
    repository_root = repository_root.resolve(strict=True)
    evidence_root = evidence_root.resolve(strict=True)
    service_profile_path = service_profile_path.resolve(strict=True)
    review = _read_json(evidence_root / "execution-review-package.json")
    scopes = _read_json(evidence_root / "approval-scope-bindings.synthetic.json")
    _verify_predecessor(evidence_root=evidence_root, review=review, scopes=scopes)
    handlers = tuple(
        {
            "id": component_id,
            "version": "0.1.0",
            "digest": _digest_file(repository_root / source),
        }
        for component_id, source in HANDLER_SOURCES
    )
    service_profile = _read_json(service_profile_path)
    validate_service_profile(service_profile)
    readiness = assess_production_readiness(profile=service_profile, adapters=[])
    policy = _policy(review=review, handlers=handlers)
    validate_automation_policy(policy)
    candidate = _candidate(review=review, handlers=handlers)
    QualificationCandidate.from_mapping(candidate)
    return {
        "policy": policy,
        "candidate": candidate,
        "service_profile": service_profile,
        "service_readiness": {
            "assessment_version": "orbit.qualification-service-readiness/1",
            "status": readiness.status,
            "ready": readiness.ready,
            "profile_digest": readiness.profile_digest,
            "blocker_codes": list(readiness.blocker_codes),
            "verified_adapter_roles": list(readiness.verified_adapter_roles),
            "release_authorization": readiness.release_authorization,
        },
        "handler_bindings": handlers,
        "predecessor_review": review,
    }


def _policy(*, review: Mapping[str, Any], handlers: tuple[Mapping[str, str], ...]) -> dict[str, Any]:
    inputs = _input_bindings(review)
    return {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "AutomationPolicy",
        "metadata": {
            "policy_id": "pol_orbit_disease_r2_qualification_syn",
            "version": "0.1.0",
            "status": "candidate",
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "created_at": POLICY_CREATED_AT,
            "expires_at": POLICY_EXPIRES_AT,
        },
        "spec": {
            "purpose": "agent_release_qualification",
            "subject_constraints": {
                "agent_ids": [AGENT_ID],
                "release_states": ["active"],
                "runtime_families": ["framework_neutral_python_state_machine"],
                "data_classifications": ["synthetic", "public"],
            },
            "stage_plan": [
                "candidate_build",
                "contract_validation",
                "artifact_closure",
                "runtime_realization",
                "isolation_e4",
                "model_literature_r2",
                "domain_evaluation",
                "company_evaluation",
                "evidence_packaging",
                "formal_registration",
                "release_review",
                "preproduction_promotion",
                "production_promotion",
            ],
            "execution_envelope": {
                "model_route_refs": [
                    {
                        "role": "model_route",
                        "ref": "model-route://model_route_orbit_disease_r2_fixture_gpt56sol_syn/0.1.0",
                        "digest": MODEL_ROUTE,
                    }
                ],
                "tool_scopes": [
                    {
                        "tool_release": {
                            "role": "literature_tool_release",
                            "ref": "tool-release://tool_orbit_literature_public_corpus/0.1.0",
                            "digest": TOOL_RELEASE,
                        },
                        "operations": [
                            "fetch_public_record",
                            "search_public_corpus",
                        ],
                    }
                ],
                "input_artifact_allowlist": inputs,
                "endpoint_origin_allowlist": [ENDPOINT],
                "isolation_profile_digests": [ISOLATION_PROFILE_DIGEST],
                "trusted_stage_handlers": list(handlers),
                "evaluation_suite_refs": [
                    {
                        "role": "domain_evaluation_suite",
                        "ref": "artifact://scientific-platform/disease-r2/evaluation-suite/0.2.0",
                        "digest": DOMAIN_SUITE_DIGEST,
                    },
                    {
                        "role": "company_evaluation_suite",
                        "ref": "artifact://control-plane/disease-r2/evaluation-suite/0.2.0",
                        "digest": COMPANY_SUITE_DIGEST,
                    },
                ],
                "max_concurrency": 1,
                "max_attempts_per_stage": 3,
                "max_total_attempts": 30,
                "max_runtime_seconds": 900,
                "max_model_requests": 8,
                "max_input_tokens": 24000,
                "max_output_tokens": 2048,
                "max_cost_usd": "0.20",
                "max_cost_cny": "1.50",
                "agent_direct_network": False,
                "agent_credentials": False,
                "nas_access": False,
                "real_medical_data": False,
            },
            "remediation_envelope": {
                "allowed_failure_classes": [
                    "engineering_compatibility",
                    "deterministic_test_failure",
                    "transient_runtime",
                    "quality_candidate_revision",
                ],
                "source_change_policy": "implementation_only_same_runtime_family",
                "immutable_attempt_history": True,
                "independent_verification": True,
                "unchanged_boundaries": list(BOUNDARY_NAMES),
            },
            "human_checkpoint_triggers": [
                "purpose_or_owner_change",
                "capability_or_tool_scope_expansion",
                "data_classification_expansion",
                "provider_model_or_endpoint_change",
                "budget_ceiling_expansion",
                "isolation_or_identity_weakening",
                "real_data_or_nas_access",
                "risk_waiver_or_evaluation_override",
                "formal_registration",
                "preproduction_promotion",
                "production_promotion",
                "policy_budget_exhausted",
            ],
            "authority_boundary": {
                "may_issue_evaluation_grant": True,
                "may_activate_agent": False,
                "may_activate_tool": False,
                "may_approve_model_route": False,
                "may_register_formally": False,
                "may_promote_preproduction": False,
                "may_promote_production": False,
                "release_authorization": False,
            },
        },
    }


def _candidate(*, review: Mapping[str, Any], handlers: tuple[Mapping[str, str], ...]) -> dict[str, Any]:
    input_digests = tuple(item["digest"] for item in _input_bindings(review))
    boundary_values = {
        "purpose": "fictional_stationery_public_literature_synthesis_r2",
        "owner": "role_scientific_research_owner",
        "agent_id": AGENT_ID,
        "capabilities": ["model.invoke", "literature.fetch", "literature.search"],
        "tool_operations": ["fetch_public_record", "search_public_corpus"],
        "data_classification": ["synthetic", "public"],
        "model_route": MODEL_ROUTE,
        "endpoint_allowlist": [ENDPOINT],
        "budget_ceiling": review["budget"],
        "isolation_profile": ISOLATION_PROFILE_DIGEST,
        "external_side_effects": {
            "agent_direct_network": False,
            "agent_credentials": False,
            "nas_access": False,
            "real_medical_data": False,
        },
    }
    return {
        "attempt_id": review["attempt_id"],
        "attempt_number": 4,
        "agent_id": AGENT_ID,
        "release_state": "active",
        "agent_release_ref": "agent-release://agt_orbit_disease_research_task_syn/0.2.0",
        "agent_release_digest": AGENT_RELEASE,
        "runtime_family": "framework_neutral_python_state_machine",
        "runtime_source_digest": review["runtime_source_digest"],
        "composition_ref": "composition://orbit_disease_r2/v4_attempt_004",
        "composition_digest": review["composition_candidate_digest"],
        "task_ref": "task://orbit_disease_r2/v4_attempt_004",
        "task_digest": review["task_candidate_digest"],
        "grant_candidate_ref": "grant://orbit_disease_r2/v4_attempt_004_candidate",
        "grant_candidate_digest": review["grant_canonical_digest"],
        "data_classification": "public",
        "model_route_digest": MODEL_ROUTE,
        "tool_operations": (
            f"{TOOL_RELEASE}#fetch_public_record",
            f"{TOOL_RELEASE}#search_public_corpus",
        ),
        "endpoint_origins": (ENDPOINT,),
        "input_artifact_digests": input_digests,
        "isolation_profile_digest": ISOLATION_PROFILE_DIGEST,
        "stage_handler_digests": tuple(item["digest"] for item in handlers),
        "evaluation_suite_digests": (DOMAIN_SUITE_DIGEST, COMPANY_SUITE_DIGEST),
        "max_model_requests": 8,
        "max_input_tokens": 24000,
        "max_output_tokens": 2048,
        "max_cost_usd": "0.20",
        "max_cost_cny": "1.50",
        "max_runtime_seconds": 900,
        "agent_direct_network": False,
        "agent_credentials": False,
        "nas_access": False,
        "real_medical_data": False,
        "boundary_digests": {
            name: canonical_digest(boundary_values[name]) for name in BOUNDARY_NAMES
        },
    }


def _input_bindings(review: Mapping[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "role": "agent_release",
            "ref": "agent-release://agt_orbit_disease_research_task_syn/0.2.0",
            "digest": AGENT_RELEASE,
        },
        {
            "role": "public_corpus_revision",
            "ref": "dataset://public/disease-r2/fictional-stationery-literature/0.1.0",
            "digest": CORPUS_REVISION,
        },
        {
            "role": "public_corpus_manifest",
            "ref": "artifact://public-corpus/disease-r2/manifest/0.1.0",
            "digest": CORPUS_MANIFEST,
        },
        {
            "role": "corpus_acquisition_review",
            "ref": "approval://public-corpus/disease-r2/acquisition-review",
            "digest": CORPUS_REVIEW,
        },
        {
            "role": "corpus_acquisition_receipt",
            "ref": "receipt://public-corpus/disease-r2/acquisition",
            "digest": CORPUS_RECEIPT,
        },
        {
            "role": "r2_execution_review_package",
            "ref": "artifact://control-plane/disease-r2/v4-attempt-004/review-package",
            "digest": EXPECTED_RAW_ARTIFACTS["execution-review-package.json"],
        },
        {
            "role": "r2_execution_intent",
            "ref": "artifact://control-plane/disease-r2/v4-attempt-004/execution-intent",
            "digest": EXPECTED_RAW_ARTIFACTS["execution-intent.synthetic.json"],
        },
        {
            "role": "approval_scope_ledger_snapshot",
            "ref": "ledger://disease-r2/approval-scopes/v4-attempt-004",
            "digest": EXPECTED_RAW_ARTIFACTS["approval-scope-bindings.synthetic.json"],
        },
        {
            "role": "price_observation",
            "ref": "artifact://control-plane/disease-r2/price-observation/2026-08-27",
            "digest": EXPECTED_RAW_ARTIFACTS["price-observation.snapshot.synthetic.json"],
        },
        {
            "role": "container_image_id",
            "ref": "runtime://nousresearch/hermes-agent/v2026.8.16",
            "digest": IMAGE_ID,
        },
    ]


def _verify_predecessor(
    *, evidence_root: Path, review: Mapping[str, Any], scopes: Mapping[str, Any]
) -> None:
    for relative, expected in EXPECTED_RAW_ARTIFACTS.items():
        if _digest_file(evidence_root / relative) != expected:
            raise DiseaseR2AutomationPolicyError("r2_predecessor_artifact_drift")
    expected_review = {
        "attempt_id": "attempt_orbit_disease_r2_v4_004_syn",
        "review_package_digest": "sha256:91e306cce150fda26ba6d046bf72bb641caeb5e12954df7332e10387b9dca49c",
        "runtime_source_digest": "sha256:9be1eec96939ae790b4a388226092941caa4033efde8c4973955b9587ec0729c",
        "composition_candidate_digest": "sha256:53ec2355a4e84bed6405cac3bb233248b83fb071d81a7520f0a0aac2aec9c1cf",
        "task_candidate_digest": "sha256:34e19ea46d3330d37b6a6cd27e87a5c162740f54abf978a79a1e999704d27684",
        "grant_canonical_digest": "sha256:ac7129c6071acf2d9824d988aba0e8b2b6eb2f6b2078d3f8fd828d67978d445d",
        "runtime_realization_digest": "sha256:d4d6778a49273415526b049519e758873f146afce5b13b45f27fca1c0476b5a6",
        "corpus_revision": CORPUS_REVISION,
        "corpus_manifest_digest": CORPUS_MANIFEST,
        "corpus_acquisition_review_digest": CORPUS_REVIEW,
        "corpus_acquisition_receipt_digest": CORPUS_RECEIPT,
        "image_id": IMAGE_ID,
        "price_observation_digest": "sha256:0bf6cd2540a9cf655aefb19064746aba68353cb504bc61923f64b4c87eaf072a",
    }
    if any(review.get(key) != value for key, value in expected_review.items()):
        raise DiseaseR2AutomationPolicyError("r2_predecessor_semantic_drift")
    scope_by_kind = {item["scope_kind"]: item for item in scopes.get("scopes", [])}
    expected_scopes = {
        "agent_activation": (AGENT_RELEASE, "applied"),
        "tool_activation": (TOOL_RELEASE, "applied"),
        "model_route_approval": (MODEL_ROUTE, "approved_unconsumed"),
        "r2_execution": (
            "sha256:0b654bc3b06a54e96585f05eeab4d5e2f61eb57052ffb00041002d7afb45c5b2",
            "pending",
        ),
    }
    if set(scope_by_kind) != set(expected_scopes):
        raise DiseaseR2AutomationPolicyError("r2_scope_ledger_drift")
    for kind, (digest, status) in expected_scopes.items():
        if (
            scope_by_kind[kind].get("subject_digest") != digest
            or scope_by_kind[kind].get("current_status") != status
        ):
            raise DiseaseR2AutomationPolicyError("r2_scope_ledger_drift")


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise DiseaseR2AutomationPolicyError("r2_policy_input_missing")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiseaseR2AutomationPolicyError("r2_policy_input_invalid") from error
    if not isinstance(value, dict):
        raise DiseaseR2AutomationPolicyError("r2_policy_input_invalid")
    return value


def _digest_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise DiseaseR2AutomationPolicyError("r2_policy_source_missing")
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def safe_output_name(value: str) -> PurePosixPath:
    result = PurePosixPath(value)
    if result.is_absolute() or ".." in result.parts or str(result) != value:
        raise DiseaseR2AutomationPolicyError("r2_policy_output_path_invalid")
    return result

