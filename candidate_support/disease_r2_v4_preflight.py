"""Fail-closed static preflight for the immutable Disease R2 v4 candidate.

This module validates references and receipts.  It does not issue an approval,
make a grant effective, call a model, access a corpus backend, or start Docker.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

CANONICALIZATION = "orbit.canonical-json/1.0"
EXPECTED_ENDPOINT = "https://models.paper-orbit.invalid/v1/chat/completions"
EXPECTED_MODEL = "fixture-structured-v1"
EXPECTED_CORPUS_REVISION = (
    "sha256:bb796b5aa76f930566e78c599eb197282595b26f2523f7b062374b7c261d6b30"
)
EXPECTED_CORPUS_MANIFEST = (
    "sha256:2af4bd9254b888670f6bf9b4932d6ac2ffd23d8874e5d44ea112485555135f08"
)
EXPECTED_CORPUS_REVIEW = (
    "sha256:aa1ead1dfa83cd93edbae0f995308ba90f1cfba3bb58ff5591fa80b1a3bd60e1"
)
EXPECTED_CORPUS_RECEIPT = (
    "sha256:4ed7fe1ebb52f586b87275f0127dc1df42f62e62fbb4fa8435c3eed356d35ec3"
)
EXPECTED_IMAGE_ID = (
    "sha256:f8f548d87d16634d1ad9e3777280f3f577ba2358703f04e18e74007ffd3621bf"
)
EXPECTED_AGENT_RELEASE = (
    "sha256:e41c15f412b87c39654978a628ac7704b5cbbb2915f41b3b9d4426cf7aa4b04a"
)
EXPECTED_TOOL_RELEASE = (
    "sha256:775e2996c5302a28e24d2b8b7b104788e0a782688ba847ae63c8a8b729b48f0d"
)
EXPECTED_MODEL_ROUTE = (
    "sha256:8bc631ae8cf7fc7f2d07ac187eb5ca0d313de00818d77abfa7b2b4a04a5c74e7"
)
SUPPORTED_ATTEMPTS = {
    "attempt_orbit_disease_r2_v4_002_syn": {
        "task_id": "tsk_orbit_disease_stationery_r2_v4_002_syn",
        "grant_id": "grant_orbit_disease_stationery_r2_v4_002_syn",
        "composition_id": "composition_orbit_disease_stationery_r2_v4_002_syn",
        "intent_id": "intent_orbit_disease_stationery_r2_v4_002_syn",
        "idempotency_key": "idem:orbit:disease-r2:v4:attempt-002",
        "approval_id": "approval_orbit_disease_r2_v4_002_syn",
    },
    "attempt_orbit_disease_r2_v4_003_syn": {
        "task_id": "tsk_orbit_disease_stationery_r2_v4_003_syn",
        "grant_id": "grant_orbit_disease_stationery_r2_v4_003_syn",
        "composition_id": "composition_orbit_disease_stationery_r2_v4_003_syn",
        "intent_id": "intent_orbit_disease_stationery_r2_v4_003_syn",
        "idempotency_key": "idem:orbit:disease-r2:v4:attempt-003",
        "approval_id": "approval_orbit_disease_r2_v4_003_syn",
    },
    "attempt_orbit_disease_r2_v4_004_syn": {
        "task_id": "tsk_orbit_disease_stationery_r2_v4_004_syn",
        "grant_id": "grant_orbit_disease_stationery_r2_v4_004_syn",
        "composition_id": "composition_orbit_disease_stationery_r2_v4_004_syn",
        "intent_id": "intent_orbit_disease_stationery_r2_v4_004_syn",
        "idempotency_key": "idem:orbit:disease-r2:v4:attempt-004",
        "approval_id": "approval_orbit_disease_r2_v4_004_syn",
    },
}
EXPECTED_POLICY_DIGEST = (
    "sha256:e651ecd0d30ea304eba5421f6cf8a6e029f960f6715244afd6e34dfe7fe9c90a"
)
EXPECTED_PRICE = {
    "source": "https://models.paper-orbit.invalid/pricing",
    "provider_id": "fixture",
    "model_id": EXPECTED_MODEL,
    "input_usd_per_million_tokens": "5.00",
    "output_usd_per_million_tokens": "30.00",
    "cached_input_usd_per_million_tokens": "0.50",
    "hard_cap_usd": "0.20",
    "cny_per_usd": "7.50",
    "hard_cap_cny": "1.50",
}
EXPECTED_SCOPE_RECEIPTS = {
    "agent_activation": {
        "subject_digest": EXPECTED_AGENT_RELEASE,
        "decision_receipt_digest": (
            "sha256:15c185eb5762f1d96c55e75417de41741eb42783c5ac2776fd850c3b240c281f"
        ),
        "status_receipt_digest": (
            "sha256:07f704e831e06ad53e4a38b75b11400ab367df59beecbede707b3a37c90bb2ae"
        ),
        "decision_sequence": 0,
        "status_sequence": 4,
        "current_status": "applied",
    },
    "tool_activation": {
        "subject_digest": EXPECTED_TOOL_RELEASE,
        "decision_receipt_digest": (
            "sha256:f53027c57a91a916c040a0261547ccd1536f189dbc895d7bd757e24f4b9a83f5"
        ),
        "status_receipt_digest": (
            "sha256:d01d3a5f2125fd9672836778c6998a9c584fc3929c7588ed1b6491679a631c97"
        ),
        "decision_sequence": 1,
        "status_sequence": 5,
        "current_status": "applied",
    },
    "model_route_approval": {
        "subject_digest": EXPECTED_MODEL_ROUTE,
        "decision_receipt_digest": (
            "sha256:7d4dff147d30899e9c9246de84f4eeca6be4a3a627ea13cf48459c96a2323cd4"
        ),
        "status_receipt_digest": (
            "sha256:8e8466e09da183e68253e37bdcec7359f734e023c5925c4066e5397b38530101"
        ),
        "decision_sequence": 2,
        "status_sequence": 6,
        "current_status": "approved_unconsumed",
    },
}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FORBIDDEN_PATHS = re.compile(
    r"(?:/Users/|/Volumes/|/home/|/mnt/|smb://|afp://|file://)", re.IGNORECASE
)
_FORBIDDEN_KEYS = {
    "api_key",
    "authorization",
    "credential",
    "password",
    "secret",
    "token_value",
}


class DiseaseR2V4PreflightError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiseaseR2V4PreflightError("r2_v4_json_invalid") from error
    if not isinstance(value, dict):
        raise DiseaseR2V4PreflightError("r2_v4_json_invalid")
    return value


def verify_candidate(
    review_path: Path,
    *,
    runtime_root: Path | None = None,
    scope_ledger_path: Path | None = None,
    execution_approval_path: Path | None = None,
    require_execution_approval: bool = False,
) -> dict[str, Any]:
    """Verify the immutable v4 reference graph without external side effects."""
    review_path = review_path.resolve(strict=True)
    root = review_path.parent
    review = read_json(review_path)
    supplied_review_digest = review.get("review_package_digest")
    review_without_digest = copy.deepcopy(review)
    review_without_digest.pop("review_package_digest", None)
    if supplied_review_digest != digest(review_without_digest):
        _fail("r2_v4_review_digest_drift")
    if review.get("status") != (
        "R2 governance closure prepared / awaiting human execution approval"
    ):
        _fail("r2_v4_review_status_invalid")
    if review.get("canonicalization") != CANONICALIZATION:
        _fail("r2_v4_canonicalization_invalid")
    artifacts = review.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        _fail("r2_v4_artifacts_invalid")
    values: dict[str, dict[str, Any]] = {}
    for role, entry in artifacts.items():
        if not isinstance(role, str) or not isinstance(entry, dict):
            _fail("r2_v4_artifacts_invalid")
        if set(entry) != {"path", "digest"}:
            _fail("r2_v4_artifact_entry_invalid")
        relative = _safe_relative(entry["path"])
        path = _regular_file(root, relative)
        if not _is_digest(entry["digest"]) or file_digest(path) != entry["digest"]:
            _fail("r2_v4_artifact_digest_drift")
        values[role] = read_json(path)

    required = {
        "attempt",
        "task",
        "execution_intent",
        "policy",
        "policy_decision",
        "approval_scopes",
        "grant",
        "isolation_profile",
        "runtime_source_lock",
        "runtime_realization",
        "price_observation",
        "composition",
        "reference_graph",
    }
    if not required <= set(values):
        _fail("r2_v4_required_artifact_missing")
    _reject_authority_or_secret(values)
    _verify_direct_graph(review, values)
    _verify_scope_bindings(values["approval_scopes"], scope_ledger_path)
    _verify_runtime_sources(values["runtime_source_lock"], runtime_root)
    approval_digest = _verify_execution_approval(
        review,
        values,
        execution_approval_path,
        required=require_execution_approval,
    )
    return {
        "status": "PASS",
        "review_package_digest": supplied_review_digest,
        "runtime_source_lock_digest": values["runtime_source_lock"][
            "runtime_source_lock_digest"
        ],
        "runtime_realization_digest": values["runtime_realization"][
            "runtime_realization_digest"
        ],
        "execution_approval_digest": approval_digest,
        "execution_scope_status": (
            "approved_unconsumed" if approval_digest else "pending"
        ),
        "effective": False,
        "runtime_started": False,
        "release_authorization": False,
    }


def _verify_direct_graph(
    review: Mapping[str, Any], values: Mapping[str, Mapping[str, Any]]
) -> None:
    attempt = values["attempt"]
    task = values["task"]
    intent = values["execution_intent"]
    policy = values["policy"]
    decision = values["policy_decision"]
    scopes = values["approval_scopes"]
    grant = values["grant"]
    isolation = values["isolation_profile"]
    source = values["runtime_source_lock"]
    realization = values["runtime_realization"]
    price = values["price_observation"]
    composition = values["composition"]
    graph = values["reference_graph"]

    self_digests = (
        (attempt, "attempt_digest"),
        (task, "task_candidate_digest"),
        (intent, "execution_intent_digest"),
        (decision, "policy_decision_digest"),
        (isolation, "isolation_profile_digest"),
        (source, "runtime_source_lock_digest"),
        (realization, "runtime_realization_digest"),
        (composition, "composition_digest"),
        (graph, "reference_graph_digest"),
    )
    for value, field in self_digests:
        _verify_self_digest(value, field)
    if (
        digest(policy) != EXPECTED_POLICY_DIGEST
        or digest(policy)
        != grant.get("implementation_extension", {}).get("policy_digest")
        or composition.get("policy_digest") != EXPECTED_POLICY_DIGEST
    ):
        _fail("r2_v4_policy_digest_mismatch")
    if digest(scopes) != grant.get("implementation_extension", {}).get(
        "approval_scope_bindings_digest"
    ):
        _fail("r2_v4_scope_bindings_digest_mismatch")

    attempt_id = attempt.get("attempt_id")
    task_id = task.get("task_id")
    idempotency_key = attempt.get("idempotency_key")
    identity = SUPPORTED_ATTEMPTS.get(attempt_id)
    if (
        identity is None
        or task_id != identity["task_id"]
        or idempotency_key != identity["idempotency_key"]
        or intent.get("intent_id") != identity["intent_id"]
        or grant.get("grant_id") != identity["grant_id"]
        or composition.get("composition_id") != identity["composition_id"]
    ):
        _fail("r2_v4_deterministic_identity_mismatch")
    grant_extension = grant.get("implementation_extension", {})
    for value in (task, intent, grant_extension, composition):
        if (
            value.get("attempt_id") != attempt_id
            or value.get("task_id") != task_id
            or value.get("idempotency_key") != idempotency_key
        ):
            _fail("r2_v4_attempt_task_idempotency_mismatch")

    exact = {
        "agent_release_digest": EXPECTED_AGENT_RELEASE,
        "literature_tool_release_digest": EXPECTED_TOOL_RELEASE,
        "model_route_digest": EXPECTED_MODEL_ROUTE,
        "corpus_revision": EXPECTED_CORPUS_REVISION,
    }
    for field, expected in exact.items():
        if grant_extension.get(field) != expected or composition.get(field) != expected:
            _fail(f"r2_v4_{field}_mismatch")
    if task.get("agent_release_digest") != EXPECTED_AGENT_RELEASE:
        _fail("r2_v4_task_agent_release_mismatch")
    if task.get("corpus_revision") != EXPECTED_CORPUS_REVISION:
        _fail("r2_v4_task_corpus_revision_mismatch")
    if intent.get("task_candidate_digest") != task.get("task_candidate_digest"):
        _fail("r2_v4_intent_task_digest_mismatch")

    operations = ["search_public_corpus", "fetch_public_record"]
    if grant_extension.get("literature_operations") != operations:
        _fail("r2_v4_literature_operations_mismatch")
    projection = grant.get("company_contract_projection")
    if not isinstance(projection, dict):
        _fail("r2_v4_company_grant_projection_invalid")
    spec = projection.get("spec")
    metadata = projection.get("metadata")
    if (
        not isinstance(spec, dict)
        or not isinstance(metadata, dict)
        or spec.get("agent_scopes") != []
        or spec.get("memory_classes") != []
        or spec.get("environment")
        != {
            "environment_id": "env_orbit_disease_r2_container_syn",
            "security_zone": "medical_research",
            "filesystem": "deny",
            "network": "deny",
            "workspace_mode": "none",
        }
        or spec.get("tool_scopes")
        != [
            {"request_name": "literature_search", "operations": ["query"]},
            {"request_name": "literature_fetch", "operations": ["read"]},
        ]
        or metadata.get("status") != "draft"
        or metadata.get("synthetic_only") is not True
        or metadata.get("grant_id") != identity["grant_id"]
        or metadata.get("task_id") != identity["task_id"]
    ):
        _fail("r2_v4_company_grant_projection_invalid")
    if composition.get("literature_operations") != operations:
        _fail("r2_v4_literature_operations_mismatch")
    if grant_extension.get("gateway_endpoint") != EXPECTED_ENDPOINT:
        _fail("r2_v4_gateway_endpoint_mismatch")
    route = composition.get("model_route")
    if not isinstance(route, dict) or (
        route.get("endpoint") != EXPECTED_ENDPOINT
        or route.get("requested_model_id") != EXPECTED_MODEL
        or route.get("allowed_returned_model_ids") != [EXPECTED_MODEL]
        or route.get("temperature") != 0
    ):
        _fail("r2_v4_model_route_mismatch")
    policy_model = policy.get("model")
    expected_policy_price = {
        "input_usd_per_million_tokens": "5.00",
        "output_usd_per_million_tokens": "30.00",
        "source": "https://models.paper-orbit.invalid/pricing",
        "observed_at": "2026-08-27",
        "recheck_required_before_execution": True,
    }
    if (
        not isinstance(policy_model, dict)
        or policy_model.get("provider_id") != "fixture"
        or policy_model.get("requested_model_id") != EXPECTED_MODEL
        or policy_model.get("temperature") != 0
        or policy_model.get("planned_calls") != 4
        or policy_model.get("max_retries") != 1
        or policy_model.get("normal_input_tokens") != 12000
        or policy_model.get("normal_output_tokens") != 1024
        or policy_model.get("billed_retry_input_tokens") != 24000
        or policy_model.get("billed_retry_output_tokens") != 2048
        or policy_model.get("hard_cap_usd") != "0.20"
        or policy_model.get("hard_cap_cny") != "1.50"
        or policy_model.get("exchange_rate_cny_per_usd") != "7.50"
        or policy_model.get("pricing_observation") != expected_policy_price
    ):
        _fail("r2_v4_policy_price_or_route_mismatch")
    price_core = {key: price.get(key) for key in EXPECTED_PRICE}
    if (
        price_core != EXPECTED_PRICE
        or price.get("observation_version")
        != "orbit.fixture-price-observation-snapshot/4"
        or price.get("observed_at") != "2026-08-27"
        or price.get("recheck_required_before_execution") is not True
        or price.get("verified_for_single_execution") is not True
        or composition.get("price_observation_digest") != digest(price)
        or grant_extension.get("price_observation_digest") != digest(price)
        or intent.get("price_observation_digest") != digest(price)
        or review.get("price_observation_digest") != digest(price)
    ):
        _fail("r2_v4_price_observation_mismatch")

    expected_budget = {
        "normal_model_calls": 4,
        "max_request_attempts": 8,
        "billed_input_tokens": 24000,
        "billed_output_tokens": 2048,
        "hard_cap_usd": "0.20",
        "hard_cap_cny": "1.50",
        "max_concurrency": 1,
        "max_runtime_seconds": 900,
    }
    if grant_extension.get("budget") != expected_budget:
        _fail("r2_v4_grant_budget_mismatch")
    if composition.get("budget") != expected_budget:
        _fail("r2_v4_composition_budget_mismatch")
    if task.get("max_lifetime_seconds") != 900:
        _fail("r2_v4_task_lifetime_mismatch")
    _verify_candidate_window(
        metadata.get("issued_at"), metadata.get("expires_at"), "grant"
    )
    if (
        grant_extension.get("candidate_issued_at") != metadata.get("issued_at")
        or grant_extension.get("candidate_expires_at")
        != metadata.get("expires_at")
        or grant_extension.get("max_lifetime_seconds") != 900
    ):
        _fail("r2_v4_grant_candidate_window_mismatch")
    company_task = task.get("company_contract_projection")
    if (
        not isinstance(company_task, dict)
        or company_task.get("status") != "pending_approval"
        or company_task.get("approval")
        != {"required": True, "state": "pending", "decision_refs": []}
        or company_task.get("hierarchy_context", {}).get("effective_grant_refs")
        != []
    ):
        _fail("r2_v4_company_task_projection_invalid")
    _verify_candidate_window(
        company_task.get("created_at"), company_task.get("deadline_at"), "task"
    )

    source_digest = source.get("runtime_source_lock_digest")
    realization_digest = realization.get("runtime_realization_digest")
    isolation_digest = isolation.get("isolation_profile_digest")
    if (
        grant_extension.get("runtime_source_lock_digest") != source_digest
        or grant_extension.get("runtime_realization_digest") != realization_digest
        or grant_extension.get("isolation_profile_digest") != isolation_digest
        or grant_extension.get("image_id") != EXPECTED_IMAGE_ID
    ):
        _fail("r2_v4_grant_runtime_binding_mismatch")
    runtime = composition.get("runtime")
    if not isinstance(runtime, dict) or runtime != {
        "runtime_source_lock_digest": source_digest,
        "runtime_realization_digest": realization_digest,
        "image_id": EXPECTED_IMAGE_ID,
        "harness_digest": realization.get("harness_digest"),
        "isolation_profile_digest": isolation_digest,
    }:
        _fail("r2_v4_composition_runtime_binding_mismatch")

    if grant_extension.get("policy_decision_digest") != decision.get(
        "policy_decision_digest"
    ):
        _fail("r2_v4_policy_decision_mismatch")
    if grant_extension.get("execution_intent_digest") != intent.get(
        "execution_intent_digest"
    ):
        _fail("r2_v4_execution_intent_mismatch")
    expected_revocation = {
        "owner_revoke": True,
        "policy_change": "revoke",
        "task_terminal": True,
        "budget_exhaustion": "revoke-and-stop",
    }
    if (
        attempt.get("status") != "proposed-not-started"
        or task.get("status") != "proposed-not-created"
        or grant.get("status") != "proposed-not-issued"
        or grant.get("issued") is not False
        or grant.get("effective") is not False
        or grant_extension.get("revocation") != expected_revocation
        or grant_extension.get("single_use") is not True
        or grant_extension.get("consume_on")
        != "execution_started_after_preflight"
        or realization.get("status") != "proposed-not-realized"
        or composition.get("status") != "proposed-not-effective"
        or composition.get("effective") is not False
    ):
        _fail("r2_v4_candidate_state_or_revocation_invalid")
    expected_receipts = _receipt_projection(scopes)
    if (
        grant_extension.get("approval_receipt_refs") != expected_receipts
        or composition.get("approval_receipt_refs") != expected_receipts
    ):
        _fail("r2_v4_direct_approval_receipt_binding_mismatch")
    if composition.get("execution_grant_canonical_digest") != grant.get(
        "grant_canonical_digest"
    ):
        _fail("r2_v4_composition_grant_digest_mismatch")
    if composition.get("execution_grant_file_digest") != review["artifacts"][
        "grant"
    ]["digest"]:
        _fail("r2_v4_composition_grant_file_digest_mismatch")
    if composition.get("approval_scope_bindings_digest") != digest(scopes):
        _fail("r2_v4_composition_approval_binding_mismatch")
    if composition.get("corpus_manifest_digest") != review.get(
        "corpus_manifest_digest"
    ):
        _fail("r2_v4_corpus_manifest_mismatch")
    corpus = values["corpus_binding"]
    if corpus != {
        "binding_version": "orbit.disease-r2-public-corpus-binding/1",
        "corpus_ref": review.get("corpus_ref"),
        "revision": EXPECTED_CORPUS_REVISION,
        "manifest_digest": EXPECTED_CORPUS_MANIFEST,
        "acquisition_review_subject_digest": EXPECTED_CORPUS_REVIEW,
        "acquisition_receipt_digest": EXPECTED_CORPUS_RECEIPT,
        "classification": "public",
        "content_scope": [
            "citation",
            "pmid",
            "doi",
            "mesh",
            "date",
            "abstract",
        ],
        "fulltext_allowed": False,
        "nas_accessed": False,
        "personal_medical_data": False,
    }:
        _fail("r2_v4_corpus_binding_mismatch")
    if (
        review.get("corpus_manifest_digest") != EXPECTED_CORPUS_MANIFEST
        or review.get("corpus_acquisition_review_digest")
        != EXPECTED_CORPUS_REVIEW
        or review.get("corpus_acquisition_receipt_digest")
        != EXPECTED_CORPUS_RECEIPT
        or grant_extension.get("corpus_manifest_digest")
        != EXPECTED_CORPUS_MANIFEST
        or grant_extension.get("corpus_acquisition_review_digest")
        != EXPECTED_CORPUS_REVIEW
        or grant_extension.get("corpus_acquisition_receipt_digest")
        != EXPECTED_CORPUS_RECEIPT
        or composition.get("corpus_acquisition_review_digest")
        != EXPECTED_CORPUS_REVIEW
        or composition.get("corpus_acquisition_receipt_digest")
        != EXPECTED_CORPUS_RECEIPT
    ):
        _fail("r2_v4_corpus_acquisition_binding_mismatch")

    expected_nodes = {
        role: entry["digest"] for role, entry in review["artifacts"].items()
        if role != "reference_graph"
    }
    if graph.get("nodes") != expected_nodes:
        _fail("r2_v4_reference_graph_nodes_mismatch")


def _verify_candidate_window(issued: Any, expires: Any, label: str) -> None:
    if not isinstance(issued, str) or not isinstance(expires, str):
        _fail(f"r2_v4_{label}_candidate_window_invalid")
    try:
        issued_at = datetime.fromisoformat(issued.replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError as error:
        raise DiseaseR2V4PreflightError(
            f"r2_v4_{label}_candidate_window_invalid"
        ) from error
    if int((expires_at - issued_at).total_seconds()) != 900:
        _fail(f"r2_v4_{label}_candidate_window_invalid")


def _receipt_projection(scopes: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "scope_kind": item["scope_kind"],
            "subject_digest": item["subject_digest"],
            "decision_ref": item["decision_ref"],
            "decision_receipt_digest": item["decision_receipt_digest"],
            "decision_sequence": item["decision_sequence"],
            "status_ref": item["status_ref"],
            "status_receipt_digest": item["status_receipt_digest"],
            "status_sequence": item["status_sequence"],
            "current_status": item["current_status"],
            "expires_at": item["expires_at"],
            "consumption_status": item["consumption_status"],
        }
        for item in scopes["scopes"]
    ]


def _verify_scope_bindings(
    value: Mapping[str, Any], scope_ledger_path: Path | None
) -> None:
    scopes = value.get("scopes")
    if not isinstance(scopes, list) or len(scopes) != 4:
        _fail("r2_v4_scope_count_invalid")
    by_kind = {item.get("scope_kind"): item for item in scopes if isinstance(item, dict)}
    if set(by_kind) != {*EXPECTED_SCOPE_RECEIPTS, "r2_execution"}:
        _fail("r2_v4_scope_kinds_invalid")
    for kind, expected in EXPECTED_SCOPE_RECEIPTS.items():
        item = by_kind[kind]
        for field, exact in expected.items():
            if item.get(field) != exact:
                _fail("r2_v4_scope_receipt_mismatch")
        if item.get("subject_digest") == item.get("decision_receipt_digest"):
            _fail("r2_v4_subject_used_as_receipt")
        if item.get("expires_at") is not None:
            _fail("r2_v4_scope_expiry_invalid")
    pending = by_kind["r2_execution"]
    if (
        pending.get("current_status") != "pending"
        or pending.get("decision_receipt_digest") is not None
        or pending.get("status_receipt_digest") is not None
        or pending.get("consumption_status") != "pending_approval"
        or not _is_digest(pending.get("subject_digest"))
    ):
        _fail("r2_v4_execution_scope_not_pending")
    if value.get("scope_conversion_allowed") is not False:
        _fail("r2_v4_scope_conversion_forbidden")
    if scope_ledger_path is not None:
        records = _read_ledger(scope_ledger_path)
        by_hash = {record.get("record_hash"): record for record in records}
        for kind, expected in EXPECTED_SCOPE_RECEIPTS.items():
            decision = by_hash.get(expected["decision_receipt_digest"])
            status = by_hash.get(expected["status_receipt_digest"])
            if (
                not decision
                or decision.get("sequence") != expected["decision_sequence"]
                or decision.get("scope") != kind
                or decision.get("payload", {}).get("decision", {}).get(
                    "subject_digest"
                )
                != expected["subject_digest"]
                or not status
                or status.get("sequence") != expected["status_sequence"]
                or status.get("payload", {}).get("status", {}).get("status")
                != expected["current_status"]
            ):
                _fail("r2_v4_scope_ledger_receipt_mismatch")


def _verify_runtime_sources(
    lock: Mapping[str, Any], runtime_root: Path | None
) -> None:
    _verify_self_digest(lock, "runtime_source_lock_digest")
    entries = lock.get("entries")
    if not isinstance(entries, list) or not entries:
        _fail("r2_v4_runtime_source_entries_invalid")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "source_path",
            "materialized_path",
            "digest",
            "role",
        }:
            _fail("r2_v4_runtime_source_entry_invalid")
        relative = _safe_relative(entry["materialized_path"])
        if str(relative) in seen or not _is_digest(entry["digest"]):
            _fail("r2_v4_runtime_source_entry_invalid")
        seen.add(str(relative))
        if runtime_root is not None:
            path = _regular_file(runtime_root.resolve(strict=True), relative)
            if file_digest(path) != entry["digest"]:
                _fail("r2_v4_runtime_source_byte_drift")


def _verify_execution_approval(
    review: Mapping[str, Any],
    values: Mapping[str, Mapping[str, Any]],
    approval_path: Path | None,
    *,
    required: bool,
) -> str | None:
    if approval_path is None:
        if required:
            _fail("r2_v4_execution_approval_missing")
        return None
    metadata = approval_path.lstat()
    if (
        approval_path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
    ):
        _fail("r2_v4_execution_approval_not_owner_only")
    approval = read_json(approval_path)
    attempt_id = values["attempt"].get("attempt_id")
    identity = SUPPORTED_ATTEMPTS.get(attempt_id)
    if identity is None:
        _fail("r2_v4_attempt_identity_invalid")
    expected = {
        "approval_version": "orbit.synthetic-disease-r2-execution-approval/4",
        "decision_id": identity["approval_id"],
        "scope": "r2_execution",
        "subject_digest": values["execution_intent"]["execution_intent_digest"],
        "review_package_digest": review["review_package_digest"],
        "runtime_source_lock_digest": values["runtime_source_lock"][
            "runtime_source_lock_digest"
        ],
        "runtime_realization_digest": values["runtime_realization"][
            "runtime_realization_digest"
        ],
        "task_candidate_digest": values["task"]["task_candidate_digest"],
        "grant_candidate_digest": review["artifacts"]["grant"]["digest"],
        "grant_canonical_digest": values["grant"]["grant_canonical_digest"],
        "composition_digest": values["composition"]["composition_digest"],
        "image_id": EXPECTED_IMAGE_ID,
        "decided_by_human_ref": "hum_orbit_platform_owner_syn",
        "decision": "approve",
        "synthetic_only": True,
        "single_use": True,
        "release_authorization": False,
    }
    if approval != expected:
        _fail("r2_v4_execution_approval_invalid")
    return file_digest(approval_path)


def _reject_authority_or_secret(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = str(key).lower()
            if (
                lowered in {"effective", "release_authorization", "runtime_started"}
                and item is True
            ):
                _fail("r2_v4_authority_widening")
            if lowered in _FORBIDDEN_KEYS:
                _fail("r2_v4_secret_field_forbidden")
            _reject_authority_or_secret(item)
    elif isinstance(value, list):
        for item in value:
            _reject_authority_or_secret(item)
    elif isinstance(value, str) and _FORBIDDEN_PATHS.search(value):
        _fail("r2_v4_physical_path_forbidden")


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o077
    ):
        _fail("r2_v4_scope_ledger_not_owner_only")
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(
                line,
                object_pairs_hook=_unique,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, DiseaseR2V4PreflightError) as error:
            raise DiseaseR2V4PreflightError("r2_v4_scope_ledger_invalid") from error
        if not isinstance(value, dict):
            _fail("r2_v4_scope_ledger_invalid")
        records.append(value)
    return records


def _verify_self_digest(value: Mapping[str, Any], field: str) -> None:
    supplied = value.get(field)
    canonical_value = copy.deepcopy(dict(value))
    canonical_value.pop(field, None)
    if supplied != digest(canonical_value):
        _fail(f"r2_v4_{field}_drift")


def _safe_relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        _fail("r2_v4_relative_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        _fail("r2_v4_relative_path_invalid")
    return path


def _regular_file(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            _fail("r2_v4_symlink_forbidden")
    if not current.is_file():
        _fail("r2_v4_artifact_missing")
    return current


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_DIGEST.fullmatch(value))


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("r2_v4_duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    _fail("r2_v4_invalid_json_constant")


def _fail(reason: str) -> None:
    raise DiseaseR2V4PreflightError(reason)

