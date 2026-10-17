"""Fail-closed preparation for a non-effective Disease R2 candidate."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

AGENT_ID = "agt_orbit_disease_research_task_syn"
AGENT_VERSION = "0.2.0"
AGENT_RELEASE_DIGEST = (
    "sha256:e41c15f412b87c39654978a628ac7704b5cbbb2915f41b3b9d4426cf7aa4b04a"
)
AGENT_DEFINITION_DIGEST = (
    "sha256:47807ec8d7c6c31437d808198d4cf9cb5a577ce16ee0100c05f8ad4047e916c6"
)
AGENT_BINDING_DIGEST = (
    "sha256:a342a7408aa97c107f65df281cfac1b991e186740f5c805fca6465902cf774de"
)
LITERATURE_TOOL_ID = "tool_orbit_literature_public_corpus"
LITERATURE_TOOL_VERSION = "0.1.0"
LITERATURE_TOOL_RELEASE_DIGEST = (
    "sha256:775e2996c5302a28e24d2b8b7b104788e0a782688ba847ae63c8a8b729b48f0d"
)
MODEL_ROUTE_ID = "model_route_orbit_disease_r2_fixture_gpt56sol_syn"
MODEL_ROUTE_DIGEST = (
    "sha256:8bc631ae8cf7fc7f2d07ac187eb5ca0d313de00818d77abfa7b2b4a04a5c74e7"
)
MODEL_GATEWAY_ORIGIN = "https://models.paper-orbit.invalid"
MODEL_GATEWAY_PATH = "/v1/chat/completions"
ALLOWED_RETURNED_MODEL_IDS = ("fixture-structured-v1",)
CORPUS_REF = "dataset://public/disease-r2/fictional-stationery-literature/0.1.0"
CORPUS_REVISION = (
    "sha256:bb796b5aa76f930566e78c599eb197282595b26f2523f7b062374b7c261d6b30"
)
PUBLIC_CORPUS_MANIFEST_DIGEST = (
    "sha256:2af4bd9254b888670f6bf9b4932d6ac2ffd23d8874e5d44ea112485555135f08"
)
PUBLIC_CORPUS_RECEIPT_DIGEST = (
    "sha256:4ed7fe1ebb52f586b87275f0127dc1df42f62e62fbb4fa8435c3eed356d35ec3"
)
PUBLIC_CORPUS_FAILED_ATTEMPT_DIGEST = (
    "sha256:aa3de8d65ee053346d1ba6b934403416abf8677737a0d5caf93f79d481737bd1"
)
PUBLIC_CORPUS_REVIEW_DIGEST = (
    "sha256:aa1ead1dfa83cd93edbae0f995308ba90f1cfba3bb58ff5591fa80b1a3bd60e1"
)
LITERATURE_COLLECTOR_DIGEST = (
    "sha256:2675f617e69fc405ffca3d3490e92d525ac3845835fd5aee6593494ea82e6723"
)
IMAGE_REF = "nousresearch/hermes-agent:v2026.8.16"
IMAGE_ID = (
    "sha256:f8f548d87d16634d1ad9e3777280f3f577ba2358703f04e18e74007ffd3621bf"
)
TASK_ID = "tsk_orbit_disease_stationery_r2_candidate_syn"
GRANT_ID = "grant_orbit_disease_stationery_r2_candidate_syn"
POLICY_ID = "pol_orbit_disease_stationery_r2_candidate_syn"
MAX_LIFETIME_SECONDS = 900
PLANNED_MODEL_CALLS = 4
NORMAL_INPUT_TOKENS = 12_000
NORMAL_OUTPUT_TOKENS = 1_024
BILLED_INPUT_TOKENS = 24_000
BILLED_OUTPUT_TOKENS = 2_048
ESTIMATED_USD = "0.18144"
HARD_CAP_USD = "0.20"
EXCHANGE_RATE_CNY_PER_USD = "7.50"
HARD_CAP_CNY = "1.50"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LEAK = re.compile(
    r"/Users/|/Volumes/|(?:file|smb|opaque)://|"
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|\bsk-[A-Za-z0-9_-]+",
    re.IGNORECASE,
)


class DiseaseR2CandidateError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def canonical_bytes(value: Any) -> bytes:
    _reject_float(value)
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def digest_mapping(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _reject_float(value: Any) -> None:
    if isinstance(value, float):
        raise DiseaseR2CandidateError("floating_point_value_forbidden")
    if isinstance(value, Mapping):
        for item in value.values():
            _reject_float(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_float(item)


def _validate_logical(value: Any) -> None:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if _LEAK.search(encoded):
        raise DiseaseR2CandidateError("candidate_sensitive_value_forbidden")


@dataclass(frozen=True)
class RuntimeSourceEntry:
    role: str
    logical_ref: str
    digest: str


def build_runtime_source_lock(
    *,
    control_source_digest: str,
    harness_digest: str,
    scientific_runtime_digest: str,
    scientific_worker_digest: str,
    literature_collector_digest: str,
) -> dict[str, Any]:
    for item in (
        control_source_digest,
        harness_digest,
        scientific_runtime_digest,
        scientific_worker_digest,
        literature_collector_digest,
        AGENT_RELEASE_DIGEST,
        LITERATURE_TOOL_RELEASE_DIGEST,
        MODEL_ROUTE_DIGEST,
    ):
        if not _DIGEST.fullmatch(item):
            raise DiseaseR2CandidateError("runtime_source_digest_invalid")
    entries = [
        RuntimeSourceEntry(
            "control_candidate",
            "artifact://control-plane/disease-r2/candidate-source",
            control_source_digest,
        ),
        RuntimeSourceEntry(
            "docker_harness",
            "artifact://control-plane/disease-r2/docker-harness",
            harness_digest,
        ),
        RuntimeSourceEntry(
            "scientific_runtime",
            "artifact://scientific-platform/disease-r2/runtime-source",
            scientific_runtime_digest,
        ),
        RuntimeSourceEntry(
            "scientific_worker",
            "artifact://scientific-platform/disease-r2/candidate-worker",
            scientific_worker_digest,
        ),
        RuntimeSourceEntry(
            "literature_collector",
            "artifact://scientific-platform/literature-tool/public-corpus-collector/0.1.0",
            literature_collector_digest,
        ),
        RuntimeSourceEntry(
            "agent_release",
            "artifact://scientific-platform/disease-agent/release/0.2.0",
            AGENT_RELEASE_DIGEST,
        ),
        RuntimeSourceEntry(
            "literature_tool_release",
            "artifact://scientific-platform/literature-tool/release/0.1.0",
            LITERATURE_TOOL_RELEASE_DIGEST,
        ),
        RuntimeSourceEntry(
            "model_route",
            "artifact://control-plane/model-route/disease-r2/0.1.0",
            MODEL_ROUTE_DIGEST,
        ),
    ]
    lock = {
        "lock_version": "orbit.disease-r2-runtime-source-lock/1",
        "status": "proposed-not-effective",
        "entries": [entry.__dict__ for entry in entries],
        "container_image": {
            "ref": IMAGE_REF,
            "expected_image_id": IMAGE_ID,
            "recheck_required_before_execution": True,
        },
        "authority_boundary": {
            "image_inspected": False,
            "container_started": False,
            "effective_task_created": False,
            "effective_grant_created": False,
            "release_authorization": False,
        },
    }
    lock["runtime_source_digest"] = digest_mapping(lock)
    return lock


def build_minimal_bundle(
    *,
    task_digest: str,
    grant_digest: str,
    composition_digest: str,
    runtime_source_digest: str,
) -> dict[str, bytes]:
    for value in (
        task_digest,
        grant_digest,
        composition_digest,
        runtime_source_digest,
    ):
        if not _DIGEST.fullmatch(value):
            raise DiseaseR2CandidateError("minimal_bundle_digest_invalid")
    event = {
        "bundle_version": "orbit.disease-r2-minimal-bundle/1",
        "task_ref": "artifact://control-plane/disease-r2/task-candidate",
        "task_digest": task_digest,
        "grant_ref": "artifact://control-plane/disease-r2/grant-candidate",
        "grant_digest": grant_digest,
        "composition_ref": (
            "artifact://control-plane/disease-r2/composition-candidate"
        ),
        "composition_digest": composition_digest,
        "runtime_source_digest": runtime_source_digest,
        "corpus_ref": CORPUS_REF,
        "corpus_revision": CORPUS_REVISION,
        "model_route_ref": MODEL_ROUTE_ID,
        "model_route_digest": MODEL_ROUTE_DIGEST,
        "literature_tool_release_digest": LITERATURE_TOOL_RELEASE_DIGEST,
        "authority_boundary": {
            "external_model_call": False,
            "external_network": False,
            "nas_access": False,
            "effective_execution": False,
        },
    }
    _validate_logical(event)
    return {"task-event.json": canonical_bytes(event)}


def build_docker_command(ephemeral_bundle_dir: Path) -> tuple[str, ...]:
    """Construct, but never execute, the reviewed R2 container command."""

    bundle = ephemeral_bundle_dir.resolve()
    allowed_roots = (Path("/private/tmp").resolve(), Path("/tmp").resolve())
    if not any(bundle.is_relative_to(root) for root in allowed_roots):
        raise DiseaseR2CandidateError("bundle_not_ephemeral")
    return (
        "docker",
        "run",
        "--rm",
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--cpus",
        "1",
        "--memory",
        "256m",
        "--pids-limit",
        "64",
        "--tmpfs",
        "/work:rw,noexec,nosuid,nodev,size=16m",
        "--mount",
        f"type=bind,src={bundle},dst=/bundle,readonly",
        "--workdir",
        "/work",
        IMAGE_REF,
        "python3",
        "-m",
        "disease_r2_candidate_worker",
    )


def company_evaluate_offline_result(
    outcome: Mapping[str, Any],
) -> dict[str, Any]:
    _validate_logical(outcome)
    records = {
        record.get("record_ref")
        for record in outcome.get("fetch_receipt", {}).get("records", [])
        if isinstance(record, Mapping)
    }
    claims = outcome.get("claims")
    claim_mapping_valid = (
        isinstance(claims, list)
        and bool(claims)
        and all(
            isinstance(claim, Mapping)
            and isinstance(claim.get("evidence_refs"), list)
            and bool(claim["evidence_refs"])
            and set(claim["evidence_refs"]).issubset(records)
            for claim in claims
        )
    )
    usage = outcome.get("model_usage", {})
    boundary = outcome.get("authority_boundary", {})
    passed = (
        outcome.get("status") == "offline-fixture-pass"
        and outcome.get("corpus_revision") == CORPUS_REVISION
        and usage.get("calls") == PLANNED_MODEL_CALLS
        and usage.get("input_tokens") <= NORMAL_INPUT_TOKENS
        and usage.get("output_tokens") <= NORMAL_OUTPUT_TOKENS
        and usage.get("external_calls") == 0
        and claim_mapping_valid
        and isinstance(boundary, Mapping)
        and not any(boundary.values())
        and bool(outcome.get("synthesis", {}).get("uncertainty"))
        and "refuse"
        in str(outcome.get("synthesis", {}).get("clinical_boundary", ""))
    )
    return {
        "evaluation_version": "orbit.disease-r2-company-offline-evaluation/1",
        "evaluator_agent_id": "agt_orbit_company_evaluator_syn",
        "verdict": "pass" if passed else "fail",
        "subject_result_digest": outcome.get("result_digest"),
        "reason_codes": (
            ["fixed_offline_suite_pass"]
            if passed
            else ["company_offline_evaluation_failed_closed"]
        ),
        "release_authorization": False,
        "model_route_approved": False,
        "effective_execution_authorized": False,
        "preproduction_authorized": False,
        "production_authorized": False,
    }


def verify_cross_repo_sources(
    root: Path, scientific_root: Path
) -> dict[str, str]:
    paths = {
        "agent_release": (
            scientific_root
            / "contracts/agents/disease-research-task-agent/candidates/0.2.0/"
            "agent-release-candidate.synthetic.yaml"
        ),
        "literature_tool_release": (
            scientific_root
            / "contracts/tools/literature-public-corpus/candidates/0.1.0/"
            "tool-release-candidate.synthetic.json"
        ),
        "model_route": (
            root / "references/disease-r2/model-route.candidate.synthetic.yaml"
        ),
        "scientific_runtime": (
            scientific_root
            / "candidate_support/disease_r2_candidate.py"
        ),
        "scientific_worker": (
            scientific_root
            / "candidate_support/disease_r2_candidate_worker.py"
        ),
        "literature_collector": (
            scientific_root
            / "candidate_support/literature_public_corpus_collector.py"
        ),
        "public_corpus_manifest": (
            scientific_root
            / "evidence/disease-agent-r2/public-corpus/2026-08-26/"
            "corpus-manifest.public.json"
        ),
        "public_corpus_normalized": (
            scientific_root
            / "evidence/disease-agent-r2/public-corpus/2026-08-26/"
            "normalized-records.public.jsonl"
        ),
        "public_corpus_receipt": (
            scientific_root
            / "evidence/disease-agent-r2/public-corpus/2026-08-26/"
            "acquisition-receipt.public.json"
        ),
        "public_corpus_failed_attempt": (
            scientific_root
            / "evidence/disease-agent-r2/public-corpus/"
            "2026-08-26-attempt-001-failed/attempt.json"
        ),
    }
    expected = {
        "agent_release": AGENT_RELEASE_DIGEST,
        "literature_tool_release": LITERATURE_TOOL_RELEASE_DIGEST,
        "model_route": MODEL_ROUTE_DIGEST,
        "literature_collector": LITERATURE_COLLECTOR_DIGEST,
        "public_corpus_manifest": PUBLIC_CORPUS_MANIFEST_DIGEST,
        "public_corpus_normalized": CORPUS_REVISION,
        "public_corpus_receipt": PUBLIC_CORPUS_RECEIPT_DIGEST,
        "public_corpus_failed_attempt": PUBLIC_CORPUS_FAILED_ATTEMPT_DIGEST,
    }
    actual = {name: digest_file(path) for name, path in paths.items()}
    for name, digest_value in expected.items():
        if actual[name] != digest_value:
            raise DiseaseR2CandidateError(f"{name}_digest_drift")
    return actual

