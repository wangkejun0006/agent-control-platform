"""Read-only preparation gate for one fictional-stationery synthetic R1."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .disease_r1 import (
    COMPANY_TASK_ID,
    DISEASE_AGENT_ID,
    EXECUTION_GRANT_ID,
    EXPECTED_AGENT_RELEASE_DIGEST,
    EXPECTED_PACKAGE_DIGEST,
    EXPECTED_PACKAGE_ID,
    EXPECTED_PACKAGE_VERSION,
    DiseaseR1Error,
    grant_digest,
    grant_from_mapping,
    plan_disease_r1,
)
from .lifecycle import LifecycleError, SyntheticAgentLifecycleLedger
from .registration import (
    DEFAULT_COMPANY_LOCK,
    DEFAULT_CONTRACT_BUNDLE,
    RegistrationError,
    _COMMON_SCHEMA_ID,
    _SchemaValidator,
    _digest,
    _load_json_bytes,
    _load_verified_company_schemas,
    _read_safe_file,
    _safe_relative_path,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_R1_REVIEW_ROOT = _REPO_ROOT
DEFAULT_R1_REVIEW_REQUEST = (
    _REPO_ROOT
    / "evidence"
    / "disease-agent-r1"
    / "2026-08-26"
    / "retry-004"
    / "execution-review-request.json"
)
DEFAULT_DISEASE_LIFECYCLE_LEDGER = (
    _REPO_ROOT
    / ".local-state"
    / "agent-lifecycle"
    / "disease-research-task-agent.synthetic.jsonl"
)
DEFAULT_PRIOR_R1_TASK_LEDGER = (
    _REPO_ROOT
    / ".local-state"
    / "disease-r1"
    / "retry-003.task.synthetic.jsonl"
)
PRIOR_R1_TASK_ID = "tsk_orbit_disease_stationery_r1_retry3_syn"
PRIOR_R1_REVIEW_DIGEST = (
    "sha256:fd5f22c5bc83d49f528229bf8ad9ae92219f913dd07f1324819315cf2d9cddd7"
)
_TASK_SCHEMA_ID = "urn:company-ai-os:schema:task:0.3"
_GRANT_SCHEMA_ID = "urn:company-ai-os:schema:execution-grant:0.1"
_EXECUTION_CHECKS = [
    "immediately preceding R1 attempt is durably recorded as fail and its Worker Lease is terminal",
    "exact owner-only approval binds this review request and all candidate digests",
    "Disease lifecycle remains active at revision 2 for the exact Agent Release",
    "local Docker image ID equals the reviewed immutable image ID",
    "fresh minimal bundle digest equals the reviewed Runtime Source digest",
    "Task and Worker Lease are written only after all approval and digest checks pass",
    "one container is run with no network non-root read-only root and zero capabilities",
    "failure evidence records only a sanitized phase code output sizes and output digests",
]
_NONCLAIMS = [
    "prior attempts did not establish R1 synthetic pass",
    "candidate bytes are not an effective Task or issued Execution Grant",
    "Docker has not been inspected or started during review preparation",
    "not a formal Company Registry record",
    "not pre-production accepted",
    "not production authorized",
    "release_authorization remains false",
]


class DiseaseR1ReviewError(ValueError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class VerifiedDiseaseR1Review:
    review_id: str
    review_request_digest: str
    task_candidate_digest: str
    grant_candidate_digest: str
    composition_candidate_digest: str
    runtime_source_digest: str
    control_source_digest: str
    image_ref: str
    image_id: str
    synthetic_grant: Mapping[str, Any]
    task_candidate: Mapping[str, Any]
    composition_candidate: Mapping[str, Any]


@dataclass(frozen=True)
class DiseaseR1ExecutionApproval:
    decision_id: str
    action: str
    review_request_digest: str
    task_candidate_digest: str
    grant_candidate_digest: str
    composition_candidate_digest: str
    runtime_source_digest: str
    control_source_digest: str
    agent_release_digest: str
    decided_by_human_ref: str
    decided_at: str
    expires_at: str
    decision: str
    reason: str
    evidence_status: str
    synthetic_only: bool


def prepare_disease_r1_review(
    root: Path | str = _REPO_ROOT,
    review_request: Path | str = DEFAULT_R1_REVIEW_REQUEST.relative_to(_REPO_ROOT),
    lifecycle_ledger: Path | str = DEFAULT_DISEASE_LIFECYCLE_LEDGER,
    prior_task_ledger: Path | str = DEFAULT_PRIOR_R1_TASK_LEDGER,
) -> dict[str, Any]:
    """Verify exact candidate bytes and current active lifecycle without writing state."""

    verified = verify_disease_r1_review(root, review_request)
    if compute_control_source_digest(Path(root)) != verified.control_source_digest:
        raise DiseaseR1ReviewError(
            "r1_control_source_drift",
            "Disease R1 Control Plane execution source differs",
        )
    from .ledger import LedgerError, SyntheticTaskLedger

    try:
        prior_state = SyntheticTaskLedger(prior_task_ledger).replay().task(
            PRIOR_R1_TASK_ID
        )
    except LedgerError as error:
        raise DiseaseR1ReviewError(
            error.reason_code, "Prior Disease R1 attempt evidence is unavailable"
        ) from error
    if (
        prior_state.disease_r1_outcome is None
        or prior_state.disease_r1_outcome["status"] != "fail"
        or prior_state.disease_r1_outcome["review_request_digest"]
        != PRIOR_R1_REVIEW_DIGEST
        or prior_state.worker_lease is None
        or prior_state.worker_lease.status != "failed"
        or prior_state.worker_lease.revision != 1
    ):
        raise DiseaseR1ReviewError(
            "prior_r1_attempt_not_terminal",
            "Prior Disease R1 attempt is not durably failed and closed",
        )
    try:
        replay = SyntheticAgentLifecycleLedger(lifecycle_ledger).replay()
        state = replay.agent(DISEASE_AGENT_ID)
    except LifecycleError as error:
        raise DiseaseR1ReviewError(
            error.reason_code, "Disease lifecycle evidence is unavailable"
        ) from error
    if (
        state.status != "active"
        or state.revision != 2
        or state.candidate.release_digest != EXPECTED_AGENT_RELEASE_DIGEST
        or state.evaluation is None
        or state.evaluation.verdict != "pass"
        or state.evaluation.release_recommendation != "recommend"
        or state.evaluation.release_authorization is not False
        or len(state.approvals) != 1
        or state.task_instantiation is not None
    ):
        raise DiseaseR1ReviewError(
            "disease_lifecycle_not_exact_active",
            "Disease lifecycle differs from the approved D0 synthetic release",
        )
    return {
        "status": "awaiting-human-execution-approval",
        "evidence_status": "synthetic",
        "review_id": verified.review_id,
        "review_request_digest": verified.review_request_digest,
        "task_candidate_digest": verified.task_candidate_digest,
        "grant_candidate_digest": verified.grant_candidate_digest,
        "composition_candidate_digest": verified.composition_candidate_digest,
        "runtime_source_digest": verified.runtime_source_digest,
        "control_source_digest": verified.control_source_digest,
        "image_id": verified.image_id,
        "agent_id": DISEASE_AGENT_ID,
        "agent_release_digest": EXPECTED_AGENT_RELEASE_DIGEST,
        "lifecycle_status": state.status,
        "lifecycle_revision": state.revision,
        "lifecycle_last_record_hash": replay.last_record_hash,
        "prior_attempt_status": prior_state.disease_r1_outcome["status"],
        "prior_worker_lease_status": prior_state.worker_lease.status,
        "effective_task_created": False,
        "effective_grant_created": False,
        "worker_lease_created": False,
        "runtime_started": False,
        "release_authorization": False,
        "production_authorized": False,
    }


def verify_disease_r1_review(
    root: Path | str,
    review_request: Path | str,
) -> VerifiedDiseaseR1Review:
    try:
        return _verify_disease_r1_review(root, review_request)
    except DiseaseR1ReviewError:
        raise
    except (DiseaseR1Error, RegistrationError) as error:
        raise DiseaseR1ReviewError(
            getattr(error, "reason_code", "r1_review_invalid"),
            "Disease R1 review failed closed",
        ) from error


def _verify_disease_r1_review(
    root: Path | str,
    review_request: Path | str,
) -> VerifiedDiseaseR1Review:
    base = Path(root)
    request_source = _safe_read(base, review_request, "Disease R1 review request")
    request = _load_json(request_source, "Disease R1 review request")
    if set(request) != {
        "review_version",
        "review_id",
        "generated_at",
        "status",
        "evidence_status",
        "synthetic_only",
        "subject",
        "runtime",
        "bindings",
        "artifacts",
        "authority_boundary",
        "required_execution_checks",
        "requested_human_decision",
        "nonclaims",
    }:
        raise DiseaseR1ReviewError(
            "r1_review_fields_invalid", "Disease R1 review fields differ"
        )
    if (
        request["review_version"] != "orbit.disease-r1-execution-review/5"
        or request["status"] != "awaiting-human-execution-approval"
        or request["evidence_status"] != "synthetic"
        or request["synthetic_only"] is not True
        or request["subject"]
        != {
            "agent_id": DISEASE_AGENT_ID,
            "agent_release_digest": EXPECTED_AGENT_RELEASE_DIGEST,
            "package_id": EXPECTED_PACKAGE_ID,
            "package_version": EXPECTED_PACKAGE_VERSION,
            "package_digest": EXPECTED_PACKAGE_DIGEST,
        }
        or request["authority_boundary"]
        != {
            "effective_task_created": False,
            "effective_grant_created": False,
            "worker_lease_created": False,
            "runtime_started": False,
            "model_allowed": False,
            "network_allowed": False,
            "host_filesystem_allowed": False,
            "nas_allowed": False,
            "real_data_allowed": False,
            "preproduction_authorized": False,
            "production_authorized": False,
            "release_authorization": False,
        }
        or request["required_execution_checks"] != _EXECUTION_CHECKS
        or request["nonclaims"] != _NONCLAIMS
        or request["requested_human_decision"]
        != (
            "批准或拒绝在 retry-003 已失败闭合后，按本审阅请求的精确摘要运行一次 "
            "fictional-stationery 0.1.0 R1 synthetic retry-004；批准仅允许创建本次本地 "
            "synthetic Task、短期 Grant 语义、"
            "Runtime Composition、Worker Lease 并启动一次受限 Docker Worker，不授权模型、"
            "网络、宿主项目/Home、NAS、真实数据、正式 Registry、Scheduler、预产、生产或发布。"
        )
    ):
        raise DiseaseR1ReviewError(
            "r1_review_boundary_invalid", "Disease R1 review boundary differs"
        )
    artifact_sources = _verify_artifacts(base, request["artifacts"])
    bindings = request["bindings"]
    if not isinstance(bindings, dict) or set(bindings) != {
        "task_candidate_digest",
        "grant_candidate_file_digest",
        "grant_candidate_digest",
        "composition_candidate_digest",
        "policy_digest",
        "runtime_source_lock_digest",
        "prior_attempt_failure_digest",
    }:
        raise DiseaseR1ReviewError(
            "r1_review_bindings_invalid", "Disease R1 review bindings differ"
        )
    expected_kinds = {
        "CompanyTaskCandidate",
        "ExecutionGrantCandidate",
        "RuntimeCompositionCandidate",
        "DiseaseR1PolicyCandidate",
        "DiseaseR1RuntimeSourceLock",
        "PriorR1FailedAttemptEvidence",
    }
    if set(artifact_sources) != expected_kinds:
        raise DiseaseR1ReviewError(
            "r1_review_artifacts_invalid", "Disease R1 review artifacts differ"
        )
    task_source = artifact_sources["CompanyTaskCandidate"]
    grant_source = artifact_sources["ExecutionGrantCandidate"]
    composition_source = artifact_sources["RuntimeCompositionCandidate"]
    policy_source = artifact_sources["DiseaseR1PolicyCandidate"]
    runtime_lock_source = artifact_sources["DiseaseR1RuntimeSourceLock"]
    prior_failure_source = artifact_sources["PriorR1FailedAttemptEvidence"]
    if (
        bindings["task_candidate_digest"] != _digest(task_source)
        or bindings["grant_candidate_file_digest"] != _digest(grant_source)
        or bindings["composition_candidate_digest"] != _digest(composition_source)
        or bindings["policy_digest"] != _digest(policy_source)
        or bindings["runtime_source_lock_digest"] != _digest(runtime_lock_source)
        or bindings["prior_attempt_failure_digest"] != _digest(prior_failure_source)
    ):
        raise DiseaseR1ReviewError(
            "r1_review_digest_mismatch", "Disease R1 review digest differs"
        )

    task_candidate = _load_json(task_source, "Disease R1 Task candidate")
    grant_candidate = _load_json(grant_source, "Disease R1 Grant candidate")
    composition_candidate = _load_json(
        composition_source, "Disease R1 composition candidate"
    )
    policy = _load_json(policy_source, "Disease R1 policy candidate")
    runtime_lock = _load_json(runtime_lock_source, "Disease R1 runtime source lock")
    prior_failure = _load_json(prior_failure_source, "Prior Disease R1 failure")
    _validate_task_candidate(task_candidate)
    synthetic_grant = _validate_grant_candidate(grant_candidate)
    actual_grant_digest = grant_digest(grant_from_mapping(synthetic_grant))
    if bindings["grant_candidate_digest"] != actual_grant_digest:
        raise DiseaseR1ReviewError(
            "r1_grant_digest_mismatch", "Disease R1 synthetic Grant digest differs"
        )
    _validate_policy(policy, bindings["policy_digest"])
    _validate_runtime_lock(runtime_lock, request["runtime"])
    _validate_prior_failure(prior_failure)
    _validate_composition_candidate(
        composition_candidate,
        task_candidate,
        synthetic_grant,
        bindings,
        request["runtime"],
    )
    return VerifiedDiseaseR1Review(
        review_id=request["review_id"],
        review_request_digest=_digest(request_source),
        task_candidate_digest=bindings["task_candidate_digest"],
        grant_candidate_digest=bindings["grant_candidate_digest"],
        composition_candidate_digest=bindings["composition_candidate_digest"],
        runtime_source_digest=request["runtime"]["runtime_source_digest"],
        control_source_digest=request["runtime"]["control_source_digest"],
        image_ref=request["runtime"]["image_ref"],
        image_id=request["runtime"]["image_id"],
        synthetic_grant=synthetic_grant,
        task_candidate=task_candidate,
        composition_candidate=composition_candidate,
    )


def load_disease_r1_execution_approval(
    path: Path | str,
    review: VerifiedDiseaseR1Review,
    *,
    checked_at: str | None = None,
) -> DiseaseR1ExecutionApproval:
    source = _read_owner_only(Path(path))
    document = _load_json(source, "Disease R1 execution approval")
    expected = set(DiseaseR1ExecutionApproval.__dataclass_fields__)
    if not isinstance(document, dict) or set(document) != expected:
        raise DiseaseR1ReviewError(
            "r1_approval_fields_invalid", "Disease R1 approval fields differ"
        )
    approval = DiseaseR1ExecutionApproval(**document)
    checked = _timestamp(checked_at) if checked_at is not None else datetime.now(timezone.utc)
    decided = _timestamp(approval.decided_at)
    expires = _timestamp(approval.expires_at)
    if (
        approval.action != "run_disease_r1_once"
        or approval.decision != "approve"
        or approval.review_request_digest != review.review_request_digest
        or approval.task_candidate_digest != review.task_candidate_digest
        or approval.grant_candidate_digest != review.grant_candidate_digest
        or approval.composition_candidate_digest
        != review.composition_candidate_digest
        or approval.runtime_source_digest != review.runtime_source_digest
        or approval.control_source_digest != review.control_source_digest
        or approval.agent_release_digest != EXPECTED_AGENT_RELEASE_DIGEST
        or approval.evidence_status != "synthetic"
        or approval.synthetic_only is not True
        or not approval.decision_id.startswith("decision_")
        or not approval.decided_by_human_ref.startswith("human_")
        or checked < decided
        or checked >= expires
        or expires <= decided
        or (expires - decided).total_seconds() > 900
        or len(approval.reason.strip()) < 20
    ):
        raise DiseaseR1ReviewError(
            "r1_approval_scope_invalid", "Disease R1 approval scope differs"
        )
    return approval


def control_source_paths(root: Path | str) -> tuple[Path, ...]:
    base = Path(root)
    paths = tuple(
        sorted(
            (
                path.relative_to(base)
                for path in (base / "src" / "orbit_agent_control_plane").glob("*.py")
            ),
            key=lambda path: path.as_posix(),
        )
    ) + (
        Path("scripts/run_disease_r1.py"),
        Path("scripts/run_disease_r1_docker.py"),
    )
    for relative in paths:
        source = base / relative
        if not source.is_file() or source.is_symlink():
            raise DiseaseR1ReviewError(
                "r1_control_source_unsafe",
                "Disease R1 control source is missing or unsafe",
            )
    return paths


def control_source_files(root: Path | str) -> list[dict[str, str]]:
    base = Path(root)
    return [
        {"path": relative.as_posix(), "sha256": _digest((base / relative).read_bytes())}
        for relative in control_source_paths(base)
    ]


def compute_control_source_digest(root: Path | str) -> str:
    base = Path(root)
    digest = sha256()
    for relative in control_source_paths(base):
        encoded_path = relative.as_posix().encode("utf-8")
        source = (base / relative).read_bytes()
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(source).to_bytes(8, "big"))
        digest.update(source)
    return f"sha256:{digest.hexdigest()}"


def _validate_task_candidate(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "candidate_version",
        "status",
        "company_task",
        "authority_boundary",
    }:
        raise DiseaseR1ReviewError(
            "r1_task_candidate_invalid", "Disease R1 Task candidate differs"
        )
    if (
        value["candidate_version"] != "orbit.disease-r1-task-candidate/1"
        or value["status"] != "proposed-not-created"
        or value["authority_boundary"]
        != {
            "task_ledger_write_performed": False,
            "effective_grant_ref_present": False,
            "dispatch_created": False,
            "runtime_started": False,
        }
    ):
        raise DiseaseR1ReviewError(
            "r1_task_candidate_boundary_invalid",
            "Disease R1 Task candidate boundary differs",
        )
    task = value["company_task"]
    schemas, _, _ = _load_verified_company_schemas(
        DEFAULT_COMPANY_LOCK,
        DEFAULT_CONTRACT_BUNDLE,
        {_TASK_SCHEMA_ID},
    )
    _SchemaValidator(schemas).validate(task, _TASK_SCHEMA_ID)
    if (
        task["task_id"] != COMPANY_TASK_ID
        or task["agent_id"] != DISEASE_AGENT_ID
        or task["parent_task_id"] is not None
        or task["created_by"]
        != {
            "subject_type": "system",
            "subject_id": "system_orbit_control_plane_syn",
        }
        or task["accountable_human_id"] != "hum_orbit_disease_r1_owner_syn"
        or task["agent_definition_ref"]
        != {
            "id": DISEASE_AGENT_ID,
            "version": "0.1.0",
            "digest": "sha256:9557e19285955432f8f41a8844d212a427a2efd3d900c86bc8fd70bad824b663",
        }
        or task["agent_binding_ref"]
        != {
            "id": "bind_orbit_disease_research_task_d0_syn",
            "version": "0.1.0",
            "digest": "sha256:a9edd1b1648650631cfeade592430e494e624a220b22fc528748adcb3cdd1334",
        }
        or task["status"] != "pending_approval"
        or task["risk_class"] != "high"
        or task["autonomy_level"] != "L1"
        or task["approval"]
        != {"required": True, "state": "pending", "decision_refs": []}
        or task["hierarchy_context"]["effective_grant_refs"]
        or task["permission_request"]["tool_operations"]
        or task["permission_request"]["dataset_requests"]
        or task["permission_request"]["knowledge_refs"]
        != [
            "urn:orbit:artifact:disease-research/packages/"
            "drpkg-smb-01-fictional-stationery/0.1.0"
        ]
        or "dispatch" in task
        or task["budget"]
        != {
            "policy_ref": "pol_orbit_disease_stationery_r1_syn",
            "max_runtime_seconds": 30,
            "max_model_tokens": 0,
            "max_tool_calls": 0,
            "max_cost": 0,
            "currency": "CNY",
            "on_exhaustion": "stop",
        }
        or task["retry_policy"]
        != {
            "max_attempts": 1,
            "side_effect_retry": "never",
            "backoff_policy": "none",
        }
    ):
        raise DiseaseR1ReviewError(
            "r1_task_candidate_scope_invalid", "Disease R1 Task scope differs"
        )


def _validate_grant_candidate(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "candidate_version",
        "status",
        "effective",
        "issued",
        "synthetic_clock",
        "grant_digest",
        "synthetic_grant",
        "company_contract_projection",
        "authority_boundary",
    }:
        raise DiseaseR1ReviewError(
            "r1_grant_candidate_invalid", "Disease R1 Grant candidate differs"
        )
    synthetic_grant = value["synthetic_grant"]
    grant = grant_from_mapping(synthetic_grant)
    actual_digest = grant_digest(grant)
    if (
        value["candidate_version"] != "orbit.disease-r1-grant-candidate/1"
        or value["status"] != "proposed-not-issued"
        or value["effective"] is not False
        or value["issued"] is not False
        or value["grant_digest"] != actual_digest
        or value["synthetic_clock"]
        != {
            "checked_at": "2026-08-26T00:05:00Z",
            "wall_clock_authority": False,
        }
        or value["authority_boundary"]
        != {
            "grant_ledger_write_performed": False,
            "workload_identity_credential_created": False,
            "task_execution_authorized": False,
            "runtime_started": False,
        }
    ):
        raise DiseaseR1ReviewError(
            "r1_grant_candidate_boundary_invalid",
            "Disease R1 Grant candidate boundary differs",
        )
    schemas, _, _ = _load_verified_company_schemas(
        DEFAULT_COMPANY_LOCK,
        DEFAULT_CONTRACT_BUNDLE,
        {_COMMON_SCHEMA_ID, _GRANT_SCHEMA_ID},
    )
    projection = value["company_contract_projection"]
    _SchemaValidator(schemas).validate(projection, _GRANT_SCHEMA_ID)
    if (
        projection["metadata"]["status"] != "draft"
        or projection["metadata"]["grant_id"] != EXECUTION_GRANT_ID
        or projection["metadata"]["task_id"] != grant.task_id
        or projection["spec"]["tool_scopes"]
        or projection["spec"]["data_scopes"]
        or projection["spec"]["agent_scopes"]
        or projection["spec"]["model_route_refs"]
        or projection["spec"]["memory_classes"]
        or projection["spec"]["environment"]
        != {
            "environment_id": "env_orbit_disease_r1_container_syn",
            "security_zone": "medical_research",
            "filesystem": "deny",
            "network": "deny",
            "workspace_mode": "none",
        }
        or projection["spec"]["resource_limits"]
        != {
            "max_tool_calls": 0,
            "max_concurrency": 1,
            "max_runtime_seconds": 30,
            "max_model_tokens": 0,
        }
    ):
        raise DiseaseR1ReviewError(
            "r1_grant_projection_scope_invalid",
            "Disease R1 Company Grant projection differs",
        )
    return synthetic_grant


def _validate_policy(value: Any, policy_digest: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "policy_version",
            "policy_id",
            "status",
            "effective",
            "allowed",
            "denied",
            "authority_boundary",
        }
        or value.get("policy_version") != "orbit.disease-r1-policy-candidate/1"
        or value.get("policy_id") != "pol_orbit_disease_stationery_r1_syn"
        or value.get("status") != "proposed"
        or value.get("effective") is not False
        or value.get("allowed")
        != {
            "classification": ["synthetic"],
            "operations": ["disease_research_task.execute_synthetic"],
            "max_concurrency": 1,
            "max_runtime_seconds": 30,
            "budget_units": 10,
        }
        or value.get("denied")
        != [
            "model",
            "network",
            "host_filesystem",
            "nas",
            "real_dataset_registry",
            "agent_to_agent",
            "publication",
            "approved_asset_release",
        ]
        or value.get("authority_boundary")
        != {
            "policy_activated": False,
            "task_execution_authorized": False,
            "release_authorization": False,
        }
        or _digest(
            (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            )
        )
        != policy_digest
    ):
        raise DiseaseR1ReviewError(
            "r1_policy_candidate_invalid", "Disease R1 policy candidate differs"
        )


def _validate_runtime_lock(value: Any, runtime: Any) -> None:
    if (
        not isinstance(value, dict)
        or not isinstance(runtime, dict)
        or set(value)
        != {
            "lock_version",
            "status",
            "generated_at",
            "image_ref",
            "image_id",
            "runtime_source_digest",
            "files",
            "control_source_digest",
            "control_files",
            "constraints",
            "runtime_started",
        }
        or set(runtime)
        != {
            "image_ref",
            "image_id",
            "runtime_source_digest",
            "control_source_digest",
            "network",
        }
        or value.get("lock_version") != "orbit.disease-r1-runtime-source-lock/1"
        or value.get("status") != "prepared-not-executed"
        or value.get("runtime_source_digest") != runtime["runtime_source_digest"]
        or value.get("control_source_digest") != runtime["control_source_digest"]
        or value.get("image_ref") != runtime["image_ref"]
        or value.get("image_id") != runtime["image_id"]
        or runtime["image_ref"] != "nousresearch/hermes-agent:v2026.8.16"
        or runtime["image_id"]
        != "sha256:f8f548d87d16634d1ad9e3777280f3f577ba2358703f04e18e74007ffd3621bf"
        or runtime["network"] != "none"
        or value.get("constraints")
        != {
            "network": "none",
            "user": "65532:65532",
            "root_filesystem": "read-only",
            "work_tmpfs": "rw,noexec,nosuid,nodev,64m",
            "capabilities": "none",
            "no_new_privileges": True,
            "memory": "256m",
            "cpus": "1",
            "pids": 64,
            "nofile": 64,
            "timeout_seconds": 30,
            "model": "forbidden",
            "host_project_home_nas_docker_socket": "not-mounted",
        }
        or value.get("runtime_started") is not False
        or not isinstance(value.get("files"), list)
        or not value["files"]
        or not isinstance(value.get("control_files"), list)
        or not value["control_files"]
    ):
        raise DiseaseR1ReviewError(
            "r1_runtime_lock_invalid", "Disease R1 runtime source lock differs"
        )
    paths: set[str] = set()
    for entries, runtime_only in (
        (value["files"], True),
        (value["control_files"], False),
    ):
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"path", "sha256"}
                or not isinstance(entry["path"], str)
                or entry["path"] in paths
                or entry["path"].startswith(("/", "../"))
                or "/../" in entry["path"]
                or any(
                    marker in entry["path"].lower()
                    for marker in (".env", "__pycache__")
                )
                or (runtime_only and "dataset_agent" in entry["path"].lower())
                or not isinstance(entry["sha256"], str)
                or len(entry["sha256"]) != 71
                or not entry["sha256"].startswith("sha256:")
            ):
                raise DiseaseR1ReviewError(
                    "r1_runtime_lock_file_invalid",
                    "Disease R1 runtime source file lock differs",
                )
            paths.add(entry["path"])
    control_paths = {entry["path"] for entry in value["control_files"]}
    if not {
        "scripts/run_disease_r1.py",
        "scripts/run_disease_r1_docker.py",
        "src/orbit_agent_control_plane/disease_r1.py",
        "src/orbit_agent_control_plane/disease_r1_review.py",
        "src/orbit_agent_control_plane/ledger.py",
        "src/orbit_agent_control_plane/router.py",
    }.issubset(control_paths):
        raise DiseaseR1ReviewError(
            "r1_control_source_lock_incomplete",
            "Disease R1 control source lock is incomplete",
        )


def _validate_prior_failure(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or value.get("evidence_version")
        != "orbit.disease-r1-execution-evidence/1"
        or value.get("status") != "R1 synthetic fail"
        or value.get("evidence_status") != "synthetic"
        or value.get("synthetic_only") is not True
        or value.get("review_request_digest") != PRIOR_R1_REVIEW_DIGEST
        or value.get("task", {}).get("task_id") != PRIOR_R1_TASK_ID
        or value.get("worker_lease", {}).get("status") != "failed"
        or value.get("worker_lease", {}).get("revision") != 1
        or value.get("failure_diagnostics")
        != {
            "phase": "container_result_validation",
            "container_exit_code": 2,
            "stdout_bytes": 0,
            "stdout_sha256": None,
            "stderr_bytes": 19,
            "sanitized_child_error_code": "input_size_invalid",
            "classified_error_code": "r1_container_result_invalid",
            "raw_output_persisted": False,
        }
        or value.get("reason_codes")
        != [
            "r1_runtime_failed_closed",
            "r1_failure_phase_container_result_validation",
            "input_size_invalid",
        ]
        or value.get("release_authorization") is not False
        or value.get("preproduction_authorized") is not False
        or value.get("production_authorized") is not False
    ):
        raise DiseaseR1ReviewError(
            "prior_r1_failure_invalid",
            "Prior Disease R1 failure evidence differs",
        )


def _validate_composition_candidate(
    value: Any,
    task_candidate: Mapping[str, Any],
    synthetic_grant: Mapping[str, Any],
    bindings: Mapping[str, Any],
    runtime: Mapping[str, Any],
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "candidate_version",
        "status",
        "checked_at",
        "route_candidate",
        "runtime_composition_candidate",
        "worker_lease_candidate",
        "authority_boundary",
    }:
        raise DiseaseR1ReviewError(
            "r1_composition_candidate_invalid",
            "Disease R1 composition candidate differs",
        )
    grant = grant_from_mapping(synthetic_grant)
    plan = plan_disease_r1(
        grant,
        checked_at=value["checked_at"],
        lifecycle_status="active",
        lifecycle_release_digest=EXPECTED_AGENT_RELEASE_DIGEST,
    )
    expected_route = _json_value(asdict(plan.route))
    expected_composition = _json_value(asdict(plan.composition))
    expected_lease = {
        **_json_value(asdict(plan.worker_lease)),
        "status": "proposed",
    }
    if (
        value["candidate_version"]
        != "orbit.disease-r1-runtime-composition-candidate/1"
        or value["status"] != "proposed-not-created"
        or task_candidate["company_task"]["task_id"] != plan.task.task_id
        or value["route_candidate"] != expected_route
        or value["runtime_composition_candidate"] != expected_composition
        or value["worker_lease_candidate"] != expected_lease
        or plan.composition.execution_grant_digest
        != bindings["grant_candidate_digest"]
        or plan.composition.policy_digest != bindings["policy_digest"]
        or grant.runtime_source_digest != runtime["runtime_source_digest"]
        or value["authority_boundary"]
        != {
            "route_decision_persisted": False,
            "runtime_composition_persisted": False,
            "worker_lease_started": False,
            "task_ledger_write_performed": False,
            "runtime_started": False,
        }
    ):
        raise DiseaseR1ReviewError(
            "r1_composition_candidate_scope_invalid",
            "Disease R1 composition candidate scope differs",
        )


def _verify_artifacts(root: Path, entries: Any) -> dict[str, bytes]:
    if not isinstance(entries, list) or not entries:
        raise DiseaseR1ReviewError(
            "r1_review_artifacts_invalid", "Disease R1 artifacts are unavailable"
        )
    result: dict[str, bytes] = {}
    paths: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"kind", "path", "sha256"}:
            raise DiseaseR1ReviewError(
                "r1_review_artifact_invalid", "Disease R1 artifact entry differs"
            )
        if entry["kind"] in result or entry["path"] in paths:
            raise DiseaseR1ReviewError(
                "r1_review_artifact_duplicate", "Disease R1 artifact is duplicated"
            )
        source = _safe_read(root, entry["path"], "Disease R1 artifact")
        if _digest(source) != entry["sha256"]:
            raise DiseaseR1ReviewError(
                "r1_review_artifact_digest_mismatch",
                "Disease R1 artifact digest differs",
            )
        paths.add(entry["path"])
        result[entry["kind"]] = source
    return result


def _safe_read(root: Path, relative: Path | str, label: str) -> bytes:
    candidate = Path(relative)
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(root.resolve(strict=True))
        except (OSError, ValueError) as error:
            raise DiseaseR1ReviewError(
                "unsafe_artifact_path", f"{label} is outside the review root"
            ) from error
    try:
        return _read_safe_file(root, _safe_relative_path(candidate, label))
    except RegistrationError as error:
        raise DiseaseR1ReviewError(error.reason_code, f"{label} is unavailable") from error


def _load_json(source: bytes, label: str) -> Any:
    try:
        return _load_json_bytes(source, label)
    except RegistrationError as error:
        raise DiseaseR1ReviewError(error.reason_code, f"{label} is invalid") from error


def _json_value(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _timestamp(value: str | None) -> datetime:
    if not isinstance(value, str):
        raise DiseaseR1ReviewError(
            "r1_approval_timestamp_invalid", "Disease R1 approval time is invalid"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DiseaseR1ReviewError(
            "r1_approval_timestamp_invalid", "Disease R1 approval time is invalid"
        ) from error
    if parsed.tzinfo is None:
        raise DiseaseR1ReviewError(
            "r1_approval_timestamp_invalid", "Disease R1 approval time lacks timezone"
        )
    return parsed.astimezone(timezone.utc)


def _read_owner_only(path: Path) -> bytes:
    if not os.path.lexists(path):
        raise DiseaseR1ReviewError(
            "r1_approval_not_found", "Disease R1 approval does not exist"
        )
    if stat.S_ISLNK(os.lstat(path).st_mode):
        raise DiseaseR1ReviewError(
            "r1_approval_symlink_forbidden", "Disease R1 approval may not be a symlink"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > 64 * 1024
        ):
            raise DiseaseR1ReviewError(
                "r1_approval_file_invalid", "Disease R1 approval file is unsafe"
            )
        return os.read(fd, metadata.st_size + 1)
    finally:
        os.close(fd)

