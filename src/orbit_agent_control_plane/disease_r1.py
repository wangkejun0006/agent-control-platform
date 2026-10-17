"""Fail-closed Company composition for one fictional-stationery synthetic R1."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Mapping

from .evaluator import CompanyEvaluator
from .ids import COMPANY_TASK_ROUTER_AGENT_ID, deterministic_id
from .models import (
    AgentReleaseSelection,
    AuditEvent,
    ClosedLoopOutcome,
    EvaluationReport,
    RouteDecision,
    RoutingTarget,
    RuntimeComposition,
    RuntimeCompositionRequest,
    TaskEnvelope,
    TaskResult,
    WorkerLease,
)
from .router import CompanyTaskRouter, RuntimeComposer


GRANT_VERSION = "orbit.synthetic-disease-r1-execution-grant/1"
COMPANY_TASK_ID = "tsk_orbit_disease_stationery_r1_retry4_syn"
EXECUTION_GRANT_ID = "grant_orbit_disease_stationery_r1_retry4_syn"
EXPECTED_PACKAGE_ID = "drpkg-smb-01-fictional-stationery"
EXPECTED_PACKAGE_VERSION = "0.1.0"
EXPECTED_PACKAGE_DIGEST = (
    "sha256:b7a5ba899283e57a7d4b9d0ad47725d7d0310537f69814bafdaab8c96dc5e5f1"
)
DISEASE_AGENT_ID = "agt_orbit_disease_research_task_syn"
EXPECTED_AGENT_RELEASE_DIGEST = (
    "sha256:629d8d9b6997baf694b5856a526721ccd69bf71348c481c5c4dc6d909f62a0cb"
)
DISEASE_CAPABILITY = "disease_research_task.execute_synthetic"
MODEL_ROUTE_REF = "model_route_none_disease_r1_syn"
MODEL_ROUTE_DIGEST = "sha256:" + sha256(b'{"usage":"forbidden"}').hexdigest()
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FORBIDDEN = re.compile(
    r"/Users/|/Volumes/|(?:file|smb|opaque)://|opaque_storage_ref|"
    r"secret|credential|endpoint|docker\.sock",
    re.IGNORECASE,
)


class DiseaseR1Error(ValueError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class DiseasePackageRef:
    package_id: str
    version: str
    digest: str
    artifact_ref: str


@dataclass(frozen=True)
class SyntheticDiseaseExecutionGrant:
    version: str
    grant_id: str
    task_id: str
    agent_id: str
    agent_release_digest: str
    package: DiseasePackageRef
    runtime_source_digest: str
    policy_ref: str
    policy_digest: str
    allowed_operations: tuple[str, ...]
    budget_units: int
    issued_at: str
    expires_at: str
    revoked: bool
    model_allowed: bool
    network_allowed: bool
    host_filesystem_allowed: bool
    nas_allowed: bool
    real_registry_allowed: bool
    agent_to_agent_allowed: bool
    publish_allowed: bool
    evidence_status: str
    synthetic_only: bool


@dataclass(frozen=True)
class DiseaseR1Plan:
    task: TaskEnvelope
    route: RouteDecision
    route_audit: AuditEvent
    grant: SyntheticDiseaseExecutionGrant
    grant_digest: str
    composition: RuntimeComposition
    worker_lease: WorkerLease
    request_id: str


@dataclass(frozen=True)
class DiseaseR1EvaluatedOutcome:
    company_outcome: ClosedLoopOutcome
    domain_evaluation: EvaluationReport


def grant_from_mapping(value: Any) -> SyntheticDiseaseExecutionGrant:
    if not isinstance(value, dict) or set(value) != {
        "version",
        "grant_id",
        "task_id",
        "agent_id",
        "agent_release_digest",
        "package",
        "runtime_source_digest",
        "policy_ref",
        "policy_digest",
        "allowed_operations",
        "budget_units",
        "issued_at",
        "expires_at",
        "revoked",
        "model_allowed",
        "network_allowed",
        "host_filesystem_allowed",
        "nas_allowed",
        "real_registry_allowed",
        "agent_to_agent_allowed",
        "publish_allowed",
        "evidence_status",
        "synthetic_only",
    }:
        raise DiseaseR1Error("grant_fields_invalid", "Disease R1 Grant fields differ")
    package_value = value["package"]
    if not isinstance(package_value, dict) or set(package_value) != {
        "package_id",
        "version",
        "digest",
        "artifact_ref",
    }:
        raise DiseaseR1Error("grant_package_invalid", "Disease R1 package ref differs")
    operations = value["allowed_operations"]
    if not isinstance(operations, list) or any(
        not isinstance(item, str) for item in operations
    ):
        raise DiseaseR1Error("grant_operations_invalid", "Disease R1 operations differ")
    grant = SyntheticDiseaseExecutionGrant(
        version=value["version"],
        grant_id=value["grant_id"],
        task_id=value["task_id"],
        agent_id=value["agent_id"],
        agent_release_digest=value["agent_release_digest"],
        package=DiseasePackageRef(**package_value),
        runtime_source_digest=value["runtime_source_digest"],
        policy_ref=value["policy_ref"],
        policy_digest=value["policy_digest"],
        allowed_operations=tuple(operations),
        budget_units=value["budget_units"],
        issued_at=value["issued_at"],
        expires_at=value["expires_at"],
        revoked=value["revoked"],
        model_allowed=value["model_allowed"],
        network_allowed=value["network_allowed"],
        host_filesystem_allowed=value["host_filesystem_allowed"],
        nas_allowed=value["nas_allowed"],
        real_registry_allowed=value["real_registry_allowed"],
        agent_to_agent_allowed=value["agent_to_agent_allowed"],
        publish_allowed=value["publish_allowed"],
        evidence_status=value["evidence_status"],
        synthetic_only=value["synthetic_only"],
    )
    _validate_grant(grant)
    return grant


def grant_digest(grant: SyntheticDiseaseExecutionGrant) -> str:
    return _digest_mapping(asdict(grant))


def plan_disease_r1(
    grant: SyntheticDiseaseExecutionGrant,
    *,
    checked_at: str,
    lifecycle_status: str,
    lifecycle_release_digest: str,
) -> DiseaseR1Plan:
    _validate_grant(grant)
    checked = _timestamp(checked_at)
    if grant.revoked:
        raise DiseaseR1Error("grant_revoked", "Disease R1 Grant is revoked")
    if checked < _timestamp(grant.issued_at) or checked >= _timestamp(grant.expires_at):
        raise DiseaseR1Error("grant_expired", "Disease R1 Grant is not currently valid")
    if lifecycle_status != "active":
        raise DiseaseR1Error("agent_inactive", "Disease Agent is not active")
    if lifecycle_release_digest != grant.agent_release_digest:
        raise DiseaseR1Error(
            "agent_release_drift", "Disease Agent lifecycle release differs from Grant"
        )
    task = TaskEnvelope(
        task_id=grant.task_id,
        capability=DISEASE_CAPABILITY,
        data_classification="synthetic",
        grant_id=grant.grant_id,
        grant_active=True,
        requested_target_id=grant.agent_id,
    )
    route = CompanyTaskRouter().route(
        task,
        (
            RoutingTarget(
                target_id=grant.agent_id,
                capabilities=frozenset({DISEASE_CAPABILITY}),
                allowed_data_classifications=frozenset({"synthetic"}),
                active=True,
            ),
        ),
    )
    if route.status != "routed":
        raise DiseaseR1Error("route_blocked", "Disease R1 route failed closed")
    route_audit = AuditEvent(
        event_id=f"audit_{route.decision_id}",
        task_id=task.task_id,
        event_type="route_decision_recorded",
        subject_ref=COMPANY_TASK_ROUTER_AGENT_ID,
    )
    digest = grant_digest(grant)
    composition = RuntimeComposer().compose(
        RuntimeCompositionRequest(
            task_id=task.task_id,
            data_classification="synthetic",
            agent=AgentReleaseSelection(
                agent_id=grant.agent_id,
                release_digest=grant.agent_release_digest,
                capabilities=frozenset({DISEASE_CAPABILITY}),
                requested_tool_capabilities=frozenset(),
                allowed_data_classifications=frozenset({"synthetic"}),
                active=True,
            ),
            tool_requirements=(),
            model_route_ref=MODEL_ROUTE_REF,
            model_route_digest=MODEL_ROUTE_DIGEST,
            policy_ref=grant.policy_ref,
            policy_digest=grant.policy_digest,
            execution_grant_ref=grant.grant_id,
            execution_grant_digest=digest,
            input_registry_revision=(
                "package_revision_sha256_" + grant.package.digest.removeprefix("sha256:")
            ),
            budget_units=grant.budget_units,
        ),
        (),
    )
    lease_id = deterministic_id(
        "lease", task.task_id, "worker_orbit_disease_r1_syn", grant.runtime_source_digest
    )
    lease = WorkerLease(
        lease_id=lease_id,
        task_id=task.task_id,
        worker_id="worker_orbit_disease_r1_syn",
        implementation_revision=grant.runtime_source_digest,
        status="active",
        revision=0,
        cancellation_requested=False,
        last_event_ref=route_audit.event_id,
    )
    return DiseaseR1Plan(
        task=task,
        route=route,
        route_audit=route_audit,
        grant=grant,
        grant_digest=digest,
        composition=composition,
        worker_lease=lease,
        request_id=deterministic_id("request", task.task_id, digest),
    )


def validate_task_input(value: Any, plan: DiseaseR1Plan) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "task_id",
        "parent_task_ref",
        "idempotency_key",
        "package",
        "research_question_ref",
        "agent_binding_ref",
        "route_decision_ref",
        "execution_grant_ref",
        "memory_namespace",
        "dataset_refs",
        "data_classification",
        "allowed_operations",
        "budget",
        "control_state",
        "synthetic_only",
        "authority_boundary",
    }:
        raise DiseaseR1Error("task_input_fields_invalid", "Disease R1 Task input differs")
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if _FORBIDDEN.search(serialized):
        raise DiseaseR1Error("task_input_permission_injection", "Disease R1 Task input leaks authority")
    package = value["package"]
    grant_package = {
        **asdict(plan.grant.package),
        "digest": plan.grant.package.digest.removeprefix("sha256:"),
    }
    if (
        value["schema_version"] != "orbit.disease-research-task-input/1.0"
        or value["task_id"] != "drtask-fictional-stationery-r1-001"
        or value["parent_task_ref"]
        != f"company-task://synthetic/{plan.task.task_id}"
        or value["idempotency_key"]
        != "idem:drtask:fictional-stationery:r1:001"
        or value["research_question_ref"]
        != "research-question://synthetic/fictional-stationery/r1-001"
        or value["agent_binding_ref"]
        != (
            "agent-binding://synthetic/"
            "bind_orbit_disease_research_task_d0_syn/0.1.0/sha256/"
            "a9edd1b1648650631cfeade592430e494e624a220b22fc528748adcb3cdd1334"
        )
        or value["route_decision_ref"] != plan.route.decision_id
        or value["execution_grant_ref"] != plan.grant.grant_id
        or value["memory_namespace"]
        != "memory://disease-task/fictional-stationery-r1-001"
        or value["data_classification"] != "synthetic"
        or value["synthetic_only"] is not True
        or value["control_state"] != "active"
        or package != grant_package
        or value["dataset_refs"]
        != [
            {
                "dataset_id": "dataset_synthetic_stationery_d0_001",
                "version_id": "0.1.0",
                "artifact_ref": (
                    "urn:orbit:artifact:dataset/synthetic-stationery-d0/0.1.0"
                ),
                "data_classification": "synthetic",
                "purpose": "R1 contract and package-resolution testing only",
                "required_operation": "read-artifact",
            }
        ]
        or value["allowed_operations"]
        != ["resolve-package", "read-artifact", "derive-synthetic-result"]
        or value["budget"]
        != {
            "max_cost_cny": "0.000000",
            "max_runtime_seconds": 30,
            "max_artifact_bytes": 1000000,
        }
        or value["authority_boundary"]
        != {
            "may_resolve_storage_path": False,
            "may_write_storage": False,
            "may_delete_storage": False,
            "may_publish_package": False,
        }
    ):
        raise DiseaseR1Error("task_input_scope_invalid", "Disease R1 Task input exceeds Grant")


def evaluate_worker_response(
    plan: DiseaseR1Plan, response: Mapping[str, Any]
) -> DiseaseR1EvaluatedOutcome:
    serialized = json.dumps(response, ensure_ascii=False, sort_keys=True)
    if _FORBIDDEN.search(serialized):
        raise DiseaseR1Error("worker_response_leak", "Disease R1 response leaks authority")
    if set(response) != {
        "schema_version",
        "request_id",
        "runtime_event",
        "result_package",
        "audit_event",
        "process_evidence",
    } or response["request_id"] != plan.request_id:
        raise DiseaseR1Error("worker_response_mismatch", "Disease R1 response differs")
    result_package = response["result_package"]
    runtime_event = response["runtime_event"]
    audit = response["audit_event"]
    if (
        result_package["status"] != "complete"
        or result_package["package"]
        != {
            "package_id": plan.grant.package.package_id,
            "version": plan.grant.package.version,
            "digest": plan.grant.package.digest.removeprefix("sha256:"),
        }
        or any(result_package["authority_boundary"].values())
        or runtime_event["spec"]["event_type"] != "completed"
        or runtime_event["metadata"]["task_id"] != plan.task.task_id
        or audit["spec"]["task_ref"] != plan.task.task_id
    ):
        raise DiseaseR1Error("worker_response_scope_invalid", "Disease R1 result exceeds scope")
    completion_audit = AuditEvent(
        event_id=deterministic_id(
            "audit", plan.task.task_id, result_package["result_id"], "disease_r1_completed"
        ),
        task_id=plan.task.task_id,
        event_type="synthetic_worker_completed",
        subject_ref=plan.grant.agent_id,
    )
    task_result = TaskResult(
        result_id=deterministic_id("result", plan.task.task_id, result_package["result_id"]),
        task_id=plan.task.task_id,
        target_id=plan.grant.agent_id,
        status="completed",
        output_ref=f"artifact://synthetic/{plan.task.task_id}/result",
        audit_event_refs=(completion_audit.event_id,),
        side_effects=(),
    )
    domain_evaluation = _domain_evaluate(plan, response, task_result)
    audits = (plan.route_audit, completion_audit)
    company_evaluation = CompanyEvaluator().evaluate(
        task=plan.task,
        route_decision=plan.route,
        result=task_result,
        audit_events=audits,
        subject_agent_id=plan.grant.agent_id,
    )
    outcome = ClosedLoopOutcome(
        task=plan.task,
        route_decision=plan.route,
        result=task_result,
        evaluation=company_evaluation,
        audit_events=audits,
    )
    return DiseaseR1EvaluatedOutcome(outcome, domain_evaluation)


def _domain_evaluate(
    plan: DiseaseR1Plan, response: Mapping[str, Any], result: TaskResult
) -> EvaluationReport:
    reasons = []
    package = response["result_package"]["package"]
    if package["package_id"] != EXPECTED_PACKAGE_ID:
        reasons.append("package_id_mismatch")
    if package["version"] != EXPECTED_PACKAGE_VERSION:
        reasons.append("package_version_mismatch")
    if "fictional-stationery" not in plan.grant.package.artifact_ref:
        reasons.append("package_artifact_mismatch")
    if response["result_package"]["evaluation_report_refs"]:
        reasons.append("self_evaluation_reference_forbidden")
    verdict = "pass" if not reasons else "fail"
    if not reasons:
        reasons.append("disease_r1_fixed_suite_pass")
    return EvaluationReport(
        report_id=deterministic_id("domain_evaluation", result.result_id, verdict, *reasons),
        evaluator_agent_id="agt_orbit_disease_domain_evaluator_syn",
        subject_result_id=result.result_id,
        verdict=verdict,
        reason_codes=tuple(reasons),
        release_authorization=False,
    )


def _validate_grant(grant: SyntheticDiseaseExecutionGrant) -> None:
    serialized = json.dumps(asdict(grant), ensure_ascii=False, sort_keys=True)
    if _FORBIDDEN.search(serialized):
        raise DiseaseR1Error("grant_permission_injection", "Disease R1 Grant leaks authority")
    if (
        grant.version != GRANT_VERSION
        or grant.grant_id != EXECUTION_GRANT_ID
        or grant.task_id != COMPANY_TASK_ID
        or grant.agent_id != DISEASE_AGENT_ID
        or grant.agent_release_digest != EXPECTED_AGENT_RELEASE_DIGEST
        or grant.package.package_id != EXPECTED_PACKAGE_ID
        or grant.package.version != EXPECTED_PACKAGE_VERSION
        or grant.package.digest != EXPECTED_PACKAGE_DIGEST
        or grant.package.artifact_ref
        != (
            "urn:orbit:artifact:disease-research/packages/"
            "drpkg-smb-01-fictional-stationery/0.1.0"
        )
        or grant.policy_ref != "pol_orbit_disease_stationery_r1_syn"
        or grant.allowed_operations != (DISEASE_CAPABILITY,)
        or grant.budget_units != 10
        or grant.evidence_status != "synthetic"
        or grant.synthetic_only is not True
        or not isinstance(grant.budget_units, int)
        or isinstance(grant.budget_units, bool)
        or grant.budget_units < 1
        or any(
            (
                grant.model_allowed,
                grant.network_allowed,
                grant.host_filesystem_allowed,
                grant.nas_allowed,
                grant.real_registry_allowed,
                grant.agent_to_agent_allowed,
                grant.publish_allowed,
            )
        )
    ):
        raise DiseaseR1Error("grant_scope_invalid", "Disease R1 Grant exceeds R1 scope")
    for digest in (
        grant.agent_release_digest,
        grant.runtime_source_digest,
        grant.policy_digest,
    ):
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise DiseaseR1Error("grant_digest_invalid", "Disease R1 Grant digest is invalid")
    issued = _timestamp(grant.issued_at)
    expires = _timestamp(grant.expires_at)
    if expires <= issued or (expires - issued).total_seconds() > 900:
        raise DiseaseR1Error("grant_lifetime_invalid", "Disease R1 Grant lifetime differs")


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise DiseaseR1Error("timestamp_invalid", "Disease R1 timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DiseaseR1Error("timestamp_invalid", "Disease R1 timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise DiseaseR1Error("timestamp_invalid", "Disease R1 timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _digest_mapping(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{sha256(encoded).hexdigest()}"

