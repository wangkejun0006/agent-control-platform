"""Deterministic Agent release qualification automation.

The module owns no human intent.  It evaluates an exact qualification
candidate against a human-approved AutomationPolicy, classifies machine versus
human checkpoints, and emits versioned receipts.  Runtime implementations and
repair workers remain replaceable behind handlers.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import Any, Protocol
from urllib.parse import urlsplit

from ..ids import deterministic_id

CONTRACT_CANDIDATE_ID = "contract-v0.1.0-alpha.2"
AUTOMATION_POLICY_SCHEMA_ID = "urn:company-ai-os:schema:automation-policy:0.1"
AUTOMATION_POLICY_ACTIVATION_RECEIPT_SCHEMA_ID = (
    "urn:company-ai-os:schema:automation-policy-activation-receipt:0.1"
)
QUALIFICATION_RUN_SCHEMA_ID = "urn:company-ai-os:schema:qualification-run:0.1"
STAGE_RECEIPT_SCHEMA_ID = "urn:company-ai-os:schema:stage-execution-receipt:0.1"
REMEDIATION_RECEIPT_SCHEMA_ID = "urn:company-ai-os:schema:remediation-receipt:0.1"
POLICY_DECISION_RECEIPT_SCHEMA_ID = (
    "urn:company-ai-os:schema:policy-decision-receipt:0.1"
)
EXECUTION_CLOSURE_RECEIPT_SCHEMA_ID = (
    "urn:company-ai-os:schema:execution-closure-receipt:0.1"
)

QUALIFICATION_STAGES = (
    "candidate_build",
    "contract_validation",
    "artifact_closure",
    "runtime_realization",
    "isolation_e4",
    "synthetic_d0",
    "capability_r1",
    "model_literature_r2",
    "domain_evaluation",
    "company_evaluation",
    "evidence_packaging",
    "formal_registration",
    "release_review",
    "preproduction_promotion",
    "production_promotion",
)
EXECUTION_STAGES = frozenset(
    {"isolation_e4", "synthetic_d0", "capability_r1", "model_literature_r2"}
)
HUMAN_STAGES = frozenset(
    {
        "formal_registration",
        "release_review",
        "preproduction_promotion",
        "production_promotion",
    }
)
REMEDIABLE_FAILURE_CLASSES = frozenset(
    {
        "engineering_compatibility",
        "deterministic_test_failure",
        "transient_runtime",
        "quality_candidate_revision",
    }
)
BOUNDARY_NAMES = (
    "purpose",
    "owner",
    "agent_id",
    "capabilities",
    "tool_operations",
    "data_classification",
    "model_route",
    "endpoint_allowlist",
    "budget_ceiling",
    "isolation_profile",
    "external_side_effects",
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9][a-z0-9_-]{1,94})$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{2,95}$")


class QualificationAutomationError(ValueError):
    """Fail-closed automation error with a stable reason code."""

    def __init__(self, reason_code: str, message: str | None = None) -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class ReceiptArtifact:
    schema_id: str
    document: Mapping[str, Any]
    digest: str


@dataclass(frozen=True)
class QualificationCandidate:
    attempt_id: str
    attempt_number: int
    agent_id: str
    release_state: str
    agent_release_ref: str
    agent_release_digest: str
    runtime_family: str
    runtime_source_digest: str
    composition_ref: str
    composition_digest: str
    task_ref: str
    task_digest: str
    grant_candidate_ref: str
    grant_candidate_digest: str
    data_classification: str
    model_route_digest: str | None
    tool_operations: tuple[str, ...]
    endpoint_origins: tuple[str, ...]
    input_artifact_digests: tuple[str, ...]
    isolation_profile_digest: str
    stage_handler_digests: tuple[str, ...]
    evaluation_suite_digests: tuple[str, ...]
    max_model_requests: int
    max_input_tokens: int
    max_output_tokens: int
    max_cost_usd: str
    max_cost_cny: str
    max_runtime_seconds: int
    agent_direct_network: bool
    agent_credentials: bool
    nas_access: bool
    real_medical_data: bool
    boundary_digests: Mapping[str, str]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> QualificationCandidate:
        expected = {
            "attempt_id",
            "attempt_number",
            "agent_id",
            "release_state",
            "agent_release_ref",
            "agent_release_digest",
            "runtime_family",
            "runtime_source_digest",
            "composition_ref",
            "composition_digest",
            "task_ref",
            "task_digest",
            "grant_candidate_ref",
            "grant_candidate_digest",
            "data_classification",
            "model_route_digest",
            "tool_operations",
            "endpoint_origins",
            "input_artifact_digests",
            "isolation_profile_digest",
            "stage_handler_digests",
            "evaluation_suite_digests",
            "max_model_requests",
            "max_input_tokens",
            "max_output_tokens",
            "max_cost_usd",
            "max_cost_cny",
            "max_runtime_seconds",
            "agent_direct_network",
            "agent_credentials",
            "nas_access",
            "real_medical_data",
            "boundary_digests",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise QualificationAutomationError("qualification_candidate_fields_invalid")
        candidate = cls(
            attempt_id=_identifier(value["attempt_id"], "attempt_id"),
            attempt_number=_positive_int(value["attempt_number"], "attempt_number"),
            agent_id=_identifier(value["agent_id"], "agent_id"),
            release_state=_choice(
                value["release_state"], {"candidate", "evaluation", "active"}
            ),
            agent_release_ref=_logical_ref(value["agent_release_ref"]),
            agent_release_digest=_digest(value["agent_release_digest"]),
            runtime_family=_token(value["runtime_family"]),
            runtime_source_digest=_digest(value["runtime_source_digest"]),
            composition_ref=_logical_ref(value["composition_ref"]),
            composition_digest=_digest(value["composition_digest"]),
            task_ref=_logical_ref(value["task_ref"]),
            task_digest=_digest(value["task_digest"]),
            grant_candidate_ref=_logical_ref(value["grant_candidate_ref"]),
            grant_candidate_digest=_digest(value["grant_candidate_digest"]),
            data_classification=_choice(
                value["data_classification"], {"synthetic", "public"}
            ),
            model_route_digest=(
                None
                if value["model_route_digest"] is None
                else _digest(value["model_route_digest"])
            ),
            tool_operations=_unique_strings(value["tool_operations"]),
            endpoint_origins=_unique_strings(value["endpoint_origins"]),
            input_artifact_digests=_unique_digests(value["input_artifact_digests"]),
            isolation_profile_digest=_digest(value["isolation_profile_digest"]),
            stage_handler_digests=_unique_digests(value["stage_handler_digests"]),
            evaluation_suite_digests=_unique_digests(value["evaluation_suite_digests"]),
            max_model_requests=_non_negative_int(
                value["max_model_requests"], "max_model_requests"
            ),
            max_input_tokens=_non_negative_int(
                value["max_input_tokens"], "max_input_tokens"
            ),
            max_output_tokens=_non_negative_int(
                value["max_output_tokens"], "max_output_tokens"
            ),
            max_cost_usd=_decimal_text(value["max_cost_usd"], "max_cost_usd"),
            max_cost_cny=_decimal_text(value["max_cost_cny"], "max_cost_cny"),
            max_runtime_seconds=_positive_int(
                value["max_runtime_seconds"], "max_runtime_seconds"
            ),
            agent_direct_network=_strict_bool(
                value["agent_direct_network"], "agent_direct_network"
            ),
            agent_credentials=_strict_bool(
                value["agent_credentials"], "agent_credentials"
            ),
            nas_access=_strict_bool(value["nas_access"], "nas_access"),
            real_medical_data=_strict_bool(
                value["real_medical_data"], "real_medical_data"
            ),
            boundary_digests=_boundary_digests(value["boundary_digests"]),
        )
        return candidate

    def to_mapping(self) -> dict[str, Any]:
        value = asdict(self)
        for name in (
            "tool_operations",
            "endpoint_origins",
            "input_artifact_digests",
            "stage_handler_digests",
            "evaluation_suite_digests",
        ):
            value[name] = list(value[name])
        value["boundary_digests"] = dict(sorted(self.boundary_digests.items()))
        return value


@dataclass(frozen=True)
class StageCheck:
    name: str
    status: str
    reason_code: str | None
    evidence_refs: tuple[Mapping[str, str], ...] = ()


@dataclass(frozen=True)
class StageSideEffects:
    effective_task_created: bool = False
    effective_grant_created: bool = False
    approval_created: bool = False
    provider_calls: int = 0
    network_calls: int = 0
    docker_started: bool = False
    nas_accessed: bool = False
    real_data_accessed: bool = False


@dataclass(frozen=True)
class StageObservation:
    stage: str
    outcome: str
    failure_class: str
    reason_codes: tuple[str, ...]
    checks: tuple[StageCheck, ...]
    inputs: tuple[Mapping[str, str], ...]
    executor: Mapping[str, Any]
    side_effects: StageSideEffects
    started_at: str
    completed_at: str


@dataclass(frozen=True)
class CheckpointDecision:
    next_action: str
    human_checkpoint_scope: str | None
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class RemediationPlan:
    successor: QualificationCandidate
    changes: tuple[Mapping[str, str], ...]
    verification_receipt_refs: tuple[Mapping[str, str], ...]


@dataclass(frozen=True)
class StageHandlerResult:
    observation: StageObservation
    execution_closure: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class EvaluationGrant:
    grant_version: str
    grant_id: str
    run_id: str
    attempt_id: str
    stage: str
    task_ref: str
    task_digest: str
    grant_candidate_ref: str
    grant_candidate_digest: str
    composition_digest: str
    agent_release_digest: str
    runtime_source_digest: str
    policy_decision_receipt_digest: str
    issued_at: str
    expires_at: str
    single_use: bool
    status: str
    synthetic_only: bool
    production_authorization: bool
    release_authorization: bool
    grant_digest: str


class StageHandler(Protocol):
    def __call__(self, context: Mapping[str, Any]) -> StageHandlerResult: ...


class RemediationHandler(Protocol):
    def __call__(
        self, context: Mapping[str, Any], observation: StageObservation
    ) -> RemediationPlan: ...


def validate_automation_policy(document: Mapping[str, Any]) -> None:
    if not isinstance(document, Mapping) or set(document) != {
        "api_version",
        "kind",
        "metadata",
        "spec",
    }:
        raise QualificationAutomationError("automation_policy_fields_invalid")
    if (
        document["api_version"] != "company-ai-os/v1alpha1"
        or document["kind"] != "AutomationPolicy"
    ):
        raise QualificationAutomationError("automation_policy_identity_invalid")
    metadata = _mapping(document["metadata"], "automation_policy_metadata_invalid")
    if set(metadata) != {
        "policy_id",
        "version",
        "status",
        "evidence_status",
        "synthetic_only",
        "created_at",
        "expires_at",
    }:
        raise QualificationAutomationError("automation_policy_metadata_invalid")
    _identifier(metadata["policy_id"], "policy_id")
    _version(metadata["version"])
    if (
        metadata["status"] != "candidate"
        or metadata["evidence_status"]
        not in {
            "architecture_reference",
            "static",
            "synthetic",
            "public",
            "verified_runtime",
        }
        or type(metadata["synthetic_only"]) is not bool
        or (
            metadata["synthetic_only"] is False
            and metadata["evidence_status"] != "public"
        )
    ):
        raise QualificationAutomationError("automation_policy_not_candidate_synthetic")
    if _time(metadata["expires_at"]) <= _time(metadata["created_at"]):
        raise QualificationAutomationError("automation_policy_time_window_invalid")
    spec = _mapping(document["spec"], "automation_policy_spec_invalid")
    required = {
        "purpose",
        "subject_constraints",
        "stage_plan",
        "execution_envelope",
        "remediation_envelope",
        "human_checkpoint_triggers",
        "authority_boundary",
    }
    if set(spec) != required or spec["purpose"] != "agent_release_qualification":
        raise QualificationAutomationError("automation_policy_spec_invalid")

    subject = _mapping(spec["subject_constraints"], "automation_policy_subject_invalid")
    if set(subject) != {
        "agent_ids",
        "release_states",
        "runtime_families",
        "data_classifications",
    }:
        raise QualificationAutomationError("automation_policy_subject_invalid")
    agent_ids = _unique_strings(subject["agent_ids"])
    release_states = _unique_strings(subject["release_states"])
    runtime_families = _unique_strings(subject["runtime_families"])
    classifications = _unique_strings(subject["data_classifications"])
    if (
        not agent_ids
        or not release_states
        or not runtime_families
        or not classifications
        or any(_identifier(item, "agent_id") != item for item in agent_ids)
        or not set(release_states).issubset({"candidate", "evaluation", "active"})
        or any(_token(item) != item for item in runtime_families)
        or not set(classifications).issubset({"synthetic", "public"})
    ):
        raise QualificationAutomationError("automation_policy_subject_invalid")

    authority = _mapping(
        spec["authority_boundary"], "automation_policy_authority_invalid"
    )
    authority_fields = {
        "may_issue_evaluation_grant",
        "may_activate_agent",
        "may_activate_tool",
        "may_approve_model_route",
        "may_register_formally",
        "may_promote_preproduction",
        "may_promote_production",
        "release_authorization",
    }
    if (
        set(authority) != authority_fields
        or authority["may_issue_evaluation_grant"] is not True
        or any(
            authority[name] is not False
            for name in (
                "may_activate_agent",
                "may_activate_tool",
                "may_approve_model_route",
                "may_register_formally",
                "may_promote_preproduction",
                "may_promote_production",
                "release_authorization",
            )
        )
    ):
        raise QualificationAutomationError("automation_policy_authority_invalid")
    stages = _unique_strings(spec["stage_plan"])
    if not stages or any(stage not in QUALIFICATION_STAGES for stage in stages):
        raise QualificationAutomationError("automation_policy_stage_plan_invalid")
    envelope = _mapping(
        spec["execution_envelope"], "automation_policy_envelope_invalid"
    )
    envelope_fields = {
        "model_route_refs",
        "tool_scopes",
        "input_artifact_allowlist",
        "endpoint_origin_allowlist",
        "isolation_profile_digests",
        "trusted_stage_handlers",
        "evaluation_suite_refs",
        "max_concurrency",
        "max_attempts_per_stage",
        "max_total_attempts",
        "max_runtime_seconds",
        "max_model_requests",
        "max_input_tokens",
        "max_output_tokens",
        "max_cost_usd",
        "max_cost_cny",
        "agent_direct_network",
        "agent_credentials",
        "nas_access",
        "real_medical_data",
    }
    if set(envelope) != envelope_fields:
        raise QualificationAutomationError("automation_policy_envelope_invalid")
    _policy_artifact_bindings(envelope["model_route_refs"], minimum=0)
    _policy_tool_scopes(envelope["tool_scopes"])
    _policy_artifact_bindings(envelope["input_artifact_allowlist"], minimum=0)
    endpoint_origins = _unique_strings(envelope["endpoint_origin_allowlist"])
    for endpoint in endpoint_origins:
        _https_endpoint(endpoint)
    isolation_profiles = _unique_digests(envelope["isolation_profile_digests"])
    if not isolation_profiles:
        raise QualificationAutomationError("automation_policy_envelope_invalid")
    _policy_components(envelope["trusted_stage_handlers"])
    _policy_artifact_bindings(envelope["evaluation_suite_refs"], minimum=2)
    _bounded_int(envelope["max_concurrency"], "max_concurrency", 1, 16)
    _bounded_int(envelope["max_attempts_per_stage"], "max_attempts_per_stage", 1, 20)
    _bounded_int(envelope["max_total_attempts"], "max_total_attempts", 1, 100)
    _bounded_int(envelope["max_runtime_seconds"], "max_runtime_seconds", 1, 86400)
    _bounded_int(envelope["max_model_requests"], "max_model_requests", 0, 1000)
    _non_negative_int(envelope["max_input_tokens"], "max_input_tokens")
    _non_negative_int(envelope["max_output_tokens"], "max_output_tokens")
    _decimal_text(envelope["max_cost_usd"], "max_cost_usd")
    _decimal_text(envelope["max_cost_cny"], "max_cost_cny")
    for flag in (
        "agent_direct_network",
        "agent_credentials",
        "nas_access",
        "real_medical_data",
    ):
        if envelope.get(flag) is not False:
            raise QualificationAutomationError("automation_policy_boundary_expanded")
    remediation = _mapping(
        spec["remediation_envelope"], "automation_policy_remediation_invalid"
    )
    if set(remediation) != {
        "allowed_failure_classes",
        "source_change_policy",
        "immutable_attempt_history",
        "independent_verification",
        "unchanged_boundaries",
    }:
        raise QualificationAutomationError("automation_policy_remediation_invalid")
    allowed = set(_unique_strings(remediation.get("allowed_failure_classes")))
    if (
        not allowed
        or not allowed.issubset(REMEDIABLE_FAILURE_CLASSES)
        or remediation.get("source_change_policy")
        != "implementation_only_same_runtime_family"
        or remediation.get("immutable_attempt_history") is not True
        or remediation.get("independent_verification") is not True
        or not set(BOUNDARY_NAMES).issubset(
            set(_unique_strings(remediation.get("unchanged_boundaries")))
        )
    ):
        raise QualificationAutomationError("automation_policy_remediation_invalid")

    triggers = _unique_strings(spec["human_checkpoint_triggers"])
    allowed_triggers = {
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
    }
    if len(triggers) < 8 or not set(triggers).issubset(allowed_triggers):
        raise QualificationAutomationError("automation_policy_triggers_invalid")


def build_policy_activation_receipt(
    *,
    policy: Mapping[str, Any],
    policy_digest: str,
    approval_decision: Mapping[str, Any],
    activated_at: str,
) -> ReceiptArtifact:
    """Bind an exact human ApprovalDecision to an immutable policy candidate."""
    validate_automation_policy(policy)
    policy_digest = _digest(policy_digest)
    if canonical_digest(policy) != policy_digest:
        raise QualificationAutomationError("automation_policy_digest_mismatch")
    approval = _validate_policy_approval_decision(
        policy=policy,
        policy_digest=policy_digest,
        document=approval_decision,
    )
    activated = _time(activated_at)
    expires = _time(policy["metadata"]["expires_at"])
    if not _time(approval["metadata"]["decided_at"]) <= activated < expires:
        raise QualificationAutomationError("automation_policy_activation_time_invalid")
    approval_digest = canonical_digest(approval)
    metadata = policy["metadata"]
    document = {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "AutomationPolicyActivationReceipt",
        "metadata": {
            "receipt_id": deterministic_id(
                "receipt",
                "automation_policy_activation",
                metadata["policy_id"],
                metadata["version"],
                policy_digest,
                approval_digest,
            ),
            "policy_id": metadata["policy_id"],
            "policy_version": metadata["version"],
            "status": "active",
            "evidence_status": metadata["evidence_status"],
            "synthetic_only": metadata["synthetic_only"],
            "activated_at": activated_at,
            "expires_at": metadata["expires_at"],
        },
        "spec": {
            "automation_policy": {
                "role": "automation_policy",
                "ref": f"policy://{metadata['policy_id']}/{metadata['version']}",
                "digest": policy_digest,
            },
            "approval_decision": {
                "role": "automation_policy_approval",
                "ref": "approval://" + approval["metadata"]["decision_id"],
                "digest": approval_digest,
            },
            "approval_scope": "automation_policy_activation",
            "activation_service": {
                "id": "component_control_plane_policy_activation",
                "version": "0.1.0",
                "digest": canonical_digest(
                    "orbit_agent_control_plane.policy_activation/0.1.0"
                ),
            },
            "authority_boundary": {
                "human_approval_verified": True,
                "may_authorize_policy_subset_evaluation": True,
                "agent_activation": False,
                "tool_activation": False,
                "model_route_approval": False,
                "formal_registration": False,
                "preproduction_promotion": False,
                "production_promotion": False,
                "release_authorization": False,
            },
        },
    }
    return ReceiptArtifact(
        AUTOMATION_POLICY_ACTIVATION_RECEIPT_SCHEMA_ID,
        document,
        canonical_digest(document),
    )


def validate_policy_activation_receipt(
    *,
    policy: Mapping[str, Any],
    policy_digest: str,
    approval_decision: Mapping[str, Any],
    receipt: ReceiptArtifact,
) -> None:
    if receipt.schema_id != AUTOMATION_POLICY_ACTIVATION_RECEIPT_SCHEMA_ID:
        raise QualificationAutomationError(
            "automation_policy_activation_schema_invalid"
        )
    expected = build_policy_activation_receipt(
        policy=policy,
        policy_digest=policy_digest,
        approval_decision=approval_decision,
        activated_at=receipt.document["metadata"]["activated_at"],
    )
    if receipt != expected:
        raise QualificationAutomationError("automation_policy_activation_invalid")


def _validate_policy_approval_decision(
    *,
    policy: Mapping[str, Any],
    policy_digest: str,
    document: Mapping[str, Any],
) -> Mapping[str, Any]:
    metadata, spec = _validate_approval_decision_shape(
        document,
        reason_code="automation_policy_approval_invalid",
    )
    expected_scope = (
        f"policy://{policy['metadata']['policy_id']}/{policy['metadata']['version']}"
    )
    if (
        metadata.get("status") != "immutable"
        or metadata.get("synthetic_only")
        is not policy["metadata"]["synthetic_only"]
        or metadata.get("evidence_status")
        != policy["metadata"]["evidence_status"]
        or spec.get("decision") != "approve"
        or spec.get("scope_ref") != expected_scope
        or spec.get("scope_digest") != policy_digest
        or spec.get("expires_at") != policy["metadata"]["expires_at"]
    ):
        raise QualificationAutomationError("automation_policy_approval_invalid")
    _time(metadata.get("decided_at"))
    _time(spec.get("expires_at"))
    return document


def _validate_approval_decision_shape(
    document: Mapping[str, Any], *, reason_code: str
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if (
        not isinstance(document, Mapping)
        or set(document) != {"api_version", "kind", "metadata", "spec"}
        or document.get("api_version") != "company-ai-os/v1alpha1"
        or document.get("kind") != "ApprovalDecision"
    ):
        raise QualificationAutomationError(reason_code)
    metadata = _mapping(document.get("metadata"), reason_code)
    spec = _mapping(document.get("spec"), reason_code)
    if set(metadata) != {
        "decision_id",
        "approval_id",
        "task_id",
        "status",
        "evidence_status",
        "synthetic_only",
        "decided_at",
    } or set(spec) != {
        "decision",
        "decided_by_human_ref",
        "decided_by_role_ref",
        "scope_ref",
        "scope_digest",
        "reason",
        "expires_at",
        "separation_of_duties_check_ref",
        "audit_event_refs",
    }:
        raise QualificationAutomationError(reason_code)
    try:
        _identifier(metadata["decision_id"], "decision_id")
        _identifier(metadata["approval_id"], "approval_id")
        _identifier(metadata["task_id"], "task_id")
        if (
            metadata["status"] != "immutable"
            or metadata["evidence_status"]
            not in {
                "synthetic",
                "public",
                "architecture_reference",
                "verified_runtime",
            }
            or type(metadata["synthetic_only"]) is not bool
            or (
                metadata["synthetic_only"] is False
                and metadata["evidence_status"] != "public"
            )
        ):
            raise QualificationAutomationError(reason_code)
        _time(metadata["decided_at"])
        if spec["decision"] not in {"approve", "reject", "revoke", "expire"}:
            raise QualificationAutomationError(reason_code)
        human_ref = _identifier(spec["decided_by_human_ref"], "human_ref")
        role_ref = _identifier(spec["decided_by_role_ref"], "role_ref")
        if not human_ref.startswith("human_") or not role_ref.startswith("role_"):
            raise QualificationAutomationError(reason_code)
        if (
            not isinstance(spec["scope_ref"], str)
            or not 3 <= len(spec["scope_ref"]) <= 240
            or not isinstance(spec["reason"], str)
            or not 3 <= len(spec["reason"]) <= 1000
            or not isinstance(spec["separation_of_duties_check_ref"], str)
            or not 3 <= len(spec["separation_of_duties_check_ref"]) <= 240
        ):
            raise QualificationAutomationError(reason_code)
        _digest(spec["scope_digest"])
        if spec["expires_at"] is not None:
            _time(spec["expires_at"])
        audit_refs = _unique_strings(spec["audit_event_refs"])
        if not audit_refs or any(
            not item.startswith("audit_") or _identifier(item, "audit_ref") != item
            for item in audit_refs
        ):
            raise QualificationAutomationError(reason_code)
    except QualificationAutomationError as cause:
        if cause.reason_code == reason_code:
            raise
        raise QualificationAutomationError(reason_code) from cause
    return metadata, spec


class PolicyEngine:
    """Prove an exact candidate is a subset of an active AutomationPolicy."""

    @staticmethod
    def evaluate(
        *,
        policy: Mapping[str, Any],
        policy_digest: str,
        policy_activation: ReceiptArtifact,
        run_id: str,
        stage: str,
        candidate: QualificationCandidate,
        decided_at: str,
    ) -> ReceiptArtifact:
        validate_automation_policy(policy)
        policy_digest = _digest(policy_digest)
        if (
            canonical_digest(policy) != policy_digest
            or canonical_digest(policy_activation.document) != policy_activation.digest
            or policy_activation.schema_id
            != AUTOMATION_POLICY_ACTIVATION_RECEIPT_SCHEMA_ID
            or policy_activation.document["spec"]["automation_policy"]["digest"]
            != policy_digest
            or policy_activation.document["metadata"]["status"] != "active"
        ):
            raise QualificationAutomationError("automation_policy_activation_invalid")
        _identifier(run_id, "run_id")
        stage = _choice(stage, set(EXECUTION_STAGES))
        now = _time(decided_at)
        metadata = policy["metadata"]
        spec = policy["spec"]
        envelope = spec["execution_envelope"]
        subject = spec["subject_constraints"]
        allowed_inputs = {
            item["digest"] for item in envelope["input_artifact_allowlist"]
        }
        checks: list[tuple[str, bool, Any]] = []
        checks.append(
            ("agent_id", candidate.agent_id in subject["agent_ids"], candidate.agent_id)
        )
        checks.append(
            (
                "release_state",
                candidate.release_state in subject["release_states"]
                and candidate.agent_release_digest in allowed_inputs,
                {
                    "release_state": candidate.release_state,
                    "agent_release_digest": candidate.agent_release_digest,
                },
            )
        )
        checks.append(
            (
                "runtime_family",
                candidate.runtime_family in subject["runtime_families"],
                candidate.runtime_family,
            )
        )
        checks.append(
            (
                "data_classification",
                candidate.data_classification in subject["data_classifications"],
                candidate.data_classification,
            )
        )
        allowed_models = {item["digest"] for item in envelope["model_route_refs"]}
        checks.append(
            (
                "model_route",
                candidate.model_route_digest is None
                or candidate.model_route_digest in allowed_models,
                candidate.model_route_digest,
            )
        )
        allowed_tools = {
            f"{item['tool_release']['digest']}#{operation}"
            for item in envelope["tool_scopes"]
            for operation in item["operations"]
        }
        checks.append(
            (
                "tool_operations",
                set(candidate.tool_operations).issubset(allowed_tools),
                candidate.tool_operations,
            )
        )
        checks.append(
            (
                "endpoint_allowlist",
                set(candidate.endpoint_origins).issubset(
                    set(envelope["endpoint_origin_allowlist"])
                ),
                candidate.endpoint_origins,
            )
        )
        checks.append(
            (
                "input_artifacts",
                set(candidate.input_artifact_digests).issubset(allowed_inputs),
                candidate.input_artifact_digests,
            )
        )
        checks.append(
            (
                "isolation_profile",
                candidate.isolation_profile_digest
                in envelope["isolation_profile_digests"],
                candidate.isolation_profile_digest,
            )
        )
        allowed_handlers = {
            item["digest"] for item in envelope["trusted_stage_handlers"]
        }
        checks.append(
            (
                "stage_handlers",
                set(candidate.stage_handler_digests).issubset(allowed_handlers),
                candidate.stage_handler_digests,
            )
        )
        allowed_suites = {item["digest"] for item in envelope["evaluation_suite_refs"]}
        checks.append(
            (
                "evaluation_suites",
                set(candidate.evaluation_suite_digests).issubset(allowed_suites),
                candidate.evaluation_suite_digests,
            )
        )
        budget_ok = (
            candidate.max_model_requests <= envelope["max_model_requests"]
            and candidate.max_input_tokens <= envelope["max_input_tokens"]
            and candidate.max_output_tokens <= envelope["max_output_tokens"]
            and Decimal(candidate.max_cost_usd) <= Decimal(envelope["max_cost_usd"])
            and Decimal(candidate.max_cost_cny) <= Decimal(envelope["max_cost_cny"])
        )
        checks.append(("budget", budget_ok, _candidate_budget(candidate)))
        checks.append(
            (
                "lifetime",
                candidate.max_runtime_seconds <= envelope["max_runtime_seconds"],
                candidate.max_runtime_seconds,
            )
        )
        side_effects_ok = not any(
            (
                candidate.agent_direct_network,
                candidate.agent_credentials,
                candidate.nas_access,
                candidate.real_medical_data,
            )
        )
        checks.append(("external_side_effects", side_effects_ok, side_effects_ok))
        active_window = (
            _time(policy_activation.document["metadata"]["activated_at"])
            <= now
            < _time(policy_activation.document["metadata"]["expires_at"])
        )
        checks.append(("policy_active_window", active_window, decided_at))

        failed = tuple(name for name, passed, _ in checks if not passed)
        decision = "allow" if not failed else "require_human"
        reason_codes = (
            ("approved_policy_subset_proven",)
            if not failed
            else tuple(f"policy_{name}_outside_envelope" for name in failed)
        )
        receipt_id = deterministic_id(
            "receipt",
            "qualification_policy",
            run_id,
            candidate.attempt_id,
            stage,
            policy_digest,
            candidate.composition_digest,
        )
        document = {
            "api_version": "company-ai-os/v1alpha1",
            "kind": "PolicyDecisionReceipt",
            "metadata": {
                "receipt_id": receipt_id,
                "run_id": run_id,
                "attempt_id": candidate.attempt_id,
                "stage": stage,
                "status": "immutable",
                "evidence_status": metadata["evidence_status"],
                "synthetic_only": metadata["synthetic_only"],
                "decided_at": decided_at,
            },
            "spec": {
                "automation_policy": {
                    "role": "automation_policy",
                    "ref": f"policy://{metadata['policy_id']}/{metadata['version']}",
                    "digest": policy_digest,
                },
                "policy_activation_receipt": {
                    "role": "automation_policy_activation_receipt",
                    "ref": (
                        "receipt://"
                        + policy_activation.document["metadata"]["receipt_id"]
                    ),
                    "digest": policy_activation.digest,
                },
                "subject": {
                    "composition_ref": candidate.composition_ref,
                    "composition_digest": candidate.composition_digest,
                    "agent_release_digest": candidate.agent_release_digest,
                    "runtime_source_digest": candidate.runtime_source_digest,
                },
                "decision": decision,
                "reason_codes": list(reason_codes),
                "subset_checks": [
                    {
                        "boundary": _contract_boundary_name(name),
                        "status": "pass" if passed else "fail",
                        "observed_digest": canonical_digest(observed),
                    }
                    for name, passed, observed in checks
                ],
                "valid_until": min(
                    _time(metadata["expires_at"]),
                    now.replace(microsecond=0),
                ).isoformat()
                if decision != "allow"
                else metadata["expires_at"],
                "grant_action": (
                    "issue_single_use_evaluation_grant"
                    if decision == "allow"
                    else "none"
                ),
                "authority_boundary": {
                    "human_approval": False,
                    "may_issue_evaluation_grant": decision == "allow",
                    "may_issue_production_grant": False,
                    "may_change_policy": False,
                    "release_authorization": False,
                },
            },
        }
        return ReceiptArtifact(
            POLICY_DECISION_RECEIPT_SCHEMA_ID,
            document,
            canonical_digest(document),
        )


class CheckpointPolicy:
    """Classify a stage outcome without inferring human approval."""

    @staticmethod
    def classify(
        *,
        policy: Mapping[str, Any],
        observation: StageObservation,
        stage_attempt: int,
        total_attempt: int,
    ) -> CheckpointDecision:
        validate_automation_policy(policy)
        if observation.stage not in policy["spec"]["stage_plan"]:
            return CheckpointDecision(
                "human_checkpoint",
                "risk_waiver",
                ("stage_not_in_automation_policy",),
            )
        if observation.side_effects.approval_created:
            return CheckpointDecision(
                "quarantine", "risk_waiver", ("machine_created_approval",)
            )
        if (
            observation.side_effects.nas_accessed
            or observation.side_effects.real_data_accessed
        ):
            return CheckpointDecision(
                "quarantine", "risk_waiver", ("forbidden_data_side_effect",)
            )
        if observation.outcome == "pass":
            if observation.stage in HUMAN_STAGES:
                scope = {
                    "formal_registration": "formal_registration",
                    "release_review": "agent_activation",
                    "preproduction_promotion": "preproduction_promotion",
                    "production_promotion": "production_promotion",
                }[observation.stage]
                return CheckpointDecision(
                    "human_checkpoint", scope, ("human_release_decision_required",)
                )
            return CheckpointDecision(
                "auto_advance", None, ("stage_passed_auto_advance",)
            )
        envelope = policy["spec"]["execution_envelope"]
        allowed = set(policy["spec"]["remediation_envelope"]["allowed_failure_classes"])
        stage_retry_available = stage_attempt < envelope["max_attempts_per_stage"]
        total_attempt_available = total_attempt < envelope["max_total_attempts"]
        if observation.failure_class in allowed and total_attempt_available:
            if stage_retry_available:
                action = (
                    "auto_retry"
                    if observation.failure_class == "transient_runtime"
                    else "auto_remediate"
                )
                return CheckpointDecision(action, None, observation.reason_codes)
            pause_reason = "verified_same_family_remediation_required"
            reasons = observation.reason_codes
            if not reasons or reasons[0] != pause_reason:
                reasons = (pause_reason, *reasons)
            return CheckpointDecision("automation_pause", None, reasons)
        if observation.failure_class == "unexplained_drift":
            return CheckpointDecision(
                "quarantine", "risk_waiver", observation.reason_codes
            )
        if not total_attempt_available or observation.failure_class == "budget_exhausted":
            return CheckpointDecision(
                "human_checkpoint",
                "risk_waiver",
                ("automation_attempt_budget_exhausted",),
            )
        if observation.failure_class == "policy_boundary":
            return CheckpointDecision(
                "human_checkpoint", "execution_approval", observation.reason_codes
            )
        return CheckpointDecision(
            "human_checkpoint", "risk_waiver", observation.reason_codes
        )


def build_stage_receipt(
    *,
    run_id: str,
    candidate: QualificationCandidate,
    sequence: int,
    observation: StageObservation,
    decision: CheckpointDecision,
) -> ReceiptArtifact:
    _validate_observation(observation)
    _identifier(run_id, "run_id")
    receipt_observation = asdict(observation)
    receipt_observation["reason_codes"] = list(decision.reason_codes)
    receipt_id = deterministic_id(
        "receipt",
        "qualification_stage",
        run_id,
        candidate.attempt_id,
        observation.stage,
        str(sequence),
        canonical_digest(receipt_observation),
    )
    document = {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "StageExecutionReceipt",
        "metadata": {
            "receipt_id": receipt_id,
            "run_id": run_id,
            "stage": observation.stage,
            "attempt_id": candidate.attempt_id,
            "attempt_number": candidate.attempt_number,
            "sequence": sequence,
            "outcome": _stage_outcome(observation.outcome),
            "evidence_status": (
                "synthetic"
                if candidate.data_classification == "synthetic"
                else "public"
            ),
            "synthetic_only": candidate.data_classification == "synthetic",
            "started_at": observation.started_at,
            "completed_at": observation.completed_at,
        },
        "spec": {
            "inputs": [_artifact_binding(item) for item in observation.inputs],
            "executor": _executor_mapping(observation.executor),
            "checks": [
                {
                    "name": _token(check.name),
                    "status": _choice(
                        check.status, {"pass", "fail", "blocked", "not_applicable"}
                    ),
                    "reason_code": (
                        None
                        if check.reason_code is None
                        else _reason(check.reason_code)
                    ),
                    "evidence_refs": [
                        _artifact_binding(item) for item in check.evidence_refs
                    ],
                }
                for check in observation.checks
            ],
            "side_effects": asdict(observation.side_effects),
            "decision": {
                "failure_class": observation.failure_class,
                "next_action": decision.next_action,
                "reason_codes": list(decision.reason_codes),
                "human_checkpoint_scope": decision.human_checkpoint_scope,
            },
            "authority_boundary": {
                "evidence_semantics": "company_authoritative",
                "human_approval": False,
                "company_registry_write": False,
                "agent_lifecycle_transition": False,
                "release_authorization": False,
            },
        },
    }
    return ReceiptArtifact(
        STAGE_RECEIPT_SCHEMA_ID, document, canonical_digest(document)
    )


def build_remediation_receipt(
    *,
    run_id: str,
    policy: Mapping[str, Any],
    policy_digest: str,
    predecessor: QualificationCandidate,
    failed_stage_receipt: ReceiptArtifact,
    plan: RemediationPlan,
    created_at: str,
) -> ReceiptArtifact:
    validate_automation_policy(policy)
    _time(created_at)
    successor = plan.successor
    if (
        predecessor.attempt_id == successor.attempt_id
        or successor.attempt_number != predecessor.attempt_number + 1
        or predecessor.runtime_family != successor.runtime_family
        or predecessor.runtime_source_digest == successor.runtime_source_digest
        or predecessor.composition_digest == successor.composition_digest
    ):
        raise QualificationAutomationError("remediation_successor_invalid")
    changed = tuple(
        boundary
        for boundary in BOUNDARY_NAMES
        if predecessor.boundary_digests[boundary]
        != successor.boundary_digests[boundary]
    )
    if changed:
        raise QualificationAutomationError("remediation_boundary_changed")
    if failed_stage_receipt.schema_id != STAGE_RECEIPT_SCHEMA_ID:
        raise QualificationAutomationError("remediation_stage_receipt_invalid")
    failure_class = failed_stage_receipt.document["spec"]["decision"]["failure_class"]
    if (
        failure_class
        not in policy["spec"]["remediation_envelope"]["allowed_failure_classes"]
    ):
        raise QualificationAutomationError("remediation_failure_class_not_allowed")
    if not plan.changes or not plan.verification_receipt_refs:
        raise QualificationAutomationError("remediation_evidence_missing")
    metadata = policy["metadata"]
    document = {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "RemediationReceipt",
        "metadata": {
            "receipt_id": deterministic_id(
                "receipt",
                "qualification_remediation",
                run_id,
                predecessor.attempt_id,
                successor.attempt_id,
                successor.runtime_source_digest,
            ),
            "run_id": run_id,
            "status": "verified",
            "evidence_status": metadata["evidence_status"],
            "synthetic_only": metadata["synthetic_only"],
            "created_at": created_at,
        },
        "spec": {
            "automation_policy": {
                "role": "automation_policy",
                "ref": f"policy://{metadata['policy_id']}/{metadata['version']}",
                "digest": _digest(policy_digest),
            },
            "failure": {
                "class": failure_class,
                "reason_codes": list(
                    failed_stage_receipt.document["spec"]["decision"]["reason_codes"]
                ),
                "stage_receipt": {
                    "role": "blocked_stage_receipt",
                    "ref": "receipt://"
                    + failed_stage_receipt.document["metadata"]["receipt_id"],
                    "digest": failed_stage_receipt.digest,
                },
            },
            "predecessor": {
                "attempt_id": predecessor.attempt_id,
                "composition_digest": predecessor.composition_digest,
                "runtime_source_digest": predecessor.runtime_source_digest,
                "terminal_status": (
                    "blocked"
                    if failed_stage_receipt.document["metadata"]["outcome"] == "blocked"
                    else "failed"
                ),
            },
            "successor": {
                "attempt_id": successor.attempt_id,
                "composition_digest": successor.composition_digest,
                "runtime_source_digest": successor.runtime_source_digest,
                "status": "candidate",
            },
            "changes": [_remediation_change(item) for item in plan.changes],
            "invariant_proofs": [
                {
                    "boundary": boundary,
                    "before_digest": predecessor.boundary_digests[boundary],
                    "after_digest": successor.boundary_digests[boundary],
                    "unchanged": True,
                }
                for boundary in BOUNDARY_NAMES
            ],
            "verification_receipt_refs": [
                _artifact_binding(item) for item in plan.verification_receipt_refs
            ],
            "approval_handling": {
                "prior_exact_execution_approval_reused": False,
                "machine_policy_decision_required": True,
                "new_human_approval_required": False,
            },
            "authority_boundary": {
                "within_approved_remediation_envelope": True,
                "permission_expanded": False,
                "data_scope_expanded": False,
                "release_authorization": False,
            },
        },
    }
    return ReceiptArtifact(
        REMEDIATION_RECEIPT_SCHEMA_ID, document, canonical_digest(document)
    )


def issue_evaluation_grant(
    *,
    run_id: str,
    candidate: QualificationCandidate,
    stage: str,
    policy_decision: ReceiptArtifact,
    issued_at: str,
    expires_at: str,
) -> EvaluationGrant:
    stage = _choice(stage, set(EXECUTION_STAGES))
    if policy_decision.schema_id != POLICY_DECISION_RECEIPT_SCHEMA_ID:
        raise QualificationAutomationError("evaluation_grant_policy_receipt_invalid")
    document = policy_decision.document
    if (
        document["spec"]["decision"] != "allow"
        or document["spec"]["grant_action"] != "issue_single_use_evaluation_grant"
        or document["metadata"]["attempt_id"] != candidate.attempt_id
        or document["metadata"]["stage"] != stage
        or document["spec"]["subject"]["composition_digest"]
        != candidate.composition_digest
    ):
        raise QualificationAutomationError("evaluation_grant_policy_denied")
    issued = _time(issued_at)
    expires = _time(expires_at)
    decision_valid_until = _time(document["spec"]["valid_until"])
    if (
        issued < _time(document["metadata"]["decided_at"])
        or not issued < expires <= decision_valid_until
        or (expires - issued).total_seconds() > candidate.max_runtime_seconds
    ):
        raise QualificationAutomationError("evaluation_grant_lifetime_invalid")
    content = {
        "grant_version": "orbit.qualification-evaluation-grant/1",
        "grant_id": deterministic_id(
            "grant", run_id, candidate.attempt_id, stage, policy_decision.digest
        ),
        "run_id": run_id,
        "attempt_id": candidate.attempt_id,
        "stage": stage,
        "task_ref": candidate.task_ref,
        "task_digest": candidate.task_digest,
        "grant_candidate_ref": candidate.grant_candidate_ref,
        "grant_candidate_digest": candidate.grant_candidate_digest,
        "composition_digest": candidate.composition_digest,
        "agent_release_digest": candidate.agent_release_digest,
        "runtime_source_digest": candidate.runtime_source_digest,
        "policy_decision_receipt_digest": policy_decision.digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "single_use": True,
        "status": "active",
        "synthetic_only": document["metadata"]["synthetic_only"],
        "production_authorization": False,
        "release_authorization": False,
    }
    grant_digest = canonical_digest(content)
    return EvaluationGrant(**content, grant_digest=grant_digest)


def validate_execution_closure(document: Mapping[str, Any]) -> None:
    if (
        not isinstance(document, Mapping)
        or document.get("api_version") != "company-ai-os/v1alpha1"
        or document.get("kind") != "ExecutionClosureReceipt"
    ):
        raise QualificationAutomationError("execution_closure_identity_invalid")
    metadata = _mapping(document.get("metadata"), "execution_closure_metadata_invalid")
    spec = _mapping(document.get("spec"), "execution_closure_spec_invalid")
    if set(metadata) != {
        "receipt_id",
        "run_id",
        "attempt_id",
        "stage",
        "status",
        "evidence_status",
        "synthetic_only",
        "closed_at",
    }:
        raise QualificationAutomationError("execution_closure_metadata_invalid")
    if set(spec) != {
        "composition",
        "task",
        "grant",
        "route",
        "worker_lease",
        "policy_decision",
        "model_route",
        "result",
        "evaluations",
        "usage",
        "cleanup",
        "audit_refs",
        "terminal_consistency",
        "authority_boundary",
    }:
        raise QualificationAutomationError("execution_closure_spec_invalid")
    _identifier(metadata.get("receipt_id"), "receipt_id")
    _identifier(metadata.get("run_id"), "run_id")
    _identifier(metadata.get("attempt_id"), "attempt_id")
    if (
        metadata.get("evidence_status") not in {"synthetic", "public"}
        or type(metadata.get("synthetic_only")) is not bool
        or (
            metadata.get("synthetic_only") is False
            and metadata.get("evidence_status") != "public"
        )
    ):
        raise QualificationAutomationError("execution_closure_evidence_invalid")
    _time(metadata.get("closed_at"))
    if metadata.get("stage") not in EXECUTION_STAGES:
        raise QualificationAutomationError("execution_closure_stage_invalid")
    if metadata.get("status") not in {"completed", "failed", "cancelled", "blocked"}:
        raise QualificationAutomationError("execution_closure_status_invalid")
    _artifact_binding(spec.get("composition"))
    terminal_statuses = {
        "task": {"completed", "failed", "cancelled", "blocked"},
        "grant": {"consumed", "revoked", "expired"},
        "route": {"consumed", "closed"},
        "worker_lease": {"closed"},
        "policy_decision": {"consumed", "revoked", "expired"},
        "model_route": {"consumed", "approved_unconsumed"},
    }
    for name, statuses in terminal_statuses.items():
        terminal_ref = spec.get(name)
        if name == "model_route" and terminal_ref is None:
            continue
        if (
            not isinstance(terminal_ref, Mapping)
            or set(terminal_ref) != {"ref", "digest", "status", "revision"}
            or terminal_ref.get("status") not in statuses
            or isinstance(terminal_ref.get("revision"), bool)
            or not isinstance(terminal_ref.get("revision"), int)
            or terminal_ref["revision"] < 0
        ):
            raise QualificationAutomationError("execution_closure_terminal_ref_invalid")
        _logical_ref(terminal_ref.get("ref"))
        _digest(terminal_ref.get("digest"))
    if spec["task"]["status"] != metadata["status"]:
        raise QualificationAutomationError("execution_closure_status_invalid")
    if spec.get("result") is not None:
        _artifact_binding(spec["result"])
    terminal = _mapping(
        spec.get("terminal_consistency"), "execution_closure_terminal_invalid"
    )
    if set(terminal) != {
        "task_terminal",
        "grant_terminal",
        "route_terminal",
        "lease_terminal",
        "policy_decision_bound",
        "result_and_evaluations_bound",
        "replay_passed",
    } or any(value is not True for value in terminal.values()):
        raise QualificationAutomationError("execution_closure_terminal_invalid")
    cleanup = _mapping(spec.get("cleanup"), "execution_closure_cleanup_invalid")
    if set(cleanup) != {
        "process_group_terminated",
        "temporary_workspace_removed",
        "credentials_absent",
        "external_handles_closed",
        "cleanup_errors",
    }:
        raise QualificationAutomationError("execution_closure_cleanup_invalid")
    for flag in (
        "process_group_terminated",
        "temporary_workspace_removed",
        "credentials_absent",
        "external_handles_closed",
    ):
        if cleanup.get(flag) is not True:
            raise QualificationAutomationError("execution_closure_cleanup_invalid")
    if not isinstance(cleanup["cleanup_errors"], list):
        raise QualificationAutomationError("execution_closure_cleanup_invalid")
    for reason_code in cleanup["cleanup_errors"]:
        _reason(reason_code)
    authority = _mapping(
        spec.get("authority_boundary"), "execution_closure_authority_invalid"
    )
    if set(authority) != {
        "formal_registry_written",
        "agent_activated",
        "preproduction_promoted",
        "production_promoted",
        "release_authorization",
    } or any(authority.values()):
        raise QualificationAutomationError("execution_closure_authority_invalid")
    evaluations = spec.get("evaluations")
    if not isinstance(evaluations, list) or len(evaluations) < 2:
        raise QualificationAutomationError("execution_closure_evaluation_invalid")
    if any(
        not isinstance(item, Mapping)
        or set(item)
        != {"evaluator_class", "report", "verdict", "release_authorization"}
        or item.get("verdict") not in {"pass", "fail", "hold", "not_run"}
        for item in evaluations
    ):
        raise QualificationAutomationError("execution_closure_evaluation_invalid")
    for item in evaluations:
        _artifact_binding(item["report"])
    classes = [item.get("evaluator_class") for item in evaluations]
    if not {"domain", "company"}.issubset(classes) or any(
        item.get("release_authorization") is not False for item in evaluations
    ):
        raise QualificationAutomationError("execution_closure_evaluation_invalid")
    if classes.count("domain") != 1 or classes.count("company") != 1:
        raise QualificationAutomationError("execution_closure_evaluation_invalid")
    usage = _mapping(spec.get("usage"), "execution_closure_usage_invalid")
    if set(usage) != {
        "model_calls",
        "request_attempts",
        "input_tokens",
        "output_tokens",
        "cost_usd",
        "cost_cny",
        "runtime_seconds",
    }:
        raise QualificationAutomationError("execution_closure_usage_invalid")
    for name in (
        "model_calls",
        "request_attempts",
        "input_tokens",
        "output_tokens",
        "runtime_seconds",
    ):
        _non_negative_int(usage.get(name), name)
    _decimal_text(usage.get("cost_usd"), "cost_usd")
    _decimal_text(usage.get("cost_cny"), "cost_cny")
    audit_refs = spec.get("audit_refs")
    if (
        not isinstance(audit_refs, list)
        or not audit_refs
        or len(audit_refs) != len(set(audit_refs))
    ):
        raise QualificationAutomationError("execution_closure_audit_invalid")
    for audit_ref in audit_refs:
        _logical_ref(audit_ref)


def receipt_artifact(schema_id: str, document: Mapping[str, Any]) -> ReceiptArtifact:
    return ReceiptArtifact(schema_id, document, canonical_digest(document))


def canonical_digest(value: Any) -> str:
    return (
        "sha256:"
        + sha256(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
    )


def _validate_observation(observation: StageObservation) -> None:
    if observation.stage not in QUALIFICATION_STAGES:
        raise QualificationAutomationError("stage_observation_stage_invalid")
    if observation.outcome not in {"pass", "blocked", "fail", "cancelled", "skipped"}:
        raise QualificationAutomationError("stage_observation_outcome_invalid")
    if observation.failure_class not in {
        "none",
        *REMEDIABLE_FAILURE_CLASSES,
        "policy_boundary",
        "safety_or_quality",
        "unexplained_drift",
        "budget_exhausted",
    }:
        raise QualificationAutomationError("stage_observation_failure_class_invalid")
    if not observation.reason_codes or not observation.checks or not observation.inputs:
        raise QualificationAutomationError("stage_observation_evidence_missing")
    for reason_code in observation.reason_codes:
        _reason(reason_code)
    started = _time(observation.started_at)
    completed = _time(observation.completed_at)
    if completed < started:
        raise QualificationAutomationError("stage_observation_time_invalid")
    if observation.side_effects.approval_created:
        raise QualificationAutomationError(
            "stage_observation_machine_approval_forbidden"
        )


def _stage_outcome(value: str) -> str:
    return {"pass": "passed", "fail": "failed"}.get(value, value)


def _contract_boundary_name(name: str) -> str:
    return {
        "input_artifacts": "data_classification",
        "stage_handlers": "runtime_family",
        "evaluation_suites": "tool_operations",
        "policy_active_window": "lifetime",
    }.get(name, name)


def _candidate_budget(candidate: QualificationCandidate) -> Mapping[str, Any]:
    return {
        "max_model_requests": candidate.max_model_requests,
        "max_input_tokens": candidate.max_input_tokens,
        "max_output_tokens": candidate.max_output_tokens,
        "max_cost_usd": candidate.max_cost_usd,
        "max_cost_cny": candidate.max_cost_cny,
    }


def _artifact_binding(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"role", "ref", "digest"}:
        raise QualificationAutomationError("artifact_binding_invalid")
    return {
        "role": _token(value["role"]),
        "ref": _logical_ref(value["ref"]),
        "digest": _digest(value["digest"]),
    }


def _executor_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "component",
        "deterministic",
        "environment_profile_digest",
    }:
        raise QualificationAutomationError("stage_executor_invalid")
    component = value["component"]
    if not isinstance(component, Mapping) or set(component) != {
        "id",
        "version",
        "digest",
    }:
        raise QualificationAutomationError("stage_executor_invalid")
    return {
        "component": {
            "id": _identifier(component["id"], "component_id"),
            "version": _version(component["version"]),
            "digest": _digest(component["digest"]),
        },
        "deterministic": _strict_bool(value["deterministic"], "deterministic"),
        "environment_profile_digest": _digest(value["environment_profile_digest"]),
    }


def _remediation_change(value: Mapping[str, str]) -> dict[str, str]:
    if set(value) != {
        "component_ref",
        "change_class",
        "before_digest",
        "after_digest",
        "reason",
    }:
        raise QualificationAutomationError("remediation_change_invalid")
    if value["change_class"] not in {
        "implementation_fix",
        "adapter_fix",
        "harness_fix",
        "test_fix",
        "prompt_candidate_revision",
        "workflow_candidate_revision",
    }:
        raise QualificationAutomationError("remediation_change_invalid")
    if not isinstance(value["reason"], str) or not 3 <= len(value["reason"]) <= 500:
        raise QualificationAutomationError("remediation_change_invalid")
    return {
        "component_ref": _logical_ref(value["component_ref"]),
        "change_class": value["change_class"],
        "before_digest": _digest(value["before_digest"]),
        "after_digest": _digest(value["after_digest"]),
        "reason": value["reason"],
    }


def _policy_artifact_bindings(
    value: Any, *, minimum: int
) -> tuple[dict[str, str], ...]:
    if not isinstance(value, list) or len(value) < minimum:
        raise QualificationAutomationError("automation_policy_envelope_invalid")
    bindings = tuple(_artifact_binding(item) for item in value)
    if len({canonical_digest(item) for item in bindings}) != len(bindings):
        raise QualificationAutomationError("automation_policy_envelope_invalid")
    return bindings


def _policy_tool_scopes(value: Any) -> None:
    if not isinstance(value, list):
        raise QualificationAutomationError("automation_policy_envelope_invalid")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "tool_release",
            "operations",
        }:
            raise QualificationAutomationError("automation_policy_envelope_invalid")
        operations = _unique_strings(item["operations"])
        if not operations or any(
            _token(operation) != operation for operation in operations
        ):
            raise QualificationAutomationError("automation_policy_envelope_invalid")
        normalized.append(
            {
                "tool_release": _artifact_binding(item["tool_release"]),
                "operations": list(operations),
            }
        )
    if len({canonical_digest(item) for item in normalized}) != len(normalized):
        raise QualificationAutomationError("automation_policy_envelope_invalid")


def _policy_components(value: Any) -> None:
    if not isinstance(value, list) or not value:
        raise QualificationAutomationError("automation_policy_envelope_invalid")
    normalized: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"id", "version", "digest"}:
            raise QualificationAutomationError("automation_policy_envelope_invalid")
        normalized.append(
            {
                "id": _identifier(item["id"], "component_id"),
                "version": _version(item["version"]),
                "digest": _digest(item["digest"]),
            }
        )
    if len({canonical_digest(item) for item in normalized}) != len(normalized):
        raise QualificationAutomationError("automation_policy_envelope_invalid")


def _https_endpoint(value: Any) -> str:
    if not isinstance(value, str):
        raise QualificationAutomationError("endpoint_origin_invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise QualificationAutomationError("endpoint_allowlist_invalid")
    return value


def _mapping(value: Any, reason_code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise QualificationAutomationError(reason_code)
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise QualificationAutomationError(f"{label}_invalid")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise QualificationAutomationError("digest_invalid")
    return value


def _logical_ref(value: Any) -> str:
    if (
        not isinstance(value, str)
        or "://" not in value
        or len(value) > 480
        or value.startswith(("file://", "smb://"))
        or "/Users/" in value
        or "/home/" in value
    ):
        raise QualificationAutomationError("logical_ref_invalid")
    return value


def _version(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?", value
    ):
        raise QualificationAutomationError("version_invalid")
    return value


def _token(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_]{2,95}", value):
        raise QualificationAutomationError("token_invalid")
    return value


def _reason(value: Any) -> str:
    if not isinstance(value, str) or not _REASON.fullmatch(value):
        raise QualificationAutomationError("reason_code_invalid")
    return value


def _choice(value: Any, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise QualificationAutomationError("enum_value_invalid")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise QualificationAutomationError(f"{label}_invalid")
    return value


def _non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise QualificationAutomationError(f"{label}_invalid")
    return value


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise QualificationAutomationError(f"{label}_invalid")
    return value


def _strict_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationAutomationError(f"{label}_invalid")
    return value


def _decimal_text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise QualificationAutomationError(f"{label}_invalid")
    try:
        parsed = Decimal(value)
    except InvalidOperation as cause:
        raise QualificationAutomationError(f"{label}_invalid") from cause
    if parsed < 0 or not parsed.is_finite():
        raise QualificationAutomationError(f"{label}_invalid")
    return value


def _unique_strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(
        not isinstance(item, str) for item in value
    ):
        raise QualificationAutomationError("string_list_invalid")
    if len(set(value)) != len(value):
        raise QualificationAutomationError("string_list_duplicate")
    return tuple(value)


def _unique_digests(value: Any) -> tuple[str, ...]:
    values = _unique_strings(value)
    return tuple(_digest(item) for item in values)


def _boundary_digests(value: Any) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or set(value) != set(BOUNDARY_NAMES):
        raise QualificationAutomationError("boundary_digest_set_invalid")
    return {name: _digest(value[name]) for name in BOUNDARY_NAMES}


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise QualificationAutomationError("time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as cause:
        raise QualificationAutomationError("time_invalid") from cause
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QualificationAutomationError("time_invalid")
    return parsed.astimezone(timezone.utc)

