"""Run one approved public-corpus R2 Pilot through the durable pipeline.

This module is a Control Plane driver, not an Agent Runtime.  It instantiates
only the digest-bound framework-neutral Adapter, deterministic evaluators and
Alpha.2 qualification state machine.  Provider credentials remain confined to
the separately running Runner and never enter this process or its output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from sqlalchemy import select

from orbit_agent_control_plane.qualification.automation import (
    QualificationCandidate,
    RemediationPlan,
    StageCheck,
    StageHandlerResult,
    StageObservation,
    StageSideEffects,
    build_policy_activation_receipt,
    canonical_digest,
    validate_automation_policy,
)
from orbit_agent_control_plane.qualification.ledger import (
    QualificationController,
    QualificationReconciler,
    qualification_run_snapshot,
)
from orbit_agent_control_plane.service_runtime.automation_supervisor import (
    AutomationSupervisor,
    AutomationSupervisorStore,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.full_chain_enablement import (
    validate_full_chain_enablement_receipt,
)
from orbit_agent_control_plane.service_runtime.local_pilot_main import (
    validate_pilot_enablement,
)
from orbit_agent_control_plane.service_runtime.managed_components import (
    ManagedComponentRegistry,
    build_governed_release_pipeline_descriptor,
)
from orbit_agent_control_plane.service_runtime.model_route import (
    ModelRouteReconciler,
    ModelRouteStore,
    OwnerOnlyFileSecretProvider,
)
from orbit_agent_control_plane.service_runtime.models import (
    AuditEventRow,
    OutboxEventRow,
    ReceiptRow,
    RuntimeRunRow,
)
from orbit_agent_control_plane.service_runtime.pipeline import (
    GovernedReleasePipeline,
    PilotBudget,
)
from orbit_agent_control_plane.service_runtime.provider_evaluation import (
    ProviderCompanyEvaluationHandler,
    ProviderDomainEvaluationHandler,
)
from orbit_agent_control_plane.service_runtime.repositories import (
    SqlAlchemyPolicyActivationRepository,
    SqlAlchemyQualificationStore,
    SqlGrantRevocationRegistry,
)
from orbit_agent_control_plane.service_runtime.runner_queue import (
    SqlRunnerTransport,
    SqlSignedGrantRegistry,
)
from orbit_agent_control_plane.service_runtime.runtime_adapter import (
    FrameworkNeutralRuntimeAdapter,
    RuntimeAdapterDescriptor,
)
from orbit_agent_control_plane.service_runtime.runtime_stage import (
    SignedRuntimeStageHandler,
)
from orbit_agent_control_plane.service_runtime.security import (
    Ed25519EvaluationGrantSigner,
    Ed25519EvaluationGrantVerifier,
)

RUN_ID = "run_orbit_disease_r2_public_pilot_002"
_RUN_ID = re.compile(r"^run_[a-z0-9_]{8,120}$")
SIGNING_KEY_ID = "local_pilot_grant_signer"
_STATIC_STAGES = frozenset(
    {
        "candidate_build",
        "contract_validation",
        "artifact_closure",
        "runtime_realization",
        "evidence_packaging",
    }
)
_COMPONENT_BY_STAGE = {
    "candidate_build": "component_governed_release_pipeline",
    "contract_validation": "component_governed_release_pipeline",
    "artifact_closure": "component_governed_release_pipeline",
    "runtime_realization": "component_governed_release_pipeline",
    "isolation_e4": "component_signed_runtime_stage_handler",
    "model_literature_r2": "component_signed_runtime_stage_handler",
    "domain_evaluation": "component_disease_r2_public_domain_evaluator",
    "company_evaluation": "component_disease_r2_public_company_evaluator",
    "evidence_packaging": "component_public_pilot_evidence_packager",
}


class PublicPilotExecutionError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def run_public_pilot(
    *,
    database_url: str,
    policy: Mapping[str, Any],
    review: Mapping[str, Any],
    enablement_receipt: Mapping[str, Any],
    candidates: Sequence[QualificationCandidate],
    private_key_pem: bytes,
    public_key_pem: bytes,
    runtime_adapter_digest: str,
    run_id: str = RUN_ID,
    model_route_id: str | None = None,
    model_route_snapshot_digest: str | None = None,
    model_route_secret_bindings_path: Path | None = None,
    model_route_preflight_result_path: Path | None = None,
    supervision_scope_ref: str | None = None,
    verified_remediation: Mapping[str, Any] | None = None,
    pilot_max_attempts: int | None = None,
    attempts_consumed_before: int = 0,
    drive_runner_once=None,
) -> dict[str, Any]:
    """Idempotently run until success or the next mandatory human checkpoint."""
    if not _RUN_ID.fullmatch(run_id):
        raise PublicPilotExecutionError("public_pilot_run_id_invalid")
    ordered = tuple(sorted(candidates, key=lambda item: item.attempt_number))
    preflight_public_pilot(
        database_url=database_url,
        policy=policy,
        review=review,
        enablement_receipt=enablement_receipt,
        candidates=ordered,
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        runtime_adapter_digest=runtime_adapter_digest,
        run_id=run_id,
        model_route_id=model_route_id,
        model_route_snapshot_digest=model_route_snapshot_digest,
        model_route_secret_bindings_path=model_route_secret_bindings_path,
        model_route_preflight_result_path=model_route_preflight_result_path,
        supervision_scope_ref=supervision_scope_ref,
        verified_remediation=verified_remediation,
        pilot_max_attempts=pilot_max_attempts,
        attempts_consumed_before=attempts_consumed_before,
    )
    policy_digest = canonical_digest(policy)
    database = Database(database_url)
    try:
        ManagedComponentRegistry(database).register(
            build_governed_release_pipeline_descriptor(
                Path(__file__).resolve().parents[3]
            )
        )
        supervisor = AutomationSupervisor(AutomationSupervisorStore(database))
        if supervision_scope_ref is not None and verified_remediation is not None:
            supervisor.record_verified_remediation(
                scope_ref=supervision_scope_ref,
                remediation_digest=verified_remediation["remediation_digest"],
                runtime_source_digest=verified_remediation[
                    "runtime_source_digest"
                ],
                regression_evidence_digest=verified_remediation[
                    "regression_evidence_digest"
                ],
                idempotency_key=(
                    "supervisor:remediation:"
                    + verified_remediation["remediation_digest"]
                ),
            )
        store = SqlAlchemyQualificationStore(database)
        controller = QualificationController(store)
        approval = _policy_approval(
            policy=policy,
            policy_digest=policy_digest,
            receipt=enablement_receipt,
        )
        activation = build_policy_activation_receipt(
            policy=policy,
            policy_digest=policy_digest,
            approval_decision=approval,
            activated_at=enablement_receipt["activated_at"],
        )
        SqlAlchemyPolicyActivationRepository(database).record(
            policy=policy,
            policy_digest=policy_digest,
            approval_decision=approval,
            receipt=activation,
        )
        _record_local_enablement(database, enablement_receipt, review)

        signer = Ed25519EvaluationGrantSigner(
            private_key_pem=private_key_pem,
            key_id=SIGNING_KEY_ID,
        )
        verifier = Ed25519EvaluationGrantVerifier(
            public_key_pem=public_key_pem,
            key_id=SIGNING_KEY_ID,
        )
        if signer.public_key_pem() != public_key_pem:
            raise PublicPilotExecutionError("public_pilot_grant_key_mismatch")
        revocations = SqlGrantRevocationRegistry(database)
        grants = SqlSignedGrantRegistry(
            database,
            verifier=verifier,
            revocations=revocations,
        )
        adapter = FrameworkNeutralRuntimeAdapter(
            descriptor=RuntimeAdapterDescriptor.from_mapping(
                {
                    "adapter_id": "runtime_adapter_framework_neutral_disease_r2_syn",
                    "version": "0.1.0",
                    "digest": runtime_adapter_digest,
                    "runtime_family": "disease_r2_v4",
                    "conformance_profiles": [
                        "core_dispatch",
                        "tool_data_enforced",
                        "isolated_workload",
                    ],
                    "supported_operations": [
                        "run_public_r2_fixture",
                        "run_public_r2_provider_attempt",
                    ],
                    "supports_checkpoint_restore": False,
                    "evidence_status": "public",
                    "synthetic_only": False,
                }
            ),
            transport=SqlRunnerTransport(database, grants=grants),
        )
        trusted_components = {
            item["id"]: dict(item)
            for item in policy["spec"]["execution_envelope"][
                "trusted_stage_handlers"
            ]
        }
        stage_bindings = {
            stage: trusted_components[_COMPONENT_BY_STAGE[stage]]
            for stage in policy["spec"]["stage_plan"]
        }
        if any(
            binding["digest"] not in set(ordered[0].stage_handler_digests)
            for binding in stage_bindings.values()
        ):
            raise PublicPilotExecutionError("public_pilot_handler_binding_invalid")
        controller.register_run(
            run_id=run_id,
            policy=policy,
            policy_digest=policy_digest,
            policy_activation=activation,
            policy_approval_decision=approval,
            candidate=ordered[0],
            stage_plan=tuple(policy["spec"]["stage_plan"]),
            stage_handlers=stage_bindings,
            registered_at=enablement_receipt["activated_at"],
            idempotency_key=f"register:{run_id}",
        )
        candidate_by_number = {item.attempt_number: item for item in ordered}
        static_handler = _StaticEvidenceHandler(
            policy=policy,
            trusted_components=trusted_components,
        )
        handlers = {stage: static_handler for stage in _STATIC_STAGES}
        handlers.update(
            {
                "isolation_e4": SignedRuntimeStageHandler(
                    adapter=adapter,
                    grants=grants,
                    signer=signer,
                    signing_key_id=SIGNING_KEY_ID,
                    operation="run_public_r2_fixture",
                    drive_runner_once=drive_runner_once,
                ),
                "model_literature_r2": SignedRuntimeStageHandler(
                    adapter=adapter,
                    grants=grants,
                    signer=signer,
                    signing_key_id=SIGNING_KEY_ID,
                    operation="run_public_r2_provider_attempt",
                    drive_runner_once=drive_runner_once,
                ),
                "domain_evaluation": ProviderDomainEvaluationHandler(
                    database,
                    component_digest=trusted_components[
                        "component_disease_r2_public_domain_evaluator"
                    ]["digest"],
                ),
                "company_evaluation": ProviderCompanyEvaluationHandler(
                    database,
                    component_digest=trusted_components[
                        "component_disease_r2_public_company_evaluator"
                    ]["digest"],
                ),
            }
        )
        remediation = _ImmutableSuccessorHandler(candidate_by_number)
        reconciler = QualificationReconciler(
            controller,
            stage_handlers=handlers,
            remediation_handlers={
                stage: remediation for stage in policy["spec"]["stage_plan"]
            },
            handler_digests={
                stage: binding["digest"] for stage, binding in stage_bindings.items()
            },
            max_transitions=250,
        )
        state = reconciler.run_until_checkpoint(run_id)
        pipeline = GovernedReleasePipeline(
            database=database,
            qualification_store=store,
            automation_supervisor=supervisor,
            budget=PilotBudget(
                max_attempts=pilot_max_attempts or len(ordered),
                max_cost_usd=Decimal("1.00"),
                max_cost_cny=Decimal("7.50"),
            ),
        )
        result = _result_document(
            database, state, pipeline.status(run_id), run_id=run_id
        )
        if supervision_scope_ref is not None:
            result["automation_supervision"] = _record_supervision_outcome(
                supervisor=supervisor,
                scope_ref=supervision_scope_ref,
                state=state,
                result=result,
                total_attempts=(
                    attempts_consumed_before + result["provider_attempts"]
                ),
                max_total_attempts=pilot_max_attempts or len(ordered),
            )
            result["next_automation_action"] = result["automation_supervision"][
                "next_automation_action"
            ]
            result["next_human_checkpoint"] = result["automation_supervision"][
                "next_human_checkpoint"
            ]
        result["local_execution_closure_receipt_digest"] = (
            _record_execution_result(database, result, run_id=run_id)
        )
        return result
    finally:
        database.dispose()


def preflight_public_pilot(
    *,
    database_url: str,
    policy: Mapping[str, Any],
    review: Mapping[str, Any],
    enablement_receipt: Mapping[str, Any],
    candidates: Sequence[QualificationCandidate],
    private_key_pem: bytes,
    public_key_pem: bytes,
    runtime_adapter_digest: str,
    run_id: str = RUN_ID,
    model_route_id: str | None = None,
    model_route_snapshot_digest: str | None = None,
    model_route_secret_bindings_path: Path | None = None,
    model_route_preflight_result_path: Path | None = None,
    supervision_scope_ref: str | None = None,
    verified_remediation: Mapping[str, Any] | None = None,
    pilot_max_attempts: int | None = None,
    attempts_consumed_before: int = 0,
) -> dict[str, Any]:
    """Read-only container preflight before any Task, Grant or queue mutation."""
    if not _RUN_ID.fullmatch(run_id):
        raise PublicPilotExecutionError("public_pilot_run_id_invalid")
    validate_automation_policy(policy)
    policy_digest = canonical_digest(policy)
    ordered = tuple(sorted(candidates, key=lambda item: item.attempt_number))
    expected_first_attempt = attempts_consumed_before + 1
    if (
        not ordered
        or ordered[0].attempt_number != expected_first_attempt
        or tuple(item.attempt_number for item in ordered)
        != tuple(
            range(
                expected_first_attempt,
                expected_first_attempt + len(ordered),
            )
        )
        or len(ordered) > 5
        or review.get("automation_policy_digest") != policy_digest
        or enablement_receipt.get("review_package_digest")
        != review.get("review_package_digest")
        or enablement_receipt.get("automation_policy_digest") != policy_digest
        or (supervision_scope_ref is None) != (verified_remediation is None)
        or (pilot_max_attempts is not None and not 1 <= pilot_max_attempts <= 5)
        or not 0 <= attempts_consumed_before <= 5
        or (
            pilot_max_attempts is not None
            and attempts_consumed_before >= pilot_max_attempts
        )
        or (
            pilot_max_attempts is not None
            and ordered[-1].attempt_number > pilot_max_attempts
        )
    ):
        raise PublicPilotExecutionError("public_pilot_binding_invalid")
    if verified_remediation is not None:
        _validate_verified_remediation(
            supervision_scope_ref=supervision_scope_ref,
            verified_remediation=verified_remediation,
            review=review,
        )
    _validate_successor_chain(ordered, policy)
    signer = Ed25519EvaluationGrantSigner(
        private_key_pem=private_key_pem,
        key_id=SIGNING_KEY_ID,
    )
    if signer.public_key_pem() != public_key_pem:
        raise PublicPilotExecutionError("public_pilot_grant_key_mismatch")
    RuntimeAdapterDescriptor.from_mapping(
        {
            "adapter_id": "runtime_adapter_framework_neutral_disease_r2_syn",
            "version": "0.1.0",
            "digest": runtime_adapter_digest,
            "runtime_family": "disease_r2_v4",
            "conformance_profiles": [
                "core_dispatch",
                "tool_data_enforced",
                "isolated_workload",
            ],
            "supported_operations": [
                "run_public_r2_fixture",
                "run_public_r2_provider_attempt",
            ],
            "supports_checkpoint_restore": False,
            "evidence_status": "public",
            "synthetic_only": False,
        }
    )
    if model_route_preflight_result_path is not None:
        if model_route_id is not None or model_route_snapshot_digest is not None:
            raise PublicPilotExecutionError(
                "public_pilot_model_route_preflight_binding_invalid"
            )
        prepared = json.loads(
            _read_protected(model_route_preflight_result_path).decode("utf-8")
        )
        if (
            not isinstance(prepared, dict)
            or prepared.get("preflight_version")
            != "orbit.full-chain-model-route-preflight/1"
            or prepared.get("status") != "ready"
            or prepared.get("provider_execution_started") is not False
        ):
            raise PublicPilotExecutionError(
                "public_pilot_model_route_preflight_binding_invalid"
            )
        model_route_id = prepared.get("route_id")
        model_route_snapshot_digest = prepared.get("snapshot_digest")
    database = Database(database_url)
    try:
        if not database.ping():
            raise PublicPilotExecutionError("public_pilot_database_not_ready")
        with database.session() as session:
            session.execute(select(ReceiptRow.receipt_id).limit(1)).all()
        route_binding = (
            model_route_id,
            model_route_snapshot_digest,
            model_route_secret_bindings_path,
        )
        if any(item is not None for item in route_binding):
            if not all(item is not None for item in route_binding):
                raise PublicPilotExecutionError(
                    "public_pilot_model_route_preflight_binding_invalid"
                )
            reconciler = ModelRouteReconciler(
                store=ModelRouteStore(database),
                secret_provider=OwnerOnlyFileSecretProvider(
                    model_route_secret_bindings_path
                ),
            )
            pipeline = GovernedReleasePipeline(
                database=database,
                qualification_store=_PreflightOnlyQualificationStore(),
                model_route_reconciler=reconciler,
            )
            try:
                route_preflight = pipeline.deploy_preflight(
                    route_id=model_route_id,
                    expected_snapshot_digest=model_route_snapshot_digest,
                )
            except ValueError as error:
                raise PublicPilotExecutionError(
                    "public_pilot_model_route_preflight_blocked"
                ) from error
        else:
            route_preflight = None
    finally:
        database.dispose()
    return {
        "preflight_version": "orbit.public-r2-pilot-container-preflight/1",
        "status": "ready",
        "policy_digest": policy_digest,
        "review_package_digest": review["review_package_digest"],
        "run_id": run_id,
        "attempts": [item.attempt_id for item in ordered],
        "runtime_adapter_digest": runtime_adapter_digest,
        "model_route_preflight": route_preflight,
        "supervision_scope_ref": supervision_scope_ref,
        "attempts_consumed_before": attempts_consumed_before,
        "pilot_max_attempts": pilot_max_attempts or len(ordered),
        "effective_task_created": False,
        "effective_grant_created": False,
        "provider_calls": 0,
        "production_authorization": False,
        "release_authorization": False,
    }


class _PreflightOnlyQualificationStore:
    """Placeholder: Model Route preflight does not read qualification state."""

    def replay(self):
        raise PublicPilotExecutionError("public_pilot_preflight_state_unavailable")


class _StaticEvidenceHandler:
    def __init__(
        self,
        *,
        policy: Mapping[str, Any],
        trusted_components: Mapping[str, Mapping[str, str]],
    ) -> None:
        self.policy = policy
        self.trusted_components = trusted_components

    def __call__(self, context: Mapping[str, Any]) -> StageHandlerResult:
        candidate = context["candidate"]
        stage = context["stage"]
        now = _time_text(datetime.now(timezone.utc))
        allowed_inputs = {
            item["digest"]
            for item in self.policy["spec"]["execution_envelope"][
                "input_artifact_allowlist"
            ]
        }
        incompatible = set(candidate["input_artifact_digests"]) - allowed_inputs
        is_initial_mapping_failure = (
            stage == "candidate_build"
            and candidate["attempt_number"] == 1
            and bool(incompatible)
        )
        passed = not is_initial_mapping_failure
        reason = (
            "public_pilot_static_evidence_passed"
            if passed
            else "candidate_input_binding_incompatible"
        )
        component = self.trusted_components[_COMPONENT_BY_STAGE[stage]]
        evidence = {
            "stage": stage,
            "attempt_id": candidate["attempt_id"],
            "composition_digest": candidate["composition_digest"],
            "runtime_source_digest": candidate["runtime_source_digest"],
            "incompatible_input_digests": sorted(incompatible),
            "passed": passed,
        }
        return StageHandlerResult(
            observation=StageObservation(
                stage=stage,
                outcome="pass" if passed else "blocked",
                failure_class="none" if passed else "engineering_compatibility",
                reason_codes=(reason,),
                checks=(
                    StageCheck(
                        "public_pilot_static_evidence",
                        "pass" if passed else "blocked",
                        None if passed else reason,
                        (
                            {
                                "role": "static_stage_evidence",
                                "ref": (
                                    "artifact://control-plane/public-pilot/"
                                    + candidate["attempt_id"]
                                    + "/"
                                    + stage
                                ),
                                "digest": canonical_digest(evidence),
                            },
                        ),
                    ),
                ),
                inputs=(
                    {
                        "role": "runtime_composition",
                        "ref": candidate["composition_ref"],
                        "digest": candidate["composition_digest"],
                    },
                ),
                executor={
                    "component": {
                        "id": component["id"],
                        "version": component["version"],
                        "digest": component["digest"],
                    },
                    "deterministic": True,
                    "environment_profile_digest": candidate[
                        "isolation_profile_digest"
                    ],
                },
                side_effects=StageSideEffects(),
                started_at=now,
                completed_at=now,
            )
        )


class _ImmutableSuccessorHandler:
    def __init__(self, candidates: Mapping[int, QualificationCandidate]) -> None:
        self.candidates = dict(candidates)

    def __call__(
        self,
        context: Mapping[str, Any],
        failed: StageObservation,
    ) -> RemediationPlan:
        predecessor = QualificationCandidate.from_mapping(context["candidate"])
        successor = self.candidates.get(predecessor.attempt_number + 1)
        if successor is None:
            raise PublicPilotExecutionError("public_pilot_successor_missing")
        source_inputs_changed = (
            set(predecessor.input_artifact_digests)
            != set(successor.input_artifact_digests)
        )
        remediation_kind = (
            "verified_source_repair" if source_inputs_changed else "bounded_retry"
        )
        verification = {
            "verification_version": "orbit.public-pilot-remediation-verification/1",
            "predecessor_attempt_id": predecessor.attempt_id,
            "successor_attempt_id": successor.attempt_id,
            "runtime_family": successor.runtime_family,
            "runtime_source_digest": successor.runtime_source_digest,
            "composition_digest": successor.composition_digest,
            "unchanged_boundary_digests": dict(successor.boundary_digests),
            "source_inputs_changed": source_inputs_changed,
            "remediation_kind": remediation_kind,
            "status": "pass",
            "release_authorization": False,
        }
        return RemediationPlan(
            successor=successor,
            changes=(
                {
                    "component_ref": (
                        "component://control-plane/public-pilot-execution-driver/0.1.0"
                    ),
                    "change_class": (
                        "implementation_fix"
                        if source_inputs_changed
                        else "workflow_candidate_revision"
                    ),
                    "before_digest": predecessor.runtime_source_digest,
                    "after_digest": successor.runtime_source_digest,
                    "reason": (
                        "Create an immutable same-family "
                        + remediation_kind
                        + " after "
                        + failed.reason_codes[0]
                    ),
                },
            ),
            verification_receipt_refs=(
                {
                    "role": "verification_receipt",
                    "ref": (
                        "receipt://public-pilot-remediation/"
                        + successor.attempt_id
                    ),
                    "digest": canonical_digest(verification),
                },
            ),
        )


def _validate_successor_chain(
    candidates: Sequence[QualificationCandidate],
    policy: Mapping[str, Any],
) -> None:
    allowed_inputs = {
        item["digest"]
        for item in policy["spec"]["execution_envelope"][
            "input_artifact_allowlist"
        ]
    }
    first = candidates[0]
    for index, candidate in enumerate(candidates):
        if index > 0:
            predecessor = candidates[index - 1]
            if (
                candidate.runtime_family != predecessor.runtime_family
                or candidate.boundary_digests != predecessor.boundary_digests
                or candidate.runtime_source_digest == predecessor.runtime_source_digest
                or candidate.composition_digest == predecessor.composition_digest
                or not set(candidate.input_artifact_digests).issubset(allowed_inputs)
            ):
                raise PublicPilotExecutionError("public_pilot_successor_invalid")
        if candidate.agent_release_digest != first.agent_release_digest:
            raise PublicPilotExecutionError("public_pilot_successor_invalid")


def _policy_approval(
    *,
    policy: Mapping[str, Any],
    policy_digest: str,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    metadata = policy["metadata"]
    return {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "ApprovalDecision",
        "metadata": {
            "decision_id": "decision_public_r2_pilot_enablement_001",
            "approval_id": "approval_public_r2_pilot_enablement_001",
            "task_id": "task_public_r2_pilot_enablement_001",
            "status": "immutable",
            "evidence_status": "public",
            "synthetic_only": False,
            "decided_at": receipt["activated_at"],
        },
        "spec": {
            "decision": "approve",
            "decided_by_human_ref": receipt["approved_by_human_ref"],
            "decided_by_role_ref": "role_local_trusted_operator",
            "scope_ref": f"policy://{metadata['policy_id']}/{metadata['version']}",
            "scope_digest": policy_digest,
            "reason": "approve exact local public R2 Pilot Enablement envelope",
            "expires_at": metadata["expires_at"],
            "separation_of_duties_check_ref": (
                "audit://local-trusted-operator/pilot-enablement"
            ),
            "audit_event_refs": ["audit_public_r2_pilot_enablement_001"],
        },
    }


def _record_local_enablement(
    database: Database,
    receipt: Mapping[str, Any],
    review: Mapping[str, Any],
) -> None:
    receipt_id = "receipt_local_public_r2_pilot_enablement_001"
    receipt_digest = receipt["receipt_digest"]
    with database.session() as session:
        existing = session.scalar(
            select(ReceiptRow).where(ReceiptRow.receipt_id == receipt_id)
        )
        if existing is not None:
            if existing.receipt_digest != receipt_digest:
                raise PublicPilotExecutionError("public_pilot_receipt_conflict")
            return
        now = datetime.now(timezone.utc)
        session.add(
            ReceiptRow(
                receipt_id=receipt_id,
                receipt_type=receipt["receipt_version"],
                receipt_digest=receipt_digest,
                subject_ref="review://" + review["review_id"],
                document=dict(receipt),
                recorded_at=now,
            )
        )
        session.add(
            AuditEventRow(
                audit_id="audit_public_r2_pilot_enablement_001",
                correlation_id=receipt_id,
                event_type="public_r2_pilot_enabled",
                actor_ref=receipt["approved_by_human_ref"],
                payload={
                    "review_package_digest": review["review_package_digest"],
                    "receipt_digest": receipt_digest,
                    "production_authorization": False,
                    "release_authorization": False,
                },
                recorded_at=now,
            )
        )
        session.add(
            OutboxEventRow(
                event_id="outbox_public_r2_pilot_enablement_001",
                topic="public_r2.pilot.enabled",
                aggregate_ref="review://" + review["review_id"],
                payload={
                    "review_package_digest": review["review_package_digest"],
                    "receipt_digest": receipt_digest,
                    "release_authorization": False,
                },
                status="pending",
                attempts=0,
                created_at=now,
                published_at=None,
            )
        )


def _result_document(
    database: Database,
    state,
    projection: Mapping[str, Any],
    *,
    run_id: str,
) -> dict[str, Any]:
    with database.session() as session:
        rows = tuple(
            session.scalars(
                select(RuntimeRunRow).order_by(RuntimeRunRow.created_at)
            )
        )
    provider_rows = tuple(
        row
        for row in rows
        if row.invocation.get("operation") == "run_public_r2_provider_attempt"
    )
    completed_provider = tuple(
        row
        for row in provider_rows
        if row.status == "completed" and row.result_document is not None
    )
    selected = completed_provider[-1] if completed_provider else None
    outcome = selected.result_document if selected is not None else None
    provider_result = outcome.get("result") if isinstance(outcome, Mapping) else None
    status = (
        "R2 provider-backed public-corpus pass"
        if state.status == "completed"
        and isinstance(provider_result, Mapping)
        and outcome.get("status") == "R2 provider-backed public-corpus pass"
        else "R2 provider-backed public-corpus blocked"
    )
    snapshot = qualification_run_snapshot(
        state,
        updated_at=_time_text(datetime.now(timezone.utc)),
    )
    return {
        "result_version": "orbit.public-r2-pilot-execution-result/1",
        "status": status,
        "qualification_status": state.status,
        "current_attempt": state.candidate.attempt_id,
        "provider_attempts": len(provider_rows),
        "provider_completed_attempts": len(completed_provider),
        "provider_result": provider_result,
        "provider_response_set_digest": (
            outcome.get("provider_response_set_digest")
            if isinstance(outcome, Mapping)
            else None
        ),
        "usage": projection["budget"],
        "runtime_runs": projection["runtime_runs"],
        "remediation_history": projection["automatic_remediation_history"],
        "receipt_set": projection["receipt_set"],
        "qualification_snapshot": {
            "digest": snapshot.digest,
            "document": snapshot.document,
        },
        "next_human_checkpoint": projection["next_human_checkpoint"],
        "next_automation_action": projection["next_automation_action"],
        "run_id": run_id,
        "production_authorization": False,
        "release_authorization": False,
    }


def _record_execution_result(
    database: Database, result: Mapping[str, Any], *, run_id: str
) -> str:
    closure = {
        "receipt_version": "orbit.local-public-r2-pilot-execution-closure/1",
        "run_id": run_id,
        "status": result["status"],
        "qualification_status": result["qualification_status"],
        "current_attempt": result["current_attempt"],
        "provider_attempts": result["provider_attempts"],
        "provider_completed_attempts": result["provider_completed_attempts"],
        "provider_result_digest": (
            None
            if result["provider_result"] is None
            else result["provider_result"].get("result_digest")
        ),
        "provider_response_set_digest": result["provider_response_set_digest"],
        "receipt_set": result["receipt_set"],
        "next_human_checkpoint": result["next_human_checkpoint"],
        "next_automation_action": result["next_automation_action"],
        "production_authorization": False,
        "release_authorization": False,
    }
    digest = canonical_digest(closure)
    identity = hashlib.sha256(run_id.encode()).hexdigest()[:20]
    receipt_id = "receipt_local_public_r2_pilot_execution_closure_" + identity
    with database.session() as session:
        existing = session.scalar(
            select(ReceiptRow).where(ReceiptRow.receipt_id == receipt_id)
        )
        if existing is not None:
            if existing.receipt_digest != digest or existing.document != closure:
                raise PublicPilotExecutionError("public_pilot_closure_conflict")
            return digest
        now = datetime.now(timezone.utc)
        session.add(
            ReceiptRow(
                receipt_id=receipt_id,
                receipt_type=closure["receipt_version"],
                receipt_digest=digest,
                subject_ref="qualification-run://" + run_id,
                document=closure,
                recorded_at=now,
            )
        )
        session.add(
            AuditEventRow(
                audit_id="audit_local_public_r2_pilot_execution_closure_" + identity,
                correlation_id=run_id,
                event_type="public_r2_pilot_execution_closed",
                actor_ref="component_governed_release_pipeline",
                payload={
                    "receipt_digest": digest,
                    "status": result["status"],
                    "provider_attempts": result["provider_attempts"],
                    "release_authorization": False,
                },
                recorded_at=now,
            )
        )
        session.add(
            OutboxEventRow(
                event_id="outbox_local_public_r2_pilot_execution_closure_" + identity,
                topic="public_r2.pilot.execution.closed",
                aggregate_ref="qualification-run://" + run_id,
                payload={
                    "receipt_digest": digest,
                    "status": result["status"],
                    "release_authorization": False,
                },
                status="pending",
                attempts=0,
                created_at=now,
                published_at=None,
            )
        )
    return digest


def _record_supervision_outcome(
    *,
    supervisor: AutomationSupervisor,
    scope_ref: str,
    state,
    result: Mapping[str, Any],
    total_attempts: int,
    max_total_attempts: int,
) -> dict[str, Any]:
    attempt_ref = "attempt://disease/" + str(result["current_attempt"])
    if result["status"] == "R2 provider-backed public-corpus pass":
        return supervisor.record_success(
            scope_ref=scope_ref,
            attempt_ref=attempt_ref,
            result_evidence_digest=result["qualification_snapshot"]["digest"],
            idempotency_key=f"supervisor:success:{result['run_id']}",
        )
    if state.last_stage_receipt is None:
        raise PublicPilotExecutionError("public_pilot_failure_receipt_missing")
    decision = state.last_stage_receipt.document["spec"]["decision"]
    reasons = tuple(decision["reason_codes"])
    if not reasons:
        raise PublicPilotExecutionError("public_pilot_failure_reason_missing")
    reason_code = reasons[-1]
    failure_class = decision["failure_class"]
    fingerprint = canonical_digest(
        {
            "stage": state.current_stage,
            "reason_code": reason_code,
            "failure_class": failure_class,
        }
    )
    return supervisor.observe_failure(
        scope_ref=scope_ref,
        attempt_ref=attempt_ref,
        failure_fingerprint=fingerprint,
        reason_code=reason_code,
        failure_class=failure_class,
        failure_evidence_digest=result["qualification_snapshot"]["digest"],
        total_attempts=total_attempts,
        max_total_attempts=max_total_attempts,
        budget_remaining=total_attempts < max_total_attempts,
        idempotency_key=f"supervisor:failure:{result['run_id']}",
    )


def _validate_verified_remediation(
    *,
    supervision_scope_ref: str | None,
    verified_remediation: Mapping[str, Any],
    review: Mapping[str, Any],
) -> None:
    expected_scope = "execution-intent://" + str(review["execution_intent_digest"])
    if (
        supervision_scope_ref != expected_scope
        or set(verified_remediation)
        != {
            "remediation_digest",
            "runtime_source_digest",
            "regression_evidence_digest",
        }
        or any(
            not isinstance(value, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            for value in verified_remediation.values()
        )
    ):
        raise PublicPilotExecutionError("public_pilot_supervision_binding_invalid")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=lambda _: _reject_constant(),
    )
    if not isinstance(value, dict):
        raise PublicPilotExecutionError("public_pilot_json_invalid")
    return value


def _validate_execution_enablement(
    *, receipt_path: Path, review_package_path: Path
) -> dict[str, Any]:
    receipt = _read_json(receipt_path)
    if (
        receipt.get("receipt_version")
        == "orbit.full-chain-pilot-enablement-receipt/1"
    ):
        return validate_full_chain_enablement_receipt(
            review_package_path=review_package_path,
            artifact_set_path=review_package_path.parent / "skill-artifact-set.json",
            receipt_path=receipt_path,
        )
    return validate_pilot_enablement(
        receipt_path=receipt_path,
        review_package_path=review_package_path,
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicPilotExecutionError("public_pilot_json_duplicate_key")
        result[key] = value
    return result


def _reject_constant() -> None:
    raise PublicPilotExecutionError("public_pilot_json_constant_invalid")


def _read_protected(path: Path, *, maximum: int = 64 * 1024) -> bytes:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or not 1 <= info.st_size <= maximum
    ):
        raise PublicPilotExecutionError("public_pilot_protected_file_invalid")
    return path.read_bytes()


def _raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url-file", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--enablement-receipt", type=Path, required=True)
    parser.add_argument("--candidate", action="append", type=Path, required=True)
    parser.add_argument("--grant-private-key", type=Path, required=True)
    parser.add_argument("--grant-public-key", type=Path, required=True)
    parser.add_argument("--runtime-adapter-source", type=Path, required=True)
    parser.add_argument("--run-id", default=RUN_ID)
    parser.add_argument("--model-route-id")
    parser.add_argument("--model-route-snapshot-digest")
    parser.add_argument("--model-route-secret-bindings", type=Path)
    parser.add_argument("--model-route-preflight-result", type=Path)
    parser.add_argument("--supervision-scope-ref")
    parser.add_argument("--verified-remediation-manifest", type=Path)
    parser.add_argument("--pilot-max-attempts", type=int)
    parser.add_argument("--attempts-consumed-before", type=int, default=0)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    _validate_execution_enablement(
        receipt_path=args.enablement_receipt,
        review_package_path=args.review,
    )
    database_url = _read_protected(args.database_url_file, maximum=4096).decode().strip()
    policy = _read_json(args.policy)
    review = _read_json(args.review)
    receipt = _read_json(args.enablement_receipt)
    supervision_scope_ref = args.supervision_scope_ref
    candidates = tuple(
        QualificationCandidate.from_mapping(_read_json(path))
        for path in args.candidate
    )
    verified_remediation = None
    if args.verified_remediation_manifest is not None:
        manifest = _read_json(args.verified_remediation_manifest)
        if (
            manifest.get("status") != "verified"
            or manifest.get("runtime_family") != "disease_r2_v4"
            or manifest.get("permission_boundary_changed") is not False
            or manifest.get("provider_model_endpoint_changed") is not False
            or manifest.get("data_scope_changed") is not False
            or manifest.get("budget_or_attempt_ceiling_changed") is not False
            or manifest.get("secret_scope_expanded") is not False
        ):
            raise PublicPilotExecutionError(
                "public_pilot_supervision_binding_invalid"
            )
        verified_remediation = {
            "remediation_digest": manifest["manifest_digest"],
            "runtime_source_digest": manifest[
                "successor_runtime_source_base_digest"
            ],
            "regression_evidence_digest": canonical_digest(
                manifest["offline_verification"]
            ),
        }
        if supervision_scope_ref is None:
            supervision_scope_ref = (
                "execution-intent://" + review["execution_intent_digest"]
            )
    inputs = {
        "database_url": database_url,
        "policy": policy,
        "review": review,
        "enablement_receipt": receipt,
        "candidates": candidates,
        "private_key_pem": _read_protected(args.grant_private_key),
        "public_key_pem": _read_protected(args.grant_public_key),
        "runtime_adapter_digest": _raw_digest(args.runtime_adapter_source),
        "run_id": args.run_id,
        "model_route_id": args.model_route_id,
        "model_route_snapshot_digest": args.model_route_snapshot_digest,
        "model_route_secret_bindings_path": args.model_route_secret_bindings,
        "model_route_preflight_result_path": args.model_route_preflight_result,
        "supervision_scope_ref": supervision_scope_ref,
        "verified_remediation": verified_remediation,
        "pilot_max_attempts": args.pilot_max_attempts,
        "attempts_consumed_before": args.attempts_consumed_before,
    }
    if args.preflight_only:
        output = preflight_public_pilot(**inputs)
        print(
            json.dumps(
                output,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
        return 0
    output = run_public_pilot(
        **inputs,
    )
    print(
        json.dumps(
            output,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )
    return 0 if output["status"] == "R2 provider-backed public-corpus pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())

