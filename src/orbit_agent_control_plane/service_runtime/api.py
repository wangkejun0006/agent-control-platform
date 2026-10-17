"""FastAPI application for the modular-monolith Control Plane service."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ..qualification.automation import (
    build_policy_activation_receipt,
    canonical_digest,
    validate_automation_policy,
)
from ..qualification.ledger import QualificationLedgerError
from ..qualification.service import (
    ProductionReadinessAssessment,
    assess_production_readiness,
    validate_service_profile,
)
from .adapters import build_adapter_bindings, load_runtime_evidence
from .automation_supervisor import AutomationSupervisor, AutomationSupervisorStore
from .config import ServiceSettings
from .database import Database
from .department_cockpit import DepartmentCockpitService
from .department_cockpit_api import install_department_cockpit_routes
from .governance_catalogs import GovernanceCatalogService
from .governance_catalogs_api import install_governance_catalog_routes
from .managed_components import (
    ManagedComponentRegistry,
    build_governed_release_pipeline_descriptor,
)
from .model_route import (
    ModelRouteError,
    ModelRouteReconciler,
    ModelRouteStore,
    OwnerOnlyFileSecretProvider,
    UnavailableSecretProvider,
)
from .models import AuditEventRow, GrantRevocationRow, ReceiptRow
from .pipeline import GovernedReleasePipeline
from .repositories import (
    ServiceRepositoryError,
    SqlAlchemyPolicyActivationRepository,
    SqlAlchemyQualificationStore,
    SqlGrantRevocationRegistry,
    SqlWorkerLeaseCoordinator,
)
from .runner_queue import SqlRunnerTransport, SqlSignedGrantRegistry
from .runtime_adapter import (
    DisabledRunnerTransport,
    FrameworkNeutralRuntimeAdapter,
    RunnerTransport,
    RuntimeAdapterDescriptor,
    RuntimeAdapterError,
    RuntimeAdapterRegistry,
)
from .runtime_artifact_api import install_runtime_artifact_routes
from .runtime_artifacts import RuntimeArtifactService
from .security import Ed25519EvaluationGrantVerifier, ServiceSecurityError


class HumanVerifierUnavailable:
    def verify_oidc_assertion(self, *, token: str, expected_audience: str) -> dict:
        raise ServiceSecurityError("oidc_adapter_unavailable")


class WorkloadVerifierUnavailable:
    def verify_mtls_peer(self, *, peer_certificate: bytes) -> dict:
        raise ServiceSecurityError("mtls_adapter_unavailable")


@dataclass
class ServiceRuntime:
    settings: ServiceSettings
    database: Database
    policy: dict[str, Any]
    policy_digest: str
    review_package: dict[str, Any]
    profile: dict[str, Any]
    adapter_bindings: list[dict[str, Any]]
    readiness: ProductionReadinessAssessment
    qualification_store: SqlAlchemyQualificationStore
    policy_activations: SqlAlchemyPolicyActivationRepository
    grant_revocations: SqlGrantRevocationRegistry
    worker_leases: SqlWorkerLeaseCoordinator
    human_verifier: Any
    workload_verifier: Any
    grant_signer: Any | None
    runtime_adapters: RuntimeAdapterRegistry
    disease_r2_runtime_adapter: FrameworkNeutralRuntimeAdapter
    automation_supervisor: AutomationSupervisor
    governed_release_pipeline: GovernedReleasePipeline
    model_route_reconciler: ModelRouteReconciler
    managed_components: ManagedComponentRegistry
    managed_component_descriptor: dict[str, Any]
    governance_catalogs: GovernanceCatalogService
    runtime_artifacts: RuntimeArtifactService


class PolicyActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    review_package_raw_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    activated_at: str
    approval_decision: dict[str, Any]


class GrantRevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str = Field(pattern=r"^grant_[a-zA-Z0-9_:-]{3,120}$")
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{2,95}$")


class WorkerLeaseClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(pattern=r"^run_[a-zA-Z0-9_:-]{3,120}$")
    ttl_seconds: int = Field(ge=5, le=300)


class WorkerLeaseHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_id: str = Field(pattern=r"^lease_[a-zA-Z0-9_:-]{3,120}$")


class WorkerLeaseCloseRequest(WorkerLeaseHeartbeatRequest):
    outcome: str = Field(pattern=r"^(completed|failed|cancelled)$")


def load_service_runtime(
    *,
    settings: ServiceSettings,
    repository_root: Path,
    human_verifier: Any | None = None,
    workload_verifier: Any | None = None,
    grant_signer: Any | None = None,
    runner_transport: RunnerTransport | None = None,
) -> ServiceRuntime:
    policy = _read_json(settings.policy_path)
    review = _read_json(settings.review_package_path)
    profile = _read_json(settings.profile_path)
    validate_automation_policy(policy)
    validate_service_profile(profile)
    policy_digest = canonical_digest(policy)
    policy_raw_digest = _file_digest(settings.policy_path)
    review_raw_digest = _file_digest(settings.review_package_path)
    review_policy = review.get("automation_policy")
    if (
        not isinstance(review_policy, dict)
        or review_policy.get("canonical_digest") != policy_digest
        or review_policy.get("raw_file_digest") != policy_raw_digest
        or review.get("authority_boundary", {}).get("release_authorization")
        is not False
        or review_raw_digest
        != "sha256:3acfcb0e1ae40ff02ddc7cb5a0410be56bd4a6fdf19b32fd19d2f53fa8b4aae9"
    ):
        raise ValueError("service_policy_review_drift")
    runtime_evidence = load_runtime_evidence(settings.adapter_evidence_path)
    bindings = build_adapter_bindings(
        repository_root=repository_root,
        runtime_evidence=runtime_evidence,
    )
    readiness = assess_production_readiness(profile=profile, adapters=bindings)
    database = Database(settings.database_url)
    grant_revocations = SqlGrantRevocationRegistry(database)
    effective_transport = runner_transport
    if effective_transport is None and settings.grant_verification_key_path is not None:
        if settings.grant_signing_key_id is None:
            raise ValueError("service_grant_verification_key_id_missing")
        verifier = Ed25519EvaluationGrantVerifier(
            public_key_pem=settings.grant_verification_key_path.read_bytes(),
            key_id=settings.grant_signing_key_id,
        )
        grants = SqlSignedGrantRegistry(
            database,
            verifier=verifier,
            revocations=grant_revocations,
        )
        effective_transport = SqlRunnerTransport(database, grants=grants)
    adapter_source = (
        repository_root
        / "src/orbit_agent_control_plane/service_runtime/runtime_adapter.py"
    )
    disease_r2_adapter = FrameworkNeutralRuntimeAdapter(
        descriptor=RuntimeAdapterDescriptor.from_mapping(
            {
                "adapter_id": "runtime_adapter_framework_neutral_disease_r2_syn",
                "version": "0.1.0",
                "digest": _file_digest(adapter_source),
                "runtime_family": "disease_r2_v4",
                "conformance_profiles": [
                    "core_dispatch",
                    "tool_data_enforced",
                    "isolated_workload",
                ],
                "supported_operations": [
                    "run_public_r2_fixture",
                    "run_public_r2_provider_attempt",
                    "run_qualification_attempt",
                ],
                "supports_checkpoint_restore": False,
                "evidence_status": (
                    "public"
                    if effective_transport is not None
                    else "architecture_reference"
                ),
                "synthetic_only": effective_transport is None,
            }
        ),
        transport=effective_transport or DisabledRunnerTransport(),
    )
    runtime_adapters = RuntimeAdapterRegistry()
    runtime_adapters.register(disease_r2_adapter)
    qualification_store = SqlAlchemyQualificationStore(database)
    model_route_secret_provider = (
        UnavailableSecretProvider()
        if settings.model_route_secret_bindings_path is None
        else OwnerOnlyFileSecretProvider(
            settings.model_route_secret_bindings_path
        )
    )
    model_route_reconciler = ModelRouteReconciler(
        store=ModelRouteStore(database),
        secret_provider=model_route_secret_provider,
    )
    automation_supervisor = AutomationSupervisor(AutomationSupervisorStore(database))
    managed_component_descriptor = build_governed_release_pipeline_descriptor(
        repository_root
    )
    managed_components = ManagedComponentRegistry(database)
    governance_catalogs = GovernanceCatalogService(
        database=database,
        repository_root=repository_root,
    )
    return ServiceRuntime(
        settings=settings,
        database=database,
        policy=policy,
        policy_digest=policy_digest,
        review_package=review,
        profile=profile,
        adapter_bindings=bindings,
        readiness=readiness,
        qualification_store=qualification_store,
        policy_activations=SqlAlchemyPolicyActivationRepository(database),
        grant_revocations=grant_revocations,
        worker_leases=SqlWorkerLeaseCoordinator(database),
        human_verifier=human_verifier or HumanVerifierUnavailable(),
        workload_verifier=workload_verifier or WorkloadVerifierUnavailable(),
        grant_signer=grant_signer,
        runtime_adapters=runtime_adapters,
        disease_r2_runtime_adapter=disease_r2_adapter,
        automation_supervisor=automation_supervisor,
        governed_release_pipeline=GovernedReleasePipeline(
            database=database,
            qualification_store=qualification_store,
            model_route_reconciler=model_route_reconciler,
            automation_supervisor=automation_supervisor,
        ),
        model_route_reconciler=model_route_reconciler,
        managed_components=managed_components,
        managed_component_descriptor=managed_component_descriptor,
        governance_catalogs=governance_catalogs,
        runtime_artifacts=RuntimeArtifactService(
            database=database,
            grant_revocations=grant_revocations,
        ),
    )


def create_app(
    runtime: ServiceRuntime,
    *,
    department_cockpit: DepartmentCockpitService | None = None,
) -> FastAPI:
    runtime.managed_components.register(runtime.managed_component_descriptor)
    runtime.governance_catalogs.bootstrap()
    app = FastAPI(
        title="Orbit Agent Control Plane",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.state.runtime = runtime

    def authenticate_human(
        request: Request, *, required_roles: frozenset[str]
    ) -> dict[str, Any]:
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or len(authorization) <= 7:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "human_identity_required")
        try:
            principal = dict(
                runtime.human_verifier.verify_oidc_assertion(
                    token=authorization[7:],
                    expected_audience=runtime.settings.oidc_audience or "",
                )
            )
        except ServiceSecurityError as error:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, error.reason_code
            ) from error
        if not required_roles.intersection(principal.get("role_refs", [])):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "human_role_not_allowed")
        return principal

    def require_human(
        request: Request, *, required_roles: frozenset[str]
    ) -> dict[str, Any]:
        if not runtime.settings.mutations_enabled:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "mutations_disabled"
            )
        return authenticate_human(request, required_roles=required_roles)

    def require_workload(request: Request) -> dict[str, Any]:
        if not runtime.settings.mutations_enabled:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "mutations_disabled"
            )
        certificate = request.scope.get("orbit.peer_certificate_der")
        if not isinstance(certificate, bytes):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "workload_identity_required"
            )
        try:
            return dict(
                runtime.workload_verifier.verify_mtls_peer(peer_certificate=certificate)
            )
        except ServiceSecurityError as error:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, error.reason_code
            ) from error

    @app.get("/health/live")
    def live() -> dict[str, Any]:
        return {
            "status": "live",
            "service_mode": runtime.settings.mode,
            "release_authorization": False,
        }

    @app.get("/health/ready")
    def ready() -> dict[str, Any]:
        database_ready = runtime.database.ping()
        ready_value = database_ready and runtime.readiness.ready
        if not ready_value:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                {
                    "status": "not_ready",
                    "database_ready": database_ready,
                    "blocker_codes": list(runtime.readiness.blocker_codes),
                    "release_authorization": False,
                },
            )
        return {
            "status": runtime.readiness.status,
            "database_ready": True,
            "release_authorization": False,
        }

    @app.get("/v1/security/status")
    def security_status() -> dict[str, Any]:
        signer_metadata = (
            dict(runtime.grant_signer.public_metadata())
            if runtime.grant_signer is not None
            else None
        )
        return {
            "identity_mode": (
                "oidc_human_and_mtls_workload"
                if runtime.settings.mutations_enabled
                else "local_trusted_operator_start_guard"
                if runtime.settings.mode == "local_trusted_operator"
                else "disabled"
            ),
            "oidc_issuer": runtime.settings.oidc_issuer,
            "oidc_audience": runtime.settings.oidc_audience,
            "grant_signer": signer_metadata,
            "mutations_enabled": runtime.settings.mutations_enabled,
            "release_authorization": False,
        }

    @app.get("/v1/policies/{policy_id}")
    def policy_status(policy_id: str) -> dict[str, Any]:
        if policy_id != runtime.policy["metadata"]["policy_id"]:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "policy_not_found")
        activation = runtime.policy_activations.get_by_policy_digest(
            runtime.policy_digest
        )
        return {
            "policy_id": policy_id,
            "policy_digest": runtime.policy_digest,
            "candidate_status": runtime.policy["metadata"]["status"],
            "activation": activation,
            "release_authorization": False,
        }

    @app.get("/v1/runtime-adapters/{adapter_id}")
    def runtime_adapter_status(adapter_id: str) -> dict[str, Any]:
        adapter = runtime.disease_r2_runtime_adapter
        if adapter_id != adapter.descriptor.adapter_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "runtime_adapter_not_found")
        return {
            "descriptor": adapter.describe_capabilities(),
            "transport": dict(adapter.health()),
            "effective": adapter.health().get("status") == "ready",
            "release_authorization": False,
        }

    @app.get("/v1/managed-components/{component_id}")
    def managed_component_status(component_id: str) -> dict[str, Any]:
        value = runtime.managed_components.current(component_id)
        if value is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "managed_component_not_found")
        return value

    @app.get("/v1/automation-supervision")
    def automation_supervision_status(scope_ref: str) -> dict[str, Any]:
        try:
            return runtime.automation_supervisor.status(scope_ref)
        except (ServiceRepositoryError, ValueError) as error:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "automation_supervision_scope_invalid",
            ) from error

    @app.get("/v1/model-routes/{route_id}")
    def model_route_status(route_id: str) -> dict[str, Any]:
        try:
            return dict(runtime.model_route_reconciler.status(route_id))
        except ModelRouteError as error:
            if error.reason_code == "model_route_revision_not_found":
                raise HTTPException(
                    status.HTTP_404_NOT_FOUND, "model_route_not_found"
                ) from error
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, error.reason_code
            ) from error

    @app.post("/v1/policies/{policy_id}/activations", status_code=201)
    def activate_policy(
        policy_id: str,
        request: PolicyActivationRequest,
        http_request: Request,
    ) -> dict[str, Any]:
        principal = require_human(
            http_request, required_roles=frozenset({"role_control_plane_admin"})
        )
        if policy_id != runtime.policy["metadata"]["policy_id"]:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "policy_not_found")
        if (
            request.policy_digest != runtime.policy_digest
            or request.review_package_raw_digest
            != _file_digest(runtime.settings.review_package_path)
            or request.approval_decision.get("spec", {}).get("decided_by_human_ref")
            != principal.get("human_ref")
            or request.approval_decision.get("spec", {}).get("decided_by_role_ref")
            not in principal.get("role_refs", [])
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT, "policy_activation_binding_drift"
            )
        receipt = build_policy_activation_receipt(
            policy=runtime.policy,
            policy_digest=runtime.policy_digest,
            approval_decision=request.approval_decision,
            activated_at=request.activated_at,
        )
        try:
            appended = runtime.policy_activations.record(
                policy=runtime.policy,
                policy_digest=runtime.policy_digest,
                approval_decision=request.approval_decision,
                receipt=receipt,
            )
        except ServiceRepositoryError as error:
            raise HTTPException(status.HTTP_409_CONFLICT, error.reason_code) from error
        return {
            "status": "active",
            "appended": appended,
            "receipt_id": receipt.document["metadata"]["receipt_id"],
            "receipt_digest": receipt.digest,
            "release_authorization": False,
        }

    @app.get("/v1/qualification-runs/{run_id}")
    def qualification_run(run_id: str) -> dict[str, Any]:
        try:
            run = runtime.qualification_store.replay().run(run_id)
        except QualificationLedgerError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "run_not_found") from error
        return {
            "run_id": run.run_id,
            "revision": run.revision,
            "status": run.status,
            "current_stage": run.current_stage,
            "next_checkpoint_scope": run.next_checkpoint_scope,
            "release_authorization": False,
        }

    @app.get("/v1/pilots/{run_id}")
    def pilot_status(run_id: str) -> dict[str, Any]:
        try:
            return runtime.governed_release_pipeline.status(run_id)
        except ValueError as error:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "pilot_not_found") from error

    @app.get("/v1/runtime-runs/{run_id}")
    def runtime_run_status(run_id: str) -> dict[str, Any]:
        transport = runtime.disease_r2_runtime_adapter.transport
        status_method = getattr(transport, "status", None)
        if status_method is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "runner_transport_not_configured"
            )
        value = status_method(run_id)
        if value is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "runtime_run_not_found")
        return dict(value)

    @app.get("/v1/runtime-runs/{run_id}/events")
    def runtime_run_events(run_id: str, after_sequence: int = -1) -> dict[str, Any]:
        if after_sequence < -1:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "cursor_invalid")
        transport = runtime.disease_r2_runtime_adapter.transport
        try:
            events = transport.events(
                run_id=run_id,
                after_sequence=after_sequence,
            )
        except RuntimeAdapterError as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "runner_transport_not_configured",
            ) from error
        return {
            "run_id": run_id,
            "events": list(events),
            "release_authorization": False,
        }

    @app.get("/v1/runtime-runs/{run_id}/result")
    def runtime_run_result(run_id: str) -> dict[str, Any]:
        transport = runtime.disease_r2_runtime_adapter.transport
        try:
            value = transport.result(run_id=run_id)
        except RuntimeAdapterError as error:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "runner_transport_not_configured",
            ) from error
        if value is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "runtime_result_not_found")
        return dict(value)

    @app.get("/v1/receipts/{receipt_id}")
    def receipt(receipt_id: str) -> dict[str, Any]:
        with runtime.database.session() as session:
            row = session.scalar(
                select(ReceiptRow).where(ReceiptRow.receipt_id == receipt_id)
            )
            if row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "receipt_not_found")
            return {
                "receipt_id": row.receipt_id,
                "receipt_type": row.receipt_type,
                "receipt_digest": row.receipt_digest,
                "subject_ref": row.subject_ref,
                "document": row.document,
                "release_authorization": False,
            }

    @app.post("/v1/grant-revocations", status_code=201)
    def revoke_grant(
        request: GrantRevocationRequest,
        http_request: Request,
    ) -> dict[str, Any]:
        principal = require_human(
            http_request, required_roles=frozenset({"role_control_plane_admin"})
        )
        revision = runtime.grant_revocations.revoke(
            grant_id=request.grant_id,
            reason_code=request.reason_code,
            revoked_by_ref=principal["human_ref"],
        )
        return {
            "grant_id": request.grant_id,
            "revision": revision,
            "revoked": True,
            "release_authorization": False,
        }

    @app.get("/v1/grant-revocations/{grant_id}")
    def grant_revocation(grant_id: str) -> dict[str, Any]:
        with runtime.database.session() as session:
            row = session.scalar(
                select(GrantRevocationRow).where(
                    GrantRevocationRow.grant_id == grant_id
                )
            )
            if row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "revocation_not_found")
            return {
                "grant_id": row.grant_id,
                "revision": row.revision,
                "reason_code": row.reason_code,
                "release_authorization": False,
            }

    @app.post("/v1/worker-leases/claims", status_code=201)
    def claim_worker_lease(
        body: WorkerLeaseClaimRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = require_workload(request)
        lease_id = runtime.worker_leases.claim(
            run_id=body.run_id,
            worker_identity=principal["workload_identity"],
            ttl_seconds=body.ttl_seconds,
        )
        return {
            "lease_id": lease_id,
            "run_id": body.run_id,
            "release_authorization": False,
        }

    @app.post("/v1/worker-leases/heartbeat")
    def heartbeat_worker_lease(
        body: WorkerLeaseHeartbeatRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = require_workload(request)
        runtime.worker_leases.heartbeat(
            lease_id=body.lease_id,
            worker_identity=principal["workload_identity"],
        )
        return {"status": "active", "release_authorization": False}

    @app.post("/v1/worker-leases/close")
    def close_worker_lease(
        body: WorkerLeaseCloseRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = require_workload(request)
        runtime.worker_leases.close(
            lease_id=body.lease_id,
            worker_identity=principal["workload_identity"],
            outcome=body.outcome,
        )
        return {"status": "closed", "release_authorization": False}

    @app.get("/v1/worker-leases/{lease_id}")
    def worker_lease(lease_id: str) -> dict[str, Any]:
        value = runtime.worker_leases.status(lease_id)
        if value is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "lease_not_found")
        return {**value, "release_authorization": False}

    @app.get("/v1/audit/events/{correlation_id}")
    def audit_events(correlation_id: str) -> dict[str, Any]:
        with runtime.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(AuditEventRow)
                    .where(AuditEventRow.correlation_id == correlation_id)
                    .order_by(AuditEventRow.id)
                )
            )
            return {
                "correlation_id": correlation_id,
                "events": [
                    {
                        "audit_id": row.audit_id,
                        "event_type": row.event_type,
                        "actor_ref": row.actor_ref,
                        "payload": row.payload,
                        "recorded_at": row.recorded_at.isoformat(),
                    }
                    for row in rows
                ],
                "release_authorization": False,
            }

    install_department_cockpit_routes(
        app,
        service=department_cockpit
        or DepartmentCockpitService(database=runtime.database),
        authenticate_human=authenticate_human,
        require_mutating_human=require_human,
    )
    install_runtime_artifact_routes(
        app,
        service=runtime.runtime_artifacts,
        authenticate_human=authenticate_human,
        require_mutating_human=require_human,
        require_workload=require_workload,
    )
    install_governance_catalog_routes(
        app,
        service=runtime.governance_catalogs,
        authenticate_human=authenticate_human,
        require_mutating_human=require_human,
    )

    return app


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("service_artifact_invalid")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: _reject_constant(),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("service_artifact_invalid") from error
    if not isinstance(value, dict):
        raise TypeError("service_artifact_invalid")
    return value


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("service_artifact_duplicate_key")
        result[key] = value
    return result


def _reject_constant() -> None:
    raise ValueError("service_artifact_nonfinite_number")

