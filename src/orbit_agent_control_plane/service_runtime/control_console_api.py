"""HTTP surface for the company resource-governance console."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from .control_console import ControlConsoleError, ControlConsoleService
from .model_catalog import ModelCatalogError
from .model_route import ModelRouteError

HumanGuard = Callable[..., dict[str, Any]]
_ADMIN = frozenset({"role_control_plane_admin"})
_DIGEST = r"^sha256:[0-9a-f]{64}$"
_EXPECTED_DIGEST = r"^(none|sha256:[0-9a-f]{64})$"
_IDEMPOTENCY = r"^[A-Za-z0-9._:-]{8,192}$"


class ModelRouteCandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document: dict[str, Any]
    expected_latest_revision_digest: str = Field(pattern=_EXPECTED_DIGEST)
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ProviderObservationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route_id: str = Field(pattern=r"^[a-z][A-Za-z0-9_:-]{2,159}$")
    expected_revision_digest: str = Field(pattern=_DIGEST)
    document: dict[str, Any]
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision_digest: str = Field(pattern=_DIGEST)
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ModelRouteApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_scope: str = Field(pattern=r"^model_route_approval$")
    route_id: str = Field(pattern=r"^[a-z][A-Za-z0-9_:-]{2,159}$")
    expected_revision_digest: str = Field(pattern=_DIGEST)
    expected_snapshot_digest: str = Field(pattern=_DIGEST)
    decision: str = Field(pattern=r"^(approved|rejected)$")
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ModelRouteRevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision_digest: str = Field(pattern=_DIGEST)
    expected_approval_decision_digest: str = Field(pattern=_DIGEST)
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ModelRouteCredentialBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route_id: str = Field(pattern=r"^[a-z][A-Za-z0-9_:-]{2,159}$")
    expected_revision_digest: str = Field(pattern=_DIGEST)
    authentication_mode: str = Field(pattern=r"^api_key_ref$")
    expected_binding_version: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,159}$"
    )
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ModelRouteAccountLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision_digest: str = Field(pattern=_DIGEST)
    node_id: str = Field(pattern=r"^[a-z][A-Za-z0-9_:-]{2,159}$")
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ModelRouteRetirementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision_digest: str = Field(pattern=_DIGEST)
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class TaskScopeReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=1)
    expected_task_digest: str = Field(pattern=_DIGEST)
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ProviderModelDiscoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_preset_id: str = Field(pattern=r"^provider_preset_[a-z0-9_]{3,120}$")
    provider_preset_revision_digest: str = Field(pattern=_DIGEST)
    region_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,95}$")
    connection_alias: str = Field(min_length=2, max_length=160)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ProviderOnboardingProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=2, max_length=160)
    requested_regions: list[str] = Field(min_length=1, max_length=8)
    required_protocols: list[str] = Field(min_length=1, max_length=8)
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ProviderOnboardingReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_proposal_digest: str = Field(pattern=_DIGEST)
    expected_review_digest: str | None = Field(default=None, pattern=_DIGEST)
    status: str = Field(pattern=r"^(revision_required|rejected|linked_to_preset)$")
    reason: str = Field(min_length=8, max_length=500)
    provider_preset_id: str | None = None
    provider_preset_revision_digest: str | None = Field(default=None, pattern=_DIGEST)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ModelCatalogEntryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_entry_revision_digest: str | None = Field(default=None, pattern=_DIGEST)
    discovery_digest: str = Field(pattern=_DIGEST)
    provider_model_key: str = Field(pattern=r"^[a-z][a-z0-9_]{2,120}$")
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ModelCatalogCredentialBindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_entry_revision_digest: str = Field(pattern=_DIGEST)
    authentication_mode: str = Field(pattern=r"^api_key_ref$")
    expected_binding_version: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,159}$"
    )
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class ModelCatalogLifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_entry_revision_digest: str = Field(pattern=_DIGEST)
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class AgentActivationDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_scope: str = Field(pattern=r"^agent_activation$")
    expected_package_digest: str = Field(pattern=_DIGEST)
    expected_agent_definition_digest: str = Field(pattern=_DIGEST)
    decision: str = Field(pattern=r"^(approved|rejected|revision_required)$")
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


def install_control_console_routes(
    app: FastAPI,
    *,
    service: ControlConsoleService,
    authenticate_human: HumanGuard,
    require_mutating_human: HumanGuard,
) -> None:
    def read_admin(request: Request) -> dict[str, Any]:
        return authenticate_human(request, required_roles=_ADMIN)

    def write_admin(request: Request) -> dict[str, Any]:
        return require_mutating_human(request, required_roles=_ADMIN)

    @app.get("/v1/control/model-provider-presets")
    def model_provider_presets(request: Request) -> dict[str, Any]:
        read_admin(request)
        return _call(service.list_model_provider_presets)

    @app.post("/v1/control/provider-model-discoveries", status_code=201)
    def discover_provider_models(
        body: ProviderModelDiscoveryRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.discover_provider_models(
                provider_preset_id=body.provider_preset_id,
                provider_preset_revision_digest=body.provider_preset_revision_digest,
                region_id=body.region_id,
                connection_alias=body.connection_alias,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post("/v1/control/provider-onboarding-proposals", status_code=201)
    def submit_provider_onboarding(
        body: ProviderOnboardingProposalRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.submit_provider_onboarding(
                display_name=body.display_name,
                requested_regions=body.requested_regions,
                required_protocols=body.required_protocols,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.get("/v1/control/provider-onboarding-proposals")
    def onboarding_history(request: Request):
        read_admin(request)
        return _call(service.list_provider_onboarding)

    @app.post("/v1/control/provider-onboarding-proposals/{proposal_id}/reviews", status_code=201)
    def onboarding_review(proposal_id: str, body: ProviderOnboardingReviewRequest, request: Request):
        principal = write_admin(request)
        return _call(lambda: service.review_provider_onboarding(proposal_id=proposal_id, actor_ref=principal['human_ref'], **body.model_dump()))

    @app.get("/v1/control/model-catalog-entries")
    def model_catalog_entries(request: Request) -> dict[str, Any]:
        read_admin(request)
        return _call(service.list_model_catalog_entries)

    @app.post("/v1/control/model-catalog-entries", status_code=201)
    def create_model_catalog_entry(
        body: ModelCatalogEntryRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.create_model_catalog_entry(
                expected_entry_revision_digest=body.expected_entry_revision_digest,
                discovery_digest=body.discovery_digest,
                provider_model_key=body.provider_model_key,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post(
        "/v1/control/model-catalog-entries/{entry_id}/credential-bindings",
        status_code=201,
    )
    def bind_model_catalog_credential(
        entry_id: str,
        body: ModelCatalogCredentialBindingRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.qualify_model_catalog_api_key(
                entry_id=entry_id,
                expected_entry_revision_digest=body.expected_entry_revision_digest,
                expected_binding_version=body.expected_binding_version,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post(
        "/v1/control/model-catalog-entries/{entry_id}/availability-receipts",
        status_code=201,
    )
    def publish_model_catalog_entry(
        entry_id: str, body: ModelCatalogLifecycleRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.publish_model_catalog_entry(
                entry_id=entry_id,
                expected_entry_revision_digest=body.expected_entry_revision_digest,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post(
        "/v1/control/model-catalog-entries/{entry_id}/retirement-receipts",
        status_code=201,
    )
    def retire_model_catalog_entry(
        entry_id: str, body: ModelCatalogLifecycleRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.retire_model_catalog_entry(
                entry_id=entry_id,
                expected_entry_revision_digest=body.expected_entry_revision_digest,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.get("/v1/control/department-agent-proposals")
    def department_agent_proposals(request: Request) -> dict[str, Any]:
        read_admin(request)
        return _call(service.list_agent_route_reviews)

    @app.post(
        "/v1/control/department-agent-proposals/{proposal_id}/activation-decisions",
        status_code=201,
    )
    def decide_agent_activation(
        proposal_id: str,
        body: AgentActivationDecisionRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.decide_agent_activation(
                proposal_id=proposal_id,
                expected_package_digest=body.expected_package_digest,
                expected_agent_definition_digest=(
                    body.expected_agent_definition_digest
                ),
                decision=body.decision,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.get("/v1/model-routes")
    def model_routes(request: Request) -> dict[str, Any]:
        read_admin(request)
        return _call(service.list_model_routes)

    @app.post("/v1/model-route-candidates", deprecated=True)
    def submit_model_route_candidate(request: Request) -> dict[str, Any]:
        # Keep the historical URL explicit but never ingest its raw Route body.
        # New routes are generated only from a department-owned proposal.
        write_admin(request)
        raise HTTPException(
            status_code=410,
            detail="model_route_candidate_requires_department_agent_proposal",
        )

    @app.get(
        "/v1/model-routes/{route_id}/revisions/{revision_digest}"
    )
    def model_route_revision(
        route_id: str, revision_digest: str, request: Request
    ) -> dict[str, Any]:
        read_admin(request)
        return _call(
            lambda: service.model_route_revision(
                route_id=route_id, revision_digest=revision_digest
            )
        )

    @app.post("/v1/provider-observations", status_code=201)
    def record_provider_observation(
        body: ProviderObservationRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.record_provider_observation(
                route_id=body.route_id,
                expected_revision_digest=body.expected_revision_digest,
                document=body.document,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post("/v1/model-routes/{route_id}/reconcile")
    def reconcile_model_route(
        route_id: str, body: ReconcileRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.reconcile_model_route(
                route_id=route_id,
                expected_revision_digest=body.expected_revision_digest,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post("/v1/approval-decisions", status_code=201)
    def decide_model_route(
        body: ModelRouteApprovalRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        role_ref = _selected_admin_role(principal)
        return _call(
            lambda: service.decide_model_route(
                route_id=body.route_id,
                expected_revision_digest=body.expected_revision_digest,
                expected_snapshot_digest=body.expected_snapshot_digest,
                decision=body.decision,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
                actor_role_ref=role_ref,
            )
        )

    @app.post(
        "/v1/model-routes/{route_id}/approval-revocations", status_code=201
    )
    def revoke_model_route_approval(
        route_id: str, body: ModelRouteRevocationRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.revoke_model_route_approval(
                route_id=route_id,
                expected_revision_digest=body.expected_revision_digest,
                expected_approval_decision_digest=(
                    body.expected_approval_decision_digest
                ),
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
                actor_role_ref=_selected_admin_role(principal),
            )
        )

    @app.post("/v1/model-route-credential-bindings", status_code=201)
    def bind_model_route_credential(
        body: ModelRouteCredentialBindingRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.bind_model_route_api_key(
                route_id=body.route_id,
                expected_revision_digest=body.expected_revision_digest,
                expected_binding_version=body.expected_binding_version,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post(
        "/v1/model-routes/{route_id}/account-login-requests", status_code=201
    )
    def request_model_route_account_login(
        route_id: str, body: ModelRouteAccountLoginRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.request_model_route_account_login(
                route_id=route_id,
                expected_revision_digest=body.expected_revision_digest,
                node_id=body.node_id,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post("/v1/model-routes/{route_id}/retirements", status_code=201)
    def retire_model_route(
        route_id: str, body: ModelRouteRetirementRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.retire_model_route(
                route_id=route_id,
                expected_revision_digest=body.expected_revision_digest,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.get("/v1/model-routes/{route_id}/evidence")
    def model_route_evidence(route_id: str, request: Request) -> dict[str, Any]:
        read_admin(request)
        return _call(lambda: service.model_route_evidence(route_id=route_id))

    @app.get("/v1/task-scope-audits")
    def task_scope_audits(request: Request) -> dict[str, Any]:
        read_admin(request)
        return _call(service.list_task_scope_audits)

    @app.get(
        "/v1/task-scope-audits/{task_id}/revisions/{revision}"
    )
    def task_scope_audit_detail(
        task_id: str, revision: int, request: Request
    ) -> dict[str, Any]:
        read_admin(request)
        return _call(
            lambda: service.task_scope_audit_detail(
                task_id=task_id, revision=revision
            )
        )

    @app.post("/v1/task-scope-audits/{task_id}/reconcile")
    def reconcile_task_scope(
        task_id: str, body: TaskScopeReconcileRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.reconcile_task_scope(
                task_id=task_id,
                expected_revision=body.expected_revision,
                expected_task_digest=body.expected_task_digest,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )


def _selected_admin_role(principal: dict[str, Any]) -> str:
    if "role_control_plane_admin" not in principal.get("role_refs", []):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "human_role_not_allowed")
    return "role_control_plane_admin"


def _call(operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return operation()
    except (ControlConsoleError, ModelCatalogError, ModelRouteError) as error:
        reason = error.reason_code
        if reason.endswith("_not_found"):
            code = status.HTTP_404_NOT_FOUND
        elif any(
            marker in reason
            for marker in (
                "drift",
                "conflict",
                "already_",
                "preflight_blocked",
                "mismatch",
            )
        ):
            code = status.HTTP_409_CONFLICT
        else:
            code = status.HTTP_422_UNPROCESSABLE_CONTENT
        raise HTTPException(code, reason) from error

