"""HTTP projection for the department cockpit BFF surface."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from .controlled_artifacts import ControlledArtifactError
from .department_cockpit import DepartmentCockpitError, DepartmentCockpitService

HumanGuard = Callable[..., dict[str, Any]]


class CreatePlanningSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=4000)
    artifact_refs: list[str] = Field(default_factory=list, max_length=8)
    context_tags: list[str] = Field(default_factory=list, max_length=5)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,192}$")


class ContinuePlanningSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    question_request_id: str = Field(
        pattern=r"^clarification_[A-Za-z0-9_:-]{3,150}$"
    )
    question_revision: int = Field(ge=1, le=1000)
    answers: dict[str, str] = Field(min_length=1, max_length=3)
    supplement: str | None = Field(default=None, max_length=4000)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,192}$")


class PlanningSessionCommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,192}$")


class ConfirmTaskPackageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_revision: int = Field(ge=1, le=1000)
    task_scope_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    package_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class TaskApprovalDecisionRequest(ConfirmTaskPackageRequest):
    package_id: str = Field(pattern=r"^[a-z][A-Za-z0-9_:-]{2,159}$")
    decision: str = Field(pattern=r"^(approved|rejected)$")
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,192}$")


class SelectDepartmentModelRouteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    route_alias: str = Field(
        pattern=r"^company-route/[a-z0-9][a-z0-9/_-]{3,150}$"
    )


class SelectAgentModelRouteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_binding_ref: str = Field(
        pattern=r"^(binding_(product|technology|market)_center_(planning|professional)_d0|agent_binding_candidate_[0-9a-f]{20})$"
    )
    route_id: str = Field(
        pattern=r"^(company-route/[a-z0-9][a-z0-9/_-]{3,150}|model_route_[0-9a-f]{20})$"
    )
    route_revision_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_selection_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,192}$")


class SelectDepartmentRuntimeArtifactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(pattern=r"^[a-z][a-z0-9_:-]{2,127}$")
    artifact_revision: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    runtime_image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expected_current_image_digest: str = Field(
        pattern=r"^(none|sha256:[0-9a-f]{64})$"
    )
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,192}$")


class AgentModelRequirementsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capabilities: list[str] = Field(min_length=1, max_length=8)
    data_classifications: list[str] = Field(min_length=1, max_length=2)


class DepartmentAgentProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_name: str = Field(min_length=2, max_length=120)
    identity: str = Field(min_length=2, max_length=500)
    task_scope: str = Field(min_length=2, max_length=500)
    typical_inputs: list[str] = Field(min_length=1, max_length=12)
    expected_outputs: list[str] = Field(min_length=1, max_length=12)
    prohibited_actions: list[str] = Field(min_length=1, max_length=12)
    model_requirements: AgentModelRequirementsRequest
    selected_catalog_entry_id: str = Field(
        pattern=r"^model_catalog_entry_[a-f0-9]{20}$"
    )
    selected_catalog_entry_revision_digest: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$"
    )
    agent_kind: str = Field(pattern=r"^(department_planning|professional)$")
    runtime_kind: str = Field(pattern=r"^(langgraph|hermes|codex)$")
    supersedes_package_digest: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9._:-]{8,192}$")


_READ_ROLES = frozenset(
    {"role_department_user", "role_department_owner", "role_control_plane_admin"}
)
_WRITE_ROLES = frozenset({"role_department_user", "role_department_owner"})
_CONFIRM_ROLES = frozenset({"role_department_owner"})
_MODEL_SELECTION_ROLES = _CONFIRM_ROLES


def install_department_cockpit_routes(
    app: FastAPI,
    *,
    service: DepartmentCockpitService,
    authenticate_human: HumanGuard,
    require_mutating_human: HumanGuard,
) -> None:
    def read_principal(request: Request, department_id: str) -> dict[str, Any]:
        principal = authenticate_human(request, required_roles=_READ_ROLES)
        _require_department_scope(principal, department_id)
        return principal

    def write_principal(
        request: Request, department_id: str, *, roles: frozenset[str] = _WRITE_ROLES
    ) -> dict[str, Any]:
        principal = require_mutating_human(request, required_roles=roles)
        _require_department_scope(principal, department_id)
        return principal

    @app.get("/v1/department-cockpit/{department_id}/bootstrap")
    def bootstrap(department_id: str, request: Request) -> dict[str, Any]:
        read_principal(request, department_id)
        return _call(lambda: service.bootstrap(department_id=department_id))

    @app.get("/v1/department-cockpit/{department_id}/model-resources")
    def model_resources(
        department_id: str, request: Request, window: str = "month_to_date"
    ) -> dict[str, Any]:
        read_principal(request, department_id)
        return _call(
            lambda: service.model_resources(
                department_id=department_id, window=window
            )
        )

    @app.get(
        "/v1/department-cockpit/{department_id}/agent-proposal-model-catalog"
    )
    def agent_proposal_model_catalog(
        department_id: str,
        request: Request,
        agent_kind: str = "professional",
        runtime_kind: str | None = None,
        capabilities: str = "text,structured_output",
        data_classifications: str = "synthetic,public",
    ) -> dict[str, Any]:
        read_principal(request, department_id)
        requirements = {
            "capabilities": [item for item in capabilities.split(",") if item],
            "data_classifications": [
                item for item in data_classifications.split(",") if item
            ],
        }
        return _call(
            lambda: service.agent_proposal_model_catalog(
                department_id=department_id,
                model_requirements=requirements, agent_kind=agent_kind, runtime_kind=runtime_kind,
            )
        )

    @app.get("/v1/department-cockpit/{department_id}/agent-proposals")
    def agent_proposal_history(department_id: str, request: Request):
        read_principal(request, department_id)
        return _call(lambda: service.agent_proposal_history(department_id=department_id))

    @app.get("/v1/department-cockpit/{department_id}/agent-proposals/{package_digest}/exchange")
    def agent_proposal_exchange(department_id: str, package_digest: str, request: Request):
        read_principal(request, department_id)
        return _call(lambda: service.export_agent_proposal(department_id=department_id, package_digest=package_digest))

    @app.post(
        "/v1/department-cockpit/{department_id}/agent-proposals",
        status_code=201,
    )
    def submit_agent_proposal(
        department_id: str,
        body: DepartmentAgentProposalRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_principal(
            request, department_id, roles=_CONFIRM_ROLES
        )
        return _call(
            lambda: service.submit_agent_proposal(
                department_id=department_id,
                agent_name=body.agent_name,
                identity=body.identity,
                task_scope=body.task_scope,
                typical_inputs=body.typical_inputs,
                expected_outputs=body.expected_outputs,
                prohibited_actions=body.prohibited_actions,
                model_requirements=body.model_requirements.model_dump(),
                selected_catalog_entry_id=body.selected_catalog_entry_id,
                selected_catalog_entry_revision_digest=(
                    body.selected_catalog_entry_revision_digest
                ),
                agent_kind=body.agent_kind,
                runtime_kind=body.runtime_kind,
                supersedes_package_digest=body.supersedes_package_digest,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
                proposer_account_ref=("account://local-stage1/" + principal["account_id"]) if principal.get("account_id") else None,
                department_owner_ref=("account://local-stage1/" + principal["account_id"]) if principal.get("account_id") else None,
            )
        )

    @app.get("/v1/department-cockpit/{department_id}/tasks/{task_id}")
    def task_detail(
        department_id: str, task_id: str, request: Request
    ) -> dict[str, Any]:
        read_principal(request, department_id)
        return _call(
            lambda: service.task_detail(department_id=department_id, task_id=task_id)
        )

    @app.post("/v1/department-cockpit/{department_id}/artifacts", status_code=201)
    async def upload_artifact(
        department_id: str, request: Request
    ) -> dict[str, Any]:
        principal = write_principal(request, department_id)
        declared_size = request.headers.get("content-length")
        if declared_size is not None:
            try:
                size = int(declared_size)
            except ValueError as error:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "artifact_size_invalid",
                ) from error
            if size <= 0 or size > 5 * 1024 * 1024:
                raise HTTPException(
                    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    "artifact_size_invalid",
                )
        content = await request.body()
        try:
            return service.artifact_store.upload(
                department_id=department_id,
                filename=unquote(request.headers.get("x-artifact-filename", "")),
                media_type=request.headers.get(
                    "content-type", "application/octet-stream"
                ),
                content=content,
                data_classification=request.headers.get(
                    "x-data-classification", "internal_standard"
                ),
                actor_ref=principal["human_ref"],
            )
        except ControlledArtifactError as error:
            code = (
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
                if error.reason_code == "artifact_size_invalid"
                else status.HTTP_422_UNPROCESSABLE_ENTITY
            )
            raise HTTPException(code, error.reason_code) from error

    @app.get("/v1/department-cockpit/{department_id}/artifacts/metadata")
    def artifact_metadata(
        department_id: str, artifact_ref: str, request: Request
    ) -> dict[str, Any]:
        read_principal(request, department_id)
        try:
            return service.artifact_store.metadata(
                department_id=department_id,
                artifact_ref=artifact_ref,
            )
        except ControlledArtifactError as error:
            code = (
                status.HTTP_404_NOT_FOUND
                if error.reason_code.endswith("_not_found")
                else status.HTTP_409_CONFLICT
                if error.reason_code.endswith("_mismatch")
                else status.HTTP_422_UNPROCESSABLE_ENTITY
            )
            raise HTTPException(code, error.reason_code) from error

    @app.post("/v1/department-cockpit/{department_id}/sessions", status_code=202)
    def create_session(
        department_id: str,
        body: CreatePlanningSessionRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_principal(request, department_id)
        return _call(
            lambda: service.create_session(
                department_id=department_id,
                actor_ref=principal["human_ref"],
                actor_name=principal.get("display_name"),
                message=body.message,
                artifact_refs=body.artifact_refs,
                context_tags=body.context_tags,
                idempotency_key=body.idempotency_key,
            )
        )

    @app.get("/v1/department-cockpit/{department_id}/sessions/{session_id}")
    def planning_session(
        department_id: str, session_id: str, request: Request
    ) -> dict[str, Any]:
        read_principal(request, department_id)
        return _call(
            lambda: service.planning_session(
                department_id=department_id, session_id=session_id
            )
        )

    @app.post("/v1/department-cockpit/{department_id}/model-route-selection")
    def select_model_route(
        department_id: str,
        body: SelectDepartmentModelRouteRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_principal(
            request, department_id, roles=_MODEL_SELECTION_ROLES
        )
        return _call(
            lambda: service.select_model_route(
                department_id=department_id,
                route_alias=body.route_alias,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post(
        "/v1/department-cockpit/{department_id}/agent-model-route-selections"
    )
    def select_agent_model_route(
        department_id: str,
        body: SelectAgentModelRouteRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_principal(
            request, department_id, roles=_MODEL_SELECTION_ROLES
        )
        return _call(
            lambda: service.select_agent_model_route(
                department_id=department_id,
                agent_binding_ref=body.agent_binding_ref,
                route_id=body.route_id,
                route_revision_digest=body.route_revision_digest,
                expected_selection_digest=body.expected_selection_digest,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post(
        "/v1/department-cockpit/{department_id}/runtime-artifact-selection"
    )
    def select_runtime_artifact(
        department_id: str,
        body: SelectDepartmentRuntimeArtifactRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_principal(
            request, department_id, roles=_MODEL_SELECTION_ROLES
        )
        return _call(
            lambda: service.select_runtime_artifact(
                department_id=department_id,
                artifact_id=body.artifact_id,
                artifact_revision=body.artifact_revision,
                runtime_image_digest=body.runtime_image_digest,
                expected_current_image_digest=body.expected_current_image_digest,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post("/v1/department-cockpit/{department_id}/sessions/{session_id}/turns")
    def continue_session(
        department_id: str,
        session_id: str,
        body: ContinuePlanningSessionRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_principal(request, department_id)
        return _call(
            lambda: service.continue_session(
                department_id=department_id,
                session_id=session_id,
                actor_ref=principal["human_ref"],
                question_request_id=body.question_request_id,
                question_revision=body.question_revision,
                answers=body.answers,
                supplement=body.supplement,
                idempotency_key=body.idempotency_key,
            )
        )

    @app.post(
        "/v1/department-cockpit/{department_id}/sessions/{session_id}/retry",
        status_code=202,
    )
    def retry_session(
        department_id: str,
        session_id: str,
        body: PlanningSessionCommandRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_principal(request, department_id)
        return _call(
            lambda: service.retry_session(
                department_id=department_id,
                session_id=session_id,
                actor_ref=principal["human_ref"],
                idempotency_key=body.idempotency_key,
            )
        )

    @app.post(
        "/v1/department-cockpit/{department_id}/sessions/{session_id}/successors",
        status_code=202,
    )
    def create_successor_session(
        department_id: str,
        session_id: str,
        body: PlanningSessionCommandRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_principal(request, department_id)
        return _call(
            lambda: service.create_successor_session(
                department_id=department_id,
                session_id=session_id,
                actor_ref=principal["human_ref"],
                idempotency_key=body.idempotency_key,
            )
        )

    @app.get("/v1/department-cockpit/{department_id}/sessions/{session_id}/events")
    def session_events(
        department_id: str,
        session_id: str,
        request: Request,
        after_sequence: int = -1,
    ) -> dict[str, Any]:
        read_principal(request, department_id)
        return _call(
            lambda: service.events(
                department_id=department_id,
                session_id=session_id,
                after_sequence=after_sequence,
            )
        )

    @app.get(
        "/v1/department-cockpit/{department_id}/sessions/{session_id}/events/stream"
    )
    def session_event_stream(
        department_id: str,
        session_id: str,
        request: Request,
        after_sequence: int = -1,
        follow: bool = True,
    ) -> StreamingResponse:
        read_principal(request, department_id)
        cursor = _event_cursor(request=request, after_sequence=after_sequence)

        async def stream():
            last_sequence = cursor
            while True:
                value = _call(
                    lambda sequence=last_sequence: service.events(
                        department_id=department_id,
                        session_id=session_id,
                        after_sequence=sequence,
                    )
                )
                for event in value["events"]:
                    sequence = event["sequence"]
                    last_sequence = max(last_sequence, sequence)
                    payload = json.dumps(
                        event,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    yield f"id: {sequence}\nevent: runtime_event\ndata: {payload}\n\n"
                checkpoint = json.dumps(
                    {
                        "session_id": value["session_id"],
                        "run_id": value["run_id"],
                        "last_sequence": last_sequence,
                        "resource_revision": value["resource_revision"],
                        "terminal": value["terminal"],
                        "runtime_projection_authoritative": False,
                        "release_authorization": False,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                yield f"event: checkpoint\ndata: {checkpoint}\n\n"
                if value["terminal"] or not follow or await request.is_disconnected():
                    break
                yield ": keep-alive\n\n"
                await asyncio.sleep(1)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-store",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/v1/department-cockpit/{department_id}/sessions/{session_id}/stop")
    def stop_session(
        department_id: str, session_id: str, request: Request
    ) -> dict[str, Any]:
        principal = write_principal(request, department_id)
        return _call(
            lambda: service.stop_session(
                department_id=department_id,
                session_id=session_id,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post(
        "/v1/department-cockpit/{department_id}/task-packages/{package_id}/confirm"
    )
    def confirm_package(
        department_id: str,
        package_id: str,
        body: ConfirmTaskPackageRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_principal(request, department_id, roles=_CONFIRM_ROLES)
        return _call(
            lambda: service.confirm_package(
                department_id=department_id,
                package_id=package_id,
                task_revision=body.task_revision,
                task_scope_digest=body.task_scope_digest,
                package_digest=body.package_digest,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post(
        "/v1/department-cockpit/{department_id}/tasks/{task_id}/approval-decisions",
        status_code=201,
    )
    def decide_task(
        department_id: str,
        task_id: str,
        body: TaskApprovalDecisionRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_principal(request, department_id, roles=_CONFIRM_ROLES)
        return _call(
            lambda: service.decide_task(
                department_id=department_id,
                task_id=task_id,
                package_id=body.package_id,
                task_revision=body.task_revision,
                task_scope_digest=body.task_scope_digest,
                package_digest=body.package_digest,
                decision=body.decision,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
                actor_role_ref="role_department_owner",
            )
        )

    @app.post(
        "/v1/department-cockpit/{department_id}/tasks/{task_id}/synthetic-acceptance"
    )
    def run_synthetic_acceptance(
        department_id: str, task_id: str, request: Request
    ) -> dict[str, Any]:
        principal = write_principal(request, department_id, roles=_CONFIRM_ROLES)
        return _call(
            lambda: service.run_synthetic_acceptance(
                department_id=department_id,
                task_id=task_id,
                actor_ref=principal["human_ref"],
            )
        )


def _require_department_scope(principal: dict[str, Any], department_id: str) -> None:
    roles = set(principal.get("role_refs", []))
    if "role_control_plane_admin" in roles:
        # LAN sessions carry an explicit access mode.  A company administrator
        # may read exactly one department only while the short-lived,
        # password-gated observation context is active.  Other entrypoints do
        # not yet expose that session primitive and retain their existing D0
        # verifier behavior.
        if "access_mode" not in principal:
            return
        if (
            principal.get("access_mode") == "company_observer"
            and principal.get("active_observation_department_ref") == department_id
        ):
            return
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "department_observation_context_required",
        )
    departments = principal.get("department_refs")
    if not isinstance(departments, list) or department_id not in departments:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "department_scope_not_allowed")


def _event_cursor(*, request: Request, after_sequence: int) -> int:
    header = request.headers.get("last-event-id")
    if header is None:
        return after_sequence
    try:
        value = int(header)
    except ValueError as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "runtime_event_cursor_invalid",
        ) from error
    return max(after_sequence, value)


def _call(callback: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return callback()
    except DepartmentCockpitError as error:
        reason = error.reason_code
        if reason.endswith("_not_found"):
            code = status.HTTP_404_NOT_FOUND
        elif reason in {
            "department_scope_mismatch",
            "planning_session_actor_mismatch",
            "task_package_revision_drift",
            "task_package_task_binding_drift",
            "task_approval_idempotency_conflict",
            "task_approval_already_decided",
            "runtime_artifact_selection_drift",
            "runtime_artifact_selection_idempotency_conflict",
            "agent_model_route_selection_drift",
            "agent_model_route_selection_idempotency_conflict",
            "agent_registry_activation_missing",
        }:
            code = status.HTTP_409_CONFLICT
        elif reason in {
            "hermes_transport_not_configured",
            "hermes_gateway_unavailable",
            "hermes_secret_unavailable",
        }:
            code = status.HTTP_503_SERVICE_UNAVAILABLE
        else:
            code = status.HTTP_422_UNPROCESSABLE_ENTITY
        raise HTTPException(code, reason) from error

