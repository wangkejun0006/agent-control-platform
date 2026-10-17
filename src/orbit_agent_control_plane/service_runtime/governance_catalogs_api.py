"""HTTP surface for governed semantic, Tool, and System projections."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from .governance_catalogs import GovernanceCatalogError, GovernanceCatalogService

HumanGuard = Callable[..., dict[str, Any]]


class ToolSemanticScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(pattern=r"^[a-z][a-z0-9_]{1,95}$")
    resource_kind: str = Field(pattern=r"^[a-z][a-z0-9_]{1,95}$")
    action: str = Field(pattern=r"^[a-z][a-z0-9_]{1,95}$")
    side_effect_class: str = Field(pattern=r"^(none|reversible|irreversible)$")


class ToolScopeRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: str = Field(pattern=r"^(canonical|alias|supersedes)$")
    target_scope_id: str | None = Field(
        default=None, pattern=r"^toolscope_[A-Za-z0-9_:-]{3,150}$"
    )


class RegisterToolSemanticScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope_id: str = Field(pattern=r"^toolscope_[A-Za-z0-9_:-]{3,150}$")
    tool_id: str = Field(pattern=r"^tool_[A-Za-z0-9_:-]{3,150}$")
    tool_version: str = Field(pattern=r"^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$")
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    operation_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,159}$")
    capability: str = Field(pattern=r"^[a-z][a-z0-9_.]{2,159}$")
    semantic_scope: ToolSemanticScope
    canonical_scope_key: str = Field(
        pattern=r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*:[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$",
        max_length=384,
    )
    relationship: ToolScopeRelationship
    status: str = Field(pattern=r"^registered$")
    evidence_status: str = Field(pattern=r"^[a-z][a-z0-9_]{2,47}$")
    owner_ref: str = Field(pattern=r"^role_[A-Za-z0-9_:-]{3,150}$")
    source_release_id: str = Field(
        pattern=r"^semantic-authority-v[0-9A-Za-z._-]{3,140}$"
    )
    registration_only: bool
    activation_authorization: bool
    production_authorized: bool


_READ_ROLES = frozenset(
    {"role_department_user", "role_department_owner", "role_control_plane_admin"}
)
_REGISTER_ROLES = frozenset(
    {"role_control_plane_admin", "role_orbit_platform_owner"}
)


def install_governance_catalog_routes(
    app: FastAPI,
    *,
    service: GovernanceCatalogService,
    authenticate_human: HumanGuard,
    require_mutating_human: HumanGuard,
) -> None:
    @app.get("/v1/semantic-terms")
    def semantic_terms(request: Request) -> dict[str, Any]:
        authenticate_human(request, required_roles=_READ_ROLES)
        return _call(service.terms)

    @app.get("/v1/semantic-terms/{term_id:path}")
    def semantic_term(term_id: str, request: Request) -> dict[str, Any]:
        authenticate_human(request, required_roles=_READ_ROLES)
        return _call(lambda: service.term(term_id))

    @app.get("/v1/tools")
    def tools(request: Request) -> dict[str, Any]:
        authenticate_human(request, required_roles=_READ_ROLES)
        return _call(service.tools)

    @app.get("/v1/tools/{tool_id}/versions/{tool_version}")
    def tool(tool_id: str, tool_version: str, request: Request) -> dict[str, Any]:
        authenticate_human(request, required_roles=_READ_ROLES)
        return _call(lambda: service.tool(tool_id=tool_id, tool_version=tool_version))

    @app.post("/v1/tool-registrations", status_code=201)
    def register_tool(
        body: RegisterToolSemanticScopeRequest, request: Request
    ) -> dict[str, Any]:
        principal = require_mutating_human(
            request, required_roles=_REGISTER_ROLES
        )
        return _call(
            lambda: service.register_tool_scope(
                candidate=body.model_dump(), actor_ref=principal["human_ref"]
            )
        )

    @app.get("/v1/systems")
    def systems(
        request: Request, department_id: str | None = None
    ) -> dict[str, Any]:
        principal = authenticate_human(request, required_roles=_READ_ROLES)
        _require_system_department_scope(principal, department_id)
        return _call(lambda: service.systems(department_id=department_id))

    @app.get("/v1/systems/{system_id}")
    def system(system_id: str, request: Request) -> dict[str, Any]:
        principal = authenticate_human(request, required_roles=_READ_ROLES)
        value = _call(lambda: service.system(system_id))
        _require_system_department_scope(
            principal, value["system"]["department_ref"]
        )
        return value


def _call(callback: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return callback()
    except GovernanceCatalogError as error:
        if error.reason_code.endswith("_not_found"):
            code = status.HTTP_404_NOT_FOUND
        elif error.reason_code.endswith("_conflict") or error.reason_code.endswith(
            "_collision"
        ):
            code = status.HTTP_409_CONFLICT
        else:
            code = status.HTTP_422_UNPROCESSABLE_ENTITY
        raise HTTPException(code, error.reason_code) from error


def _require_system_department_scope(
    principal: dict[str, Any], department_id: str | None
) -> None:
    roles = set(principal.get("role_refs", []))
    if "role_control_plane_admin" in roles:
        return
    departments = principal.get("department_refs")
    if (
        department_id is None
        or not isinstance(departments, list)
        or department_id not in departments
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "department_scope_not_allowed"
        )

