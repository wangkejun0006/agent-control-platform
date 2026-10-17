"""HTTP surface for loopback-only Department Cockpit accounts."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from .cockpit_local_identity import (
    ALLOWED_APPROVAL_ROLES,
    CockpitLocalIdentityError,
    CockpitLocalIdentityService,
)

SESSION_COOKIE = "orbit_d0_session"
REQUEST_MARKER_HEADER = "x-orbit-request"
REQUEST_MARKER_VALUE = "department-cockpit"


class RegisterLocalAccountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=12, max_length=128)
    display_name: str = Field(min_length=2, max_length=40)
    department_id: str | None = Field(default=None, max_length=96)


class LoginLocalAccountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=12, max_length=128)


class ApproveLocalAccountRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_ref: str = Field(max_length=96)


class ChangeLocalPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=12, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


MutatingRequestGuard = Callable[[Request], None]


def install_cockpit_local_identity_routes(
    app: FastAPI,
    *,
    service: CockpitLocalIdentityService,
    require_mutating_request: MutatingRequestGuard,
) -> None:
    @app.get("/v1/auth/status")
    def auth_status() -> dict[str, Any]:
        return service.public_status()

    @app.post("/v1/auth/register", status_code=201)
    def register(
        body: RegisterLocalAccountRequest, request: Request
    ) -> dict[str, Any]:
        require_mutating_request(request)
        return _call(
            lambda: service.register(
                username=body.username,
                password=body.password,
                display_name=body.display_name,
                department_id=body.department_id,
            )
        )

    @app.post("/v1/auth/login")
    def login(
        body: LoginLocalAccountRequest,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        require_mutating_request(request)
        token, principal = _call(
            lambda: service.login(username=body.username, password=body.password)
        )
        response.set_cookie(
            key=SESSION_COOKIE,
            value=token,
            max_age=int(service.session_ttl.total_seconds()),
            httponly=True,
            secure=False,
            samesite="strict",
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return {"user": principal}

    @app.get("/v1/auth/me")
    def me(request: Request) -> dict[str, Any]:
        return {"user": _authenticate(service, request)}

    @app.post("/v1/auth/logout", status_code=204)
    def logout(request: Request, response: Response) -> Response:
        require_mutating_request(request)
        service.logout(request.cookies.get(SESSION_COOKIE))
        response.delete_cookie(
            key=SESSION_COOKIE,
            httponly=True,
            secure=False,
            samesite="strict",
            path="/",
        )
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    @app.get("/v1/auth/pending-accounts")
    def pending_accounts(
        request: Request, department_id: str | None = None
    ) -> dict[str, Any]:
        principal = _authenticate(service, request)
        return {
            "accounts": _call(
                lambda: service.pending_accounts(
                    requester=principal, department_id=department_id
                )
            )
        }

    @app.post("/v1/auth/accounts/{account_id}/approve")
    def approve_account(
        account_id: str,
        body: ApproveLocalAccountRequest,
        request: Request,
    ) -> dict[str, Any]:
        require_mutating_request(request)
        principal = _authenticate(service, request)
        if body.role_ref not in ALLOWED_APPROVAL_ROLES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "local_account_approval_invalid",
            )
        return {
            "account": _call(
                lambda: service.approve_account(
                    requester=principal,
                    account_id=account_id,
                    role_ref=body.role_ref,
                )
            )
        }

    @app.post("/v1/auth/change-password", status_code=204)
    def change_password(
        body: ChangeLocalPasswordRequest,
        request: Request,
        response: Response,
    ) -> Response:
        require_mutating_request(request)
        principal = _authenticate(service, request)
        _call(
            lambda: service.change_password(
                requester=principal,
                current_password=body.current_password,
                new_password=body.new_password,
            )
        )
        response.status_code = status.HTTP_204_NO_CONTENT
        return response


def authenticate_cockpit_local_human(
    service: CockpitLocalIdentityService,
    request: Request,
    *,
    required_roles: frozenset[str],
) -> dict[str, Any]:
    principal = _authenticate(service, request)
    if not required_roles.intersection(principal["role_refs"]):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "local_human_role_not_allowed"
        )
    return principal


def _authenticate(
    service: CockpitLocalIdentityService, request: Request
) -> dict[str, Any]:
    try:
        return service.authenticate(request.cookies.get(SESSION_COOKIE))
    except CockpitLocalIdentityError as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, error.reason_code) from error


def _call(callback):
    try:
        return callback()
    except CockpitLocalIdentityError as error:
        reason = error.reason_code
        if reason.endswith("_not_found"):
            code = status.HTTP_404_NOT_FOUND
        elif reason in {
            "department_scope_not_allowed",
            "local_account_approval_not_allowed",
            "local_account_role_assignment_not_allowed",
        }:
            code = status.HTTP_403_FORBIDDEN
        elif reason in {
            "local_account_username_unavailable",
            "local_account_not_pending",
        }:
            code = status.HTTP_409_CONFLICT
        elif reason == "local_login_invalid":
            code = status.HTTP_401_UNAUTHORIZED
        else:
            code = status.HTTP_422_UNPROCESSABLE_ENTITY
        raise HTTPException(code, reason) from error

