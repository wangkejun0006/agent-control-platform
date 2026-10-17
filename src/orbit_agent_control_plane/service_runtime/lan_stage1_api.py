"""Independent human and workload HTTP surfaces for the LAN candidate."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Mapping, Sequence
from datetime import timedelta, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import Response as RawResponse
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from .cockpit_local_identity import (
    ROLE_CONTROL_PLANE_ADMIN,
    ROLE_DEPARTMENT_OWNER,
)
from .codex_installation import CodexInstallationError, CodexInstallationService
from .control_console import ControlConsoleService
from .control_console_api import install_control_console_routes
from .department_cockpit import DepartmentCockpitService
from .department_cockpit_api import install_department_cockpit_routes
from .governance_catalogs import GovernanceCatalogError, GovernanceCatalogService
from .lan_stage1 import (
    LanHumanIdentityService,
    LanNodeService,
    LanStage1Error,
    LanWorkloadIdentityService,
)
from .lan_stage1_models import (
    LanArtifactDownloadAssignmentRow,
    LanArtifactDownloadReceiptRow,
    LanCertificateBindingRow,
    LanEnrollmentCodeRow,
    LanHumanAccountRow,
    LanInviteRow,
    LanNodeHeartbeatRow,
)
from .model_route_credentials import ModelRouteCredentialService
from .models import AuditEventRow
from .runtime_artifact_api import (
    RuntimeArtifactCandidateRequest,
    RuntimeArtifactQualificationRequest,
    RuntimeArtifactRevocationRequest,
)
from .runtime_artifact_models import (
    RuntimeArtifactImportReceiptRow,
    RuntimeArtifactRevisionRow,
    RuntimeArtifactRevocationRow,
    RuntimeNodeCapabilityReportRow,
)
from .runtime_artifacts import RuntimeArtifactError

SESSION_COOKIE = "__Host-orbit_session"
CSRF_HEADER = "x-orbit-csrf-token"
CERT_DER_HEADER = "x-orbit-client-cert-der"
CERT_FINGERPRINT_HEADER = "x-orbit-client-cert-fingerprint"
_IDEMPOTENCY = r"^[A-Za-z0-9._:-]{8,192}$"
_DIGEST = r"^sha256:[0-9a-f]{64}$"


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=12, max_length=128)


class RegisterRequest(LoginRequest):
    invite_code: str = Field(min_length=20, max_length=128)
    display_name: str = Field(min_length=2, max_length=40)


class ReauthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=12, max_length=128)


class DepartmentObservationContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    department_id: str = Field(pattern=r"^(product|technology|market)_center$")


class InviteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    department_id: str = Field(max_length=96)
    role_ref: str = Field(max_length=96)


class EnrollmentCodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    department_id: str = Field(max_length=96)
    node_id: str = Field(max_length=160)


class RevokeCertificateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprint: str = Field(pattern=_DIGEST)
    reason: str = Field(min_length=8, max_length=500)


class ArtifactDownloadAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    department_id: str = Field(max_length=96)
    artifact_id: str = Field(max_length=160)
    revision_digest: str = Field(pattern=_DIGEST)
    bundle_digest: str = Field(pattern=_DIGEST)


class DeploymentReleaseLockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict[str, Any]


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enrollment_id: str = Field(min_length=16, max_length=128)
    enrollment_code: str = Field(min_length=20, max_length=128)
    csr_pem_base64: str = Field(min_length=32, max_length=128 * 1024)


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capability_report_digest: str = Field(pattern=_DIGEST)
    status: str = Field(pattern=r"^(ready|busy|degraded|offline_spooling)$")
    document: dict[str, Any]


class LeaseClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_capability_report_digest: str = Field(pattern=_DIGEST)


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=12, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class CertificateRenewalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    csr_pem_base64: str = Field(min_length=32, max_length=128 * 1024)


class NodeDocumentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict[str, Any]


class AdapterCapabilityReportRequest(NodeDocumentRequest):
    authentication_modes: list[str] = Field(min_length=1, max_length=4)
    expires_at: str


class AssistedMaintenanceSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requested_handler_ids: list[str] = Field(min_length=1, max_length=16)
    duration_seconds: int = Field(ge=60, le=1800)
    local_user_initiated: bool


class MaintenanceReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict[str, Any]


def create_human_app(
    *,
    identity: LanHumanIdentityService,
    workloads: LanWorkloadIdentityService,
    nodes: LanNodeService,
    allowed_origins: Sequence[str],
    cockpit: DepartmentCockpitService | None = None,
    governance_catalogs: GovernanceCatalogService | None = None,
    control_console: ControlConsoleService | None = None,
    codex_installation: CodexInstallationService | None = None,
    model_route_authoring_context: dict[str, Any] | None = None,
) -> FastAPI:
    origins = frozenset(allowed_origins)
    if not origins or any(not item.startswith("https://") for item in origins):
        raise LanStage1Error("lan_origin_allowlist_invalid")
    app = FastAPI(
        title="Orbit LAN Human UDS", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.transport = "unix_domain_socket_only"
    app.state.production_authorization = False

    def origin(request: Request) -> None:
        if request.headers.get("origin") not in origins:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "lan_origin_not_allowed")

    def principal(
        request: Request,
        *,
        roles: frozenset[str] | None = None,
        unsafe: bool = False,
        reauth: bool = False,
    ) -> dict[str, Any]:
        if unsafe:
            origin(request)
        value = _call(
            lambda: identity.authenticate(
                request.cookies.get(SESSION_COOKIE),
                csrf_token=request.headers.get(CSRF_HEADER),
                unsafe=unsafe,
                require_recent_reauth=reauth,
            )
        )
        if roles is not None and not roles.intersection(value["role_refs"]):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "lan_role_not_allowed")
        return value

    if (cockpit is None) != (governance_catalogs is None):
        raise LanStage1Error("lan_cockpit_dependencies_incomplete")

    if control_console is not None:
        def control_read(
            request: Request, *, required_roles: frozenset[str]
        ) -> dict[str, Any]:
            return principal(request, roles=required_roles)

        def control_write(
            request: Request, *, required_roles: frozenset[str]
        ) -> dict[str, Any]:
            return principal(
                request,
                roles=required_roles,
                unsafe=True,
                reauth=True,
            )

        install_control_console_routes(
            app,
            service=control_console,
            authenticate_human=control_read,
            require_mutating_human=control_write,
        )

        @app.get("/v1/control/model-route-authoring-context")
        def control_model_route_authoring_context(
            request: Request,
        ) -> dict[str, Any]:
            principal(request, roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}))
            if model_route_authoring_context is None:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "model_route_authoring_context_unavailable",
                )
            return dict(model_route_authoring_context)

    @app.get("/health/live")
    def live() -> dict[str, Any]:
        return {
            "status": "live",
            "entrypoint": "lan_human_uds",
            "synthetic_only": True,
            "production_authorization": False,
            "release_authorization": False,
        }

    @app.get("/v1/auth/status")
    def auth_status() -> dict[str, Any]:
        return identity.public_status()

    @app.get("/v1/control/bootstrap")
    def control_bootstrap(request: Request, response: Response) -> dict[str, Any]:
        user = principal(request, roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}))
        response.headers[CSRF_HEADER] = str(user.pop("csrf_token"))
        response.headers["Cache-Control"] = "no-store"
        value = _control_bootstrap_projection(identity=identity, nodes=nodes, user=user)
        if cockpit is not None:
            value["department_model_resources"] = [
                {
                    "department_id": department_id,
                    "agents": [
                        {
                            "agent_ref": agent["agent_ref"],
                            "agent_binding_ref": agent["agent_binding_ref"],
                            "display_name": agent["display_name"],
                            "kind": agent["kind"],
                            "model_requirements": agent["model_requirements"],
                            "current_route": agent["current_route"],
                            "available_routes": agent["available_routes"],
                        }
                        for agent in cockpit.model_resources(
                            department_id=department_id
                        )["agents"]
                    ],
                }
                for department_id in (
                    "product_center",
                    "technology_center",
                    "market_center",
                )
            ]
        else:
            value["department_model_resources"] = []
        value["department_readiness"] = _department_readiness_matrix(value)
        if codex_installation is not None:
            _apply_codex_installation_readiness(
                value["department_readiness"], codex_installation
            )
        return value

    @app.post("/v1/auth/register", status_code=201)
    def register(
        body: RegisterRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        origin(request)
        return {
            "user": _call(
                lambda: identity.register(
                    invite_code=body.invite_code,
                    username=body.username,
                    password=body.password,
                    display_name=body.display_name,
                    idempotency_key=idempotency_key,
                )
            )
        }

    @app.post("/v1/auth/login")
    def login(
        body: LoginRequest,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        origin(request)
        token, csrf, user = _call(
            lambda: identity.login(
                username=body.username,
                password=body.password,
                idempotency_key=idempotency_key,
            )
        )
        response.set_cookie(
            key=SESSION_COOKIE,
            value=token,
            max_age=8 * 60 * 60,
            secure=True,
            httponly=True,
            samesite="strict",
            path="/",
        )
        response.headers[CSRF_HEADER] = csrf
        response.headers["Cache-Control"] = "no-store"
        return {"user": user, "csrf_header": CSRF_HEADER}

    @app.get("/v1/auth/me")
    def me(request: Request, response: Response) -> dict[str, Any]:
        user = principal(request)
        response.headers[CSRF_HEADER] = str(user.pop("csrf_token"))
        response.headers["Cache-Control"] = "no-store"
        return {"user": user, "reauthentication": _call(
            lambda: identity.reauthentication_status(request.cookies.get(SESSION_COOKIE))
        )}

    @app.post("/v1/auth/reauth")
    def reauth(
        body: ReauthRequest,
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        principal(request, unsafe=True)
        user = _call(
            lambda: identity.reauthenticate(
                token=request.cookies.get(SESSION_COOKIE),
                password=body.password,
                idempotency_key=idempotency_key,
            )
        )
        response.headers[CSRF_HEADER] = str(user.pop("csrf_token"))
        response.headers["Cache-Control"] = "no-store"
        projection = _call(lambda: identity.reauthentication_status(request.cookies.get(SESSION_COOKIE)))
        return {
            "user": user,
            "reauth_valid_for_seconds": 900,
            "reauthenticated_until": projection["reauthenticated_until"],
            "observed_at": projection["observed_at"],
            "receipt_id": None,
            "production_authorized": False,
        }

    @app.post("/v1/auth/department-observation-contexts", status_code=201)
    def activate_department_observation(
        body: DepartmentObservationContextRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        principal(
            request,
            unsafe=True,
            reauth=True,
            roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}),
        )
        return _call(
            lambda: identity.activate_department_observation(
                token=request.cookies.get(SESSION_COOKIE),
                department_id=body.department_id,
                idempotency_key=idempotency_key,
            )
        )

    @app.delete("/v1/auth/department-observation-contexts/current")
    def clear_department_observation(
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        principal(
            request,
            unsafe=True,
            roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}),
        )
        return _call(
            lambda: identity.clear_department_observation(
                token=request.cookies.get(SESSION_COOKIE),
                idempotency_key=idempotency_key,
            )
        )

    @app.post("/v1/auth/logout", status_code=204)
    def logout(
        request: Request,
        response: Response,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> Response:
        origin(request)
        _call(
            lambda: identity.logout(
                token=request.cookies.get(SESSION_COOKIE),
                csrf_token=request.headers.get(CSRF_HEADER),
                idempotency_key=idempotency_key,
            )
        )
        response.delete_cookie(
            key=SESSION_COOKIE, secure=True, httponly=True, samesite="strict", path="/"
        )
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    @app.post("/v1/auth/invitations", status_code=201)
    def invite(
        body: InviteRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(
            request,
            unsafe=True,
            reauth=True,
            roles=frozenset({ROLE_CONTROL_PLANE_ADMIN, ROLE_DEPARTMENT_OWNER}),
        )
        return _call(
            lambda: identity.create_invite(
                principal=actor,
                department_id=body.department_id,
                role_ref=body.role_ref,
                idempotency_key=idempotency_key,
            )
        )

    @app.get("/v1/auth/pending-accounts")
    def pending_accounts(
        request: Request, department_id: str | None = None
    ) -> dict[str, Any]:
        actor = principal(
            request, roles=frozenset({ROLE_CONTROL_PLANE_ADMIN, ROLE_DEPARTMENT_OWNER})
        )
        return {
            "accounts": _call(
                lambda: identity.pending_accounts(
                    principal=actor, department_id=department_id
                )
            )
        }

    @app.post("/v1/auth/accounts/{account_id}/approve")
    def approve_account(
        account_id: str,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(
            request,
            unsafe=True,
            reauth=True,
            roles=frozenset({ROLE_CONTROL_PLANE_ADMIN, ROLE_DEPARTMENT_OWNER}),
        )
        return _call(
            lambda: identity.approve_account(
                principal=actor,
                account_id=account_id,
                idempotency_key=idempotency_key,
            )
        )

    @app.post("/v1/auth/change-password")
    def change_password(
        body: ChangePasswordRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request, unsafe=True, reauth=True)
        return _call(
            lambda: identity.change_password(
                principal=actor,
                current_password=body.current_password,
                new_password=body.new_password,
                idempotency_key=idempotency_key,
            )
        )

    @app.post("/v1/runtime-node-enrollment-codes", status_code=201)
    def enrollment_code(
        body: EnrollmentCodeRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(
            request, unsafe=True, reauth=True, roles=frozenset({ROLE_DEPARTMENT_OWNER})
        )
        return _call(
            lambda: workloads.create_enrollment_code(
                principal=actor,
                department_id=body.department_id,
                node_id=body.node_id,
                idempotency_key=idempotency_key,
            )
        )

    @app.post("/v1/department-cockpit/{department_id}/device-pilot-bundle")
    def department_device_bundle(
        department_id: str,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> RawResponse:
        actor = principal(
            request,
            unsafe=True,
            roles=frozenset({ROLE_DEPARTMENT_OWNER}),
        )
        value = _call(
            lambda: nodes.download_department_device_bundle(
                principal=actor,
                department_id=department_id,
                idempotency_key=idempotency_key,
            )
        )
        headers = {
            "Content-Disposition": f'attachment; filename="{value["filename"]}"',
            "Digest": value["bundle_digest"],
            "X-Orbit-Manifest-Digest": value["manifest_digest"],
            "X-Orbit-Deployment-Release-Lock": value["deployment_release_lock_digest"],
            "X-Orbit-Download-Receipt": value["receipt_id"],
            "Cache-Control": "private, no-store",
        }
        return RawResponse(
            content=value["content"],
            media_type="application/zip",
            headers=headers,
        )

    @app.post("/v1/runtime-node-enrollments", status_code=201)
    def enroll(
        body: EnrollRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        origin(request)
        try:
            csr = base64.b64decode(body.csr_pem_base64, validate=True)
        except ValueError as error:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "lan_csr_encoding_invalid"
            ) from error
        # The enrollment code is itself the short-lived authority.  The
        # idempotency header is mandatory even though a successful code is
        # single-use; no browser session or CSRF exists yet.
        if not idempotency_key:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "lan_idempotency_key_invalid"
            )
        return _call(
            lambda: workloads.enroll(
                enrollment_id=body.enrollment_id,
                enrollment_code=body.enrollment_code,
                csr_pem=csr,
                idempotency_key=idempotency_key,
            )
        )

    @app.post("/v1/runtime-nodes/certificate-revocations", status_code=201)
    def revoke_certificate(
        body: RevokeCertificateRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(
            request,
            unsafe=True,
            reauth=True,
            roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}),
        )
        return _call(
            lambda: workloads.revoke_certificate(
                principal=actor,
                fingerprint=body.fingerprint,
                reason=body.reason,
                idempotency_key=idempotency_key,
            )
        )

    @app.post("/v1/artifact-download-assignments", status_code=201)
    def artifact_download_assignment(
        body: ArtifactDownloadAssignmentRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(
            request,
            unsafe=True,
            reauth=True,
            roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}),
        )
        return _call(
            lambda: nodes.create_artifact_download_assignment(
                principal=actor,
                department_id=body.department_id,
                artifact_id=body.artifact_id,
                revision_digest=body.revision_digest,
                bundle_digest=body.bundle_digest,
                idempotency_key=idempotency_key,
            )
        )

    @app.post("/v1/deployment-release-locks", status_code=201)
    def deployment_release_lock(
        body: DeploymentReleaseLockRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(
            request,
            unsafe=True,
            reauth=True,
            roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}),
        )
        return _call(
            lambda: nodes.create_deployment_release_lock(
                principal=actor,
                document=body.document,
                idempotency_key=idempotency_key,
            )
        )

    @app.get("/v1/runtime-artifacts")
    def runtime_artifacts(request: Request) -> dict[str, Any]:
        principal(request, roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}))
        if nodes.runtime_artifacts is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "lan_runtime_artifact_catalog_unavailable",
            )
        return _call(nodes.runtime_artifacts.list_artifacts)

    @app.post("/v1/runtime-artifact-candidates", status_code=201)
    def runtime_artifact_candidate(
        body: RuntimeArtifactCandidateRequest,
        request: Request,
    ) -> dict[str, Any]:
        actor = principal(
            request,
            unsafe=True,
            reauth=True,
            roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}),
        )
        if nodes.runtime_artifacts is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "lan_runtime_artifact_catalog_unavailable",
            )
        return _call(
            lambda: nodes.runtime_artifacts.record_candidate(
                document=body.document,
                expected_latest_revision_digest=body.expected_latest_revision_digest,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=str(actor["human_ref"]),
            )
        )

    @app.get("/v1/runtime-artifacts/{artifact_id}/revisions/{revision_digest}")
    def runtime_artifact_revision(
        artifact_id: str,
        revision_digest: str,
        request: Request,
    ) -> dict[str, Any]:
        principal(request, roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}))
        if nodes.runtime_artifacts is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "lan_runtime_artifact_catalog_unavailable",
            )
        return _call(
            lambda: nodes.runtime_artifacts.revision(
                artifact_id=artifact_id,
                revision_digest=revision_digest,
            )
        )

    @app.get("/v1/runtime-artifacts/{artifact_id}/revisions/{revision_digest}/bundle")
    def runtime_artifact_bundle_metadata(
        artifact_id: str,
        revision_digest: str,
        request: Request,
    ) -> dict[str, Any]:
        principal(request, roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}))
        if nodes.runtime_artifacts is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "lan_runtime_artifact_catalog_unavailable",
            )
        return _call(
            lambda: nodes.runtime_artifacts.bundle_metadata(
                artifact_id=artifact_id,
                revision_digest=revision_digest,
            )
        )

    @app.post(
        "/v1/runtime-artifacts/{artifact_id}/revisions/{revision_digest}/qualifications",
        status_code=201,
    )
    def runtime_artifact_qualification(
        artifact_id: str,
        revision_digest: str,
        body: RuntimeArtifactQualificationRequest,
        request: Request,
    ) -> dict[str, Any]:
        actor = principal(
            request,
            unsafe=True,
            reauth=True,
            roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}),
        )
        if nodes.runtime_artifacts is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "lan_runtime_artifact_catalog_unavailable",
            )
        bindings = body.model_dump(exclude={"reason", "idempotency_key"}, mode="json")
        return _call(
            lambda: nodes.runtime_artifacts.qualify_d0(
                artifact_id=artifact_id,
                revision_digest=revision_digest,
                expected_bindings=bindings,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=str(actor["human_ref"]),
            )
        )

    @app.post(
        "/v1/runtime-artifacts/{artifact_id}/revocations",
        status_code=201,
    )
    def runtime_artifact_revocation(
        artifact_id: str,
        body: RuntimeArtifactRevocationRequest,
        request: Request,
    ) -> dict[str, Any]:
        actor = principal(
            request,
            unsafe=True,
            reauth=True,
            roles=frozenset({ROLE_CONTROL_PLANE_ADMIN}),
        )
        if nodes.runtime_artifacts is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "lan_runtime_artifact_catalog_unavailable",
            )
        return _call(
            lambda: nodes.runtime_artifacts.revoke(
                artifact_id=artifact_id,
                expected_revision_digest=body.expected_revision_digest,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=str(actor["human_ref"]),
            )
        )

    if cockpit is not None and governance_catalogs is not None:

        def cockpit_read(
            request: Request, *, required_roles: frozenset[str]
        ) -> dict[str, Any]:
            return principal(request, roles=required_roles)

        def cockpit_write(
            request: Request, *, required_roles: frozenset[str]
        ) -> dict[str, Any]:
            return principal(
                request,
                roles=required_roles,
                unsafe=True,
                reauth=required_roles == frozenset({ROLE_DEPARTMENT_OWNER}),
            )

        install_department_cockpit_routes(
            app,
            service=cockpit,
            authenticate_human=cockpit_read,
            require_mutating_human=cockpit_write,
        )

        @app.get("/v1/department-cockpit/{department_id}/runtime-status")
        def department_runtime_status(
            department_id: str, request: Request
        ) -> dict[str, Any]:
            actor = cockpit_read(
                request,
                required_roles=frozenset(
                    {
                        "role_department_user",
                        ROLE_DEPARTMENT_OWNER,
                        ROLE_CONTROL_PLANE_ADMIN,
                    }
                ),
            )
            _require_department_read_scope(actor, department_id)
            value = _department_runtime_status_projection(
                identity=identity,
                nodes=nodes,
                department_id=department_id,
            )
            if codex_installation is not None:
                value["codex_installation"] = codex_installation.projection(
                    department_id=department_id
                )
            return value

        @app.get("/v1/department-cockpit/{department_id}/codex-installation")
        def department_codex_installation(
            department_id: str, request: Request
        ) -> dict[str, Any]:
            actor = cockpit_read(
                request,
                required_roles=frozenset(
                    {
                        "role_department_user",
                        ROLE_DEPARTMENT_OWNER,
                        ROLE_CONTROL_PLANE_ADMIN,
                    }
                ),
            )
            _require_department_read_scope(actor, department_id)
            if codex_installation is None:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "codex_installation_service_unavailable",
                )
            projection = codex_installation.projection(department_id=department_id)
            if control_console is not None:
                projection["llm_api_readiness"] = _llm_api_readiness(
                    control_console=control_console
                )
            return projection

        @app.get(
            "/v1/department-cockpit/{department_id}/codex-installation/events"
        )
        async def department_codex_installation_events(
            department_id: str,
            request: Request,
            after_sequence: int = 0,
        ) -> StreamingResponse:
            actor = cockpit_read(
                request,
                required_roles=frozenset(
                    {
                        "role_department_user",
                        ROLE_DEPARTMENT_OWNER,
                        ROLE_CONTROL_PLANE_ADMIN,
                    }
                ),
            )
            _require_department_read_scope(actor, department_id)
            if codex_installation is None:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "codex_installation_service_unavailable",
                )

            async def stream():
                last_event_id = request.headers.get("last-event-id", "")
                cursor = max(
                    0,
                    after_sequence,
                    int(last_event_id) if last_event_id.isdigit() else 0,
                )
                heartbeat_at = 0
                while not await request.is_disconnected():
                    events = codex_installation.events(
                        department_id=department_id, after_sequence=cursor
                    )
                    for event in events:
                        cursor = max(cursor, int(event["event_cursor"]))
                        yield (
                            f"id: {cursor}\n"
                            "event: installation_stage\n"
                            f"data: {json.dumps(event, ensure_ascii=False, sort_keys=True)}\n\n"
                        )
                    projection = codex_installation.projection(
                        department_id=department_id
                    )
                    if projection["overall_status"] in {"complete", "failed"}:
                        terminal = {
                            "attempt_id": projection["attempt_id"],
                            "resource_revision": projection["resource_revision"],
                        }
                        yield (
                            "event: installation_terminal\n"
                            f"data: {json.dumps(terminal, sort_keys=True)}\n\n"
                        )
                        return
                    heartbeat_at += 1
                    if heartbeat_at >= 15:
                        heartbeat_at = 0
                        yield ": keepalive\n\n"
                    await asyncio.sleep(1)

            return StreamingResponse(
                stream(),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
            )

        @app.get("/v1/systems")
        def systems(
            request: Request, department_id: str | None = None
        ) -> dict[str, Any]:
            actor = principal(
                request,
                roles=frozenset(
                    {
                        "role_department_user",
                        ROLE_DEPARTMENT_OWNER,
                        ROLE_CONTROL_PLANE_ADMIN,
                    }
                ),
            )
            if department_id is None:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, "department_scope_not_allowed"
                )
            _require_department_read_scope(actor, department_id)
            try:
                return governance_catalogs.systems(department_id=department_id)
            except GovernanceCatalogError as error:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY, error.reason_code
                ) from error

    return app


def _require_department_read_scope(
    principal: dict[str, Any], department_id: str
) -> None:
    roles = set(principal.get("role_refs", ()))
    if ROLE_CONTROL_PLANE_ADMIN in roles:
        if (
            principal.get("access_mode") == "company_observer"
            and principal.get("active_observation_department_ref") == department_id
        ):
            return
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "department_observation_context_required",
        )
    if department_id not in principal.get("department_refs", ()):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "department_scope_not_allowed")


def create_workload_app(
    *,
    workloads: LanWorkloadIdentityService,
    nodes: LanNodeService,
    credentials: ModelRouteCredentialService | None = None,
    codex_installation: CodexInstallationService | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Orbit LAN Workload UDS", docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.transport = "unix_domain_socket_only"
    app.state.production_authorization = False

    def principal(request: Request) -> dict[str, Any]:
        return _call(
            lambda: workloads.verify_caddy_forwarded_peer(
                certificate_der_base64=request.headers.get(CERT_DER_HEADER),
                forwarded_fingerprint=request.headers.get(CERT_FINGERPRINT_HEADER),
            )
        )

    @app.get("/health/live")
    def live() -> dict[str, Any]:
        return {
            "status": "live",
            "entrypoint": "lan_workload_uds",
            "synthetic_only": True,
            "production_authorization": False,
            "release_authorization": False,
        }

    @app.post("/v1/runtime-nodes/{node_id}/certificate-renewals", status_code=201)
    def renew_certificate(
        node_id: str,
        body: CertificateRenewalRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request)
        try:
            csr = base64.b64decode(body.csr_pem_base64, validate=True)
        except ValueError as error:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "lan_csr_encoding_invalid"
            ) from error
        return _call(
            lambda: workloads.renew_certificate(
                principal=actor,
                node_id=node_id,
                csr_pem=csr,
                idempotency_key=idempotency_key,
            )
        )

    @app.post("/v1/runtime-nodes/{node_id}/heartbeats", status_code=201)
    def heartbeat(
        node_id: str,
        body: HeartbeatRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request)
        return _call(
            lambda: nodes.heartbeat(
                principal=actor,
                node_id=node_id,
                capability_report_digest=body.capability_report_digest,
                status=body.status,
                document=body.document,
                idempotency_key=idempotency_key,
            )
        )

    @app.get(
        "/v1/runtime-nodes/{node_id}/artifact-download-assignments/current"
    )
    def current_artifact_download_assignment(
        node_id: str,
        request: Request,
    ) -> Any:
        actor = principal(request)
        value = _call(
            lambda: nodes.current_artifact_download_assignment(
                principal=actor,
                node_id=node_id,
            )
        )
        if value is None:
            return RawResponse(status_code=status.HTTP_204_NO_CONTENT)
        return value

    @app.post(
        "/v1/runtime-nodes/{node_id}/codex-installation-events",
        status_code=201,
    )
    def codex_installation_event(
        node_id: str,
        body: NodeDocumentRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request)
        if codex_installation is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "codex_installation_service_unavailable",
            )
        if str(actor["node_id"]) != node_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "lan_wrong_node")
        return _call(
            lambda: codex_installation.record_event(
                node_id=node_id,
                document=body.document,
                idempotency_key=idempotency_key,
                workload_identity=str(actor["workload_identity"]),
            )
        )

    @app.post(
        "/v1/runtime-nodes/{node_id}/codex-installation-receipts",
        status_code=201,
    )
    def codex_installation_receipt(
        node_id: str,
        body: NodeDocumentRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request)
        if codex_installation is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "codex_installation_service_unavailable",
            )
        if str(actor["node_id"]) != node_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "lan_wrong_node")
        return _call(
            lambda: codex_installation.record_receipt(
                node_id=node_id,
                document=body.document,
                idempotency_key=idempotency_key,
                workload_identity=str(actor["workload_identity"]),
            )
        )

    @app.post(
        "/v1/runtime-nodes/{node_id}/assisted-maintenance-sessions",
        status_code=201,
    )
    def assisted_maintenance_session(
        node_id: str,
        body: AssistedMaintenanceSessionRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request)
        return _call(
            lambda: nodes.open_assisted_maintenance_session(
                principal=actor,
                node_id=node_id,
                requested_handler_ids=body.requested_handler_ids,
                duration_seconds=body.duration_seconds,
                local_user_initiated=body.local_user_initiated,
                idempotency_key=idempotency_key,
            )
        )

    @app.post(
        "/v1/runtime-nodes/{node_id}/assisted-maintenance-sessions/"
        "{session_id}/job-claims"
    )
    def assisted_maintenance_job_claim(
        node_id: str,
        session_id: str,
        request: Request,
        wait_seconds: float = 25,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> Any:
        actor = principal(request)
        value = _call(
            lambda: nodes.claim_maintenance_job_long_poll(
                principal=actor,
                node_id=node_id,
                session_id=session_id,
                idempotency_key=idempotency_key,
                wait_seconds=wait_seconds,
            )
        )
        if value is None:
            return RawResponse(status_code=status.HTTP_204_NO_CONTENT)
        return value

    @app.post(
        "/v1/runtime-nodes/{node_id}/maintenance-jobs/{job_id}/receipts",
        status_code=201,
    )
    def maintenance_receipt(
        node_id: str,
        job_id: str,
        body: MaintenanceReceiptRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request)
        return _call(
            lambda: nodes.record_maintenance_receipt(
                principal=actor,
                node_id=node_id,
                job_id=job_id,
                document=body.document,
                idempotency_key=idempotency_key,
            )
        )

    @app.post("/v1/runtime-nodes/{node_id}/capability-reports", status_code=201)
    def capability_report(
        node_id: str,
        body: NodeDocumentRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request)
        return _runtime_call(
            nodes,
            lambda service: service.record_capability_report(
                node_id=node_id,
                document=body.document,
                idempotency_key=idempotency_key,
                workload_identity=str(actor["workload_identity"]),
            ),
        )

    @app.post(
        "/v1/runtime-nodes/{node_id}/adapter-capability-reports",
        status_code=201,
    )
    def adapter_capability_report(
        node_id: str,
        body: AdapterCapabilityReportRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request)
        if credentials is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "model_route_credentials_unavailable",
            )
        if str(actor["node_id"]) != node_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "lan_wrong_node")
        return _call(
            lambda: credentials.record_adapter_capability_report(
                node_id=node_id,
                document=body.document,
                authentication_modes=body.authentication_modes,
                expires_at=body.expires_at,
                idempotency_key=idempotency_key,
            )
        )

    @app.post(
        "/v1/runtime-nodes/{node_id}/account-login-receipts",
        status_code=201,
    )
    def account_login_receipt(
        node_id: str,
        body: NodeDocumentRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request)
        if credentials is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "model_route_credentials_unavailable",
            )
        if str(actor["node_id"]) != node_id:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "lan_wrong_node")
        return _call(
            lambda: credentials.record_account_login_receipt(
                node_id=node_id,
                document=body.document,
                idempotency_key=idempotency_key,
                workload_identity=str(actor["workload_identity"]),
            )
        )

    @app.post("/v1/runtime-nodes/{node_id}/artifact-import-receipts", status_code=201)
    def import_receipt(
        node_id: str,
        body: NodeDocumentRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        actor = principal(request)
        return _runtime_call(
            nodes,
            lambda service: service.record_import_receipt(
                node_id=node_id,
                document=body.document,
                idempotency_key=idempotency_key,
                workload_identity=str(actor["workload_identity"]),
            ),
        )

    @app.post("/v1/runtime-nodes/{node_id}/lease-claims")
    def lease_claim(
        node_id: str,
        body: LeaseClaimRequest,
        request: Request,
        wait_seconds: float = 25,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> Any:
        actor = principal(request)
        value = _call(
            lambda: nodes.claim_lease_long_poll(
                principal=actor,
                node_id=node_id,
                expected_capability_report_digest=body.expected_capability_report_digest,
                idempotency_key=idempotency_key,
                wait_seconds=wait_seconds,
            )
        )
        if value is None:
            return RawResponse(status_code=status.HTTP_204_NO_CONTENT)
        return value

    def append_runtime_evidence(
        *,
        run_id: str,
        evidence_type: str,
        body: NodeDocumentRequest,
        request: Request,
        idempotency_key: str,
    ) -> dict[str, Any]:
        actor = principal(request)
        return _runtime_call(
            nodes,
            lambda service: service.append_run_evidence(
                node_id=str(actor["node_id"]),
                run_id=run_id,
                evidence_type=evidence_type,
                document=body.document,
                idempotency_key=idempotency_key,
                workload_identity=str(actor["workload_identity"]),
            ),
        )

    @app.post("/v1/runtime-runs/{run_id}/container-events", status_code=201)
    def container_event(
        run_id: str,
        body: NodeDocumentRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        return append_runtime_evidence(
            run_id=run_id,
            evidence_type="container_event",
            body=body,
            request=request,
            idempotency_key=idempotency_key,
        )

    @app.post("/v1/runtime-runs/{run_id}/checkpoint-receipts", status_code=201)
    def checkpoint_receipt(
        run_id: str,
        body: NodeDocumentRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        return append_runtime_evidence(
            run_id=run_id,
            evidence_type="checkpoint_receipt",
            body=body,
            request=request,
            idempotency_key=idempotency_key,
        )

    @app.post("/v1/runtime-runs/{run_id}/cleanup-receipts", status_code=201)
    def cleanup_receipt(
        run_id: str,
        body: NodeDocumentRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        return append_runtime_evidence(
            run_id=run_id,
            evidence_type="cleanup_receipt",
            body=body,
            request=request,
            idempotency_key=idempotency_key,
        )

    @app.post("/v1/runtime-runs/{run_id}/results", status_code=201)
    def runtime_result(
        run_id: str,
        body: NodeDocumentRequest,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> dict[str, Any]:
        return append_runtime_evidence(
            run_id=run_id,
            evidence_type="result_package",
            body=body,
            request=request,
            idempotency_key=idempotency_key,
        )

    @app.get(
        "/v1/runtime-artifacts/{artifact_id}/revisions/{revision_digest}/bundle/content"
    )
    def artifact_bundle(
        artifact_id: str,
        revision_digest: str,
        request: Request,
        idempotency_key: str = Header(alias="Idempotency-Key", pattern=_IDEMPOTENCY),
    ) -> RawResponse:
        actor = principal(request)
        value = _call(
            lambda: nodes.download(
                principal=actor,
                node_id=str(actor["node_id"]),
                artifact_id=artifact_id,
                revision_digest=revision_digest,
                range_header=request.headers.get("range"),
                idempotency_key=idempotency_key,
            )
        )
        headers = {
            "ETag": value["etag"],
            "Accept-Ranges": "bytes",
            "Digest": value["bundle_digest"],
            "X-Orbit-Download-Receipt": value["receipt_id"],
            "Cache-Control": "private, no-store",
        }
        if value["content_range"] is not None:
            headers["Content-Range"] = value["content_range"]
        return RawResponse(
            content=value["content"],
            status_code=value["status_code"],
            media_type="application/vnd.oci.image.layout.v1.tar",
            headers=headers,
        )

    return app


def _runtime_call(nodes: LanNodeService, callback):
    if nodes.runtime_artifacts is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "lan_runtime_queue_unavailable"
        )
    try:
        return callback(nodes.runtime_artifacts)
    except Exception as error:
        reason = getattr(error, "reason_code", None)
        if not isinstance(reason, str):
            raise
        return _call(lambda: (_ for _ in ()).throw(LanStage1Error(reason)))


def _control_bootstrap_projection(
    *,
    identity: LanHumanIdentityService,
    nodes: LanNodeService,
    user: dict[str, Any],
) -> dict[str, Any]:
    with identity.database.session() as session:
        invitations = tuple(
            session.scalars(
                select(LanInviteRow).order_by(LanInviteRow.id.desc()).limit(50)
            )
        )
        accounts = tuple(session.scalars(select(LanHumanAccountRow)))
        certificates = tuple(
            session.scalars(
                select(LanCertificateBindingRow).order_by(
                    LanCertificateBindingRow.id.desc()
                )
            )
        )
        enrollment_codes = tuple(
            session.scalars(
                select(LanEnrollmentCodeRow).order_by(LanEnrollmentCodeRow.id.desc())
            )
        )
        heartbeats = tuple(
            session.scalars(
                select(LanNodeHeartbeatRow).order_by(LanNodeHeartbeatRow.id.desc())
            )
        )
        assignments = tuple(
            session.scalars(
                select(LanArtifactDownloadAssignmentRow).where(
                    LanArtifactDownloadAssignmentRow.status == "d0_assigned"
                )
            )
        )
        audit_count = len(
            tuple(
                session.scalars(
                    select(AuditEventRow).order_by(AuditEventRow.id.desc()).limit(20)
                )
            )
        )
    observed_at = identity.now()
    role_by_human = {item.human_ref: item.role_ref for item in accounts}
    latest_cert = {}
    for item in certificates:
        latest_cert.setdefault(item.node_id, item)
    latest_heartbeat = {}
    for item in heartbeats:
        latest_heartbeat.setdefault(item.node_id, item)
    enrollment_by_node = {}
    for item in enrollment_codes:
        enrollment_by_node.setdefault(item.node_id, item)
    assignment_by_department = {item.department_id: item for item in assignments}
    node_ids = sorted(
        set(latest_cert) | set(latest_heartbeat) | set(enrollment_by_node)
    )
    artifact_counts = {
        "qualified_count": 0,
        "candidate_count": 0,
        "revoked_count": 0,
    }
    if nodes.runtime_artifacts is not None:
        for item in nodes.runtime_artifacts.list_artifacts().get("items", ()):
            status_value = str(item.get("status"))
            if status_value == "qualified_d0":
                artifact_counts["qualified_count"] += 1
            elif status_value == "revoked":
                artifact_counts["revoked_count"] += 1
            else:
                artifact_counts["candidate_count"] += 1

    def invitation_status(item: LanInviteRow) -> str:
        if item.consumed_at is not None:
            return "claimed"
        if item.expires_at.replace(tzinfo=observed_at.tzinfo) <= observed_at:
            return "expired"
        return "available"

    def certificate_projection(node_id: str) -> tuple[str, str, str | None, str | None]:
        certificate = latest_cert.get(node_id)
        if certificate is None:
            return "pending", "not_issued", None, None
        expires_at = certificate.not_after.replace(tzinfo=observed_at.tzinfo)
        if certificate.status != "active":
            return (
                "suspended",
                "revoked",
                expires_at.isoformat(),
                certificate.fingerprint,
            )
        if expires_at <= observed_at:
            return (
                "suspended",
                "expired",
                expires_at.isoformat(),
                certificate.fingerprint,
            )
        if expires_at <= observed_at + timedelta(days=7):
            return (
                "enrolled",
                "expiring",
                expires_at.isoformat(),
                certificate.fingerprint,
            )
        return "enrolled", "valid", expires_at.isoformat(), certificate.fingerprint

    def heartbeat_projection(node_id: str) -> tuple[str, str | None]:
        heartbeat = latest_heartbeat.get(node_id)
        if heartbeat is None:
            return "missing", None
        recorded_at = heartbeat.recorded_at.replace(tzinfo=observed_at.tzinfo)
        age = observed_at - recorded_at
        if age <= timedelta(minutes=2):
            state = "current"
        elif age <= timedelta(minutes=10):
            state = "late"
        else:
            state = "offline"
        return state, recorded_at.isoformat()

    def artifact_stages(node_id: str) -> list[dict[str, Any]]:
        certificate = latest_cert.get(node_id)
        department_id = None if certificate is None else certificate.department_id
        assignment = (
            None
            if department_id is None
            else assignment_by_department.get(department_id)
        )
        installed = certificate is not None and certificate.status == "active"
        stages: list[dict[str, Any]] = []
        for stage in ("install", "download", "verify", "import", "probe", "ready"):
            if stage == "install" and installed:
                state = ("passed", "节点证书已绑定；仅表示登记证据", "recorded")
                recorded_at = certificate.issued_at.isoformat() if certificate else None
            elif stage == "download" and assignment is not None:
                state = ("waiting", "等待满足全部下载授权联检", "waiting")
                recorded_at = None
            else:
                state = ("not_started", "尚无对应 D0 回执", "not_expected")
                recorded_at = None
            stages.append(
                {
                    "stage": stage,
                    "status": state[0],
                    "summary": state[1],
                    "receipt_status": state[2],
                    "recorded_at": recorded_at,
                }
            )
        return stages

    runtime_nodes = []
    for node_id in node_ids:
        enrollment_status, certificate_status, certificate_expires_at, fingerprint = (
            certificate_projection(node_id)
        )
        heartbeat_status, last_heartbeat_at = heartbeat_projection(node_id)
        department_id = (
            latest_cert[node_id].department_id
            if node_id in latest_cert
            else enrollment_by_node[node_id].department_id
        )
        assignment = assignment_by_department.get(department_id)
        runtime_nodes.append(
            {
                "node_id": node_id,
                "display_name": node_id.replace("_", " "),
                "department_ref": department_id,
                "enrollment_status": enrollment_status,
                "certificate_status": certificate_status,
                "certificate_expires_at": certificate_expires_at,
                "certificate_fingerprint": fingerprint,
                "heartbeat_status": heartbeat_status,
                "last_heartbeat_at": last_heartbeat_at,
                "artifact_stages": artifact_stages(node_id),
                "current_artifact_digest": None
                if assignment is None
                else (assignment.revision_digest[:15] + "…"),
                "evidence_status": "runtime_node_projection",
                "runtime_started": False,
                "model_called": False,
                "production_authorized": False,
                "release_authorization": False,
            }
        )

    return {
        "observed_at": observed_at.isoformat(),
        "service_mode": "d0_synthetic_only",
        "connections": [
            {
                "service": "control_plane",
                "status": "ready",
                "summary": "LAN D0 Control Plane 投影可读",
                "checked_at": observed_at.isoformat(),
            },
            {
                "service": "identity",
                "status": "ready",
                "summary": "本地邀请、审批与会话证据可读",
                "checked_at": observed_at.isoformat(),
            },
            {
                "service": "runtime_nodes",
                "status": "ready" if runtime_nodes else "degraded",
                "summary": "已记录部门节点投影"
                if runtime_nodes
                else "尚无部门节点证据",
                "checked_at": observed_at.isoformat(),
            },
            {
                "service": "audit",
                "status": "ready",
                "summary": f"本地 append-only 审计投影可读（最近 {audit_count} 条）",
                "checked_at": observed_at.isoformat(),
            },
        ],
        "invitations": [
            {
                "invite_id": item.invite_id,
                "department_id": item.department_id,
                "role_ref": item.role_ref,
                "status": invitation_status(item),
                "expires_at": item.expires_at.isoformat(),
                "created_by_role_ref": role_by_human.get(item.invited_by_ref),
                "synthetic_only": True,
                "production_authorized": False,
            }
            for item in invitations
        ],
        "runtime_nodes": runtime_nodes,
        "department_accounts": [
            {
                "human_ref": item.human_ref,
                "display_name": item.display_name,
                "department_id": item.department_id,
                "role_ref": item.role_ref,
                "status": item.status,
                "observed_at": observed_at.isoformat(),
            }
            for item in accounts
            if item.department_id in {
                "product_center",
                "technology_center",
                "market_center",
            }
        ],
        "artifact_catalog": artifact_counts,
        "release_authorization": False,
    }


def _department_readiness_matrix(
    bootstrap: Mapping[str, Any],
) -> list[dict[str, Any]]:
    observed_at = str(bootstrap["observed_at"])
    names = {
        "product_center": "产品中心",
        "technology_center": "技术中心",
        "market_center": "市场中心",
    }
    accounts = list(bootstrap.get("department_accounts", []))
    nodes = list(bootstrap.get("runtime_nodes", []))
    resources = {
        item["department_id"]: item
        for item in bootstrap.get("department_model_resources", [])
    }

    def cell(
        *,
        status: str,
        evidence_level: str,
        blocker_reason: str | None,
        next_action: str,
        summary: str,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "summary": summary,
            "observed_at": observed_at,
            "evidence_level": evidence_level,
            "blocker_reason": blocker_reason,
            "next_action": next_action,
            "read_only": True,
        }

    rows = []
    for department_id, name in names.items():
        owner = next(
            (
                item
                for item in accounts
                if item["department_id"] == department_id
                and item["role_ref"] == "role_department_owner"
                and item["status"] == "active"
            ),
            None,
        )
        node = next(
            (item for item in nodes if item["department_ref"] == department_id),
            None,
        )
        planning_agent = next(
            (
                item
                for item in resources.get(department_id, {}).get("agents", [])
                if item["kind"] == "department_planning"
            ),
            None,
        )
        route = None if planning_agent is None else planning_agent["current_route"]
        planning_enabled = department_id in {
            "product_center",
            "technology_center",
        }
        route_qualified = bool(
            planning_enabled
            and route is not None
            and route.get("selectable")
            and route.get("company_approval_status") in {"approved", "d0_approved"}
            and route.get("health_status") == "ready"
        )
        node_ready = bool(
            node is not None
            and node.get("certificate_status") == "valid"
            and node.get("heartbeat_status") == "current"
        )
        cells = {
            "owner_account": cell(
                status="ready" if owner else "blocked",
                evidence_level="control_plane_record",
                blocker_reason=None if owner else "department_owner_missing",
                next_action="保持负责人账号有效"
                if owner
                else "审批并绑定唯一部门负责人账号",
                summary=(owner["display_name"] if owner else "未发现有效负责人"),
            ),
            "planning_model": cell(
                # Registry health does not verify the planning model transport.
                status="attention" if route_qualified else "blocked",
                evidence_level="registry_projection",
                blocker_reason=(
                    "planning_model_transport_not_verified"
                    if route_qualified
                    else "department_workflow_not_enabled"
                    if not planning_enabled
                    else "approved_route_or_health_missing"
                ),
                next_action=(
                    "核验规划 Runtime 与模型调用证据"
                    if route_qualified
                    else "等待技术中心验收后按顺序接入"
                    if not planning_enabled
                    else "完成精确路线批准与健康读回"
                ),
                summary=(
                    "规划路线配置已就绪；模型调用尚未验证"
                    if route_qualified
                    else "规划模型尚未就绪"
                ),
            ),
            "fixed_node": cell(
                status="ready" if node_ready else "blocked",
                evidence_level="runtime_node_projection",
                blocker_reason=None if node_ready else "node_evidence_not_current",
                next_action="保持证书与心跳新鲜"
                if node_ready
                else "登记固定节点并刷新证书与心跳",
                summary=node.get("display_name", "未发现固定节点")
                if node
                else "未发现固定节点",
            ),
            "professional_runtime": cell(
                status="blocked",
                evidence_level="architecture_boundary",
                blocker_reason="professional_runtime_not_authorized",
                next_action="技术规划切片验收后另行资格审查与授权",
                summary="专业 Codex 或 Hermes Runtime 未启动、未授权",
            ),
            "evidence_freshness": cell(
                status="attention",
                evidence_level="combined_readback",
                blocker_reason=(
                    "planning_model_transport_not_verified"
                    if owner and route_qualified and node_ready
                    else "readiness_evidence_incomplete"
                ),
                next_action="核验规划 Runtime 与模型调用证据"
                if owner and route_qualified and node_ready
                else "补齐阻塞证据",
                summary="配置与通信已读回；模型调用证据待核验"
                if owner and route_qualified and node_ready
                else "存在缺失或过期证据",
            ),
        }
        rows.append(
            {
                "department_id": department_id,
                "department_name": name,
                "cells": cells,
                "observed_at": observed_at,
                "read_only": True,
            }
        )
    return rows


def _department_runtime_status_projection(
    *,
    identity: LanHumanIdentityService,
    nodes: LanNodeService,
    department_id: str,
) -> dict[str, Any]:
    projection = _control_bootstrap_projection(
        identity=identity,
        nodes=nodes,
        user={},
    )
    department_nodes = [
        item
        for item in projection["runtime_nodes"]
        if item["department_ref"] == department_id
    ]
    primary = department_nodes[0] if department_nodes else None
    if primary is None:
        summary = "本部门尚未登记运行节点"
        connection_status = "not_enrolled"
    else:
        connection_status = str(primary["heartbeat_status"])
        summary = {
            "current": "部门节点通信正常；不表示 Runtime 已启动",
            "late": "部门节点心跳延迟，正在等待下一次上报",
            "offline": "部门节点已超过十分钟没有上报",
            "missing": "部门节点已登记，但尚无 Heartbeat 证据",
        }.get(connection_status, "部门节点状态待核对")
    professional_runtime_artifact = _professional_runtime_artifact_projection(
        nodes=nodes,
        department_id=department_id,
        node_id=None if primary is None else str(primary["node_id"]),
        observed_at=str(projection["observed_at"]),
    )
    return {
        "department_id": department_id,
        "observed_at": projection["observed_at"],
        "connection_status": connection_status,
        "summary": summary,
        "primary_node": primary,
        "nodes": department_nodes,
        "professional_runtime_artifact": professional_runtime_artifact,
        "runtime_started": False,
        "model_called": False,
        "execution_authorized": False,
        "production_authorization": False,
        "release_authorization": False,
    }


def _professional_runtime_artifact_projection(
    *,
    nodes: LanNodeService,
    department_id: str,
    node_id: str | None,
    observed_at: str,
) -> dict[str, Any]:
    """Build a redacted receipt-derived artifact progress projection.

    The six stage labels are implementation projection labels, not Company
    Task states.  No stage is allowed to imply an ExecutionGrant, Lease,
    professional task start, or model call.
    """

    expected_family = {
        "product_center": "hermes",
        "technology_center": "codex",
        "market_center": "hermes",
    }[department_id]
    assignment = None
    artifact = None
    download = None
    import_receipt = None
    capability = None
    revoked = False
    if node_id is not None:
        with nodes.database.session() as session:
            assignment = session.scalar(
                select(LanArtifactDownloadAssignmentRow)
                .where(
                    LanArtifactDownloadAssignmentRow.department_id
                    == department_id,
                    LanArtifactDownloadAssignmentRow.status == "d0_assigned",
                    LanArtifactDownloadAssignmentRow.revoked_at.is_(None),
                )
                .order_by(LanArtifactDownloadAssignmentRow.id.desc())
                .limit(1)
            )
            if assignment is not None:
                artifact = session.scalar(
                    select(RuntimeArtifactRevisionRow).where(
                        RuntimeArtifactRevisionRow.artifact_id
                        == assignment.artifact_id,
                        RuntimeArtifactRevisionRow.revision_digest
                        == assignment.revision_digest,
                    )
                )
                revoked = (
                    session.scalar(
                        select(RuntimeArtifactRevocationRow).where(
                            RuntimeArtifactRevocationRow.artifact_id
                            == assignment.artifact_id,
                            RuntimeArtifactRevocationRow.revision_digest
                            == assignment.revision_digest,
                        )
                    )
                    is not None
                )
                download = session.scalar(
                    select(LanArtifactDownloadReceiptRow)
                    .where(
                        LanArtifactDownloadReceiptRow.node_id == node_id,
                        LanArtifactDownloadReceiptRow.department_id
                        == department_id,
                        LanArtifactDownloadReceiptRow.artifact_id
                        == assignment.artifact_id,
                        LanArtifactDownloadReceiptRow.revision_digest
                        == assignment.revision_digest,
                        LanArtifactDownloadReceiptRow.bundle_digest
                        == assignment.bundle_digest,
                        LanArtifactDownloadReceiptRow.completed.is_(True),
                    )
                    .order_by(LanArtifactDownloadReceiptRow.id.desc())
                    .limit(1)
                )
                import_receipt = session.scalar(
                    select(RuntimeArtifactImportReceiptRow)
                    .where(
                        RuntimeArtifactImportReceiptRow.node_id == node_id,
                        RuntimeArtifactImportReceiptRow.artifact_id
                        == assignment.artifact_id,
                        RuntimeArtifactImportReceiptRow.revision_digest
                        == assignment.revision_digest,
                    )
                    .order_by(RuntimeArtifactImportReceiptRow.id.desc())
                    .limit(1)
                )
                capability = session.scalar(
                    select(RuntimeNodeCapabilityReportRow)
                    .where(RuntimeNodeCapabilityReportRow.node_id == node_id)
                    .order_by(RuntimeNodeCapabilityReportRow.id.desc())
                    .limit(1)
                )

    verification = (
        {}
        if import_receipt is None
        else dict(import_receipt.document.get("spec", {}).get("verification", {}))
    )
    imported = import_receipt is not None and import_receipt.outcome == "imported"
    rejected = import_receipt is not None and import_receipt.outcome == "rejected"
    verified = imported and all(
        verification.get(item) is True
        for item in (
            "signature_valid",
            "artifact_set_valid",
            "manifest_digest_valid",
            "source_digest_valid",
            "image_digest_valid",
            "platform_compatible",
            "isolation_compatible",
            "artifact_not_revoked",
        )
    )
    probed = imported and verification.get("probe_passed") is True
    post_import_capability = bool(
        assignment is not None
        and artifact is not None
        and import_receipt is not None
        and capability is not None
        and capability.status == "eligible_d0"
        and assignment.revision_digest
        in capability.document.get("verified_runtime_artifact_digests", ())
        and artifact.runtime_image_digest
        in capability.document.get("verified_image_digests", ())
        and import_receipt.receipt_digest
        in capability.document.get("verified_import_receipt_digests", ())
        and not revoked
    )

    def timestamp(value: Any) -> str | None:
        if value is None:
            return None
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    def stage(
        name: str,
        *,
        passed: bool,
        waiting: bool,
        failed: bool = False,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        status_value = (
            "failed"
            if failed
            else "passed"
            if passed
            else "waiting"
            if waiting
            else "not_started"
        )
        return {
            "stage": name,
            "status": status_value,
            "recorded_at": recorded_at if passed or failed else None,
        }

    assigned_at = None if assignment is None else timestamp(assignment.created_at)
    downloaded_at = None if download is None else timestamp(download.recorded_at)
    imported_at = (
        None if import_receipt is None else timestamp(import_receipt.recorded_at)
    )
    completed_at = None if capability is None else timestamp(capability.recorded_at)
    stages = [
        stage(
            "assigned",
            passed=assignment is not None and not revoked,
            waiting=assignment is None,
            failed=revoked,
            recorded_at=assigned_at,
        ),
        stage(
            "download",
            passed=download is not None,
            waiting=assignment is not None and download is None,
            recorded_at=downloaded_at,
        ),
        stage(
            "verify",
            passed=verified,
            waiting=download is not None and import_receipt is None,
            failed=rejected or revoked,
            recorded_at=imported_at,
        ),
        stage(
            "import",
            passed=imported,
            waiting=verified and not imported,
            failed=rejected or revoked,
            recorded_at=imported_at,
        ),
        stage(
            "probe",
            passed=probed,
            waiting=imported and not probed,
            failed=rejected or revoked,
            recorded_at=imported_at,
        ),
        stage(
            "complete",
            passed=post_import_capability,
            waiting=imported and not post_import_capability and not revoked,
            failed=revoked,
            recorded_at=completed_at,
        ),
    ]
    artifact_version = None
    target_platform = "linux/amd64"
    runtime_family = expected_family
    if artifact is not None:
        artifact_version = artifact.document.get("metadata", {}).get("version")
        target_platform = artifact.target_platform
        runtime_family = artifact.runtime_family
    return {
        "kind": "ProfessionalRuntimeArtifactProjection",
        "runtime_family": runtime_family,
        "version": artifact_version,
        "target_platform": target_platform,
        "artifact_id": None if assignment is None else assignment.artifact_id,
        "artifact_revision": (
            None if assignment is None else assignment.revision_digest
        ),
        "assignment_status": (
            "revoked"
            if revoked
            else "assigned"
            if assignment is not None
            else "not_assigned"
        ),
        "stages": stages,
        "import_receipt_digest": (
            None if import_receipt is None else import_receipt.receipt_digest
        ),
        "capability_report_digest": (
            None if capability is None else capability.report_digest
        ),
        "observed_at": observed_at,
        "qualification_probe_executed": probed,
        "professional_task_runtime_started": False,
        "model_called": False,
        "execution_authorized": False,
        "synthetic_only": True,
        "production_authorization": False,
        "release_authorization": False,
    }



def _llm_api_readiness(
    *, control_console: ControlConsoleService
) -> dict[str, Any]:
    options = [
        {
            "route_id": item["route_id"],
            "route_revision_digest": item["revision_digest"],
            "requested_model": item["requested_model"],
            "provider": item["provider"],
            "authentication_mode": "api_key_ref",
        }
        for item in control_console.list_model_routes().get("items", ())
        if item.get("route_version") == "orbit.model-route-revision/2"
        and item.get("authentication_mode") == "api_key_ref"
        and item.get("approval_status") == "approved"
        and item.get("eligible") is True
        and not item.get("retired")
        and "model_route_snapshot_expired"
        not in item.get("health", {}).get("reason_codes", ())
        and "model_route_revision_not_latest"
        not in item.get("health", {}).get("reason_codes", ())
    ]
    selected = options[0] if len(options) == 1 else None
    return {
        "status": "ready" if options else "blocked",
        "reason_code": (
            None
            if options
            else "approved_compatible_api_route_required"
        ),
        "route_options": options,
        "selected_route_id": None if selected is None else selected["route_id"],
        "selected_route_revision_digest": (
            None if selected is None else selected["route_revision_digest"]
        ),
        "central_secret_only": True,
        "browser_secret_allowed": False,
        "device_secret_allowed": False,
        "execution_grant_issued": False,
        "runtime_started": False,
        "model_called": False,
    }


def _apply_codex_installation_readiness(
    rows: list[dict[str, Any]], service: CodexInstallationService
) -> None:
    # Installation receipts describe a separate fact from node connectivity.
    # Keep the five readiness cells intact, including non-Codex departments.
    for row in rows:
        row["codex_installation"] = service.projection(
            department_id=str(row["department_id"])
        )


def _call(callback):
    try:
        return callback()
    except (LanStage1Error, RuntimeArtifactError, CodexInstallationError) as error:
        reason = error.reason_code
        if reason.endswith("_not_found"):
            code = status.HTTP_404_NOT_FOUND
        elif reason in {
            "lan_session_required",
            "lan_session_invalid",
            "lan_login_invalid",
            "lan_workload_certificate_not_active",
            "lan_forwarded_certificate_required",
            "lan_forwarded_certificate_invalid",
            "lan_forwarded_fingerprint_mismatch",
        }:
            code = status.HTTP_401_UNAUTHORIZED
        elif (
            reason == "lan_csrf_invalid"
            or "scope_not_allowed" in reason
            or reason
            in {
                "lan_artifact_not_authorized",
                "lan_department_artifact_selection_required",
            }
            or reason.endswith(("_required", "_not_allowed"))
        ):
            code = status.HTTP_403_FORBIDDEN
        elif (
            "conflict" in reason or "idempotency" in reason or "binding_drift" in reason
        ):
            code = status.HTTP_409_CONFLICT
        elif reason in {
            "lan_certificate_issuer_unavailable",
            "lan_artifact_bundle_unavailable",
            "lan_department_device_bundle_unavailable",
            "lan_runtime_queue_unavailable",
            "lan_runtime_artifact_catalog_unavailable",
        }:
            code = status.HTTP_503_SERVICE_UNAVAILABLE
        elif reason == "lan_artifact_range_unsatisfiable":
            code = status.HTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE
        else:
            code = status.HTTP_422_UNPROCESSABLE_ENTITY
        raise HTTPException(code, reason) from error

