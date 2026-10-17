"""Loopback-only D0 harness for Department Cockpit browser integration.

This module is intentionally separate from the governed service entrypoint. It
exposes only the Department Cockpit and governance projection routes, uses a
loopback-only local account mapping, and configures only a persistent D0
LangGraph planning state machine. It never configures a live model, professional
runtime, provider credential, workload identity, signer, or production authority.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from .api import load_service_runtime
from .cockpit_local_identity import CockpitLocalIdentityService, ScryptPasswordHasher
from .cockpit_local_identity_api import (
    authenticate_cockpit_local_human,
    install_cockpit_local_identity_routes,
)
from .config import ServiceSettings
from .department_cockpit import (
    DepartmentCockpitService,
    LangGraphPlanningTransport,
)
from .department_cockpit_api import install_department_cockpit_routes
from .model_catalog import ModelCatalogService
from .models import Base

_AUDIENCE = "department_cockpit_d0"
_HOST = "127.0.0.1"
_PORT = 8431
_POLICY_ROOT = Path(
    "evidence/disease-agent-r2/2026-08-27-automation-policy-alpha2"
)


def build_d0_app(
    *, database_path: Path | None = None, password_scrypt_n: int = 2**17,
    frontend_origins: frozenset[str] | None = None,
    private_state_root: Path | None = None,
) -> FastAPI:
    """Build the isolated loopback app without weakening the formal service."""

    repository_root = Path(__file__).resolve().parents[3]
    effective_database_path = database_path or _default_database_path()
    _prepare_database_path(effective_database_path, private_state_root=private_state_root)
    checkpoint_path = effective_database_path.with_name(
        "cockpit.langgraph.sqlite3"
    )
    _prepare_database_path(checkpoint_path, private_state_root=private_state_root)
    policy_root = repository_root / _POLICY_ROOT
    settings = ServiceSettings(
        mode="local_synthetic",
        database_url=f"sqlite+pysqlite:///{effective_database_path}",
        policy_path=policy_root / "automation-policy.disease-r2.synthetic.json",
        review_package_path=policy_root / "automation-policy-review-package.json",
        profile_path=(
            repository_root
            / "references/qualification-service-profile.candidate.json"
        ),
        adapter_evidence_path=None,
        oidc_issuer=None,
        oidc_audience=_AUDIENCE,
        oidc_required_key_id=None,
        oidc_allowed_roles=(),
        oidc_admin_subject_digests=(),
        oidc_public_key_ref=None,
        workload_ca_ref=None,
        workload_allowed_identities=(),
        grant_signing_key_ref=None,
        grant_signing_key_id=None,
        secret_bindings_path=None,
        workload_trust_domain=None,
        mutations_enabled=False,
        host=_HOST,
        port=_PORT,
        local_state_root=effective_database_path.parent,
    )
    runtime = load_service_runtime(
        settings=settings,
        repository_root=repository_root,
    )
    Base.metadata.create_all(runtime.database.engine)
    runtime.managed_components.register(runtime.managed_component_descriptor)
    runtime.governance_catalogs.bootstrap()
    planning_transport = LangGraphPlanningTransport(
        checkpoint_path=checkpoint_path
    )
    cockpit = DepartmentCockpitService(
        database=runtime.database,
        transport=planning_transport,
        agent_proposals=ModelCatalogService(
            database=runtime.database,
            model_routes=runtime.model_route_reconciler,
        ),
    )
    identity = CockpitLocalIdentityService(
        runtime.database,
        password_hasher=ScryptPasswordHasher(n=password_scrypt_n),
    )
    app = FastAPI(
        title="Orbit Department Cockpit D0 Integration Harness",
        version="0.1.0-d0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.runtime = runtime
    app.state.department_cockpit = cockpit
    app.state.planning_transport = planning_transport
    app.state.cockpit_local_identity = identity
    app.state.d0_only = True

    @app.middleware("http")
    async def loopback_only(request: Request, call_next):
        client_host = request.client.host if request.client else ""
        if client_host not in {_HOST, "::1", "testclient"}:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "d0_loopback_required"},
            )
        return await call_next(request)

    def require_mutating_request(request: Request) -> None:
        if (
            request.headers.get("x-orbit-request") != "department-cockpit"
            or request.headers.get("origin")
            not in (frontend_origins or frozenset({
                "http://127.0.0.1:4173",
                "http://localhost:4173",
                "http://testserver",
            }))
        ):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "d0_same_origin_request_required"
            )

    def authenticate_human(
        request: Request, *, required_roles: frozenset[str]
    ) -> dict[str, Any]:
        return authenticate_cockpit_local_human(
            identity, request, required_roles=required_roles
        )

    def require_mutating_human(
        request: Request, *, required_roles: frozenset[str]
    ) -> dict[str, Any]:
        require_mutating_request(request)
        return authenticate_human(request, required_roles=required_roles)

    @app.get("/health/live")
    def live() -> dict[str, Any]:
        return {
            "status": "live",
            "service_mode": "local_department_cockpit_d0",
            "identity_mode": "loopback_d0_local_account_session",
            "synthetic_only": True,
            "planning_runtime_started": True,
            "professional_runtime_started": False,
            "live_model_enabled": False,
            "release_authorization": False,
            "production_authorized": False,
        }

    @app.get("/health/ready")
    def ready() -> dict[str, Any]:
        if not runtime.database.ping():
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "d0_database_not_ready"
            )
        return {
            "status": "synthetic_ready",
            "database_ready": True,
            "planning_runtime": "langgraph_d0",
            "professional_runtime_ready": False,
            "synthetic_only": True,
            "release_authorization": False,
        }

    install_cockpit_local_identity_routes(
        app,
        service=identity,
        require_mutating_request=require_mutating_request,
    )
    install_department_cockpit_routes(
        app,
        service=cockpit,
        authenticate_human=authenticate_human,
        require_mutating_human=require_mutating_human,
    )

    @app.get("/v1/systems")
    def systems(
        request: Request, department_id: str | None = None
    ) -> dict[str, Any]:
        principal = authenticate_human(
            request,
            required_roles=frozenset(
                {
                    "role_department_user",
                    "role_department_owner",
                    "role_control_plane_admin",
                }
            ),
        )
        departments = principal.get("department_refs", [])
        if (
            department_id is None
            or department_id not in departments
            and "role_control_plane_admin" not in principal["role_refs"]
        ):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "department_scope_not_allowed"
            )
        return runtime.governance_catalogs.systems(department_id=department_id)

    return app


def app_factory() -> FastAPI:
    return build_d0_app()


def run() -> None:
    """Run only on the fixed loopback address and fixed local BFF port."""

    uvicorn.run(
        "orbit_agent_control_plane.service_runtime.department_cockpit_d0_main:app_factory",
        factory=True,
        host=_HOST,
        port=_PORT,
        access_log=False,
        reload=False,
    )


def _default_database_path() -> Path:
    configured = os.environ.get("ORBIT_COCKPIT_D0_DATABASE_PATH")
    if configured:
        return Path(configured)
    return (
        Path(tempfile.gettempdir()).resolve()
        / "orbit-department-cockpit-d0"
        / "cockpit.sqlite3"
    )


def _prepare_database_path(path: Path, *, private_state_root: Path | None = None) -> None:
    resolved = path.resolve()
    allowed_roots = {
        Path(tempfile.gettempdir()).resolve(),
        Path("/private/tmp").resolve(),
        Path("/tmp").resolve(),
    }
    if private_state_root is not None:
        # Explicit delivery-adapter opt-in only. The old harness keeps its
        # tmp-only default; never allow arbitrary project/source directories.
        expected = Path(__file__).resolve().parents[3] / ".runtime" / "workbench"
        approved = private_state_root.absolute()
        if (approved != approved.resolve() or not approved.is_relative_to(expected)
                or approved.is_symlink() or not approved.is_dir()
                or approved.stat().st_uid != os.getuid()
                or approved.stat().st_mode & 0o077):
            raise ValueError("department_cockpit_private_state_root_invalid")
        allowed_roots.add(approved)
    if (
        not path.is_absolute()
        or path.suffix != ".sqlite3"
        or not any(resolved.is_relative_to(root) for root in allowed_roots)
        or path.is_symlink()
    ):
        raise ValueError("department_cockpit_d0_database_path_invalid")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Never change a shared temporary root such as /private/tmp itself.  A
    # dedicated child directory is owner-private, while a direct file override
    # relies on the database file permission applied after initialization.
    if path.parent.resolve() not in allowed_roots:
        os.chmod(path.parent, 0o700)
    if path.exists():
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
        ):
            raise ValueError("department_cockpit_d0_database_path_invalid")
    else:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        os.close(descriptor)
    os.chmod(path, 0o600)

