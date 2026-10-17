"""Loopback-only D0 harness for the company Control Plane console.

The fixed principal is synthetic and exists only to exercise browser/API
integration.  This module does not weaken the formal OIDC/mTLS service, expose
secret bytes, enable a model call, or authorize production.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from .api import load_service_runtime
from .config import ServiceSettings
from .control_console import ControlConsoleService
from .control_console_api import install_control_console_routes
from .department_cockpit import DepartmentCockpitService
from .model_catalog import ModelCatalogService
from .model_route import ModelRouteError
from .models import Base, DepartmentCockpitObjectRow
from .runtime_artifact_api import install_runtime_artifact_routes

_HOST = "127.0.0.1"
_PORT = 8432
_POLICY_ROOT = Path(
    "evidence/disease-agent-r2/2026-08-27-automation-policy-alpha2"
)
_FRONTEND_ORIGINS = {
    "http://127.0.0.1:4174",
    "http://localhost:4174",
    "http://127.0.0.1:8432",
    "http://localhost:8432",
    "http://testserver",
}


class D0LogicalSecretProvider:
    """Health-only logical binding; secret reads always fail closed."""

    def health(self, logical_ref: str) -> dict[str, Any]:
        if not logical_ref.startswith("secret://"):
            raise ModelRouteError("model_route_secret_ref_invalid")
        return {
            "logical_ref": logical_ref,
            "binding_version": "synthetic-binding-v1",
            "healthy": True,
        }

    def read(self, logical_ref: str) -> bytes:
        del logical_ref
        raise ModelRouteError("model_route_secret_read_forbidden_in_d0")


def build_d0_app(*, database_path: Path | None = None) -> FastAPI:
    repository_root = Path(__file__).resolve().parents[3]
    effective_database_path = database_path or _default_database_path()
    _prepare_database_path(effective_database_path)
    policy_root = repository_root / _POLICY_ROOT
    settings = ServiceSettings(
        mode="local_synthetic",
        database_url=f"sqlite+pysqlite:///{effective_database_path}",
        policy_path=policy_root / "automation-policy.disease-r2.synthetic.json",
        review_package_path=policy_root / "automation-policy-review-package.json",
        profile_path=repository_root / "references/qualification-service-profile.candidate.json",
        adapter_evidence_path=None,
        oidc_issuer=None,
        oidc_audience="control_console_d0",
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
    runtime = load_service_runtime(settings=settings, repository_root=repository_root)
    Base.metadata.create_all(runtime.database.engine)
    runtime.model_route_reconciler.secret_provider = D0LogicalSecretProvider()
    model_catalog = ModelCatalogService(
        database=runtime.database,
        model_routes=runtime.model_route_reconciler,
    )
    DepartmentCockpitService(
        database=runtime.database,
        agent_proposals=model_catalog,
    )
    _seed_model_route(runtime, repository_root)
    _seed_task_scope_fixture(runtime)
    control_console = ControlConsoleService(
        database=runtime.database,
        model_routes=runtime.model_route_reconciler,
        grant_revocations=runtime.grant_revocations,
        model_catalog=model_catalog,
    )

    app = FastAPI(
        title="Orbit Company Control Plane Console D0",
        version="0.1.0-d0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.runtime = runtime
    app.state.control_console = control_console
    app.state.d0_only = True
    app.add_middleware(
        CORSMiddleware,
        allow_origins=sorted(_FRONTEND_ORIGINS),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-Orbit-Request"],
    )

    @app.middleware("http")
    async def loopback_only(request: Request, call_next):
        client_host = request.client.host if request.client else ""
        if client_host not in {_HOST, "::1", "testclient"}:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "d0_loopback_required"},
            )
        return await call_next(request)

    def authenticate_admin(
        request: Request, *, required_roles: frozenset[str]
    ) -> dict[str, Any]:
        del request
        principal = {
            "human_ref": "human_control_plane_admin_syn",
            "display_name": "D0 公司控制台管理员",
            "role_refs": ["role_control_plane_admin"],
        }
        if not required_roles.intersection(principal["role_refs"]):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "human_role_not_allowed")
        return principal

    def require_mutating_admin(
        request: Request, *, required_roles: frozenset[str]
    ) -> dict[str, Any]:
        if (
            request.headers.get("x-orbit-request") != "control-console"
            or request.headers.get("origin") not in _FRONTEND_ORIGINS
        ):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "d0_same_origin_request_required"
            )
        return authenticate_admin(request, required_roles=required_roles)

    @app.get("/health/live")
    def live() -> dict[str, Any]:
        return {
            "status": "live",
            "service_mode": "local_control_console_d0",
            "identity_mode": "fixed_loopback_synthetic_admin",
            "synthetic_only": True,
            "model_execution_started": False,
            "secret_bytes_accessed": False,
            "release_authorization": False,
            "production_authorized": False,
        }

    @app.get("/v1/control-console/bootstrap")
    def bootstrap(request: Request) -> dict[str, Any]:
        principal = authenticate_admin(
            request, required_roles=frozenset({"role_control_plane_admin"})
        )
        return {
            "principal": principal,
            "environment": "loopback_d0_synthetic",
            "navigation": [
                {"id": "overview", "enabled": True},
                {"id": "model_routes", "enabled": True},
                {"id": "runtime_adapters", "enabled": False},
                {"id": "agent_registry", "enabled": False},
                {"id": "task_scope_audit", "enabled": True},
                {"id": "evidence_audit", "enabled": True},
            ],
            "mobile_mutations_enabled": False,
            "release_authorization": False,
        }

    install_control_console_routes(
        app,
        service=control_console,
        authenticate_human=authenticate_admin,
        require_mutating_human=require_mutating_admin,
    )
    install_runtime_artifact_routes(
        app,
        service=runtime.runtime_artifacts,
        authenticate_human=authenticate_admin,
        require_mutating_human=require_mutating_admin,
        require_workload=None,
    )

    frontend_dist = repository_root / "packages/orbit-control-plane-console/dist"
    if frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="console")
    return app


def _seed_model_route(runtime: Any, repository_root: Path) -> None:
    route_path = repository_root / (
        "references/model-route-revisions/"
        "disease-r2-fixture-fixture-structured-v1.public.json"
    )
    observation_path = repository_root / (
        "evidence/model-route/2026-08-28/"
        "fixture-fixture-structured-v1-observation.public.json"
    )
    route = json.loads(route_path.read_text(encoding="utf-8"))
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    observation["observed_at"] = (now - timedelta(minutes=2)).isoformat().replace(
        "+00:00", "Z"
    )
    observation["expires_at"] = (now + timedelta(hours=5, minutes=58)).isoformat().replace(
        "+00:00", "Z"
    )
    store = runtime.model_route_reconciler.store
    store.record_route(route)
    store.record_observation(observation)
    runtime.model_route_reconciler.reconcile(route["route_id"])


def _seed_task_scope_fixture(runtime: Any) -> None:
    route = runtime.model_route_reconciler.store.latest_route(
        "model_route_orbit_disease_r2_fixture_gpt56sol_public"
    )
    if route is None:
        return
    with runtime.database.session() as session:
        row = session.scalar(
            select(DepartmentCockpitObjectRow).where(
                DepartmentCockpitObjectRow.object_type == "task",
                DepartmentCockpitObjectRow.object_id == "task_technology_syn_001",
            )
        )
        if row is None:
            return
        document = dict(row.document)
        document.update(
            {
                "model_route_id": route.route_id,
                "model_route_revision_digest": route.revision_digest,
                "requested_tool_refs": [],
                "allowed_tool_refs": [],
                "requested_dataset_refs": [],
                "allowed_dataset_refs": [],
                "requested_max_cost_usd": "0.10",
                "allowed_max_cost_usd": "0.20",
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(days=1)
                ).isoformat().replace("+00:00", "Z"),
                "runtime_adapter_selectable": True,
                "policy_allows_scope": True,
                "agent_binding_allows_scope": True,
            }
        )
        row.document = document


def app_factory() -> FastAPI:
    return build_d0_app()


def run() -> None:
    uvicorn.run(
        "orbit_agent_control_plane.service_runtime.control_console_d0_main:app_factory",
        factory=True,
        host=_HOST,
        port=_PORT,
        access_log=False,
        reload=False,
    )


def _default_database_path() -> Path:
    configured = os.environ.get("ORBIT_CONTROL_CONSOLE_D0_DATABASE_PATH")
    if configured:
        return Path(configured)
    return (
        Path(tempfile.gettempdir()).resolve()
        / "orbit-control-plane-console-d0"
        / "control-console.sqlite3"
    )


def _prepare_database_path(path: Path) -> None:
    resolved = path.resolve()
    allowed_roots = {
        Path(tempfile.gettempdir()).resolve(),
        Path("/private/tmp").resolve(),
        Path("/tmp").resolve(),
    }
    if (
        not path.is_absolute()
        or path.suffix != ".sqlite3"
        or not any(resolved.is_relative_to(root) for root in allowed_roots)
        or path.is_symlink()
    ):
        raise ValueError("control_console_d0_database_path_invalid")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.resolve() not in allowed_roots:
        os.chmod(path.parent, 0o700)
    if path.exists():
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
        ):
            raise ValueError("control_console_d0_database_path_invalid")
    else:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        os.close(descriptor)
    os.chmod(path, 0o600)

