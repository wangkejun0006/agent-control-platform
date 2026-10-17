"""One loopback app with real local sessions, native BFF, and delivery APIs."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, inspect

from orbit_agent_control_plane.service_runtime.cockpit_local_identity_api import (
    authenticate_cockpit_local_human,
)
from orbit_agent_control_plane.service_runtime.control_console import (
    ControlConsoleService,
)
from orbit_agent_control_plane.service_runtime.control_console_api import (
    install_control_console_routes,
)
from orbit_agent_control_plane.service_runtime.control_console_d0_main import (
    D0LogicalSecretProvider,
    _seed_model_route,
    _seed_task_scope_fixture,
)
from orbit_agent_control_plane.service_runtime.department_cockpit_d0_main import (
    build_d0_app,
)
from orbit_agent_control_plane.service_runtime.runtime_artifact_api import (
    install_runtime_artifact_routes,
)
from showcase.live_budget import LiveError, private_read, require

from .service import (
    DEPARTMENTS,
    ROOT,
    DeliveryService,
    OfflineDeliveryPlanningPort,
    legacy_human_ref,
)
from .storage import DeliveryRecordRow

ORIGINS = frozenset(
    {
        "http://127.0.0.1:8432",
        "http://localhost:8432",
        "http://127.0.0.1:4174",
        "http://localhost:4174",
        "http://testserver",
    }
)
ROLES = frozenset(
    {"role_control_plane_admin", "role_department_owner", "role_department_user"}
)


def migrate_delivery_index(database_path):
    if database_path.exists() or database_path.is_symlink():
        private_read(database_path)
    engine = create_engine("sqlite+pysqlite:///" + str(database_path))
    try:
        if not inspect(engine).has_table("orbit_delivery_records"):
            source = ROOT / "alembic/versions/20261016_0017_delivery_workbench.py"
            spec = importlib.util.spec_from_file_location(
                "delivery_additive_migration", source
            )
            migration = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(migration)
            with (
                engine.begin() as connection,
                Operations.context(MigrationContext.configure(connection)),
            ):
                migration.upgrade()
    finally:
        engine.dispose()


def create_workbench_app(
    *, state_root=None, start_worker=True, password_scrypt_n=2**17, live_campaign=None
):
    os.umask(0o077)
    root = Path(state_root) if state_root else ROOT / ".runtime/workbench"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(
        not root.is_symlink() and root.stat().st_mode & 0o077 == 0,
        "workbench_private_directory_required",
    )
    migrate_delivery_index(root / "state.sqlite3")
    app = build_d0_app(
        database_path=root / "state.sqlite3",
        password_scrypt_n=password_scrypt_n,
        frontend_origins=ORIGINS,
        private_state_root=root
        if root.absolute().is_relative_to(ROOT / ".runtime" / "workbench")
        else None,
    )
    runtime, cockpit = app.state.runtime, app.state.department_cockpit
    # Bootstrap only this additive table; never migrate or modify old demo DBs.
    DeliveryRecordRow.__table__.create(runtime.database.engine, checkfirst=True)
    cockpit.model_port = OfflineDeliveryPlanningPort()
    runtime.model_route_reconciler.secret_provider = D0LogicalSecretProvider()
    _seed_model_route(runtime, ROOT)
    _seed_task_scope_fixture(runtime)
    service = DeliveryService(runtime, cockpit, root)
    broker = None
    if live_campaign is not None:
        from .live import (
            DeliveryModelBroker,
            LiveDeliveryPlanningPort,
            LiveDeliveryRoutes,
        )

        state = live_campaign.state()
        require(
            not state["closed"]
            and (state.get("input_price"), state.get("output_price")) == (3, 12),
            "live_campaign_authorization_invalid",
        )
        require(
            root.resolve() != (ROOT / ".runtime/workbench").resolve(),
            "live_requires_separate_state_directory",
        )
        service.live_campaign = live_campaign
        cockpit.model_port = LiveDeliveryPlanningPort(live_campaign)
        cockpit.model_route_catalog = LiveDeliveryRoutes()
        cockpit.planning_workflow_departments = frozenset(DEPARTMENTS)
        for selection in list(cockpit.agent_model_route_selections.values()):
            route = cockpit.model_route_catalog.routes(
                department_id=selection["department_id"]
            )[0]
            if selection["route_revision_digest"] != route["route_revision_digest"]:
                cockpit.select_agent_model_route(
                    department_id=selection["department_id"],
                    agent_binding_ref=selection["agent_binding_ref"],
                    route_id=route["route_id"],
                    route_revision_digest=route["route_revision_digest"],
                    expected_selection_digest=selection["selection_digest"],
                    idempotency_key="workbench-live-route:"
                    + selection["agent_binding_ref"],
                    actor_ref="human_validation_route_operator_syn",
                )
        broker = DeliveryModelBroker(service, live_campaign)
    app.state.delivery_broker = broker
    app.state.delivery = service
    app.state.worker_process = None
    app.router.routes = [
        route
        for route in app.router.routes
        if getattr(route, "path", None) not in {"/health/live", "/health/ready"}
    ]

    @app.get("/health/live")
    def health_live():
        process = app.state.worker_process
        return {
            "status": "live",
            "service_mode": "local_delivery_workbench",
            "identity_mode": "loopback_d0_local_account_session",
            "live_model_enabled": live_campaign is not None,
            "professional_runtime_started": bool(process and process.poll() is None),
            "production_authorized": False,
            "release_authorization": False,
        }

    @app.get("/health/ready")
    def health_ready():
        database_ready = runtime.database.ping()
        process = app.state.worker_process
        worker_ready = bool(process and process.poll() is None)
        if not database_ready or (start_worker and not worker_ready):
            raise HTTPException(503, "workbench_database_or_worker_not_ready")
        return {
            "status": "local_ready",
            "database_ready": database_ready,
            "professional_runtime_ready": worker_ready,
            "manual_test_worker": not start_worker,
            "live_model_enabled": live_campaign is not None,
            "production_authorized": False,
        }

    def principal(request, *, write=False, admin=False):
        if write and (
            request.headers.get("origin") not in ORIGINS
            or request.headers.get("x-orbit-request")
            not in {"department-cockpit", "control-console"}
        ):
            raise HTTPException(403, "same_origin_request_required")
        return authenticate_cockpit_local_human(
            app.state.cockpit_local_identity,
            request,
            required_roles=frozenset({"role_control_plane_admin"}) if admin else ROLES,
        )

    def legacy_admin(request, *, write=False):
        actor = principal(request, write=write, admin=True)
        return {
            **actor,
            "human_ref": legacy_human_ref(actor["human_ref"]),
            "identity_source_ref": actor["human_ref"],
        }

    @app.exception_handler(LiveError)
    async def live_error(_request, error):
        return JSONResponse({"detail": str(error)}, status_code=409)

    @app.exception_handler(ValueError)
    async def value_error(_request, error):
        return JSONResponse(
            {"detail": getattr(error, "reason_code", str(error))}, status_code=409
        )

    @asynccontextmanager
    async def lifespan(_app):
        process = None
        if broker:
            broker.start()

        async def reconcile():
            while True:
                try:
                    await asyncio.to_thread(service.reconcile)
                    app.state.reconciliation_error = None
                except Exception as error:  # noqa: BLE001 - fail closed, no payload/credential logging
                    app.state.reconciliation_error = type(error).__name__
                await asyncio.sleep(0.3)

        task = asyncio.create_task(reconcile())
        if start_worker:
            environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "LANG": "C.UTF-8",
                "PYTHONHASHSEED": "0",
            }
            log_fd = os.open(
                root / "worker.log",
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(log_fd, "ab") as worker_log:
                process = await asyncio.to_thread(
                    subprocess.Popen,
                    [
                        sys.executable,
                        "-m",
                        "showcase.workbench.worker",
                        "--root",
                        str(root),
                    ],
                    cwd=ROOT,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=worker_log,
                )
            app.state.worker_process = process
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if broker:
                await asyncio.to_thread(broker.close)
            cockpit.transport.close()
            runtime.database.dispose()

    app.router.lifespan_context = lifespan

    @app.get("/v1/workflows")
    def workflows(request: Request):
        actor = principal(request)
        return {
            "items": [
                service.view(actor, w["workflow_id"])
                for w in service.store.list("workflow")
            ]
        }

    @app.get("/v1/control-console/bootstrap")
    def governance_bootstrap(request: Request):
        actor = principal(request, admin=True)
        return {
            "principal": actor,
            "environment": "loopback_local_account_session",
            "navigation": [
                {"id": item, "enabled": True}
                for item in (
                    "overview",
                    "model_routes",
                    "task_scope_audit",
                    "evidence_audit",
                )
            ],
            "mobile_mutations_enabled": False,
            "release_authorization": False,
        }

    async def body_for(request):
        raw = await request.body()
        require(len(raw) <= 400_000, "request_too_large")
        from showcase.live_budget import strict_json

        body = strict_json(raw)
        require(isinstance(body, dict), "request_object_required")
        key = body.pop("idempotency_key", "")
        return body, key

    @app.post("/v1/workflows", status_code=201)
    async def create_workflow(request: Request):
        actor = principal(request, write=True)
        body, key = await body_for(request)
        require(
            set(body) <= {"title", "goal", "department_id", "scenario"},
            "unknown_fields",
        )
        return service.command(
            actor,
            key,
            {"operation": "create", **body},
            lambda: service.create(actor, body),
        )

    @app.get("/v1/workflows/{workflow_id}")
    def workflow_detail(workflow_id: str, request: Request):
        return service.view(principal(request), workflow_id)

    @app.get("/v1/workflows/{workflow_id}/events")
    def workflow_events(workflow_id: str, request: Request, after_sequence: int = -1):
        value = service.view(principal(request), workflow_id)
        return {
            "events": [e for e in value["events"] if e["sequence"] > after_sequence]
        }

    @app.post("/v1/workflows/{workflow_id}/{action}")
    async def workflow_action(workflow_id: str, action: str, request: Request):
        actor = principal(request, write=True)
        body, key = await body_for(request)
        require(
            action in {"import-fixtures", "artifacts", "deliver"},
            "workflow_action_invalid",
        )
        allowed = {
            "import-fixtures": set(),
            "artifacts": {
                "department_id",
                "filename",
                "document_id",
                "version",
                "content_base64",
            },
            "deliver": {"reason"},
        }[action]
        require(set(body) <= allowed, "unknown_fields")

        def operation():
            if action == "import-fixtures":
                return service.import_fixtures(actor, workflow_id)
            if action == "artifacts":
                return service.upload(actor, workflow_id, body)
            return service.deliver(actor, workflow_id, body.get("reason", ""))

        return service.command(
            actor,
            key,
            {"workflow_id": workflow_id, "action": action, **body},
            operation,
        )

    @app.post("/v1/workflows/{workflow_id}/departments/{department}/{action}")
    async def department_action(
        workflow_id: str, department: str, action: str, request: Request
    ):
        actor = principal(request, write=True)
        body, key = await body_for(request)
        require(department in DEPARTMENTS, "department_invalid")
        allowed = {
            "plan": set(),
            "answers": {"answers", "supplement"},
            "approve-plan": {"reason", "package_digest"},
            "execute": set(),
            "review": {
                "decision",
                "reason",
                "candidate_digest",
                "revision",
                "handoff_to",
            },
            "handoff": {"target_department"},
            "revise": {"reason", "acknowledge_uncertain", "revision_kind"},
            "cancel": set(),
            "revoke": set(),
        }
        require(
            action in allowed and set(body) <= allowed[action],
            "department_action_or_fields_invalid",
        )

        def operation():
            if action == "plan":
                return service.start_plan(actor, workflow_id, department, key)
            if action == "answers":
                return service.answer(actor, workflow_id, department, body, key)
            if action == "approve-plan":
                return service.approve_plan(actor, workflow_id, department, body, key)
            if action == "execute":
                return service.execute(actor, workflow_id, department, key)
            if action == "review":
                return service.review(actor, workflow_id, department, body, key)
            if action == "revise":
                return service.revise(actor, workflow_id, department, body, key)
            if action in {"cancel", "revoke"}:
                return service.cancel(
                    actor, workflow_id, department, revoke=action == "revoke"
                )
            service.handoff(
                actor, workflow_id, department, body.get("target_department")
            )
            return service.view(actor, workflow_id)

        return service.command(
            actor,
            key,
            {
                "workflow_id": workflow_id,
                "department": department,
                "action": action,
                **body,
            },
            operation,
        )

    @app.get("/v1/workbench/assets")
    def asset_catalog(request: Request):
        principal(request)
        return service.catalog()

    @app.post("/v1/workbench/assets/{kind}/{identity}/{action}")
    async def asset_action(kind: str, identity: str, action: str, request: Request):
        actor = principal(request, write=True, admin=True)
        body, key = await body_for(request)
        require(not body, "unknown_fields")
        return service.command(
            actor,
            key,
            {"kind": kind, "identity": identity, "action": action},
            lambda: service.asset_action(
                kind, identity, action, actor["human_ref"], key
            ),
        )

    @app.post("/v1/workbench/assets/batch/{action}")
    async def batch_asset_action(action: str, request: Request):
        actor = principal(request, write=True, admin=True)
        body, key = await body_for(request)
        require(set(body) == {"items"}, "asset_batch_fields_invalid")
        return service.command(
            actor,
            key,
            {"action": action, **body},
            lambda: service.asset_batch(action, body["items"], actor["human_ref"], key),
        )

    @app.get("/v1/workbench/runtime")
    def runtime_status(request: Request):
        principal(request, admin=True)
        process = app.state.worker_process
        return {
            **service.runtime_status(),
            **({"worker_online": process.poll() is None} if process else {}),
            "reconciliation_error": getattr(app.state, "reconciliation_error", None),
        }

    @app.get("/v1/workflows/{workflow_id}/download")
    def download(workflow_id: str, request: Request):
        actor = principal(request, admin=True)
        view = service.view(actor, workflow_id)
        require(view["delivery"] is not None, "当前版本尚未完成最终审核")
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            for node in view["nodes"]:
                payload = node["candidate"]["payload"]
                archive.writestr(node["department_id"] + ".md", payload["body"])
                archive.writestr(
                    node["department_id"] + "-evidence.json",
                    json.dumps(payload, ensure_ascii=False, indent=2),
                )
            archive.writestr(
                "review-records.json",
                json.dumps(
                    service.store.list("review", workflow_id),
                    ensure_ascii=False,
                    indent=2,
                ),
            )
            archive.writestr(
                "delivery.json",
                json.dumps(view["delivery"], ensure_ascii=False, indent=2),
            )
        return Response(
            stream.getvalue(),
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="local-delivery.zip"'
            },
        )

    control = ControlConsoleService(
        database=runtime.database,
        model_routes=runtime.model_route_reconciler,
        grant_revocations=runtime.grant_revocations,
        model_catalog=cockpit.agent_proposals,
    )
    install_control_console_routes(
        app,
        service=control,
        authenticate_human=lambda request, **_: legacy_admin(request),
        require_mutating_human=lambda request, **_: legacy_admin(request, write=True),
    )
    install_runtime_artifact_routes(
        app,
        service=runtime.runtime_artifacts,
        authenticate_human=lambda request, **_: legacy_admin(request),
        require_mutating_human=lambda request, **_: legacy_admin(request, write=True),
        require_workload=None,
    )

    @app.get("/v1/showcase/report")
    def offline_report(request: Request):
        principal(request)
        return json.loads((ROOT / "reports/offline-demo.json").read_text())

    @app.get("/v1/showcase/workbench-live-report")
    def workbench_live_report(request: Request):
        principal(request, admin=True)
        path = ROOT / "reports/workbench-live-validation.json"
        if not path.is_file():
            raise HTTPException(404, "workbench_live_report_not_available")
        report = json.loads(path.read_text())
        fix_path = ROOT / "reports/sharing-semantics-validation.json"
        if fix_path.is_file():
            report["offline_sharing_fix"] = json.loads(fix_path.read_text())
        return report

    def public_history_bytes(path):
        # Public Git files may be 0644. Do not weaken private_read for secrets,
        # databases or private runtime evidence; validate the fixed public set.
        folder = ROOT / "examples/historical-workbench"
        manifest = folder / "artifact-sha256.json"
        require(
            not path.is_symlink()
            and path.resolve().parent == folder.resolve()
            and not manifest.is_symlink(),
            "public_history_path_invalid",
        )
        expected = json.loads(manifest.read_text())
        raw = path.read_bytes()
        require(
            hashlib.sha256(raw).hexdigest() == expected.get(path.name),
            "public_history_digest_mismatch",
        )
        return raw

    @app.get("/v1/showcase/workbench-live-comparison")
    def workbench_live_comparison(request: Request):
        principal(request, admin=True)
        path = ROOT / "examples/historical-workbench/rework-comparison.json"
        if not path.is_file():
            raise HTTPException(404, "private_validation_comparison_not_available")
        return json.loads(public_history_bytes(path))

    @app.get("/v1/showcase/workbench-live-delivery")
    def workbench_live_delivery(request: Request):
        principal(request, admin=True)
        path = ROOT / "examples/historical-workbench/delivery.zip"
        if not path.is_file():
            raise HTTPException(404, "private_validation_delivery_not_available")
        return Response(
            public_history_bytes(path),
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="workbench-live-delivery.zip"'
            },
        )

    @app.get("/v1/showcase/live-report")
    def historical_live(request: Request):
        principal(request)
        report = json.loads((ROOT / "reports/live-validation.json").read_text())
        return {
            k: report[k]
            for k in (
                "requests",
                "request_limit",
                "accounted_cost_cny",
                "cost_limit_cny",
                "closed",
                "close_reason",
                "failed_requests",
                "human_review_status",
                "data_status",
                "events",
            )
        }

    @app.post("/v1/showcase/run")
    def old_demo(request: Request, body: dict):
        principal(request, write=True, admin=True)
        require(body == {}, "fixed_demo_body_required")
        from showcase.demo import run_demo

        return run_demo(root / ("legacy-demo-" + __import__("uuid").uuid4().hex))

    frontend = ROOT / "packages/orbit-control-plane-console/dist"
    if frontend.is_dir():
        app.mount("/", StaticFiles(directory=frontend, html=True), name="workbench")
    return app
