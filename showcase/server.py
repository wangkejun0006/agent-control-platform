"""Local console: offline actions plus read-only live validation evidence."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from orbit_agent_control_plane.service_runtime.control_console_d0_main import (
    build_d0_app,
)

from .demo import ROOT, run_demo


def create_showcase_app(*, database_path: Path | None = None):
    state_root = ROOT / ".runtime/console"
    state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    local_database = (
        Path(tempfile.gettempdir())
        / f"orbit-control-platform-{os.getuid()}"
        / "console.sqlite3"
    )
    if os.environ.get("ORBIT_CONTROL_CONSOLE_D0_DATABASE_PATH"):
        local_database = Path(os.environ["ORBIT_CONTROL_CONSOLE_D0_DATABASE_PATH"])
    app = build_d0_app(database_path=database_path or local_database)
    router = APIRouter()
    execution_lock = threading.Lock()
    report_path = ROOT / "reports/offline-demo.json"

    @router.get("/v1/showcase/report")
    def report():
        if not report_path.is_file():
            raise HTTPException(404, "offline_demo_not_run")
        return json.loads(report_path.read_text())

    @router.get("/v1/showcase/live-report")
    def live_report():
        path = ROOT / "reports/live-validation.json"
        if not path.is_file() or path.is_symlink():
            raise HTTPException(404, "live_validation_not_available")
        value = json.loads(path.read_text())
        # Read only: viewing the console cannot load a key or make model calls.
        return {key: value[key] for key in (
            "requests", "request_limit", "accounted_cost_cny", "cost_limit_cny",
            "closed", "close_reason", "failed_requests", "human_review_status",
            "data_status", "events",
        )}

    @router.post("/v1/showcase/run")
    def execute(request: Request, body: dict):
        if (
            request.headers.get("x-orbit-request") != "control-console"
            or request.headers.get("origin")
            not in {
                "http://127.0.0.1:8432",
                "http://localhost:8432",
                "http://testserver",
            }
            or body != {}
        ):
            raise HTTPException(403, "offline_demo_fixed_same_origin_request_required")
        if not execution_lock.acquire(blocking=False):
            raise HTTPException(409, "offline_demo_already_running")
        try:
            value = run_demo(state_root / uuid.uuid4().hex)
            temporary = state_root / "latest-report.json"
            temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            # One service process is the supported local boundary; never overwrite a partial report.
            temporary.replace(report_path)
            return value
        finally:
            execution_lock.release()

    # The original console mounts static files last. Insert these exact API
    # routes ahead of that mount without changing its authentication middleware.
    app.router.routes[0:0] = router.routes
    return app


def main():
    import uvicorn
    from .workbench.api import create_workbench_app

    uvicorn.run(create_workbench_app(state_root=os.environ.get("ORBIT_WORKBENCH_STATE_ROOT")), host="127.0.0.1", port=8432, access_log=False)


if __name__ == "__main__":
    main()
