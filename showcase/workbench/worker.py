"""Single offline Worker using native queue, signed grants and process isolation."""

import argparse
import ctypes
import fcntl
import os
import signal
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.models import (
    RuntimeRunRow,
    WorkerLeaseRow,
)
from orbit_agent_control_plane.service_runtime.repositories import (
    SqlAuditExporter,
    SqlWorkerLeaseCoordinator,
)
from orbit_agent_control_plane.service_runtime.runner_queue import DurableRunnerWorker
from showcase.live_budget import (
    LiveError,
    atomic_private,
    digest,
    private_read,
    require,
    strict_json,
)

from .assets import DeliveryAssets
from .service import queue_components, source_revision
from .tools import run_professional


class ProfessionalHandler:
    def __init__(self, root):
        self.root = Path(root)

    def __call__(self, invocation):
        try:
            return self._execute(invocation)
        except LiveError as error:
            error.reason_code = str(error)
            raise

    def _execute(self, invocation):
        parent = os.getppid()
        # Linux child dies if the supervising Worker is killed. The API process
        # launches that Worker with an environment allowlist, without model keys.
        if os.name == "posix":
            ctypes.CDLL(None).prctl(1, signal.SIGTERM)
            require(os.getppid() == parent, "worker_parent_changed")
        require(
            invocation["operation"] == "run_delivery_professional",
            "runtime_handler_not_registered",
        )
        require(
            invocation["runtime_source_digest"] == source_revision(),
            "delivery_source_drift",
        )
        name = invocation["grant_id"]
        require(
            name.startswith("grant_delivery_") and name.replace("_", "").isalnum(),
            "grant_identifier_invalid",
        )
        snapshot = strict_json(private_read(self.root / (name + ".json")))
        require(
            invocation["grant_digest"]
            == digest({"grant": name, "snapshot": digest(snapshot)})
            and invocation["task_digest"] == digest(snapshot["task_binding"])
            and invocation["input_refs"] == [snapshot["manifest_ref"]],
            "execution_grant_snapshot_mismatch",
        )
        require(
            snapshot["source_revision"] == invocation["runtime_source_digest"]
            and snapshot["task_id"] == invocation["task_id"],
            "execution_snapshot_mismatch",
        )
        require(
            not any("KEY" in key or "TOKEN" in key for key in os.environ),
            "worker_credential_environment_forbidden",
        )
        atomic_private(
            self.root / ("process-" + name + ".json"),
            {
                "pid": os.getpid(),
                "worker_pid": parent,
                "started_at": int(time.time()),
                "task_id": snapshot["task_id"],
            },
        )
        assets = DeliveryAssets(self.root)
        require(
            assets.agents.replay()
            .agent("agt_delivery_" + snapshot["department_id"])
            .status
            == "active",
            "agent_not_active",
        )
        require(
            all(state.status == "active" for state in assets.tools.replay().tools),
            "tool_not_active",
        )
        if snapshot.get("model_mode") == "live_authorized_campaign":
            from .live import LiveDecisionPort

            result = run_professional(
                snapshot,
                decision_port=LiveDecisionPort(self.root / "model-ipc", snapshot, name),
            )
        else:
            result = run_professional(snapshot)
        require(
            source_revision() == invocation["runtime_source_digest"],
            "delivery_source_drift",
        )
        return result


def recover_interrupted(database):
    """Under the single Worker lock: preserve unknown runs; never rerun them."""
    with database.session() as session:
        for row in session.scalars(
            select(RuntimeRunRow).where(
                RuntimeRunRow.invocation["operation"].as_string()
                == "run_delivery_professional",
                RuntimeRunRow.status == "running",
            )
        ):
            row.status, row.failure_reason_code = (
                "failed",
                "runtime_interrupted_unknown",
            )
            row.closed_at = datetime.now(timezone.utc)
            row.revision += 1
            for lease in session.scalars(
                select(WorkerLeaseRow).where(
                    WorkerLeaseRow.run_id == row.run_id,
                    WorkerLeaseRow.status == "active",
                )
            ):
                lease.status, lease.outcome, lease.closed_at = (
                    "closed",
                    "failed",
                    datetime.now(timezone.utc),
                )


def run_once(root, *, recover=False):
    database = Database("sqlite+pysqlite:///" + str(Path(root) / "state.sqlite3"))
    try:
        _, _, grants, _ = queue_components(database, Path(root))
        if recover:
            recover_interrupted(database)
        worker = DurableRunnerWorker(
            database,
            grants=grants,
            leases=SqlWorkerLeaseCoordinator(database),
            audit=SqlAuditExporter(database),
            handlers={"run_delivery_professional": ProfessionalHandler(root)},
            worker_identity="workload_delivery_runner",
        )
        return worker.run_once()
    finally:
        database.dispose()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)

    def deny_network(*_args, **_kwargs):
        raise RuntimeError("offline_worker_network_forbidden")

    # Inherited by tool handler processes; not an OS security sandbox.
    socket.socket.connect = deny_network
    socket.socket.connect_ex = deny_network
    socket.create_connection = deny_network
    socket.getaddrinfo = deny_network
    require(
        not args.root.is_symlink() and args.root.stat().st_mode & 0o077 == 0,
        "worker_directory_invalid",
    )
    fd = os.open(
        args.root / "worker.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Only after acquiring the single-writer lock: a terminated predecessor
        # may leave a heartbeat write half-finished. Keep it as evidence rather
        # than treating this non-authoritative liveness projection as a ledger.
        pending = args.root / "worker-heartbeat.json.pending"
        if pending.exists() or pending.is_symlink():
            private_read(pending)
            os.rename(
                pending,
                args.root / f"worker-heartbeat.interrupted-{time.time_ns()}.json",
            )
        recover = True
        while True:
            atomic_private(
                args.root / "worker-heartbeat.json",
                {
                    "pid": os.getpid(),
                    "at": int(time.time()),
                    "mode": "offline_single_worker",
                },
            )
            run_once(args.root, recover=recover)
            recover = False
            if args.once:
                break
            time.sleep(0.2)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
