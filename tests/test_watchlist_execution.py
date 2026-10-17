from __future__ import annotations

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from orbit_agent_control_plane.authorization import (
    SyntheticOperatorGrant,
    authorize_control,
)
from orbit_agent_control_plane.control import TaskController
from orbit_agent_control_plane.cli import main
from orbit_agent_control_plane.ledger import LedgerError, SyntheticTaskLedger
from orbit_agent_control_plane.watchlist_execution import (
    monthly_budget_reason,
    run_watchlist_with_ledger,
    watchlist_task_envelope,
)
from orbit_agent_control_plane.watchlist_process import (
    WatchlistProcessAdapter,
    WatchlistProcessError,
    load_watchlist_implementation_lock,
    materialize_watchlist_runtime_bundle,
    verify_watchlist_runtime_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
STAGE_ROOT = ROOT.parent
REGISTRY = (
    STAGE_ROOT
    / "orbit-health-system"
    / "capabilities"
    / "data-asset-foundation"
    / "dataset-acquisition-registry"
)
SCIENTIFIC = STAGE_ROOT / "orbit-health-system" / "scientific-research-platform"
BASELINE = REGISTRY / "tests" / "fixtures" / "watchlist" / "tpehgdb.synthetic.baseline.json"
CHANGED = REGISTRY / "tests" / "fixtures" / "watchlist" / "tpehgdb.synthetic.changed.json"


class BlockingAdapter:
    def __init__(self, *, cancellation_aware: bool) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancellation_aware = cancellation_aware

    def observe(self, *, cancellation_probe=None, **_kwargs):
        self.started.set()
        while not self.release.wait(0.01):
            if self.cancellation_aware and cancellation_probe and cancellation_probe():
                raise WatchlistProcessError(
                    "watchlist_task_cancelled", "synthetic cancellation"
                )
        raise WatchlistProcessError("synthetic_process_stopped", "synthetic stop")

    def evaluate(self, *_args, **_kwargs):
        raise AssertionError("Scientific process must not start")


class WatchlistTaskIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime_temporary = tempfile.TemporaryDirectory()
        runtime_root = Path(cls.runtime_temporary.name) / "runtime-sources"
        cls.runtime_evidence = materialize_watchlist_runtime_bundle(
            REGISTRY,
            SCIENTIFIC,
            runtime_root,
        )
        cls.registry_runtime = runtime_root / cls.runtime_evidence.registry.runtime_source_name
        cls.scientific_runtime = runtime_root / cls.runtime_evidence.scientific.runtime_source_name

    @classmethod
    def tearDownClass(cls) -> None:
        cls.runtime_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.ledger = self.root / "control.jsonl"
        self.watchlist_ledger = self.root / "registry-watchlist.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_task(self, run_id: str, fixture: Path, adapter=None):
        return run_watchlist_with_ledger(
            ledger_path=self.ledger,
            watchlist_ledger_path=self.watchlist_ledger,
            registry_runtime_source=self.registry_runtime,
            scientific_runtime_source=self.scientific_runtime,
            target="tpehgdb",
            run_id=run_id,
            fixture=fixture,
            monthly_period="2026-08",
            process_adapter=adapter,
        )

    def test_runtime_bundle_is_exact_clean_detached_and_remote_free(self) -> None:
        lock = load_watchlist_implementation_lock()
        verified = verify_watchlist_runtime_bundle(
            self.registry_runtime,
            self.scientific_runtime,
        )
        self.assertEqual(lock.bundle_revision, verified.bundle_revision)
        self.assertEqual(lock.registry.implementation_commit, verified.registry.implementation_revision)
        self.assertEqual(
            lock.scientific.implementation_commit,
            verified.scientific.implementation_revision,
        )
        self.assertTrue(verified.registry.detached_head)
        self.assertTrue(verified.scientific.detached_head)
        self.assertEqual((0, 0), (verified.registry.remote_count, verified.scientific.remote_count))

    def test_baseline_no_change_changed_and_restart_are_one_controlled_chain(self) -> None:
        adapter = WatchlistProcessAdapter(self.registry_runtime, self.scientific_runtime)
        baseline = self.run_task("run_control_baseline_001", BASELINE, adapter)
        unchanged = self.run_task("run_control_unchanged_001", BASELINE, adapter)
        changed = self.run_task("run_control_changed_001", CHANGED, adapter)

        self.assertEqual((0, 0), (
            baseline.outcome.model_invocation_count,
            baseline.outcome.worker_invocation_count,
        ))
        self.assertEqual((0, 0), (
            unchanged.outcome.model_invocation_count,
            unchanged.outcome.worker_invocation_count,
        ))
        self.assertEqual((1, 1), (
            changed.outcome.model_invocation_count,
            changed.outcome.worker_invocation_count,
        ))
        self.assertEqual(69, changed.outcome.monthly_budget_reserved_bytes)
        self.assertEqual(69, SyntheticTaskLedger(self.ledger).replay().monthly_used_bytes("2026-08"))
        self.assertEqual((3, 3), (
            adapter.registry_invocation_count,
            adapter.scientific_invocation_count,
        ))

        restarted = WatchlistProcessAdapter(self.registry_runtime, self.scientific_runtime)
        replayed = self.run_task("run_control_changed_001", CHANGED, restarted)
        self.assertEqual(changed.outcome, replayed.outcome)
        self.assertEqual((0, 0), (
            restarted.registry_invocation_count,
            restarted.scientific_invocation_count,
        ))
        self.assertFalse(dict(replayed.append_results)["task"].appended)
        rendered = json.dumps(replayed.outcome, default=lambda value: value.__dict__)
        self.assertNotIn(str(self.root), rendered)
        self.assertFalse(replayed.outcome.registry_write_performed)
        self.assertFalse(replayed.outcome.real_data_download_performed)
        self.assertFalse(replayed.outcome.release_authorization)

    def test_monthly_budget_math_is_fail_closed(self) -> None:
        self.assertIsNone(monthly_budget_reason(80_000_000_000, 20_000_000_000))
        self.assertEqual(
            "month_size_limit_exceeded",
            monthly_budget_reason(80_000_000_001, 20_000_000_000),
        )
        self.assertEqual(
            "task_size_limit_exceeded",
            monthly_budget_reason(0, 20_000_000_001),
        )
        self.assertEqual("watchlist_budget_input_invalid", monthly_budget_reason(-1, 69))

    def test_cli_run_status_replay_and_runtime_verify(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(
                [
                    "synthetic-watchlist-task",
                    "run",
                    "--ledger",
                    str(self.ledger),
                    "--watchlist-ledger",
                    str(self.watchlist_ledger),
                    "--registry-runtime-source",
                    str(self.registry_runtime),
                    "--scientific-runtime-source",
                    str(self.scientific_runtime),
                    "--target",
                    "tpehgdb",
                    "--run-id",
                    "run_cli_baseline_001",
                    "--fixture",
                    str(BASELINE),
                    "--monthly-period",
                    "2026-08",
                ]
            )
        document = json.loads(output.getvalue())
        self.assertEqual(0, exit_code)
        self.assertEqual((0, 0), (
            document["outcome"]["model_invocation_count"],
            document["outcome"]["worker_invocation_count"],
        ))
        self.assertNotIn(str(self.root), output.getvalue())

        for operation in ("status", "replay"):
            rendered = io.StringIO()
            arguments = [
                "synthetic-watchlist-task",
                operation,
                "--ledger",
                str(self.ledger),
            ]
            if operation == "status":
                arguments.extend(
                    [
                        "--target",
                        "tpehgdb",
                        "--run-id",
                        "run_cli_baseline_001",
                        "--monthly-period",
                        "2026-08",
                    ]
                )
            with redirect_stdout(rendered):
                self.assertEqual(0, main(arguments))
            self.assertEqual("verified", json.loads(rendered.getvalue())["status"])

        verified_output = io.StringIO()
        with redirect_stdout(verified_output):
            self.assertEqual(
                0,
                main(
                    [
                        "watchlist-runtime-source",
                        "verify",
                        "--registry-runtime-source",
                        str(self.registry_runtime),
                        "--scientific-runtime-source",
                        str(self.scientific_runtime),
                    ]
                ),
            )
        self.assertEqual("ready", json.loads(verified_output.getvalue())["status"])

    def test_concurrency_one_rejects_second_run(self) -> None:
        adapter = BlockingAdapter(cancellation_aware=False)
        errors: list[BaseException] = []

        def first() -> None:
            try:
                self.run_task("run_concurrency_first_001", BASELINE, adapter)
            except BaseException as error:  # pragma: no cover - assertion captures it
                errors.append(error)

        thread = threading.Thread(target=first)
        thread.start()
        self.assertTrue(adapter.started.wait(2))
        with self.assertRaises(LedgerError) as caught:
            self.run_task("run_concurrency_second_001", BASELINE, adapter)
        self.assertEqual("watchlist_concurrency_limit_reached", caught.exception.reason_code)
        adapter.release.set()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], errors)

    def test_running_task_is_cancelled_from_replayed_control(self) -> None:
        adapter = BlockingAdapter(cancellation_aware=True)
        errors: list[BaseException] = []

        def running() -> None:
            try:
                self.run_task("run_cancel_active_001", BASELINE, adapter)
            except BaseException as error:  # pragma: no cover - assertion captures it
                errors.append(error)

        thread = threading.Thread(target=running)
        thread.start()
        self.assertTrue(adapter.started.wait(2))
        task = watchlist_task_envelope("tpehgdb", "run_cancel_active_001")
        ledger = SyntheticTaskLedger(self.ledger)
        state = ledger.replay().task(task.task_id)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        grant = SyntheticOperatorGrant(
            version="orbit.synthetic-operator-grant/1",
            grant_id="operator_grant_watchlist_cancel_syn",
            operator_ref="human_operator_watchlist_cancel_syn",
            task_id=task.task_id,
            allowed_actions=("cancel",),
            issued_at=(now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            expires_at=(now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
            evidence_status="synthetic",
            synthetic_only=True,
        )
        checked = now.isoformat().replace("+00:00", "Z")
        authorization = authorize_control(
            grant,
            operator_ref=grant.operator_ref,
            task_id=task.task_id,
            action="cancel",
            request_reason="cancel active synthetic Watchlist Task",
            checked_at=checked,
            confirmed_action="cancel",
        )
        transition = TaskController().apply(
            state.control_snapshot or TaskController.initial(task),
            "cancel",
            actor_id=grant.operator_ref,
        )
        ledger.record_control_attempt(
            authorization,
            transition,
            idempotency_key=f"control:{task.task_id}:cancel-active-001",
        )
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual([], errors)
        replayed = ledger.replay().task(task.task_id)
        self.assertEqual("cancelled", replayed.worker_lease.status)
        self.assertIn("watchlist_task_cancelled", replayed.watchlist_outcome.reason_codes)
        self.assertEqual("cancelled", replayed.control_snapshot.task_status)


if __name__ == "__main__":
    unittest.main()

