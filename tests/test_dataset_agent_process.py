from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from orbit_agent_control_plane.cli import main
from orbit_agent_control_plane.control import TaskController
from orbit_agent_control_plane.dataset_agent_process import (
    DATASET_AGENT_CAPABILITY,
    DATASET_AGENT_ID,
    BoundedProcessRunner,
    DatasetAgentCompanyLoop,
    DatasetAgentProcessAdapter,
    DatasetAgentProcessError,
    ProcessCapture,
    create_dataset_agent_company_loop,
    dataset_synthetic_task,
    load_dataset_agent_implementation_lock,
    verify_dataset_agent_implementation,
)
from orbit_agent_control_plane.models import RoutingTarget
from orbit_agent_control_plane.router import CompanyTaskRouter
from orbit_agent_control_plane.runtime_source import materialize_dataset_runtime_source


ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_PLATFORM = (
    ROOT.parent / "orbit-health-system" / "scientific-research-platform"
)


class FixedRunner:
    def __init__(self, capture: ProcessCapture) -> None:
        self.capture = capture
        self.calls: list[dict[str, object]] = []

    def run(self, argv, **kwargs):
        self.calls.append({"argv": tuple(argv), **kwargs})
        return self.capture


class CountingAdapter:
    def __init__(self, execution=None) -> None:
        self.execution = execution
        self.call_count = 0

    def execute(self, task, route_decision):
        self.call_count += 1
        if self.execution is None:
            raise AssertionError("adapter must not be called")
        return self.execution


class DatasetAgentProcessIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime_temporary = tempfile.TemporaryDirectory()
        runtime_root = Path(cls.runtime_temporary.name) / "runtime-sources"
        evidence = materialize_dataset_runtime_source(
            SCIENTIFIC_PLATFORM,
            runtime_root,
        )
        cls.runtime_source = runtime_root / evidence.runtime_source_name

    @classmethod
    def tearDownClass(cls) -> None:
        cls.runtime_temporary.cleanup()

    def setUp(self) -> None:
        self.task = dataset_synthetic_task()
        self.lock = load_dataset_agent_implementation_lock()
        target = RoutingTarget(
            target_id=DATASET_AGENT_ID,
            capabilities=frozenset({DATASET_AGENT_CAPABILITY}),
            allowed_data_classifications=frozenset({"public"}),
        )
        self.route = CompanyTaskRouter().route(self.task, (target,))

    def valid_domain_stdout(self) -> bytes:
        completed = subprocess.run(
            (
                sys.executable,
                "-m",
                self.lock.python_module,
                self.lock.command,
                "--task-id",
                self.task.task_id,
                "--route-decision-ref",
                self.route.decision_id,
                "--execution-grant-ref",
                self.task.grant_id,
                "--model-route-ref",
                self.lock.model_route_ref,
            ),
            cwd=self.runtime_source,
            env={
                "PYTHONPATH": str(self.runtime_source / "src"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
            },
            check=True,
            capture_output=True,
            timeout=5,
        )
        return completed.stdout

    def test_lock_matches_materialized_clean_runtime_source(self) -> None:
        resolved = verify_dataset_agent_implementation(
            self.runtime_source,
            self.lock,
        )
        self.assertEqual(self.runtime_source.resolve(), resolved)
        self.assertEqual(
            self.lock.implementation_commit,
            subprocess.run(
                ("git", "rev-parse", "HEAD"),
                cwd=self.runtime_source,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip(),
        )

    def test_real_cross_repository_loop_passes_company_evaluation(self) -> None:
        result = create_dataset_agent_company_loop(self.runtime_source).run(self.task)

        self.assertEqual("pass", result.status)
        self.assertEqual(("fixed_suite_pass",), result.reason_codes)
        self.assertEqual("pass", result.company_outcome.evaluation.verdict)
        self.assertFalse(result.company_outcome.evaluation.release_authorization)
        self.assertEqual(DATASET_AGENT_ID, result.company_outcome.result.target_id)
        self.assertEqual(
            "dataset_agent_process_completed",
            result.company_outcome.audit_events[-1].event_type,
        )
        self.assertEqual("verified", result.adapter_evidence.receipt_status)
        self.assertEqual(69, result.adapter_evidence.actual_size_bytes)
        self.assertEqual("0.000000", result.adapter_evidence.model_cost_cny)
        self.assertEqual(4, len(result.adapter_evidence.domain_audit_event_refs))
        self.assertFalse(result.adapter_evidence.storage_write_performed)
        self.assertFalse(result.adapter_evidence.data_use_approved)
        self.assertFalse(result.adapter_evidence.registry_publish_performed)
        self.assertFalse(result.adapter_evidence.approved_asset_release_created)

    def test_control_blocks_before_process_adapter(self) -> None:
        adapter = CountingAdapter()
        transition = TaskController().apply(
            TaskController.initial(self.task),
            "cancel",
            actor_id="human_operator_dataset_integration_syn",
        )

        result = DatasetAgentCompanyLoop(adapter).run(
            self.task,
            control_snapshot=transition.after,
            control_audit_events=(transition.audit_event,),
        )

        self.assertEqual("blocked", result.status)
        self.assertIn("task_cancelled", result.reason_codes)
        self.assertIn("grant_revoked", result.reason_codes)
        self.assertEqual(0, adapter.call_count)
        self.assertIsNone(result.company_outcome.result)
        self.assertIsNone(result.company_outcome.evaluation)

    def test_company_evaluator_does_not_inherit_domain_pass(self) -> None:
        execution = DatasetAgentProcessAdapter(self.runtime_source).execute(
            self.task,
            self.route,
        )
        invalid_execution = replace(
            execution,
            result=replace(execution.result, target_id="agt_orbit_wrong_target_syn"),
        )

        result = DatasetAgentCompanyLoop(CountingAdapter(invalid_execution)).run(
            self.task
        )

        self.assertEqual("fail", result.status)
        self.assertEqual("pass", result.adapter_evidence.domain_evaluation_decision)
        self.assertEqual("fail", result.company_outcome.evaluation.verdict)
        self.assertIn("result_target_mismatch", result.reason_codes)

    def test_wrong_revision_fails_closed_before_process(self) -> None:
        wrong_lock = replace(self.lock, implementation_commit="0" * 40)
        with self.assertRaises(DatasetAgentProcessError) as raised:
            verify_dataset_agent_implementation(self.runtime_source, wrong_lock)
        self.assertEqual("dataset_agent_revision_mismatch", raised.exception.reason_code)

    def test_duplicate_json_is_rejected_and_environment_is_allowlisted(self) -> None:
        runner = FixedRunner(ProcessCapture(0, b'{"a":1,"a":2}', b""))
        adapter = DatasetAgentProcessAdapter(self.runtime_source, runner=runner)

        with patch.dict(os.environ, {"ORBIT_SECRET_SENTINEL": "must-not-pass"}):
            with self.assertRaises(DatasetAgentProcessError) as raised:
                adapter.execute(self.task, self.route)

        self.assertEqual("dataset_agent_duplicate_json_key", raised.exception.reason_code)
        self.assertEqual(1, len(runner.calls))
        call = runner.calls[0]
        self.assertEqual(
            {"PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED"},
            set(call["environment"]),
        )
        self.assertNotIn("ORBIT_SECRET_SENTINEL", call["environment"])
        self.assertNotIn("must-not-pass", " ".join(call["argv"]))
        self.assertNotIn("--endpoint", call["argv"])

    def test_domain_storage_or_authority_claim_fails_closed(self) -> None:
        document = json.loads(self.valid_domain_stdout())
        document["receipt"]["storage_write_performed"] = True
        runner = FixedRunner(
            ProcessCapture(
                0,
                json.dumps(document, sort_keys=True).encode("utf-8"),
                b"",
            )
        )
        adapter = DatasetAgentProcessAdapter(self.runtime_source, runner=runner)

        with self.assertRaises(DatasetAgentProcessError) as raised:
            adapter.execute(self.task, self.route)

        self.assertEqual(
            "dataset_agent_receipt_verification_failed",
            raised.exception.reason_code,
        )

    def test_bounded_runner_stops_oversized_output_and_timeout(self) -> None:
        runner = BoundedProcessRunner()
        with self.assertRaises(DatasetAgentProcessError) as oversized:
            runner.run(
                (sys.executable, "-c", "import sys; sys.stdout.write('x' * 1024)"),
                cwd=ROOT,
                environment={"PYTHONDONTWRITEBYTECODE": "1"},
                timeout_seconds=2,
                max_stdout_bytes=64,
                max_stderr_bytes=64,
            )
        self.assertEqual(
            "dataset_agent_stdout_limit_exceeded",
            oversized.exception.reason_code,
        )

        with self.assertRaises(DatasetAgentProcessError) as timed_out:
            runner.run(
                (sys.executable, "-c", "import time; time.sleep(2)"),
                cwd=ROOT,
                environment={"PYTHONDONTWRITEBYTECODE": "1"},
                timeout_seconds=0.05,
                max_stdout_bytes=64,
                max_stderr_bytes=64,
            )
        self.assertEqual(
            "dataset_agent_process_timeout",
            timed_out.exception.reason_code,
        )

    def test_cli_emits_sanitized_cross_repository_evidence(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(
                [
                    "synthetic-dataset-loop",
                    "--platform-root",
                    str(self.runtime_source),
                ]
            )
        document = json.loads(stdout.getvalue())

        self.assertEqual(0, exit_code)
        self.assertEqual("pass", document["status"])
        self.assertEqual("synthetic", document["evidence_status"])
        self.assertFalse(document["company_authoritative"])
        self.assertNotIn(str(self.runtime_source), stdout.getvalue())
        self.assertEqual(
            "pass",
            document["company_outcome"]["evaluation"]["verdict"],
        )


if __name__ == "__main__":
    unittest.main()

