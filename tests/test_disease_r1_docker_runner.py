from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from orbit_agent_control_plane.disease_r1 import (
    evaluate_worker_response,
    grant_from_mapping,
    plan_disease_r1,
)
from orbit_agent_control_plane.disease_r1_review import (
    DiseaseR1ReviewError,
    verify_disease_r1_review,
)

ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_ROOT = ROOT.parent / "orbit-health-system" / "scientific-research-platform"
sys.path.insert(0, str(SCIENTIFIC_ROOT / "src"))
from orbit_scientific_research_platform.disease_research import (
    ipc as disease_ipc,
)

RUNNER_PATH = ROOT / "scripts" / "run_disease_r1_docker.py"
CONTAINER_RUNNER_PATH = ROOT / "scripts" / "run_disease_r1.py"
REVIEW = (
    ROOT
    / "evidence/disease-agent-r1/2026-08-26/retry-004/execution-review-request.json"
)
LIFECYCLE_SNAPSHOT = (
    ROOT
    / "evidence/publication-baseline/2026-08-26/"
    "disease-lifecycle.snapshot.synthetic.jsonl"
)
PRIOR_TASK_SNAPSHOT = (
    ROOT
    / "evidence/publication-baseline/2026-08-26/"
    "disease-r1-retry-003-task.snapshot.synthetic.jsonl"
)


def load_runner():
    spec = importlib.util.spec_from_file_location("disease_r1_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("R1 Docker runner unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_container_runner():
    spec = importlib.util.spec_from_file_location(
        "disease_r1_container_runner", CONTAINER_RUNNER_PATH
    )
    if spec is None or spec.loader is None:
        raise AssertionError("R1 container runner unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DiseaseR1DockerRunnerTest(unittest.TestCase):
    def test_exact_inner_worker_passes_json_stdio_process_boundary(self) -> None:
        docker_runner = load_runner()
        container_runner = load_container_runner()
        review = verify_disease_r1_review(ROOT, REVIEW)
        grant = grant_from_mapping(review.synthetic_grant)
        plan = plan_disease_r1(
            grant,
            checked_at="2026-08-26T00:05:00Z",
            lifecycle_status="active",
            lifecycle_release_digest=grant.agent_release_digest,
        )
        task_input = docker_runner._task_input(SCIENTIFIC_ROOT, plan)
        event = disease_ipc.build_task_event(
            task_input,
            event_id="drevent_orbit_disease_r1_process_test_syn",
            company_task_id=plan.task.task_id,
            invocation_id="inv_orbit_disease_r1_process_test_syn",
            runtime_adapter_ref={
                "id": "runtime_adapter_orbit_disease_r1_syn",
                "version": "0.1.0",
                "digest": grant.runtime_source_digest,
            },
        )
        request = disease_ipc.build_ipc_request(event, request_id=plan.request_id)
        encoded = json.dumps(
            request,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as workdir:
            completed = subprocess.run(
                container_runner._worker_command(SCIENTIFIC_ROOT),
                input=encoded + b"\n",
                capture_output=True,
                cwd=workdir,
                env={
                    "PYTHONHASHSEED": "0",
                    "ORBIT_RUNTIME_EVIDENCE": "synthetic-r1-process-test",
                },
                check=False,
                close_fds=True,
                start_new_session=True,
                timeout=20,
            )
        self.assertEqual(0, completed.returncode, completed.stderr.decode("ascii"))
        self.assertEqual(b"", completed.stderr)
        response = json.loads(completed.stdout)
        evaluated = evaluate_worker_response(plan, response)
        self.assertEqual("pass", evaluated.domain_evaluation.verdict)
        self.assertEqual("pass", evaluated.company_outcome.evaluation.verdict)

    def test_container_wrapper_propagates_only_sanitized_child_codes(self) -> None:
        runner = load_container_runner()
        self.assertEqual(
            "ipc_environment_not_allowlisted",
            runner._safe_child_error_code(b"ipc_environment_not_allowlisted"),
        )
        self.assertIsNone(runner._safe_child_error_code(b"contains /Users/private"))
        self.assertIsNone(runner._safe_child_error_code(b"A" * 129))
        error = runner.RunnerError("inner_worker_exit_nonzero")
        self.assertEqual("inner_worker_exit_nonzero", error.code)

    def test_failure_diagnostics_are_sanitized_and_classified(self) -> None:
        runner = load_runner()
        self.assertEqual(
            "ipc_environment_not_allowlisted",
            runner._safe_child_error_code(b"ipc_environment_not_allowlisted"),
        )
        self.assertIsNone(runner._safe_child_error_code(b"contains /Users/private"))
        self.assertIsNone(runner._safe_child_error_code(b"A" * 129))
        self.assertEqual(
            "r1_worker_output_json_invalid",
            runner._failure_reason_code(
                runner.json.JSONDecodeError("invalid", "{", 1)
            ),
        )
        self.assertEqual(
            "r1_container_result_invalid",
            runner._failure_reason_code(RuntimeError("private detail")),
        )

    def test_bundle_is_minimal_read_only_and_matches_review(self) -> None:
        runner = load_runner()
        review = verify_disease_r1_review(ROOT, REVIEW)
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            bundle.mkdir()
            runner._prepare_bundle(bundle, ROOT, SCIENTIFIC_ROOT)
            files = runner._bundle_files(bundle)
            paths = [entry["path"] for entry in files]
            self.assertIn("control/scripts/run_disease_r1.py", paths)
            self.assertIn(
                "scientific/src/orbit_scientific_research_platform/"
                "disease_research/r1_worker.py",
                paths,
            )
            self.assertFalse(any("dataset_agent" in path for path in paths))
            self.assertFalse(any(".env" in path for path in paths))
            self.assertFalse(any(path.is_symlink() for path in bundle.rglob("*")))
            self.assertEqual(review.runtime_source_digest, runner._tree_digest(bundle))
            self.assertTrue(
                all(
                    (path.stat().st_mode & 0o222) == 0
                    for path in bundle.rglob("*")
                    if path.is_file()
                )
            )

    def test_docker_command_has_no_network_or_output_mount(self) -> None:
        runner = load_runner()
        command = runner._docker_command(
            name="orbit-disease-r1-test",
            bundle=Path("/private/tmp/orbit-disease-r1-bundle"),
            image_id="sha256:" + ("a" * 64),
        )
        joined = " ".join(command)
        for expected in (
            "--pull never",
            "--network none",
            "--read-only",
            "--user 65532:65532",
            "--memory 256m",
            "--cpus 1",
            "--pids-limit 64",
            "--security-opt no-new-privileges",
            "--cap-drop ALL",
            "--ulimit nofile=64:64",
            "--tmpfs /work:rw,noexec,nosuid,nodev",
            "dst=/bundle,readonly",
            "--entrypoint /usr/bin/env",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, joined)
        self.assertNotIn("/Users", joined)
        self.assertNotIn("/Volumes", joined)
        self.assertNotIn("docker.sock", joined)
        self.assertNotIn("dst=/evidence", joined)
        image_index = command.index("sha256:" + ("a" * 64))
        self.assertIn("-i", command[2:image_index])
        self.assertEqual("-i", command[image_index + 1])
        self.assertEqual(2, command.count("-i"))

    def test_missing_execution_approval_blocks_before_docker_and_ledger(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task_ledger = root / "task.jsonl"
            output = root / "result.json"
            lifecycle_ledger = root / "lifecycle.synthetic.jsonl"
            prior_task_ledger = root / "prior-task.synthetic.jsonl"
            lifecycle_ledger.write_bytes(LIFECYCLE_SNAPSHOT.read_bytes())
            prior_task_ledger.write_bytes(PRIOR_TASK_SNAPSHOT.read_bytes())
            os.chmod(lifecycle_ledger, 0o600)
            os.chmod(prior_task_ledger, 0o600)
            prepare = runner.prepare_disease_r1_review

            def prepare_with_published_prior(
                control: Path,
                review_request: Path,
                lifecycle: Path,
            ):
                return prepare(
                    control,
                    review_request,
                    lifecycle,
                    prior_task_ledger=prior_task_ledger,
                )

            with mock.patch.object(runner, "_image_id") as image_id, mock.patch.object(
                runner.subprocess, "Popen"
            ) as popen, mock.patch.object(
                runner,
                "prepare_disease_r1_review",
                side_effect=prepare_with_published_prior,
            ):
                with self.assertRaises(DiseaseR1ReviewError) as raised:
                    runner.run(
                        control=ROOT,
                        scientific=SCIENTIFIC_ROOT,
                        review_request=REVIEW,
                        approval=root / "missing-approval.json",
                        lifecycle_ledger=lifecycle_ledger,
                        task_ledger=task_ledger,
                        output=output,
                        image=runner.DEFAULT_IMAGE,
                    )
                self.assertEqual("r1_control_source_drift", raised.exception.reason_code)
                image_id.assert_not_called()
                popen.assert_not_called()
                self.assertFalse(task_ledger.exists())
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()

