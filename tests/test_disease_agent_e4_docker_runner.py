from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_ROOT = ROOT.parent / "orbit-health-system" / "scientific-research-platform"
RUNNER_PATH = ROOT / "scripts" / "run_disease_agent_e4_docker.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("disease_e4_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("runner module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DiseaseAgentE4DockerRunnerTest(unittest.TestCase):
    def test_bundle_is_minimal_read_only_and_content_addressed(self) -> None:
        runner = load_runner()
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            bundle.mkdir()
            runner._prepare_bundle(bundle, ROOT, SCIENTIFIC_ROOT)
            files = sorted(
                path.relative_to(bundle).as_posix()
                for path in bundle.rglob("*")
                if path.is_file()
            )
            self.assertIn(
                "scientific/src/orbit_scientific_research_platform/disease_research/r1_worker.py",
                files,
            )
            self.assertIn(
                "scientific/contracts/disease-research/fixtures/synthetic/fictional-stationery.task-input.synthetic.json",
                files,
            )
            self.assertFalse(any("dataset_agent" in path for path in files))
            self.assertFalse(any(".env" in path for path in files))
            self.assertFalse(any(path.is_symlink() for path in bundle.rglob("*")))
            first = runner._tree_digest(bundle)
            second = runner._tree_digest(bundle)
            self.assertEqual(first, second)
            self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")
            self.assertTrue(
                all(
                    (path.stat().st_mode & 0o222) == 0
                    for path in bundle.rglob("*")
                    if path.is_file()
                )
            )

    def test_docker_command_enforces_e4_isolation_and_no_output_mount(self) -> None:
        runner = load_runner()
        command = runner._docker_command(
            name="orbit-disease-e4-test",
            bundle=Path("/private/tmp/orbit-disease-e4-bundle"),
            image="example.invalid/orbit/e4:test",
            image_id="sha256:" + ("a" * 64),
            runtime_source_digest="sha256:" + ("b" * 64),
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
            " -i ",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, joined)
        self.assertNotIn("/Users", joined)
        self.assertNotIn("/Volumes", joined)
        self.assertNotIn("docker.sock", joined)
        self.assertNotIn("dst=/evidence", joined)
        self.assertIn("sha256:" + ("a" * 64), command)
        self.assertNotIn("example.invalid/orbit/e4:test", command)

    def test_run_blocks_approval_digest_drift_before_container_start(self) -> None:
        runner = load_runner()
        expected_image_id = "sha256:" + ("a" * 64)
        expected_runtime_digest = "sha256:" + ("b" * 64)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence.json"
            with mock.patch.object(
                runner, "_image_id", return_value="sha256:" + ("c" * 64)
            ), mock.patch.object(runner.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(ValueError, "approved image id"):
                    runner.run(
                        control=ROOT,
                        scientific=SCIENTIFIC_ROOT,
                        output=output,
                        image="example.invalid/orbit/e4:test",
                        expected_image_id=expected_image_id,
                        expected_runtime_source_digest=expected_runtime_digest,
                    )
                popen.assert_not_called()

            with mock.patch.object(
                runner, "_image_id", return_value=expected_image_id
            ), mock.patch.object(
                runner,
                "_tree_digest",
                return_value="sha256:" + ("d" * 64),
            ), mock.patch.object(runner.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(ValueError, "approved source digest"):
                    runner.run(
                        control=ROOT,
                        scientific=SCIENTIFIC_ROOT,
                        output=output,
                        image="example.invalid/orbit/e4:test",
                        expected_image_id=expected_image_id,
                        expected_runtime_source_digest=expected_runtime_digest,
                    )
                popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()

