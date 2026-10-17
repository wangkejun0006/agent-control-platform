from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from orbit_agent_control_plane.cli import main
from orbit_agent_control_plane.dataset_agent_process import (
    create_dataset_agent_company_loop,
    dataset_synthetic_task,
)
from orbit_agent_control_plane.runtime_source import (
    DatasetRuntimeSourceError,
    materialize_dataset_runtime_source,
    verify_dataset_runtime_source,
)


ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_PLATFORM = ROOT.parent / "orbit-health-system" / "scientific-research-platform"


class DatasetRuntimeSourceTest(unittest.TestCase):
    def test_dirty_development_clone_materializes_independent_locked_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            development = base / "development"
            subprocess.run(
                (
                    "git",
                    "clone",
                    "--no-local",
                    "--quiet",
                    "--no-tags",
                    str(SCIENTIFIC_PLATFORM),
                    str(development),
                ),
                check=True,
                capture_output=True,
                timeout=30,
            )
            (development / "local-development-note.txt").write_text(
                "uncommitted development state\n",
                encoding="utf-8",
            )
            self.assertTrue(
                subprocess.run(
                    ("git", "-C", str(development), "status", "--porcelain"),
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
            )

            runtime_root = base / "runtime-sources"
            first = materialize_dataset_runtime_source(development, runtime_root)
            runtime_source = runtime_root / first.runtime_source_name
            second = materialize_dataset_runtime_source(development, runtime_root)

            self.assertTrue(first.created)
            self.assertFalse(second.created)
            self.assertEqual(first.implementation_revision, second.implementation_revision)
            self.assertTrue(first.detached_head)
            self.assertEqual(0, first.remote_count)
            self.assertEqual(
                "",
                subprocess.run(
                    ("git", "-C", str(runtime_source), "status", "--porcelain"),
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
            )
            outcome = create_dataset_agent_company_loop(runtime_source).run(
                dataset_synthetic_task()
            )
            self.assertEqual("pass", outcome.status)

    def test_runtime_root_must_be_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime-sources"
            runtime_root.mkdir(mode=0o755)
            os.chmod(runtime_root, 0o755)
            with self.assertRaises(DatasetRuntimeSourceError) as caught:
                materialize_dataset_runtime_source(SCIENTIFIC_PLATFORM, runtime_root)
            self.assertEqual(
                "dataset_runtime_root_permissions_invalid",
                caught.exception.reason_code,
            )

    def test_runtime_source_name_is_bound_to_locked_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime-sources"
            evidence = materialize_dataset_runtime_source(
                SCIENTIFIC_PLATFORM,
                runtime_root,
            )
            runtime_source = runtime_root / evidence.runtime_source_name
            renamed = runtime_root / "unbound-runtime-source"
            runtime_source.rename(renamed)
            with self.assertRaises(DatasetRuntimeSourceError) as caught:
                verify_dataset_runtime_source(renamed)
            self.assertEqual(
                "dataset_runtime_source_name_mismatch",
                caught.exception.reason_code,
            )

    def test_cli_materializes_and_verifies_without_disclosing_local_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime_root = Path(temporary) / "runtime-sources"
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = main(
                    [
                        "dataset-runtime-source",
                        "materialize",
                        "--source-repository",
                        str(SCIENTIFIC_PLATFORM),
                        "--runtime-root",
                        str(runtime_root),
                    ]
                )
            document = json.loads(output.getvalue())
            runtime_source = runtime_root / document["runtime_source_name"]

            verify_output = io.StringIO()
            with redirect_stdout(verify_output):
                verify_code = main(
                    [
                        "dataset-runtime-source",
                        "verify",
                        "--runtime-source",
                        str(runtime_source),
                    ]
                )
            verified = json.loads(verify_output.getvalue())

            self.assertEqual((0, 0), (exit_code, verify_code))
            self.assertEqual("ready", document["status"])
            self.assertTrue(document["created"])
            self.assertFalse(document["production_authorization"])
            self.assertEqual("ready", verified["status"])
            self.assertNotIn(str(temporary), output.getvalue())
            self.assertNotIn(str(temporary), verify_output.getvalue())
            self.assertEqual(
                document["implementation_revision"],
                verify_dataset_runtime_source(runtime_source).implementation_revision,
            )


if __name__ == "__main__":
    unittest.main()

