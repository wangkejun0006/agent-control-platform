from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.run_dataset_public_pilot_docker import docker_command


class DatasetPublicDockerHarnessTests(unittest.TestCase):
    def test_command_is_non_root_read_only_tmpfs_and_capability_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = docker_command(
                image="nousresearch/hermes-agent:v2026.8.16",
                image_digest="sha256:" + "f" * 64,
                bundle=root / "bundle",
                evidence=root / "evidence",
            )
        joined = " ".join(command)
        self.assertIn("--pull never", joined)
        self.assertIn("--read-only", command)
        self.assertIn("--user 65532:65532", joined)
        self.assertIn("--tmpfs /work:rw,noexec,nosuid,nodev", joined)
        self.assertIn("--security-opt no-new-privileges", joined)
        self.assertIn("--cap-drop ALL", joined)
        self.assertIn("--memory 256m", joined)
        self.assertIn("--cpus 1", joined)
        self.assertIn("--pids-limit 64", joined)
        self.assertNotIn("/Users/", " ".join(item for item in command if "dst=" in item))


if __name__ == "__main__":
    unittest.main()

