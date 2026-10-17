from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CODEX = ROOT / "deploy/lan-stage1/codex-cli"
DEVICE = ROOT / "deploy/lan-stage1/department-device"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CodexCliLanDistributionTests(unittest.TestCase):
    def test_prepared_official_release_is_exact_and_tamper_evident(self) -> None:
        prepare = load("orbit_codex_prepare_test", CODEX / "prepare-release.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package_root = root / "package"
            for directory in ("bin", "codex-path", "codex-resources"):
                (package_root / directory).mkdir(parents=True, exist_ok=True)
            for relative in (
                "bin/codex", "bin/codex-code-mode-host", "codex-path/rg",
                "codex-resources/bwrap",
            ):
                (package_root / relative).write_text("synthetic executable\n")
            (package_root / "codex-package.json").write_text(
                json.dumps({
                    "layoutVersion": 1,
                    "version": "0.153.0",
                    "target": prepare.TARGET,
                    "variant": "codex",
                    "entrypoint": "bin/codex",
                    "resourcesDir": "codex-resources",
                    "pathDir": "codex-path",
                }),
                encoding="utf-8",
            )
            archive = root / prepare.ARCHIVE_NAME
            with tarfile.open(archive, "w:gz") as output:
                for path in sorted(package_root.rglob("*")):
                    output.add(path, arcname=path.relative_to(package_root))
            archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            checksums = root / prepare.CHECKSUMS_NAME
            checksums.write_text(
                f"{archive_digest}  {archive.name}\n", encoding="utf-8"
            )
            checksums_digest = hashlib.sha256(checksums.read_bytes()).hexdigest()
            metadata = root / "release.json"
            metadata.write_text(
                json.dumps({
                    "tag_name": "rust-v0.153.0",
                    "assets": [
                        {"name": archive.name, "digest": f"sha256:{archive_digest}"},
                        {"name": checksums.name, "digest": f"sha256:{checksums_digest}"},
                    ],
                }),
                encoding="utf-8",
            )
            outputs = (root / "prepared-one", root / "prepared-two")
            for output in outputs:
                result = subprocess.run(
                    [
                        sys.executable, str(CODEX / "prepare-release.py"),
                        "--release-metadata", str(metadata),
                        "--checksums", str(checksums),
                        "--archive", str(archive),
                        "--output", str(output),
                    ],
                    check=True, capture_output=True, text=True,
                )
                self.assertEqual("codex_cli_release_prepared", json.loads(result.stdout)["status"])
            self.assertEqual(
                {path.name: path.read_bytes() for path in outputs[0].iterdir()},
                {path.name: path.read_bytes() for path in outputs[1].iterdir()},
            )
            verified = prepare.verify_prepared_release(outputs[0])
            self.assertEqual("0.153.0", verified["version"])
            (outputs[0] / archive.name).write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "codex_cli_release_file_invalid"):
                prepare.verify_prepared_release(outputs[0])

    def test_one_click_entry_is_technology_scoped_user_only_and_pinned(self) -> None:
        powershell_path = DEVICE / "Install-OrbitCodexCliFromLan.ps1"
        powershell = powershell_path.read_text(encoding="utf-8-sig")
        launcher_path = DEVICE / "Start-OrbitCodexCliInstall.cmd"
        launcher = launcher_path.read_text(encoding="ascii")
        installer = (CODEX / "install-offline.py").read_text(encoding="utf-8")
        self.assertIn("technology_center", powershell)
        self.assertIn("node_technology_001", powershell)
        self.assertIn("0.153.0", powershell)
        self.assertIn("x86_64-unknown-linux-musl", powershell)
        self.assertIn("--user", powershell)
        self.assertIn('"orbit-runner"', powershell)
        self.assertNotIn("--user root", powershell)
        self.assertNotIn("-SkipCertificateCheck", powershell)
        self.assertIn("PowerShell\\7\\pwsh.exe", launcher)
        self.assertIn(
            hashlib.sha256(powershell_path.read_bytes()).hexdigest(), launcher
        )
        self.assertIn("Path.home() != RUNNER_HOME", installer)
        self.assertIn('os.geteuid() == 0', installer)
        self.assertIn('"account_logged_in": False', installer)
        self.assertIn('"runtime_started": False', installer)
        self.assertNotIn("codex login", installer)

    def test_runner_recovers_only_owner_private_regular_receipt(self) -> None:
        runner = load(
            "orbit_codex_runner_recovery_test",
            DEVICE / "runner/orbit-lan-runner.py",
        )
        config = {
            "department": {"id": "technology_center"},
            "node": {"node_id": "node_technology_001"},
        }
        receipt = {
            "schema_version": "orbit.codex-cli-installation-receipt/0.1-draft",
            "status": "codex_cli_installed",
            "version": runner.CODEX_VERSION,
            "target": runner.CODEX_TARGET,
            "release_manifest_digest": runner.CODEX_MANIFEST_DIGEST,
            "archive_digest": runner.CODEX_ARCHIVE_DIGEST,
            "credential_present": False,
            "account_logged_in": False,
            "execution_grant_issued": False,
            "lease_issued": False,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            path = state / "codex-cli-installation.json"
            path.write_text(json.dumps(receipt), encoding="utf-8")
            path.chmod(0o600)
            runner.recover_existing_codex_receipt(state, config)
            queued = tuple((state / "codex-installation-events").glob("*.json"))
            self.assertEqual(1, len(queued))
            document = json.loads(queued[0].read_text(encoding="utf-8"))["document"]
            self.assertEqual("recovered_existing_receipt", document["evidence_source"])
            self.assertFalse(document["intermediate_events_available"])

            (state / "codex-installation-recovery-queued.json").unlink()
            queued[0].unlink()
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "receipt_permissions_invalid"):
                runner.recover_existing_codex_receipt(state, config)

            path.unlink()
            target = state / "receipt-target.json"
            target.write_text(json.dumps(receipt), encoding="utf-8")
            target.chmod(0o600)
            path.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, "receipt_permissions_invalid"):
                runner.recover_existing_codex_receipt(state, config)

    def test_runner_deletes_queue_item_only_after_server_acknowledges(self) -> None:
        runner = load(
            "orbit_codex_runner_queue_test",
            DEVICE / "runner/orbit-lan-runner.py",
        )
        config = {
            "department": {"id": "technology_center"},
            "node": {"node_id": "node_technology_001"},
        }

        class Client:
            def __init__(self, status: int) -> None:
                self.status = status

            def post(self, *_: object) -> tuple[int, dict[str, bool]]:
                return self.status, {"accepted": True}

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            queue = state / "codex-installation-events"
            queue.mkdir(mode=0o700)
            item = queue / "0001.json"
            item.write_text(
                json.dumps({
                    "kind": "stage_event",
                    "idempotency_key": "codex-event-queue-test-0001",
                    "document": {"synthetic": True},
                }),
                encoding="utf-8",
            )
            item.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "upload_response_invalid"):
                runner.flush_codex_installation_queue(state, config, Client(503))
            self.assertTrue(item.exists())
            self.assertEqual(
                1,
                runner.flush_codex_installation_queue(state, config, Client(201)),
            )
            self.assertFalse(item.exists())


if __name__ == "__main__":
    unittest.main()

