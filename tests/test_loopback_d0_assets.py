from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.service_runtime.lan_stage1 import (
    _validate_deployment_release_lock,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "deploy/lan-stage1/loopback-d0"


class LoopbackD0AssetsTests(unittest.TestCase):
    @staticmethod
    def _git_repository(root: Path, files: dict[str, str]) -> str:
        for relative, value in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(
            [
                "git", "-C", str(root), "-c", "user.name=Orbit Synthetic",
                "-c", "user.email=synthetic@orbit.invalid", "commit", "-qm",
                "synthetic fixture",
            ],
            check=True,
        )
        return subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def test_caddy_and_launch_templates_are_loopback_only(self) -> None:
        caddy = (FIXTURE / "Caddyfile").read_text(encoding="utf-8")
        self.assertIn("https://127.0.0.1:8443", caddy)
        self.assertIn("https://127.0.0.1:9443", caddy)
        self.assertEqual(2, caddy.count("bind 127.0.0.1"))
        self.assertNotIn("192.168.21.22", caddy)
        self.assertNotIn("0.0.0.0", caddy)
        self.assertIn("request_header -X-Orbit-Client-Cert-Der", caddy)
        self.assertIn("request_header -X-Orbit-Client-Cert-Fingerprint", caddy)
        self.assertIn(
            "request_header X-Orbit-Client-Cert-Der {tls_client_certificate_der_base64}",
            caddy,
        )
        self.assertIn(
            "request_header X-Orbit-Client-Cert-Fingerprint {tls_client_fingerprint}",
            caddy,
        )
        self.assertIn("flush_interval -1", caddy)
        for name in (
            "com.orbit.control-plane-loopback-human.plist",
            "com.orbit.control-plane-loopback-workload.plist",
        ):
            value = (FIXTURE / name).read_text(encoding="utf-8")
            self.assertIn("ORBIT_LAN_ARTIFACT_ROOT", value)
            self.assertNotIn("192.168.21.22", value)
        postgres = (
            FIXTURE / "com.orbit.control-plane-loopback-postgresql.plist"
        ).read_text(encoding="utf-8")
        self.assertIn("<key>LC_ALL</key><string>C</string>", postgres)
        self.assertIn("<key>LANG</key><string>C</string>", postgres)

    def test_persistent_candidate_assets_keep_the_24_hour_and_authority_gates(self) -> None:
        python_scripts = tuple(FIXTURE.glob("*.py"))
        shell_scripts = tuple(FIXTURE.glob("*.sh"))
        plists = tuple(FIXTURE.glob("*.plist"))
        self.assertGreaterEqual(len(python_scripts), 8)
        self.assertGreaterEqual(len(shell_scripts), 7)
        self.assertEqual(5, len(plists))
        for path in python_scripts:
            subprocess.run(
                ["python3", "-m", "py_compile", str(path)],
                check=True,
                capture_output=True,
            )
        for path in shell_scripts:
            subprocess.run(
                ["sh", "-n", str(path)], check=True, capture_output=True,
            )
        for path in plists:
            subprocess.run(
                ["plutil", "-lint", str(path)], check=True, capture_output=True,
            )
        soak = (FIXTURE / "run-loopback-soak-supervisor.sh").read_text()
        finalize = (FIXTURE / "finalize-loopback-soak.sh").read_text()
        install = (FIXTURE / "install-loopback-candidate.sh").read_text()
        trust = (FIXTURE / "trust-loopback-human-ca.sh").read_text()
        self.assertIn("duration=86400", soak)
        self.assertIn('test "$elapsed" -ge "$duration"', soak)
        self.assertIn('value.get("elapsed_seconds", 0) < 86400', finalize)
        self.assertIn("_orbitcontrolplane", install)
        self.assertIn("127.0.0.1:8443", install)
        self.assertIn('cd "$root"', install)
        self.assertIn('UV_PYTHON_INSTALL_DIR="$root/cache/python"', install)
        self.assertIn("sync --python 3.12.13 --no-config --frozen", install)
        self.assertIn('cd "$root/source"', install)
        self.assertEqual(
            2, install.count("basicConstraints=critical,CA:TRUE,pathlen:0")
        )
        self.assertIn("basicConstraints=critical,CA:FALSE", install)
        self.assertIn('test -x "$root/source/deploy/lan-stage1/loopback-d0/wait-for-postgresql.sh"', install)
        self.assertNotIn("192.168.21.22", install)
        start_soak = (FIXTURE / "start-loopback-soak.sh").read_text()
        finalize = (FIXTURE / "finalize-loopback-soak.sh").read_text()
        self.assertIn("--password-file", start_soak)
        self.assertIn("--password-file", finalize)
        self.assertIn("prompt-password-file.py", start_soak)
        self.assertIn("prompt-password-file.py", finalize)
        self.assertNotIn("stty", start_soak)
        self.assertNotIn("Re-enter the same D0-only password", start_soak)
        self.assertIn("workload_ca_trusted\": False", trust)
        for path in python_scripts + shell_scripts:
            value = path.read_text(encoding="utf-8")
            self.assertNotIn("runtime_started\": True", value)
            self.assertNotIn("release_authorization\": True", value)

    def test_non_runnable_oci_fixtures_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            script = FIXTURE / "build-synthetic-oci-fixtures.py"
            subprocess.run(["python3", str(script), first], check=True, capture_output=True)
            subprocess.run(["python3", str(script), second], check=True, capture_output=True)
            first_manifest = json.loads((Path(first) / "synthetic-artifacts.manifest.json").read_text())
            second_manifest = json.loads((Path(second) / "synthetic-artifacts.manifest.json").read_text())
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual({"hermes", "codex"}, {item["runtime_family"] for item in first_manifest["artifacts"]})
            for item in first_manifest["artifacts"]:
                runtime_manifest = item["runtime_artifact_manifest"]
                self.assertEqual(
                    item["revision_digest"],
                    runtime_manifest["spec"]["manifest_digest"],
                )
                self.assertNotEqual(
                    item["revision_digest"], item["oci_manifest_digest"]
                )
                artifact_key = __import__("hashlib").sha256(
                    item["artifact_id"].encode()
                ).hexdigest()
                archive = (
                    Path(first)
                    / artifact_key
                    / item["revision_digest"][7:]
                    / f"{item['bundle_digest'][7:]}.oci.tar"
                )
                self.assertTrue(archive.is_file())
                self.assertFalse(item["runtime_started"])
                self.assertFalse(item["model_called"])
                self.assertFalse(item["production_authorized"])
                self.assertFalse(item["release_authorization"])

    def test_lan_profile_uses_distinct_non_runnable_artifact_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            script = FIXTURE / "build-synthetic-oci-fixtures.py"
            subprocess.run(
                ["python3", str(script), temporary, "--profile", "lan"],
                check=True,
                capture_output=True,
            )
            manifest = json.loads(
                (Path(temporary) / "synthetic-artifacts.manifest.json").read_text()
            )
            self.assertEqual("synthetic_lan_d0", manifest["evidence_status"])
            serialized = json.dumps(manifest, sort_keys=True)
            self.assertNotIn("loopback", serialized)
            self.assertIn("runtime_artifact_hermes_lan_syn", serialized)
            self.assertIn("runtime_artifact_codex_lan_syn", serialized)
            for item in manifest["artifacts"]:
                self.assertFalse(item["runtime_started"])
                self.assertFalse(item["model_called"])
                self.assertFalse(item["production_authorized"])
                self.assertFalse(item["release_authorization"])

    def test_bundle_modes_preserve_only_source_executables(self) -> None:
        module_path = FIXTURE / "build-loopback-install-bundle.py"
        spec = importlib.util.spec_from_file_location("loopback_modes", module_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "control-plane-source"
            source.mkdir()
            executable = source / "run.sh"
            executable.write_text("#!/bin/sh\n")
            executable.chmod(0o755)
            data = source / "data.json"
            data.write_text("{}\n")
            data.chmod(0o644)
            binary = root / "bin/caddy"
            binary.parent.mkdir()
            binary.write_text("synthetic\n")
            binary.chmod(0o755)
            module.normalize_bundle_modes(root)
            self.assertEqual(0o700, executable.stat().st_mode & 0o777)
            self.assertEqual(0o600, data.stat().st_mode & 0o777)
            self.assertEqual(0o555, binary.stat().st_mode & 0o777)
            entries = {
                item["path"]: item for item in module.directory_entries(root)
            }
            self.assertEqual(0o700, entries["control-plane-source/run.sh"]["mode"])
            self.assertEqual(0o600, entries["control-plane-source/data.json"]["mode"])
            self.assertEqual(0o555, entries["bin/caddy"]["mode"])

    def test_exact_install_release_lock_passes_the_existing_contract(self) -> None:
        module_path = FIXTURE / "build-loopback-install-bundle.py"
        spec = importlib.util.spec_from_file_location("loopback_bundle", module_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            architecture = root / "architecture"
            control_plane = root / "control-plane"
            cockpit = root / "cockpit"
            semantic = (
                "references/semantic-authority-v0.1.0-alpha.5/manifest.json"
            )
            architecture_commit = self._git_repository(
                architecture, {semantic: '{"synthetic":true}\n'}
            )
            control_plane_commit = self._git_repository(
                control_plane, {"source.txt": "control plane\n"}
            )
            cockpit_commit = self._git_repository(
                cockpit, {"source.txt": "cockpit\n"}
            )
            artifact_root = root / "artifacts"
            subprocess.run(
                [
                    "python3", str(FIXTURE / "build-synthetic-oci-fixtures.py"),
                    str(artifact_root),
                ],
                check=True,
                capture_output=True,
            )
            artifacts = json.loads(
                (artifact_root / "synthetic-artifacts.manifest.json").read_text()
            )["artifacts"]
            value = module.release_lock(
                architecture=architecture,
                architecture_commit=architecture_commit,
                control_plane=control_plane,
                control_plane_commit=control_plane_commit,
                cockpit=cockpit,
                cockpit_commit=cockpit_commit,
                frontend_entries=[{
                    "path": "index.html", "size": 1,
                    "sha256": "sha256:" + "1" * 64,
                }],
                installer_entries=[{
                    "path": "bin/caddy", "size": 1,
                    "sha256": "sha256:" + "2" * 64,
                }],
                artifacts=artifacts,
            )
            _validate_deployment_release_lock(value)
            self.assertFalse(value["authority_boundary"]["release_authorization"])


if __name__ == "__main__":
    unittest.main()

