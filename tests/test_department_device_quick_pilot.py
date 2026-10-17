from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
DEVICE = ROOT / "deploy/lan-stage1/department-device"
BUILDER = DEVICE / "build-device-bundle.py"
PUBLISHER = DEVICE / "publish-device-bundles.py"
RUNNER = DEVICE / "runner/orbit-lan-runner.py"
TRANSPORT_RECOVERY = DEVICE / "wsl/recover-transport-state.py"
POWERSHELL_51_GATE = ROOT / "deploy/lan-stage1/Test-OrbitWindowsPowerShell51.ps1"
LAN_BUNDLE_BUILDER = ROOT / "deploy/lan-stage1/build-lan-install-bundle.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("orbit_device_bundle", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_runner():
    spec = importlib.util.spec_from_file_location("orbit_lan_runner", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_transport_recovery():
    spec = importlib.util.spec_from_file_location(
        "orbit_transport_recovery", TRANSPORT_RECOVERY
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ca_certificate(path: Path) -> None:
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Orbit LAN Human D0 Test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o600)


class DepartmentDeviceQuickPilotTests(unittest.TestCase):
    def test_windows_powershell_51_parser_gate_covers_every_entrypoint(self) -> None:
        gate = POWERSHELL_51_GATE.read_text(encoding="utf-8-sig")
        self.assertIn("$PSVersionTable.PSVersion.Major -ne 5", gate)
        self.assertIn("System.Management.Automation.Language.Parser", gate)
        for name in (
            "Prepare-OrbitDepartmentBrowser.ps1",
            "Start-OrbitDepartmentPilot.ps1",
            "Initialize-OrbitWsl.ps1",
            "Repair-OrbitRootlessDockerFromLan.ps1",
            "Repair-OrbitWorkloadSniFromLan.ps1",
            "Resume-OrbitDockerFromLan.ps1",
            "Install-OrbitWslRunner.ps1",
            "Install-OrbitTransportRunnerTask.ps1",
        ):
            self.assertIn(name, gate)

    def test_lan_host_bundle_carries_complete_runner_bootstrap_set(self) -> None:
        builder = LAN_BUNDLE_BUILDER.read_text(encoding="utf-8")
        for name in (
            "Start-OrbitCodexCliInstall.cmd",
            "Install-OrbitCodexCliFromLan-v1.ps1",
            "install-orbit-codex-cli-v1.py",
            "recover-transport-state-v1.py",
            "write-orbit-bundle-file-v3.py",
            "install-orbit-runner-v8.sh",
            "orbit-lan-runner-v7.py",
        ):
            self.assertIn(name, builder)
        for archived_name in (
            "Start-OrbitAssistedMaintenance.cmd",
            "Install-OrbitWslKeepaliveFromLan-v6.ps1",
            "run-wsl-keepalive-v2.sh",
        ):
            self.assertNotIn(archived_name, builder)
        self.assertIn('bootstrap_root = args.output / "web/bootstrap"', builder)
        self.assertIn('bootstrap_root / "archive/device-recovery-v1"', builder)
        self.assertIn("lan_bootstrap_asset_invalid", builder)
        self.assertIn("--codex-cli-release-root", builder)
        self.assertIn('"0.153.0"', builder)

    def test_launchers_are_ascii_pinned_and_keep_failures_visible(self) -> None:
        launcher_path = DEVICE / "Start-OrbitTechnologyRunner.cmd"
        launcher = launcher_path.read_text(encoding="ascii")
        self.assertEqual(launcher.encode("ascii"), launcher_path.read_bytes())
        self.assertIn(r"D:\OrbitCockpit\technology-center-lan-d0", launcher)
        self.assertIn("Install-OrbitWslRunner-v8.ps1", launcher)
        self.assertIn("44a030930b6bf1a7d14f1b2cc41a2a45c03d06d6e8e06ca7b4a696bbfd41291f", launcher)
        self.assertIn("Get-FileHash -Algorithm SHA256", launcher)
        self.assertIn("orbit-runner-startup.log", launcher)
        self.assertIn("pause", launcher)
        self.assertNotIn("Enrollment Code", launcher)
        transport_launcher_path = DEVICE / "Start-OrbitTransportRunner.cmd"
        transport_launcher = transport_launcher_path.read_text(encoding="ascii")
        self.assertEqual(
            transport_launcher.encode("ascii"), transport_launcher_path.read_bytes()
        )
        self.assertIn("Install-OrbitTransportRunnerTask-v5.ps1", transport_launcher)
        self.assertIn(r"%ProgramFiles%\PowerShell\7\pwsh.exe", transport_launcher)
        self.assertIn("where pwsh.exe", transport_launcher)
        self.assertIn('"%ORBIT_POWERSHELL%"', transport_launcher)
        self.assertIn("PowerShell host:", transport_launcher)
        transport_script_digest = hashlib.sha256(
            (DEVICE / "Install-OrbitTransportRunnerTask.ps1").read_bytes()
        ).hexdigest()
        self.assertIn(transport_script_digest, transport_launcher)
        self.assertIn("pause", transport_launcher)

    def test_powershell_entrypoints_are_windows_powershell_compatible_utf8(self) -> None:
        for name in (
            "Prepare-OrbitDepartmentBrowser.ps1",
            "Start-OrbitDepartmentPilot.ps1",
            "Initialize-OrbitWsl.ps1",
            "Repair-OrbitRootlessDockerFromLan.ps1",
            "Repair-OrbitWorkloadSniFromLan.ps1",
            "Resume-OrbitDockerFromLan.ps1",
            "Install-OrbitWslRunner.ps1",
            "Install-OrbitTransportRunnerTask.ps1",
        ):
            raw = (DEVICE / name).read_bytes()
            self.assertTrue(raw.startswith(b"\xef\xbb\xbf"), name)
            raw.decode("utf-8-sig", errors="strict")

    def test_static_assets_keep_lan_scope_and_fail_closed_boundaries(self) -> None:
        readme = (DEVICE / "README.md").read_text(encoding="utf-8")
        prepare = (DEVICE / "Prepare-OrbitDepartmentBrowser.ps1").read_text(encoding="utf-8")
        initialize = (DEVICE / "Initialize-OrbitWsl.ps1").read_text(encoding="utf-8")
        install_ps = (DEVICE / "Install-OrbitWslRunner.ps1").read_text(encoding="utf-8")
        install = (DEVICE / "runner/install-runner.sh").read_text(encoding="utf-8")
        runner = (DEVICE / "runner/orbit-lan-runner.py").read_text(encoding="utf-8")
        scopes = json.loads((DEVICE / "runtime-node-scopes.lan-d0.json").read_text())

        self.assertIn("192.168.21.22", prepare)
        self.assertIn(r"D:\OrbitCockpit\technology-center-lan-d0", readme)
        self.assertIn("orbit-admin", readme)
        self.assertIn("批准为技术中心负责人", readme)
        self.assertIn("/technology/access", readme)
        self.assertIn("邀请代码有效期为 24 小时且只能使用一次", readme)
        self.assertNotIn("-SkipCertificateCheck", prepare)
        self.assertNotIn("curl -k", prepare)
        self.assertNotIn("curl -k", install)
        self.assertIn("OrbitRuntime-Ubuntu-22.04", initialize)
        self.assertIn("Start-OrbitDepartmentPilot.cmd", readme)
        self.assertIn("orbit-setup-last.log", readme)
        self.assertIn("node_technology_001", readme)
        self.assertIn("Enrollment ID", readme)
        start_cmd = (DEVICE / "Start-OrbitDepartmentPilot.cmd").read_text(
            encoding="ascii"
        )
        self.assertIn("Start-OrbitDepartmentPilot.ps1", start_cmd)
        self.assertIn('if "%ORBIT_EXIT%"=="3010"', start_cmd)
        self.assertIn("double-click Start-OrbitDepartmentPilot.cmd again", start_cmd)
        self.assertIn("orbit-setup-last.log", start_cmd)
        self.assertIn("Get-Content -LiteralPath $log -Tail 40", start_cmd)
        self.assertIn(r"D:\OrbitCockpit\technology-center-lan-d0", readme)
        self.assertNotIn('.Replace([char]0, "")', initialize)
        self.assertIn("([char]0).ToString()", initialize)
        self.assertIn("([char]0).ToString()", install_ps)
        self.assertIn('if (Test-OrbitNativeInstallOptions $Help)', initialize)
        self.assertIn('OrbitRuntime-Ubuntu-22.04', initialize)
        self.assertIn('@("--install", "-d", $SourceDistroName, "--no-launch")', initialize)
        self.assertIn('@("--export", $SourceDistroName, $ExportArchive)', initialize)
        self.assertIn('@("--import", $DistroName, $ImportLocation, $ExportArchive, "--version", "2")', initialize)
        self.assertIn('source_created_by_orbit = $true', initialize)
        self.assertIn('if ($Distros -contains $SourceDistroName -and $null -eq $BootstrapState)', initialize)
        self.assertLess(initialize.index('status = "target_imported"'), initialize.index('@("--unregister", $SourceDistroName)'))
        self.assertNotIn('Ubuntu-24.04', initialize)
        self.assertNotIn('$Output = @(& wsl.exe @Arguments 2>&1)', initialize)
        start_ps = (DEVICE / "Start-OrbitDepartmentPilot.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("Start-Transcript", start_ps)
        self.assertIn("orbit-setup-last.log", start_ps)
        self.assertIn("Orbit 接入失败，真实错误如下", start_ps)
        self.assertIn("if ($SetupFailed) { exit 1 }", start_ps)
        bootstrap = (DEVICE / "wsl/bootstrap-root.sh").read_text()
        self.assertIn("automount", bootstrap)
        self.assertIn("enabled=false", bootstrap)
        self.assertIn("policy-rc.d", bootstrap)
        self.assertIn("ORBIT_RUNNER_DOCKER_GPG_FINGERPRINT", bootstrap)
        self.assertIn("systemctl mask docker.service docker.socket", bootstrap)
        recovery = (DEVICE / "Resume-OrbitDockerFromLan.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("https://192.168.21.22:8443", recovery)
        self.assertIn("sha256sum -c -", recovery)
        self.assertIn("orbit-human-ca.pem", recovery)
        self.assertNotIn("download.docker.com", recovery)
        repair = (DEVICE / "Repair-OrbitRootlessDockerFromLan.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("repair-orbit-rootless-docker-v2.sh", repair)
        self.assertIn("/usr/bin/sha256sum", repair)
        self.assertNotIn("bash -lc $RootlessRepair", repair)
        repair_shell = (DEVICE / "wsl/repair-rootless-docker.sh").read_text()
        self.assertIn("runuser -u orbit-runner", repair_shell)
        self.assertIn("user-runtime-dir@${runner_uid}.service", repair_shell)
        self.assertIn("user@${runner_uid}.service", repair_shell)
        self.assertIn("journalctl", repair_shell)
        self.assertIn("runtime_started=false", repair_shell)
        sni_repair = (DEVICE / "Repair-OrbitWorkloadSniFromLan.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("repair-workload-sni-v1.py", sni_repair)
        self.assertIn("orbit-lan-runner-v6.py", sni_repair)
        self.assertIn("resume-runner-after-sni-v1.sh", sni_repair)
        self.assertIn("/opt/orbit-device-pilot/resume-runner-after-sni.sh", sni_repair)
        self.assertIn("--connect-timeout 10 --max-time 60", sni_repair)
        self.assertNotIn("Enrollment Code", sni_repair)
        sni_helper = (DEVICE / "wsl/repair-workload-sni.py").read_text()
        self.assertIn("generateHosts=false", sni_helper)
        self.assertIn("control-plane.orbit.local", sni_helper)
        self.assertIn("os.replace(temporary, path)", sni_helper)
        self.assertIn("rewrite_in_place(HOSTS", sni_helper)
        sni_resume = (DEVICE / "runner/resume-runner-after-sni.sh").read_text()
        self.assertIn("client-cert.pem", sni_resume)
        self.assertIn("--once", sni_resume)
        self.assertNotIn("systemctl --user", sni_resume)
        self.assertIn("windows_task_required=true", sni_resume)
        self.assertNotIn("enrollment_code", sni_resume)
        transport_ps = (DEVICE / "Install-OrbitTransportRunnerTask.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("New-ScheduledTaskPrincipal", transport_ps)
        self.assertIn("-LogonType Interactive -RunLevel Limited", transport_ps)
        self.assertIn("-ExecutionTimeLimit ([TimeSpan]::Zero)", transport_ps)
        self.assertIn("Orbit-Department-Transport-Runner", transport_ps)
        self.assertIn("Orbit-Department-Runner-Keepalive", transport_ps)
        self.assertIn("Export-ScheduledTask", transport_ps)
        self.assertIn("Disable-ScheduledTask", transport_ps)
        self.assertIn("default.target.wants/docker.service", transport_ps)
        self.assertIn("--exec", transport_ps)
        self.assertIn("orbit-lan-runner.py", transport_ps)
        self.assertIn("--serve", transport_ps)
        self.assertIn("transport_mode", transport_ps)
        self.assertIn("heartbeat_only", transport_ps)
        self.assertIn("lease_status", transport_ps)
        self.assertIn("$RegisteredConfigResult", transport_ps)
        self.assertIn("ORBIT_DEVICE_CONFIG_B64:", transport_ps)
        self.assertIn("base64.b64encode", transport_ps)
        self.assertIn("$ConfigMarkerPayloads.Count -ne 1", transport_ps)
        self.assertIn("[System.StringComparison]::Ordinal", transport_ps)
        self.assertIn("[System.Convert]::FromBase64String", transport_ps)
        self.assertIn(".TrimStart([char]0xFEFF)", transport_ps)
        self.assertNotIn("$JsonStart", transport_ps)
        self.assertIn("/opt/orbit-device-pilot/device-config.json", transport_ps)
        self.assertIn("$Config.PSObject.Properties[$OptionalBoundary]", transport_ps)
        self.assertIn("$RegisteredConfig.runtime_started -ne $false", transport_ps)
        self.assertIn("node_id = [string]$RegisteredConfig.node.node_id", transport_ps)
        self.assertIn("recover-transport-state-v1.py", transport_ps)
        self.assertIn("$RecoveryHelperDigest", transport_ps)
        self.assertIn("--runner-log", transport_ps)
        self.assertIn("--output", transport_ps)
        self.assertNotIn('"--once"', transport_ps)
        self.assertNotIn("dockerd-rootless", transport_ps)
        self.assertNotIn("systemctl --user", transport_ps)
        self.assertNotIn("Enrollment Code", transport_ps)
        self.assertNotIn("Password", transport_ps)
        self.assertIn("Install-OrbitTransportRunnerTask.ps1", start_ps)
        offline = (DEVICE / "wsl/install-docker-offline.sh").read_text()
        self.assertIn("gpgv --keyring", offline)
        self.assertIn("signed_packages_index_digest_drift", offline)
        self.assertIn("ORBIT_RUNNER_DOCKER_GPG_FINGERPRINT", offline)
        self.assertNotIn("curl -k", offline)
        self.assertNotIn("chown orbit-runner", install_ps)
        self.assertIn("write-orbit-bundle-file-v3.py", install_ps)
        self.assertIn("install-orbit-runner-v8.sh", install_ps)
        self.assertIn("orbit-lan-runner-v7.py", install_ps)
        self.assertIn("$RunnerInstallerDigest", install_ps)
        self.assertIn("$RunnerDigest", install_ps)
        self.assertIn("/usr/bin/python3 $WslWriter $Target $Mode $Encoded", install_ps)
        self.assertIn('HOME=/home/orbit-runner', install_ps)
        self.assertIn('XDG_RUNTIME_DIR=/run/user/$RunnerUserId', install_ps)
        self.assertIn('/usr/bin/install -d -o orbit-runner -g orbit-runner -m 0700', install_ps)
        self.assertIn("System.Windows.Forms", install_ps)
        self.assertIn('ShortcutsEnabled = $true', install_ps)
        self.assertIn('UseSystemPasswordChar = $true', install_ps)
        self.assertIn('RedirectStandardInput = $true', install_ps)
        self.assertIn('--credential-stdin', install_ps)
        self.assertIn('orbit-runner-startup.log', install_ps)
        self.assertIn('stage=failed', install_ps)
        self.assertIn('script_started', install_ps)
        self.assertIn('opening_enrollment_window', install_ps)
        self.assertIn('Show-OrbitRunnerFailure', install_ps)
        self.assertIn('$Form.TopMost = $true', install_ps)
        self.assertIn('--connect-timeout 10 --max-time 60', install_ps)
        argument_line = next(
            line for line in install_ps.splitlines()
            if line.strip().startswith('$StartInfo.Arguments =')
        )
        self.assertNotIn("EnrollmentId", argument_line)
        self.assertNotIn("EnrollmentCode", argument_line)
        self.assertNotIn("$Encoded | & wsl.exe", install_ps)
        bundle_writer = (DEVICE / "wsl/write-bundle-file.py").read_text()
        self.assertIn("base64.b64decode(encoded, validate=True)", bundle_writer)
        self.assertIn('"/opt/orbit-device-pilot/orbit-lan-runner.py": 0o555', bundle_writer)
        self.assertIn("os.chown(temporary, 0, 0)", bundle_writer)
        self.assertIn("os.replace(temporary, target)", bundle_writer)
        self.assertIn("runner_home=/home/orbit-runner", install)
        self.assertIn("runner_home_scope_invalid", install)
        self.assertIn("runner_home_directory_invalid", install)
        self.assertIn("Shift+Insert", install)
        self.assertIn('if [[ $# -ne 1 || $1 != --credential-stdin ]]', install)
        self.assertIn('IFS= read -r enrollment_id', install)
        self.assertIn('IFS= read -r enrollment_code', install)
        self.assertIn("--write-out '%{http_code}'", install)
        self.assertIn("lan_enrollment_code_invalid", install)
        self.assertIn("Code 不匹配、已过期、已使用或暂时锁定", install)
        self.assertNotIn("--fail-with-body", install)
        self.assertIn("read -r -s", install)
        self.assertNotIn("enrollment_code=", install)
        self.assertIn("transport-state.json", install)
        self.assertIn("windows_task_required=true", install)
        self.assertNotIn("systemctl --user", install)
        self.assertIn("unexpected_lease_claimed_fail_closed", runner)
        self.assertIn("control-plane.orbit.local", runner)
        self.assertNotIn('f"https://{ALLOWED_SERVER}:9443"', runner)
        self.assertNotIn("subprocess.run([\"docker\", \"run\"", runner)
        self.assertIn("save_transport_state", runner)
        self.assertIn("load_transport_state", runner)
        self.assertIn('"lease_status": "not_polled"', runner)
        self.assertIn('"transport_mode": "heartbeat_only"', runner)
        serve_loop = runner[runner.index("while not STOP:"):]
        self.assertNotIn("publish_capability(", serve_loop)
        self.assertNotIn("claim_no_work(", serve_loop)
        recovery = TRANSPORT_RECOVERY.read_text(encoding="utf-8")
        self.assertIn('record.get("lease_status") != 204', recovery)
        self.assertIn('"verified_at": observed_at', recovery)
        self.assertIn('"requires_task_preflight"', recovery)
        self.assertIn("args.runner_log, expected_uid=os.geteuid()", recovery)
        self.assertNotIn("docker", recovery.lower())
        self.assertNotIn("urllib", recovery)
        self.assertEqual(
            {"node_product_001", "node_technology_001", "node_market_001"},
            set(scopes),
        )
        serialized = json.dumps(scopes, sort_keys=True)
        self.assertIn("-lan-d0", serialized)
        self.assertNotIn("loopback", serialized)

    def test_transport_recovery_uses_only_prior_successful_preflight(self) -> None:
        recovery = load_transport_recovery()
        config = {
            "schema_version": "orbit.department-device-pilot/0.1",
            "node": {"node_id": "node_technology_001"},
            "contains_secret": False,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }
        with tempfile.TemporaryDirectory() as temporary:
            log_path = Path(temporary) / "runner.jsonl"
            valid = {
                "observed_at": "2026-09-02T12:13:46.343422Z",
                "status": "transport_ready",
                "node_id": "node_technology_001",
                "capability_report_digest": "sha256:" + "a" * 64,
                "heartbeat_sequence": 1,
                "lease_status": 204,
                "runtime_started": False,
                "model_called": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            log_path.write_text(
                json.dumps({**valid, "lease_status": "not_polled"}) + "\n"
                + json.dumps(valid) + "\n",
                encoding="utf-8",
            )
            log_path.chmod(0o600)
            state = recovery.recover(config, log_path)
            self.assertEqual("orbit.lan-transport-state/0.1", state["schema_version"])
            self.assertEqual(
                valid["capability_report_digest"], state["capability_report_digest"]
            )
            self.assertEqual(valid["observed_at"], state["verified_at"])
            self.assertFalse(state["runtime_started"])
            log_path.write_text(
                json.dumps({**valid, "lease_status": "not_polled"}) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                SystemExit, "recoverable_transport_evidence_missing"
            ):
                recovery.recover(config, log_path)

    def test_builder_is_deterministic_department_scoped_and_secret_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ca = root / "human-ca.pem"
            ca_certificate(ca)
            outputs = []
            for name in ("one", "two"):
                output = root / name
                result = subprocess.run(
                    [
                        sys.executable, str(BUILDER),
                        "--department", "market_center",
                        "--human-ca", str(ca),
                        "--release-lock-digest", "sha256:" + "a" * 64,
                        "--output", str(output),
                    ],
                    check=True, capture_output=True, text=True,
                )
                summary = json.loads(result.stdout)
                self.assertFalse(summary["contains_secret"])
                self.assertFalse(summary["release_authorization"])
                outputs.append(output / "orbit-market_center-lan-d0.zip")
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())

            with zipfile.ZipFile(outputs[0]) as archive:
                names = set(archive.namelist())
                self.assertIn("device-config.json", names)
                self.assertIn("deployment-layout.json", names)
                self.assertIn("START-HERE.md", names)
                self.assertIn("artifact-set-manifest.json", names)
                self.assertIn("runner/orbit-lan-runner.py", names)
                self.assertIn(
                    "runner/orbit_runtime_artifact_importer.py", names
                )
                self.assertIn("OrbitFirstInstall.ps1", names)
                self.assertIn("docker-bootstrap.lock.json", names)
                self.assertIn("wsl/prepare-docker-from-lan.py", names)
                self.assertIn("wsl/repair-rootless-docker.sh", names)
                self.assertNotIn("Resume-OrbitDockerFromLan.ps1", names)
                self.assertNotIn("Repair-OrbitRootlessDockerFromLan.ps1", names)
                self.assertNotIn("Repair-OrbitWorkloadSniFromLan.ps1", names)
                self.assertNotIn("enrollment-code", " ".join(names).lower())
                for name in (
                    "Prepare-OrbitDepartmentBrowser.ps1",
                    "Start-OrbitDepartmentPilot.ps1",
                    "Initialize-OrbitWsl.ps1",
                    "Install-OrbitWslRunner.ps1",
                ):
                    self.assertTrue(archive.read(name).startswith(b"\xef\xbb\xbf"), name)
                self.assertIn("Start-OrbitDepartmentPilot.cmd", names)
                self.assertNotIn("Start-OrbitTransportRunner.cmd", names)
                self.assertIn("Install-OrbitTransportRunnerTask.ps1", names)
                self.assertNotIn("Start-OrbitAssistedMaintenance.cmd", names)
                self.assertNotIn("addons/codex-cli/Start-OrbitCodexCliInstall.cmd", names)
                config = json.loads(archive.read("device-config.json"))
                manifest = json.loads(archive.read("artifact-set-manifest.json"))
                layout = json.loads(archive.read("deployment-layout.json"))
                self.assertEqual([], layout["addons"])
                self.assertEqual(
                    "Start-OrbitDepartmentPilot.cmd", layout["primary_entrypoint"]
                )
                self.assertEqual("market_center", config["department"]["id"])
                self.assertEqual("node_market_001", config["node"]["node_id"])
                self.assertEqual("192.168.21.22", config["server"]["address"])
                self.assertFalse(config["contains_secret"])
                self.assertFalse(config["production_authorization"])
                self.assertFalse(config["release_authorization"])
                self.assertFalse(config["runtime_artifact_import"]["enabled"])
                self.assertIsNone(
                    config["runtime_artifact_import"]["verification_key_digest"]
                )
                extracted_config = root / "runner-device-config.json"
                extracted_config.write_text(
                    json.dumps(config, ensure_ascii=False), encoding="utf-8"
                )
                validated = load_runner().load_config(extracted_config)
                self.assertEqual("market_center", validated["department"]["id"])
                for entry in manifest["files"]:
                    self.assertEqual(
                        entry["sha256"],
                        "sha256:" + hashlib.sha256(archive.read(entry["path"])).hexdigest(),
                    )

            technology_output = root / "technology"
            subprocess.run(
                [
                    sys.executable, str(BUILDER),
                    "--department", "technology_center",
                    "--human-ca", str(ca),
                    "--release-lock-digest", "sha256:" + "b" * 64,
                    "--output", str(technology_output),
                ],
                check=True, capture_output=True, text=True,
            )
            with zipfile.ZipFile(
                technology_output / "orbit-technology_center-lan-d0.zip"
            ) as archive:
                names = set(archive.namelist())
                addon = "addons/codex-cli/Start-OrbitCodexCliInstall.cmd"
                self.assertIn(addon, names)
                layout = json.loads(archive.read("deployment-layout.json"))
                self.assertEqual([addon], layout["addons"])

    def test_product_bundle_pins_only_runtime_artifact_public_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ca = root / "human-ca.pem"
            ca_certificate(ca)
            key = Ed25519PrivateKey.generate()
            public_key = root / "runtime-artifact-public.pem"
            public_key.write_bytes(
                key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            output = root / "product"
            subprocess.run(
                [
                    sys.executable,
                    str(BUILDER),
                    "--department",
                    "product_center",
                    "--human-ca",
                    str(ca),
                    "--release-lock-digest",
                    "sha256:" + "d" * 64,
                    "--runtime-artifact-verification-public-key",
                    str(public_key),
                    "--output",
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            with zipfile.ZipFile(
                output / "orbit-product_center-lan-d0.zip"
            ) as archive:
                names = set(archive.namelist())
                self.assertIn("runtime-artifact-verification-public.pem", names)
                self.assertFalse(
                    any(
                        "private" in name.lower() or name.endswith(".key")
                        for name in names
                    )
                )
                config = json.loads(archive.read("device-config.json"))
                self.assertTrue(config["runtime_artifact_import"]["enabled"])
                self.assertRegex(
                    config["runtime_artifact_import"]["verification_key_digest"],
                    r"^sha256:[0-9a-f]{64}$",
                )

    def test_publisher_places_three_idempotent_release_scoped_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ca = root / "human-ca.pem"
            ca_certificate(ca)
            artifacts = root / "artifacts"
            artifacts.mkdir(mode=0o700)
            release = "sha256:" + "7" * 64
            command = [
                sys.executable,
                str(PUBLISHER),
                "--human-ca",
                str(ca),
                "--release-lock-digest",
                release,
                "--artifact-root",
                str(artifacts),
            ]
            first = subprocess.run(
                command, check=True, capture_output=True, text=True
            )
            second = subprocess.run(
                command, check=True, capture_output=True, text=True
            )
            self.assertEqual(json.loads(first.stdout), json.loads(second.stdout))
            summary = json.loads(first.stdout)
            self.assertFalse(summary["contains_secret"])
            self.assertFalse(summary["runtime_started"])
            self.assertFalse(summary["release_authorization"])
            self.assertEqual(3, len(summary["bundles"]))
            for department_id in (
                "product_center",
                "technology_center",
                "market_center",
            ):
                bundle = (
                    artifacts
                    / "department-device"
                    / department_id
                    / release.removeprefix("sha256:")
                    / "bundle.zip"
                )
                self.assertTrue(bundle.is_file())
                self.assertEqual(0o600, bundle.stat().st_mode & 0o777)

    def test_builder_rejects_non_ca_and_invalid_release_lock(self) -> None:
        builder = load_builder()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invalid = root / "invalid.pem"
            invalid.write_text("not a certificate" * 16, encoding="utf-8")
            invalid.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "human_ca_pem_invalid"):
                builder.load_ca(invalid)
            result = subprocess.run(
                [
                    sys.executable, str(BUILDER),
                    "--department", "product_center",
                    "--human-ca", str(invalid),
                    "--release-lock-digest", "sha256:bad",
                    "--output", str(root / "out"),
                ],
                check=False, capture_output=True, text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("release_lock_digest_invalid", result.stderr)


if __name__ == "__main__":
    unittest.main()

