from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DEVICE = ROOT / "deploy/lan-stage1/department-device"


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREPARE = load(
    "deploy/lan-stage1/department-device/wsl/prepare-docker-from-lan.py",
    "docker_prepare_test",
)
HOST = load("deploy/lan-stage1/build-lan-install-bundle.py", "first_install_host_test")


def fixture_archive(path, extra=None):
    files = {
        name: b"synthetic-public-fixture"
        for name in (
            "metadata.json",
            "versions.env",
            "install-docker-offline.sh",
            "docker.asc",
            "InRelease",
            "Packages.gz",
            "packages/test.deb",
        )
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if extra:
            member = tarfile.TarInfo(extra)
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
    return {
        "expected_digest": hashlib.sha256(path.read_bytes()).hexdigest(),
        "expected_size": path.stat().st_size,
    }


class DepartmentFirstInstallTests(unittest.TestCase):
    def test_archive_refuses_changed_bytes_before_creating_destination(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            archive = root / "package.tar.gz"
            pins = fixture_archive(archive)
            archive.write_bytes(archive.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "digest_or_size_mismatch"):
                PREPARE.unpack_verified(
                    archive, root / "unpacked", root / "versions", **pins
                )
            self.assertFalse((root / "unpacked").exists())

    def test_archive_rejects_traversal_and_duplicate_members(self):
        for extra in ("../escape", "/tmp/escape", "metadata.json"):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as t:
                archive = Path(t) / "package.tar.gz"
                pins = fixture_archive(archive, extra)
                with self.assertRaisesRegex(ValueError, "member"):
                    PREPARE.verify_archive(archive, **pins)

    def test_archive_rejects_links(self):
        with tempfile.TemporaryDirectory() as t:
            archive = Path(t) / "package.tar.gz"
            fixture_archive(archive)
            with tarfile.open(archive, "r:gz") as original:
                members = [(m, original.extractfile(m).read()) for m in original]
            with tarfile.open(archive, "w:gz") as out:
                for m, data in members:
                    out.addfile(m, io.BytesIO(data))
                link = tarfile.TarInfo("packages/link")
                link.type = tarfile.SYMTYPE
                link.linkname = "/etc/passwd"
                out.addfile(link)
            with self.assertRaisesRegex(ValueError, "member_invalid"):
                PREPARE.verify_archive(
                    archive,
                    hashlib.sha256(archive.read_bytes()).hexdigest(),
                    archive.stat().st_size,
                )

    def test_version_pin_rejects_before_extracting(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            archive = root / "package.tar.gz"
            pins = fixture_archive(archive)
            versions = root / "versions"
            versions.write_bytes(b"drift")
            with self.assertRaisesRegex(ValueError, "version_pin_mismatch"):
                PREPARE.unpack_verified(archive, root / "unpacked", versions, **pins)
            self.assertFalse((root / "unpacked").exists())

    def test_resume_reuses_only_identical_unpack_and_preserves_drift(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            archive = root / "package.tar.gz"
            pins = fixture_archive(archive)
            versions = root / "versions"
            versions.write_bytes(b"synthetic-public-fixture")
            target = root / "unpacked"
            self.assertTrue(PREPARE.unpack_verified(archive, target, versions, **pins))
            self.assertFalse(PREPARE.unpack_verified(archive, target, versions, **pins))
            payload = target / "packages/test.deb"
            payload.chmod(0o600)
            payload.write_bytes(b"preserve-for-review")
            with self.assertRaisesRegex(ValueError, "existing_unpack_drift"):
                PREPARE.unpack_verified(archive, target, versions, **pins)
            self.assertEqual(payload.read_bytes(), b"preserve-for-review")

    def test_interrupted_unpack_can_retry_without_partial_final_directory(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            archive = root / "package.tar.gz"
            pins = fixture_archive(archive)
            versions = root / "versions"
            versions.write_bytes(b"synthetic-public-fixture")
            target = root / "unpacked"
            original_open = Path.open

            def fail_once(path, mode="r", *args, **kwargs):
                if path.name == "test.deb" and mode == "xb":
                    raise OSError("synthetic_interrupted_write")
                return original_open(path, mode, *args, **kwargs)

            with (
                patch.object(Path, "open", fail_once),
                self.assertRaisesRegex(OSError, "synthetic_interrupted_write"),
            ):
                PREPARE.unpack_verified(archive, target, versions, **pins)
            self.assertFalse(
                target.exists(), "partial output must never occupy final directory"
            )
            self.assertFalse(list(root.glob(".orbit-docker-unpack-*")))
            self.assertTrue(PREPARE.unpack_verified(archive, target, versions, **pins))
            self.assertFalse(PREPARE.unpack_verified(archive, target, versions, **pins))

    def test_atomic_publication_preserves_existing_empty_destination(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            source = root / "own-temporary"
            target = root / "existing-empty"
            source.mkdir()
            (source / "fixture").write_bytes(b"synthetic")
            target.mkdir()
            before = target.stat().st_ino
            with self.assertRaises(FileExistsError):
                PREPARE.publish_directory_without_replace(source, target)
            self.assertEqual(target.stat().st_ino, before)
            self.assertEqual(list(target.iterdir()), [])
            self.assertEqual((source / "fixture").read_bytes(), b"synthetic")

    def test_runner_dialog_uses_verified_department_presentation(self):
        script = (DEVICE / "Install-OrbitWslRunner.ps1").read_text(encoding="utf-8-sig")
        self.assertNotIn("/technology/setup", script)
        self.assertNotIn("技术中心", script)
        self.assertIn("$Form.Text = $Presentation.WindowTitle", script)
        self.assertIn("$IdHint.Text = $Presentation.IdHint", script)
        self.assertIn('$IdLabel.Text = "登记编号"', script)
        self.assertIn('$CodeLabel.Text = "一次性代码"', script)
        self.assertLess(
            script.index("Get-OrbitEnrollmentPresentation $DeviceConfig"),
            script.index("$EnrollmentPresentation.WindowTitle"),
        )

    def test_redirect_is_rejected_without_following(self):
        with self.assertRaisesRegex(ValueError, "redirect_rejected"):
            PREPARE.NoRedirect().redirect_request(
                None, None, 302, "found", {}, "https://unexpected.invalid/"
            )

    def test_host_publication_requires_complete_digest_bound_delivery(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            source = root / "source"
            source.mkdir()
            manifest_name = "docker-jammy-amd64-offline.json"
            archive_name = "docker-jammy-amd64-offline.tar.gz"
            payload = b"synthetic-public-docker-delivery"
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            manifest = {
                "sha256": digest,
                "size": len(payload),
                "bundle_path": "/bootstrap/" + archive_name,
                "production_authorization": False,
                "release_authorization": False,
            }
            manifest_bytes = json.dumps(manifest).encode()
            pin = {
                "schema_version": "orbit.docker-bootstrap-pin/1",
                "bundle_sha256": digest,
                "bundle_size": len(payload),
                "manifest_sha256": "sha256:"
                + hashlib.sha256(manifest_bytes).hexdigest(),
            }
            pin_path = root / "pin.json"
            pin_path.write_text(json.dumps(pin))
            (source / manifest_name).write_bytes(manifest_bytes)
            with self.assertRaisesRegex(RuntimeError, "delivery_missing"):
                HOST.copy_verified_docker_bootstrap(source, root / "missing", pin_path)
            self.assertFalse((root / "missing").exists())
            (source / archive_name).write_bytes(b"drift")
            with self.assertRaisesRegex(RuntimeError, "digest_mismatch"):
                HOST.copy_verified_docker_bootstrap(source, root / "drifted", pin_path)
            self.assertFalse((root / "drifted").exists())
            (source / archive_name).write_bytes(payload)
            result = HOST.copy_verified_docker_bootstrap(
                source, root / "good", pin_path
            )
            self.assertFalse(result["ubuntu_base_dependencies_offline"])
            self.assertEqual((root / "good" / archive_name).read_bytes(), payload)

    def test_normal_entry_preserves_identity_before_initialization(self):
        initialize = (DEVICE / "Initialize-OrbitWsl.ps1").read_text(
            encoding="utf-8-sig"
        )
        self.assertLess(
            initialize.index("Assert-OrbitNoRunnerIdentity $DistroName"),
            initialize.index("Copy-OrbitVerifiedBootstrapFile $BundleRoot"),
        )
        self.assertIn('"--location", $ImportLocation', initialize)
        self.assertNotIn('if ($Help -match "--name")', initialize)
        self.assertLess(
            initialize.index("Get-OrbitDockerDelivery $BundleRoot"),
            initialize.index("$Distros = Get-Distros"),
        )
        self.assertIn("prepare-base", initialize)
        self.assertIn("prepare-docker-from-lan.py", initialize)
        self.assertNotIn("Resume-OrbitDockerFromLan", initialize)

    @unittest.skipUnless(
        os.environ.get("ORBIT_TEST_PWSH") or shutil.which("pwsh"),
        "optional PowerShell interpreter unavailable",
    )
    def test_real_powershell_synthetic_refusal_harness(self):
        pwsh = os.environ.get("ORBIT_TEST_PWSH") or shutil.which("pwsh")
        result = subprocess.run(
            [
                pwsh,
                "-NoLogo",
                "-NoProfile",
                "-File",
                str(ROOT / "tests/powershell/first-install.tests.ps1"),
                "-SourceRoot",
                str(ROOT),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("FINAL: 21 synthetic first-install checks passed", result.stdout)

    @unittest.skipUnless(
        os.environ.get("ORBIT_TEST_PWSH") or shutil.which("pwsh"),
        "optional PowerShell interpreter unavailable",
    )
    def test_initialize_production_control_flow_with_synthetic_adapters(self):
        pwsh = os.environ.get("ORBIT_TEST_PWSH") or shutil.which("pwsh")
        result = subprocess.run(
            [
                pwsh,
                "-NoLogo",
                "-NoProfile",
                "-File",
                str(ROOT / "tests/powershell/initialize-flow.tests.ps1"),
                "-SourceRoot",
                str(ROOT),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "FINAL: 4 production Initialize control-flow scenarios passed",
            result.stdout,
        )

