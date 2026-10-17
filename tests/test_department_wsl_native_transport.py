"""Exercise a real native process boundary; this is not Windows/WSL acceptance."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PWSH = os.environ.get("ORBIT_TEST_PWSH") or shutil.which("pwsh")

# The executable adapter receives argv/stdin after PowerShell's native transport.
# Only its OS boundary is synthetic; the production helper is dot-sourced intact.
ADAPTER = '''#!{python}
import json, os, pathlib, shutil, subprocess, sys
root = pathlib.Path(os.environ['ORBIT_NATIVE_FIXTURE'])
args = sys.argv[1:]
with (root / 'calls.jsonl').open('a') as out:
    out.write(json.dumps(args) + '\\n')
assert args[:5] == ['--distribution', 'OrbitRuntime-Ubuntu-22.04', '--user', 'root', '--exec'], args
if args[5:6] == ['/usr/bin/test']:
    assert len(args) == 8 and args[6] in ('-e', '-L'), args
    name = pathlib.PurePosixPath(args[7]).name
    assert args[7] == '/home/orbit-runner/.config/orbit-runner/' + name
    assert name in ('client-key.pem', 'client-cert.pem', 'enrollment-receipt.json')
    if os.environ.get('ORBIT_NATIVE_DIAGNOSTIC'):
        stream = sys.stderr if os.environ['ORBIT_NATIVE_DIAGNOSTIC'] == 'stderr' else sys.stdout
        print('synthetic_wsl_startup_error', file=stream)
    if os.environ.get('ORBIT_NATIVE_EXIT'):
        sys.exit(int(os.environ['ORBIT_NATIVE_EXIT']))
    test = shutil.which('test')
    assert test, 'POSIX test unavailable'
    sys.exit(subprocess.run([test, args[6], str(root / name)]).returncode)
assert args[5:] == ['/bin/bash', '-s'], args
(root / 'stdin.bin').write_bytes(sys.stdin.buffer.read())
sys.exit(int(os.environ.get('ORBIT_NATIVE_EXIT', '0')))
'''


@unittest.skipUnless(PWSH and os.name == "posix", "optional POSIX native-boundary harness")
class DepartmentWslNativeTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="orbit-native-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        adapter = self.bin / "wsl.exe"
        adapter.write_text(ADAPTER.format(python=sys.executable))
        adapter.chmod(0o700)
        self.env = dict(os.environ, ORBIT_NATIVE_FIXTURE=str(self.root))
        self.env["PATH"] = str(self.bin) + os.pathsep + os.environ.get("PATH", "")
        self.payload = b"synthetic public bytes: '$p' $(not-a-command)\r\n\x00\xff"
        self.bundle = self.root / "bundle with spaces"
        self.bundle.mkdir()
        (self.bundle / "orbit-human-ca.pem").write_bytes(self.payload)
        self.digest = hashlib.sha256(self.payload).hexdigest()
        (self.bundle / "artifact-set-manifest.json").write_text(json.dumps({
            "files": [{"path": "orbit-human-ca.pem", "sha256": "sha256:" + self.digest}]
        }))

    def run_helper(self, mode, action, expected=None, exit_code=None):
        script = self.root / "run.ps1"
        script.write_text('''param($SourceRoot, $Mode, $Action, $Bundle, $Expected)
$ErrorActionPreference = 'Stop'
$PSNativeCommandArgumentPassing = $Mode
$PSNativeCommandUseErrorActionPreference = $true
. (Join-Path $SourceRoot 'deploy/lan-stage1/department-device/OrbitFirstInstall.ps1')
$OriginalEncoding = $OutputEncoding
try {
    if ($Action -eq 'identity') { Assert-OrbitNoRunnerIdentity 'OrbitRuntime-Ubuntu-22.04' }
    else { Copy-OrbitVerifiedBootstrapFile $Bundle 'orbit-human-ca.pem' 'OrbitRuntime-Ubuntu-22.04' '/opt/orbit-offline/orbit-human-ca.pem' }
    if ($Expected -ne 'pass') { throw 'expected_rejection_missing' }
} catch {
    if ($Expected -eq 'pass' -or $_.Exception.Message -notlike "*$Expected*") { throw }
}
if (-not [object]::ReferenceEquals($OriginalEncoding, $OutputEncoding)) { throw 'caller_encoding_changed' }
Write-Output 'native_boundary_case_passed'
''')
        env = dict(self.env)
        if exit_code is not None:
            env["ORBIT_NATIVE_EXIT"] = str(exit_code)
        result = subprocess.run(
            [PWSH, "-NoLogo", "-NoProfile", "-File", str(script),
             str(ROOT), mode, action, str(self.bundle), expected or "pass"],
            env=env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("native_boundary_case_passed", result.stdout)
        self.assertEqual(result.stderr, "", result.stderr)

    def test_absent_paths_cross_native_boundary_in_both_modes(self):
        for mode in ("Legacy", "Standard"):
            with self.subTest(mode=mode):
                self.run_helper(mode, "identity")
                calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
                self.assertEqual(len(calls), 6)
                self.assertEqual([call[6] for call in calls], ["-e", "-L"] * 3)
                (self.root / "calls.jsonl").unlink()

    def test_each_existing_identity_and_dangling_link_still_rejects(self):
        for name in ("client-key.pem", "client-cert.pem", "enrollment-receipt.json"):
            for kind in ("file", "dangling"):
                with self.subTest(name=name, kind=kind):
                    path = self.root / name
                    if kind == "file":
                        path.write_text("synthetic identity marker")
                    else:
                        path.symlink_to(self.root / "missing-target")
                    self.run_helper("Legacy", "identity", "existing_runner_identity_requires_review")
                    self.assertTrue(path.exists() or path.is_symlink())
                    path.unlink()

    def test_wsl_error_is_not_absence(self):
        for code in (2, 31, 127):
            with self.subTest(code=code):
                self.run_helper("Legacy", "identity", "runner_identity_preflight_failed:" + str(code), code)

    def test_exit_one_with_wsl_diagnostic_is_not_absence(self):
        for mode in ("Legacy", "Standard"):
            for stream in ("stdout", "stderr"):
                with self.subTest(mode=mode, stream=stream):
                    self.env["ORBIT_NATIVE_DIAGNOSTIC"] = stream
                    self.run_helper(mode, "identity", "runner_identity_preflight_failed:unexpected_output", 1)

    def captured_copy_script(self, mode):
        self.run_helper(mode, "copy")
        raw = (self.root / "stdin.bin").read_bytes()
        self.assertTrue(raw.isascii())
        self.assertNotIn(b"\r", raw)
        self.assertIn(b"exit 0\n", raw)
        # Model Windows PowerShell's extra final CRLF; bash must exit before it.
        raw += b"\r\n"
        sandbox = self.root / "synthetic copy targets with spaces"
        sandbox.mkdir(exist_ok=True)
        script = raw.decode().replace("/opt/orbit-bootstrap", str(sandbox / "bootstrap"))
        script = script.replace("/opt/orbit-offline", str(sandbox / "offline"))
        script = script.replace(
            "for p in " + str(sandbox / "bootstrap") + " " + str(sandbox / "offline") + "; do",
            "for p in '" + str(sandbox / "bootstrap") + "' '" + str(sandbox / "offline") + "'; do",
        )
        # Account ownership is an OS adapter; retain the real shell/data/hash flow.
        script = script.replace('install -d -o root -g root -m 0700 "$p"', 'mkdir -p -- "$p"; chmod 0700 "$p"')
        sha = self.bin / "sha256sum"
        sha.write_text('#!/bin/sh\nexec /usr/bin/shasum -a 256 "$@"\n')
        sha.chmod(0o700)
        return script, sandbox / "offline/orbit-human-ca.pem"

    def execute_copy_script(self, script):
        return subprocess.run(["/bin/bash", "-s"], input=script.encode(),
                              env=self.env, capture_output=True, timeout=10)

    def test_stdin_copy_keeps_bytes_and_quotes_in_both_modes(self):
        for mode in ("Legacy", "Standard"):
            with self.subTest(mode=mode):
                script, target = self.captured_copy_script(mode)
                result = self.execute_copy_script(script)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(target.read_bytes(), self.payload)
                self.assertEqual(target.stat().st_mode & 0o777, 0o400)

    def test_wrong_digest_preserves_existing_target_and_removes_temporary(self):
        script, target = self.captured_copy_script("Legacy")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"preserved synthetic prior file")
        result = self.execute_copy_script(script.replace(self.digest, "0" * 64))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), b"preserved synthetic prior file")
        self.assertEqual(list(target.parent.iterdir()), [target])

    def test_copy_refuses_symlink_and_directory_targets(self):
        script, target = self.captured_copy_script("Legacy")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(self.root / "missing-copy-target")
        self.assertNotEqual(self.execute_copy_script(script).returncode, 0)
        self.assertTrue(target.is_symlink())
        target.unlink()
        target.mkdir()
        self.assertNotEqual(self.execute_copy_script(script).returncode, 0)
        self.assertTrue(target.is_dir())

    def test_copy_native_failure_is_not_swallowed(self):
        # PSNativeCommandUseErrorActionPreference=true also must not mask failure.
        self.run_helper("Legacy", "copy", "Program", 7)

