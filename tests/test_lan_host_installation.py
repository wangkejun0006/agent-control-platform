from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from orbit_agent_control_plane.service_runtime.lan_stage1 import (
    _validate_deployment_release_lock,
)

from tests.test_lan_stage1 import deployment_release_lock

ROOT = Path(__file__).resolve().parents[1]
LAN = ROOT / "deploy/lan-stage1"


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode()


def create_ca(path: Path, common_name: str) -> ec.EllipticCurvePrivateKey:
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o600)
    return key


def create_server(path: Path, ca_path: Path, ca_key: ec.EllipticCurvePrivateKey) -> None:
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "192.168.21.22")])
    issuer = x509.load_pem_x509_certificate(ca_path.read_bytes()).subject
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o600)


class LanHostInstallationTests(unittest.TestCase):
    def test_installer_keeps_candidate_and_host_boundaries(self) -> None:
        installer = (LAN / "install-lan-candidate.sh").read_text(encoding="utf-8")
        finalizer = (LAN / "finalize-lan-release-lock.py").read_text(encoding="utf-8")
        self.assertIn("192.168.21.22", installer)
        self.assertIn("DNS:control-plane.orbit.local", installer)
        self.assertIn("socketfilterfw --setglobalstate on", installer)
        self.assertIn("OrbitControlPlane.pre-lan-", installer)
        self.assertIn("orbit-lan-install-failure-", installer)
        self.assertIn("--certificate-identity", installer)
        self.assertIn("--certificate-oidc-issuer", installer)
        self.assertNotIn("--reservation-verified", installer)
        self.assertIn('test -S "$root/sockets/control-plane-human.sock"', installer)
        self.assertIn('test -S "$root/sockets/control-plane-workload.sock"', installer)
        self.assertGreaterEqual(installer.count('test "$attempt" -lt 60'), 4)
        self.assertIn('"runtime_started": False', finalizer)
        self.assertIn('"release_authorization": False', finalizer)
        self.assertNotIn("docker run", installer)
        self.assertIn("publish-device-bundles.py", installer)
        postgres = (LAN / "com.orbit.control-plane-lan-postgresql.plist").read_text()
        self.assertIn("<key>LC_ALL</key><string>C</string>", postgres)
        self.assertIn("<key>LANG</key><string>C</string>", postgres)
        updater = (LAN / "update-lan-frontend.sh").read_text(encoding="utf-8")
        persister = (LAN / "persist-lan-release-lock.py").read_text(encoding="utf-8")
        self.assertIn("prepare-lan-frontend-update.py", updater)
        self.assertIn("persist-lan-release-lock.py", updater)
        self.assertIn('"$root/venv/bin/python" -B - "$bundle" "$new_lock"', updater)
        self.assertNotIn('/usr/bin/python3 - "$bundle" "$new_lock"', updater)
        self.assertNotIn("负责人账号接力", updater)
        self.assertIn("verify-lan-update.py", updater)
        self.assertIn("verified after rollback", updater)
        self.assertIn("rollback incomplete", updater)
        self.assertIn("lan-surface-control.py", updater)
        self.assertIn("surface-pids.json", updater)
        self.assertNotIn("/bin/sleep 3", updater)
        self.assertNotIn("docker run", updater)
        self.assertNotIn("alembic downgrade", updater)
        self.assertIn('"$root/venv/bin/alembic"', updater)
        self.assertIn("upgrade head", updater)
        self.assertIn("ORBIT_SERVICE_DATABASE_URL_FILE", updater)
        self.assertIn("new immutable deployment lock id required", updater)
        self.assertIn("publish-device-bundles.py", updater)
        self.assertIn('), 204)', persister)
        sni_repair = (LAN / "repair-lan-workload-sni.sh").read_text()
        self.assertIn("--resolve \"$server_name:9443:$server_ip\"", sni_repair)
        self.assertIn("DNS:$server_name", sni_repair)
        self.assertIn('x509 -in "$temporary/lan-server-cert.pem" -text -noout', sni_repair)
        self.assertNotIn("-noout -ext subjectAltName", sni_repair)
        self.assertNotIn("strict_sni_host insecure_off", sni_repair)
        self.assertIn("runtime_started=false", sni_repair)

    def test_frontend_update_creates_new_lock_without_scope_drift(self) -> None:
        current = deployment_release_lock()
        spec = current["spec"]

        def fresh(label: str) -> str:
            return "sha256:" + hashlib.sha256(label.encode()).hexdigest()

        inputs = {
            "schema_version": "orbit.stage1-lan-install-inputs/0.1-draft",
            "semantic_authority": {
                "release_id": spec["architecture_authority"]["release_id"],
                "release_manifest_digest": spec["architecture_authority"]["release_manifest_digest"],
                "repository_commit": spec["architecture_authority"]["repository_commit"],
            },
            "repository_commits": spec["repository_commits"],
            "build_bundle": {
                **spec["build_bundle"],
                "bundle_digest": fresh("updated-build-bundle"),
                "manifest_digest": fresh("updated-build-manifest"),
                "provenance_digest": fresh("updated-build-provenance"),
            },
            "installer_bundle": {
                **spec["installer_bundle"],
                "bundle_digest": fresh("updated-installer-bundle"),
                "manifest_digest": fresh("updated-installer-manifest"),
            },
            "runtime_artifacts": spec["runtime_artifacts"],
            "authority_boundary": {
                "approval_created": False, "execution_grant_issued": False,
                "worker_lease_issued": False, "qualification_conferred": False,
                "deployment_activated": False, "runtime_started": False,
                "production_authorized": False, "release_authorization": False,
            },
        }
        inputs["inputs_digest"] = "sha256:" + hashlib.sha256(canonical(inputs)).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current_path = root / "current.json"
            inputs_path = root / "inputs.json"
            output = root / "updated.json"
            current_path.write_text(json.dumps(current), encoding="utf-8")
            inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
            subprocess.run([
                sys.executable, str(LAN / "prepare-lan-frontend-update.py"),
                "--current-lock", str(current_path.resolve()),
                "--inputs", str(inputs_path.resolve()),
                "--output", str(output.resolve()),
                "--lock-id", "synthetic_frontend_update_0002",
                "--version", "0.3.1-synthetic.2", "--revision", "2",
            ], check=True, capture_output=True, text=True)
            updated = json.loads(output.read_text())
        _validate_deployment_release_lock(updated)
        self.assertEqual(spec["lan_service_profile_digest"], updated["spec"]["lan_service_profile_digest"])
        self.assertEqual(spec["runtime_artifacts"], updated["spec"]["runtime_artifacts"])
        self.assertNotEqual(spec["build_bundle"], updated["spec"]["build_bundle"])
        self.assertFalse(updated["authority_boundary"]["runtime_started"])
        self.assertFalse(updated["authority_boundary"]["release_authorization"])

    def test_source_update_advances_semantic_release_without_runtime_drift(self) -> None:
        current = deployment_release_lock()
        spec = current["spec"]
        spec["architecture_authority"]["release_id"] = (
            "semantic-authority-v0.1.0-alpha.5"
        )
        spec["architecture_authority"]["release_manifest_ref"] = (
            "artifact://architecture/semantic-authority-v0.1.0-alpha.5/manifest"
        )
        inputs = {
            "schema_version": "orbit.stage1-lan-install-inputs/0.1-draft",
            "semantic_authority": {
                "release_id": "semantic-authority-v0.1.0-alpha.7",
                "release_manifest_digest": "sha256:" + hashlib.sha256(
                    b"semantic-authority-alpha6-manifest"
                ).hexdigest(),
                "repository_commit": "9" * 40,
            },
            "repository_commits": [
                {
                    **item,
                    "commit_sha": "9" * 40
                    if item["repository_role"] == "architecture"
                    else item["commit_sha"],
                }
                for item in spec["repository_commits"]
            ],
            "build_bundle": spec["build_bundle"],
            "installer_bundle": spec["installer_bundle"],
            "runtime_artifacts": spec["runtime_artifacts"],
            "authority_boundary": {
                "approval_created": False, "execution_grant_issued": False,
                "worker_lease_issued": False, "qualification_conferred": False,
                "deployment_activated": False, "runtime_started": False,
                "production_authorized": False, "release_authorization": False,
            },
        }
        inputs["inputs_digest"] = "sha256:" + hashlib.sha256(canonical(inputs)).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current_path = root / "current.json"
            inputs_path = root / "inputs.json"
            output = root / "updated.json"
            current_path.write_text(json.dumps(current), encoding="utf-8")
            inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
            subprocess.run([
                sys.executable, str(LAN / "prepare-lan-frontend-update.py"),
                "--current-lock", str(current_path.resolve()),
                "--inputs", str(inputs_path.resolve()),
                "--output", str(output.resolve()),
                "--lock-id", "synthetic_source_update_alpha6",
                "--version", "0.3.2-synthetic.1", "--revision", "3",
            ], check=True, capture_output=True, text=True)
            updated = json.loads(output.read_text())
        _validate_deployment_release_lock(updated)
        self.assertEqual(
            "semantic-authority-v0.1.0-alpha.7",
            updated["spec"]["architecture_authority"]["release_id"],
        )
        self.assertEqual(spec["runtime_artifacts"], updated["spec"]["runtime_artifacts"])
        self.assertEqual(
            spec["lan_service_profile_digest"],
            updated["spec"]["lan_service_profile_digest"],
        )
        self.assertFalse(updated["authority_boundary"]["release_authorization"])

        inputs["semantic_authority"]["release_id"] = (
            "semantic-authority-v0.1.0-alpha.4"
        )
        inputs.pop("inputs_digest")
        inputs["inputs_digest"] = "sha256:" + hashlib.sha256(canonical(inputs)).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current_path = root / "current.json"
            inputs_path = root / "inputs.json"
            output = root / "regressed.json"
            current_path.write_text(json.dumps(current), encoding="utf-8")
            inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
            failed = subprocess.run([
                sys.executable, str(LAN / "prepare-lan-frontend-update.py"),
                "--current-lock", str(current_path.resolve()),
                "--inputs", str(inputs_path.resolve()),
                "--output", str(output.resolve()),
                "--lock-id", "synthetic_source_update_regression",
                "--version", "0.3.2-synthetic.2", "--revision", "4",
            ], capture_output=True, text=True)
        self.assertNotEqual(0, failed.returncode)
        self.assertIn("lan_frontend_update_semantic_release_regression", failed.stderr)

    def test_finalizer_binds_certificates_and_keeps_reservation_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            human_ca = root / "human-ca.pem"
            workload_ca = root / "workload-ca.pem"
            server = root / "server.pem"
            human_key = create_ca(human_ca, "Human Test")
            create_ca(workload_ca, "Workload Test")
            create_server(server, human_ca, human_key)
            inputs = {
                "schema_version": "orbit.stage1-lan-install-inputs/0.1-draft",
                "semantic_authority": {
                    "release_id": "semantic-authority-v0.1.0-alpha.7",
                    "release_manifest_digest": "sha256:" + "1" * 64,
                    "repository_commit": "1" * 40,
                },
                "repository_commits": [
                    {
                        "repository_role": role, "repository_id": f"synthetic_{role}",
                        "commit_sha": digit * 40, "source_tree_digest": "sha256:" + digit * 64,
                    }
                    for role, digit in (
                        ("architecture", "1"), ("control_plane", "2"),
                        ("department_cockpit", "3"),
                    )
                ],
                "build_bundle": {
                    "manifest_ref": "artifact://synthetic/build", "bundle_digest": "sha256:" + "4" * 64,
                    "manifest_digest": "sha256:" + "5" * 64, "provenance_digest": "sha256:" + "6" * 64,
                },
                "installer_bundle": {
                    "bundle_ref": "artifact://synthetic/installer", "bundle_digest": "sha256:" + "7" * 64,
                    "manifest_digest": "sha256:" + "8" * 64,
                },
                "runtime_artifacts": [],
                "authority_boundary": {
                    "approval_created": False, "execution_grant_issued": False,
                    "worker_lease_issued": False, "qualification_conferred": False,
                    "deployment_activated": False, "runtime_started": False,
                    "production_authorized": False, "release_authorization": False,
                },
            }
            inputs["inputs_digest"] = "sha256:" + hashlib.sha256(canonical(inputs)).hexdigest()
            inputs_path = root / "inputs.json"
            inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable, str(LAN / "finalize-lan-release-lock.py"),
                    "--inputs", str(inputs_path), "--human-ca", str(human_ca),
                    "--workload-ca", str(workload_ca), "--server-cert", str(server),
                    "--output-root", str(root / "output"),
                ],
                check=True, capture_output=True, text=True,
            )
            summary = json.loads(result.stdout)
            profile = json.loads((root / "output/stage1-lan-service-profile.json").read_text())
            lock = json.loads((root / "output/deployment-release-lock.json").read_text())
            self.assertFalse(summary["reservation_verified"])
            self.assertFalse(profile["spec"]["network_binding"]["reservation_verified"])
            self.assertEqual("192.168.21.22", profile["spec"]["network_binding"]["control_plane_ipv4"])
            self.assertFalse(lock["authority_boundary"]["runtime_started"])
            self.assertFalse(lock["authority_boundary"]["release_authorization"])
            candidate = json.loads(json.dumps(lock))
            embedded = candidate["spec"].pop("lock_digest")
            self.assertEqual(embedded, "sha256:" + hashlib.sha256(canonical(candidate)).hexdigest())


if __name__ == "__main__":
    unittest.main()

