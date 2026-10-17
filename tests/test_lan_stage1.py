from __future__ import annotations

import base64
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
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.cockpit_local_identity import (
    ROLE_DEPARTMENT_OWNER,
    ROLE_DEPARTMENT_USER,
    ScryptPasswordHasher,
)
from orbit_agent_control_plane.service_runtime.codex_installation import (
    CodexInstallationService,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.department_cockpit import (
    DepartmentCockpitService,
    LangGraphPlanningTransport,
)
from orbit_agent_control_plane.service_runtime.governance_catalogs import (
    GovernanceCatalogService,
)
from orbit_agent_control_plane.service_runtime.lan_stage1 import (
    DatabaseArtifactDownloadAuthority,
    FileArtifactBundleResolver,
    FileDepartmentDeviceBundleResolver,
    LanHumanIdentityService,
    LanNodeService,
    LanStage1Error,
    LanWorkloadIdentityService,
    OfflineReceiptSpool,
)
from orbit_agent_control_plane.service_runtime.lan_stage1_api import (
    CSRF_HEADER,
    create_human_app,
    create_workload_app,
)
from orbit_agent_control_plane.service_runtime.lan_stage1_main import (
    _bootstrap_password_from_file,
)
from orbit_agent_control_plane.service_runtime.lan_stage1_models import (
    LanArtifactDownloadAssignmentRow,
    LanArtifactDownloadReceiptRow,
    LanCertificateBindingRow,
    LanDepartmentObservationContextRow,
    LanDeploymentReleaseLockRow,
    LanHumanAccountRow,
    LanInviteRow,
    LanSessionRow,
)
from orbit_agent_control_plane.service_runtime.models import (
    Base,
    DepartmentCockpitObjectRow,
    ReceiptRow,
)
from orbit_agent_control_plane.service_runtime.runtime_artifact_models import (
    RuntimeArtifactImportReceiptRow,
    RuntimeArtifactRevisionRow,
    RuntimeNodeCapabilityReportRow,
)

NOW = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
DEVICE_BUILDER = ROOT / "deploy/lan-stage1/department-device/build-device-bundle.py"


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        return self.value


class SyntheticIssuer:
    """Ephemeral test-only issuer; no key or certificate is persisted."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())

    def issue_client_certificate(
        self,
        *,
        csr: x509.CertificateSigningRequest,
        uri_san: str,
        not_before: datetime,
        not_after: datetime,
    ) -> bytes:
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic D0 CA")])
            )
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri_san)]),
                critical=True,
            )
            .sign(self.key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def verify_mtls_peer(self, *, peer_certificate: bytes) -> dict[str, str]:
        cert = x509.load_der_x509_certificate(peer_certificate)
        self.key.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        uri = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)[0]
        return {
            "spiffe_id": uri,
            "certificate_fingerprint": "sha256:"
            + cert.fingerprint(hashes.SHA256()).hex(),
        }


class MemoryBundleResolver:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def read_bundle(self, **_: object) -> bytes:
        return self.content


class NoWorkRuntimeArtifacts:
    def claim_lease(self, **_: object) -> dict[str, object]:
        return {"claimed": False, "reason_code": "runtime_node_no_eligible_work"}

    def revision(self, **_: object) -> dict[str, object]:
        return {"status": "qualified_d0", "revoked": False}

    def record_capability_report(self, **_: object) -> dict[str, object]:
        return {
            "receipt_id": "receipt_capability_syn",
            "production_authorization": False,
        }

    def record_import_receipt(self, **_: object) -> dict[str, object]:
        return {"receipt_id": "receipt_import_syn", "production_authorization": False}

    def append_run_evidence(self, **_: object) -> dict[str, object]:
        return {
            "receipt_id": "receipt_runtime_evidence_syn",
            "production_authorization": False,
        }


class SyntheticDownloadAuthority:
    def authorize_download(self, **_: object) -> None:
        return None


class FileArtifactBundleResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.artifact_id = "runtime_artifact_hermes_loopback_syn"
        self.revision_digest = "sha256:" + "a" * 64
        self.content = b"synthetic-oci-layout-without-executable-runtime"
        self.bundle_digest = "sha256:" + hashlib.sha256(self.content).hexdigest()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_bundle(self) -> Path:
        path = FileArtifactBundleResolver.bundle_path(
            root=self.root,
            artifact_id=self.artifact_id,
            revision_digest=self.revision_digest,
            bundle_digest=self.bundle_digest,
        )
        path.parent.mkdir(parents=True, mode=0o700)
        for parent in (path.parent.parent, path.parent):
            parent.chmod(0o700)
        path.write_bytes(self.content)
        path.chmod(0o600)
        return path

    def test_reads_only_exact_owner_only_digest_bound_file(self) -> None:
        self._write_bundle()
        resolver = FileArtifactBundleResolver(self.root)
        self.assertEqual(
            self.content,
            resolver.read_bundle(
                artifact_id=self.artifact_id,
                revision_digest=self.revision_digest,
                bundle_digest=self.bundle_digest,
            ),
        )

    def test_rejects_symlink_permissions_and_digest_drift(self) -> None:
        path = self._write_bundle()
        resolver = FileArtifactBundleResolver(self.root)

        path.chmod(0o640)
        with self.assertRaisesRegex(
            LanStage1Error, "lan_artifact_bundle_permissions_invalid"
        ):
            resolver.read_bundle(
                artifact_id=self.artifact_id,
                revision_digest=self.revision_digest,
                bundle_digest=self.bundle_digest,
            )

        path.chmod(0o600)
        path.write_bytes(b"drifted")
        with self.assertRaisesRegex(LanStage1Error, "lan_artifact_bundle_digest_drift"):
            resolver.read_bundle(
                artifact_id=self.artifact_id,
                revision_digest=self.revision_digest,
                bundle_digest=self.bundle_digest,
            )

        path.unlink()
        target = self.root / "outside.oci.tar"
        target.write_bytes(self.content)
        target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaisesRegex(LanStage1Error, "lan_artifact_bundle_path_invalid"):
            resolver.read_bundle(
                artifact_id=self.artifact_id,
                revision_digest=self.revision_digest,
                bundle_digest=self.bundle_digest,
            )


class FileDepartmentDeviceBundleResolverTests(unittest.TestCase):
    def test_reads_exact_department_release_and_rejects_permission_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            lock_digest = "sha256:" + "4" * 64
            content = stage_department_device_bundle(
                root,
                department_id="technology_center",
                release_lock_digest=lock_digest,
            )
            resolver = FileDepartmentDeviceBundleResolver(root)
            package = resolver.read_bundle(
                department_id="technology_center",
                deployment_release_lock_digest=lock_digest,
            )
            self.assertEqual(content, package["content"])
            self.assertEqual("orbit-technology-center-lan-d0.zip", package["filename"])
            self.assertRegex(package["bundle_digest"], r"^sha256:[0-9a-f]{64}$")

            path = FileDepartmentDeviceBundleResolver.bundle_path(
                root=root,
                department_id="technology_center",
                deployment_release_lock_digest=lock_digest,
            )
            path.chmod(0o640)
            with self.assertRaisesRegex(
                LanStage1Error, "lan_department_device_bundle_path_invalid"
            ):
                resolver.read_bundle(
                    department_id="technology_center",
                    deployment_release_lock_digest=lock_digest,
                )

            with self.assertRaisesRegex(
                LanStage1Error, "lan_department_device_bundle_path_invalid"
            ):
                resolver.read_bundle(
                    department_id="market_center",
                    deployment_release_lock_digest=lock_digest,
                )


def csr(uri_san: str, *, curve: ec.EllipticCurve | None = None) -> bytes:
    key = ec.generate_private_key(curve or ec.SECP256R1())
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic LAN node")])
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri_san)]),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return request.public_bytes(serialization.Encoding.PEM)


def deployment_release_lock(
    *,
    artifact_id: str = "synthetic_runtime_artifact",
    revision_digest: str = "sha256:" + "d" * 64,
) -> dict[str, object]:
    value: dict[str, object] = {
        "api_version": "company-ai-os/v1alpha3-draft",
        "kind": "DeploymentReleaseLock",
        "metadata": {
            "lock_id": "synthetic_stage1_deployment_lock",
            "version": "0.3.0-synthetic.1",
            "revision": 1,
            "status": "candidate",
            "evidence_status": "synthetic_d0",
            "synthetic_only": True,
            "created_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        "spec": {
            "architecture_authority": {
                "release_id": "semantic-authority-v0.1.0-alpha.7",
                "release_manifest_ref": "artifact://synthetic/semantic-authority-alpha6/manifest",
                "release_manifest_digest": "sha256:" + "1" * 64,
                "repository_commit": "1" * 40,
            },
            "repository_commits": [
                {
                    "repository_role": "architecture",
                    "repository_id": "orbit_agent_architecture",
                    "commit_sha": "1" * 40,
                    "source_tree_digest": "sha256:" + "2" * 64,
                },
                {
                    "repository_role": "control_plane",
                    "repository_id": "orbit_agent_control_plane",
                    "commit_sha": "2" * 40,
                    "source_tree_digest": "sha256:" + "3" * 64,
                },
                {
                    "repository_role": "department_cockpit",
                    "repository_id": "orbit_department_cockpit_core",
                    "commit_sha": "3" * 40,
                    "source_tree_digest": "sha256:" + "4" * 64,
                },
            ],
            "build_bundle": {
                "manifest_ref": "artifact://synthetic/cockpit-build/manifest",
                "bundle_digest": "sha256:" + "5" * 64,
                "manifest_digest": "sha256:" + "6" * 64,
                "provenance_digest": "sha256:" + "7" * 64,
            },
            "installer_bundle": {
                "bundle_ref": "artifact://synthetic/wsl-installer/bundle",
                "bundle_digest": "sha256:" + "8" * 64,
                "manifest_digest": "sha256:" + "9" * 64,
            },
            "lan_service_profile_ref": {
                "id": "synthetic_stage1_lan_profile",
                "version": "0.3.0-synthetic.1",
                "digest": "sha256:" + "a" * 64,
            },
            "lan_service_profile_digest": "sha256:" + "a" * 64,
            "runtime_artifacts": [
                {
                    "runtime_family": "hermes",
                    "runtime_artifact_ref": {
                        "id": artifact_id,
                        "version": "0.3.0-synthetic.1",
                        "digest": revision_digest,
                    },
                    "runtime_artifact_manifest_digest": revision_digest,
                    "runtime_source_digest": "sha256:" + "e" * 64,
                    "runtime_image_manifest_digest": "sha256:" + "f" * 64,
                }
            ],
            "lock_digest": "sha256:" + "0" * 64,
        },
        "authority_boundary": {
            "approval_created": False,
            "execution_grant_issued": False,
            "worker_lease_issued": False,
            "qualification_conferred": False,
            "deployment_activated": False,
            "runtime_started": False,
            "contract_published": False,
            "production_authorized": False,
            "release_authorization": False,
        },
    }
    candidate = json.loads(json.dumps(value))
    del candidate["spec"]["lock_digest"]
    encoded = json.dumps(
        candidate,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    value["spec"]["lock_digest"] = "sha256:" + hashlib.sha256(encoded).hexdigest()
    return value


def stage_department_device_bundle(
    root: Path,
    *,
    department_id: str,
    release_lock_digest: str,
) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic Human D0 CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=1))
        .not_valid_after(NOW + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca = root / "human-ca.pem"
    ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    ca.chmod(0o600)
    output = root / "build"
    subprocess.run(
        [
            sys.executable,
            str(DEVICE_BUILDER),
            "--department",
            department_id,
            "--human-ca",
            str(ca),
            "--release-lock-digest",
            release_lock_digest,
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    content = (output / f"orbit-{department_id}-lan-d0.zip").read_bytes()
    target = FileDepartmentDeviceBundleResolver.bundle_path(
        root=root,
        department_id=department_id,
        deployment_release_lock_digest=release_lock_digest,
    )
    target.parent.mkdir(parents=True, mode=0o700)
    for parent in (target.parent.parent.parent, target.parent.parent, target.parent):
        parent.chmod(0o700)
    target.write_bytes(content)
    target.chmod(0o600)
    return content


class LanStage1Tests(unittest.TestCase):
    def test_bootstrap_password_file_is_owner_only_single_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "password"
            path.write_text("D0-only-password!\n", encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual("D0-only-password!", _bootstrap_password_from_file(path))
            path.chmod(0o644)
            with self.assertRaisesRegex(
                LanStage1Error, "lan_bootstrap_password_file_invalid"
            ):
                _bootstrap_password_from_file(path)
            path.chmod(0o600)
            path.write_text("first-password\nsecond-password\n", encoding="utf-8")
            with self.assertRaisesRegex(
                LanStage1Error, "lan_bootstrap_password_file_invalid"
            ):
                _bootstrap_password_from_file(path)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = Database(f"sqlite+pysqlite:///{self.root / 'lan.sqlite3'}")
        Base.metadata.create_all(self.database.engine)
        self.clock = Clock()
        self.identity = LanHumanIdentityService(
            self.database,
            password_hasher=ScryptPasswordHasher(n=2**12),
            now=self.clock,
        )
        self.issuer = SyntheticIssuer()
        self.workloads = LanWorkloadIdentityService(
            self.database,
            issuer=self.issuer,
            direct_mtls_verifier=self.issuer,
            now=self.clock,
        )
        self.nodes = LanNodeService(self.database, now=self.clock)
        self.password = "Stage1-LAN-Password!"
        self.admin = self.identity.bootstrap_admin_cli_only(
            username="company.admin",
            password=self.password,
            display_name="公司管理员",
        )

    def tearDown(self) -> None:
        self.database.dispose()
        self.temporary.cleanup()

    def _owner(self) -> dict[str, object]:
        invite = self.identity.create_invite(
            principal=self.admin,
            department_id="market_center",
            role_ref=ROLE_DEPARTMENT_OWNER,
            idempotency_key="invite-owner-0001",
        )
        pending = self.identity.register(
            invite_code=str(invite["invite_code"]),
            username="market.owner",
            password=self.password,
            display_name="市场负责人",
            idempotency_key="register-owner-0001",
        )
        return self.identity.approve_account(
            principal=self.admin,
            account_id=str(pending["account_id"]),
            idempotency_key="approve-owner-0001",
        )["account"] | {
            "human_ref": pending["human_ref"],
            "role_refs": pending["role_refs"],
            "department_refs": pending["department_refs"],
            "permissions": pending["permissions"],
        }

    def _enrolled(self) -> tuple[dict[str, object], dict[str, object]]:
        owner = self._owner()
        enrollment = self.workloads.create_enrollment_code(
            principal=owner,
            department_id="market_center",
            node_id="node_market_001",
            idempotency_key="enroll-node-0001",
        )
        certificate = self.workloads.enroll(
            enrollment_id=str(enrollment["enrollment_id"]),
            enrollment_code=str(enrollment["enrollment_code"]),
            csr_pem=csr(str(enrollment["expected_uri_san"])),
            idempotency_key="bind-node-0001",
        )
        return owner, certificate

    def test_metadata_registers_all_lan_tables_and_bootstrap_is_admin_only(
        self,
    ) -> None:
        expected = {
            "control_plane_lan_human_accounts",
            "control_plane_lan_invites",
            "control_plane_lan_sessions",
            "control_plane_lan_enrollment_codes",
            "control_plane_lan_certificate_bindings",
            "control_plane_lan_certificate_revocations",
            "control_plane_lan_node_heartbeats",
            "control_plane_lan_artifact_download_assignments",
            "control_plane_lan_deployment_release_locks",
            "control_plane_lan_artifact_download_receipts",
            "control_plane_lan_mutation_commands",
            "control_plane_lan_department_observation_contexts",
            "control_plane_lan_codex_installation_attempts",
            "control_plane_lan_codex_installation_events",
            "control_plane_lan_codex_installation_receipts",
        }
        self.assertTrue(expected.issubset(Base.metadata.tables))
        self.assertFalse(self.admin["permissions"]["confirm_tasks"])
        with self.assertRaisesRegex(LanStage1Error, "lan_bootstrap_already_completed"):
            self.identity.bootstrap_admin_cli_only(
                username="another.admin",
                password=self.password,
                display_name="另一管理员",
            )
        with self.assertRaisesRegex(LanStage1Error, "lan_scrypt_cost_too_low"):
            LanHumanIdentityService(
                self.database, password_hasher=ScryptPasswordHasher(n=2**10)
            )

    def test_invite_is_hash_only_single_use_and_replay_never_returns_code(self) -> None:
        owner = self._owner()
        with self.assertRaisesRegex(LanStage1Error, "lan_invite_role_not_allowed"):
            self.identity.create_invite(
                principal=self.admin,
                department_id="product_center",
                role_ref=ROLE_DEPARTMENT_USER,
                idempotency_key="invite-admin-user-0001",
            )
        result = self.identity.create_invite(
            principal=owner,
            department_id="market_center",
            role_ref=ROLE_DEPARTMENT_USER,
            idempotency_key="invite-user-0001",
        )
        replay = self.identity.create_invite(
            principal=owner,
            department_id="market_center",
            role_ref=ROLE_DEPARTMENT_USER,
            idempotency_key="invite-user-0001",
        )
        self.assertIsNone(replay["invite_code"])
        raw = str(result["invite_code"])
        with self.database.session() as session:
            row = session.scalar(
                select(LanInviteRow).where(
                    LanInviteRow.invite_id == result["invite_id"]
                )
            )
            assert row is not None
            self.assertNotEqual(raw, row.token_digest)
            self.assertEqual(
                24 * 60 * 60,
                int(
                    (row.expires_at.replace(tzinfo=timezone.utc) - NOW).total_seconds()
                ),
            )
        self.identity.register(
            invite_code=raw,
            username="product.user",
            password=self.password,
            display_name="产品用户",
            idempotency_key="register-product-0001",
        )
        with self.assertRaisesRegex(LanStage1Error, "lan_invite_invalid"):
            self.identity.register(
                invite_code=raw,
                username="product.second",
                password=self.password,
                display_name="产品二号",
                idempotency_key="register-product-0002",
            )

    def test_five_failures_lock_for_fifteen_minutes_and_session_is_digest_only(
        self,
    ) -> None:
        for attempt in range(5):
            with self.assertRaisesRegex(LanStage1Error, "lan_login_invalid"):
                self.identity.login(
                    username="company.admin",
                    password="Wrong-LAN-Password!",
                    idempotency_key=f"wrong-login-{attempt:04d}",
                )
        with self.assertRaisesRegex(LanStage1Error, "lan_login_invalid"):
            self.identity.login(
                username="company.admin",
                password=self.password,
                idempotency_key="login-locked-0001",
            )
        self.clock.value += timedelta(minutes=15, seconds=1)
        token, csrf_token, principal = self.identity.login(
            username="company.admin",
            password=self.password,
            idempotency_key="login-admin-0001",
        )
        self.assertEqual(self.admin["account_id"], principal["account_id"])
        with self.database.session() as session:
            account = session.scalar(
                select(LanHumanAccountRow).where(
                    LanHumanAccountRow.account_id == self.admin["account_id"]
                )
            )
            session_row = session.scalar(select(LanSessionRow))
            assert account is not None and session_row is not None
            self.assertEqual(5 * 0, account.failed_login_count)
            self.assertNotIn(token, session_row.session_digest)
            self.assertNotIn(csrf_token, session_row.csrf_digest)
            self.assertEqual(
                8 * 60 * 60,
                int(
                    (
                        session_row.expires_at.replace(tzinfo=timezone.utc)
                        - self.clock.value
                    ).total_seconds()
                ),
            )

    def test_reauth_projection_is_read_only_session_scoped_and_expires(self) -> None:
        app = create_human_app(identity=self.identity, workloads=self.workloads,
                               nodes=self.nodes, allowed_origins=("https://control-plane.lan",))
        client = TestClient(app, base_url="https://control-plane.lan")
        self.assertEqual(401, client.get("/v1/auth/me").status_code)
        login = client.post("/v1/auth/login", json={"username": "company.admin", "password": self.password},
                            headers={"origin": "https://control-plane.lan", "Idempotency-Key": "projection-login-0001"})
        headers = {"origin": "https://control-plane.lan", CSRF_HEADER: login.headers[CSRF_HEADER],
                   "Idempotency-Key": "projection-reauth-0001"}
        self.assertIsNone(client.get("/v1/auth/me").json()["reauthentication"]["reauthenticated_until"])
        denied = client.post("/v1/auth/reauth", json={"password": "Incorrect-password!"}, headers=headers)
        self.assertEqual(422, denied.status_code)
        self.assertIsNone(client.get("/v1/auth/me").json()["reauthentication"]["reauthenticated_until"])
        accepted = client.post("/v1/auth/reauth", json={"password": self.password}, headers=headers)
        deadline = accepted.json()["reauthenticated_until"]
        self.clock.value += timedelta(minutes=5)
        response = client.get("/v1/auth/me")
        self.assertEqual("no-store", response.headers["cache-control"])
        projection = response.json()["reauthentication"]
        self.assertEqual(deadline, projection["reauthenticated_until"])
        self.assertEqual({"reauthenticated_until", "observed_at"}, set(projection))
        replay = client.post("/v1/auth/reauth", json={"password": self.password}, headers=headers)
        self.assertEqual(deadline, replay.json()["reauthenticated_until"])
        other = TestClient(app, base_url="https://control-plane.lan")
        other.post("/v1/auth/login", json={"username": "company.admin", "password": self.password},
                   headers={"origin": "https://control-plane.lan", "Idempotency-Key": "projection-login-0002"})
        self.assertIsNone(other.get("/v1/auth/me").json()["reauthentication"]["reauthenticated_until"])
        self.clock.value += timedelta(minutes=10)
        self.assertIsNone(client.get("/v1/auth/me").json()["reauthentication"]["reauthenticated_until"])
        headers["Idempotency-Key"] = "projection-expired-invite"
        self.assertEqual(403, client.post("/v1/auth/invitations", json={"department_id": "market_center", "role_ref": ROLE_DEPARTMENT_OWNER}, headers=headers).status_code)
        headers["Idempotency-Key"] = "projection-logout-0001"
        client.post("/v1/auth/logout", headers=headers)
        self.assertEqual(401, client.get("/v1/auth/me").status_code)

    def test_origin_csrf_reauth_and_role_are_all_required(self) -> None:
        app = create_human_app(
            identity=self.identity,
            workloads=self.workloads,
            nodes=self.nodes,
            allowed_origins=("https://control-plane.lan",),
        )
        client = TestClient(app, base_url="https://control-plane.lan")
        self.assertEqual(404, client.post("/v1/bootstrap-admin").status_code)
        self.assertEqual(
            403,
            client.post(
                "/v1/auth/login",
                json={
                    "username": "company.admin",
                    "password": self.password,
                },
                headers={
                    "origin": "https://evil.invalid",
                    "Idempotency-Key": "evil-login-0001",
                },
            ).status_code,
        )
        login = client.post(
            "/v1/auth/login",
            json={
                "username": "company.admin",
                "password": self.password,
            },
            headers={
                "origin": "https://control-plane.lan",
                "Idempotency-Key": "http-login-0001",
            },
        )
        self.assertEqual(200, login.status_code)
        self.assertIn("Secure", login.headers["set-cookie"])
        self.assertIn("HttpOnly", login.headers["set-cookie"])
        self.assertIn("SameSite=strict", login.headers["set-cookie"])
        csrf_token = login.headers[CSRF_HEADER]
        invite = {"department_id": "market_center", "role_ref": ROLE_DEPARTMENT_OWNER}
        self.assertEqual(
            403,
            client.post(
                "/v1/auth/invitations",
                json=invite,
                headers={
                    "origin": "https://control-plane.lan",
                    "Idempotency-Key": "http-no-csrf-0001",
                },
            ).status_code,
        )
        self.assertEqual(
            403,
            client.post(
                "/v1/auth/invitations",
                json=invite,
                headers={
                    "origin": "https://control-plane.lan",
                    CSRF_HEADER: csrf_token,
                    "Idempotency-Key": "http-invite-0001",
                },
            ).status_code,
        )
        reauth = client.post(
            "/v1/auth/reauth",
            json={"password": self.password},
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf_token,
                "Idempotency-Key": "http-reauth-0001",
            },
        )
        self.assertEqual(200, reauth.status_code)
        created = client.post(
            "/v1/auth/invitations",
            json=invite,
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf_token,
                "Idempotency-Key": "http-invite-0001",
            },
        )
        self.assertEqual(201, created.status_code)
        self.assertEqual(
            403,
            client.post(
                "/v1/runtime-node-enrollment-codes",
                json={
                    "department_id": "market_center",
                    "node_id": "node_market_001",
                },
                headers={
                    "origin": "https://control-plane.lan",
                    CSRF_HEADER: csrf_token,
                    "Idempotency-Key": "http-enroll-0001",
                },
            ).status_code,
        )

    def test_admin_observation_context_is_single_department_read_only_and_expires(
        self,
    ) -> None:
        governance = GovernanceCatalogService(
            database=self.database,
            repository_root=ROOT,
        )
        governance.bootstrap()
        transport = LangGraphPlanningTransport(
            checkpoint_path=Path(self.temporary.name) / "observer-planning.sqlite3"
        )
        self.addCleanup(transport.close)
        cockpit = DepartmentCockpitService(
            database=self.database,
            transport=transport,
        )
        app = create_human_app(
            identity=self.identity,
            workloads=self.workloads,
            nodes=self.nodes,
            allowed_origins=("https://control-plane.lan",),
            cockpit=cockpit,
            governance_catalogs=governance,
        )
        client = TestClient(app, base_url="https://control-plane.lan")
        login = client.post(
            "/v1/auth/login",
            json={"username": "company.admin", "password": self.password},
            headers={
                "origin": "https://control-plane.lan",
                "Idempotency-Key": "observer-login-0001",
            },
        )
        self.assertEqual(200, login.status_code, login.text)
        csrf = login.headers[CSRF_HEADER]
        self.assertEqual(
            "company_control", client.get("/v1/auth/me").json()["user"]["access_mode"]
        )
        self.assertEqual(
            403,
            client.get("/v1/department-cockpit/product_center/bootstrap").status_code,
        )
        self.assertEqual(
            200,
            client.post(
                "/v1/auth/reauth",
                json={"password": self.password},
                headers={
                    "origin": "https://control-plane.lan",
                    CSRF_HEADER: csrf,
                    "Idempotency-Key": "observer-reauth-0001",
                },
            ).status_code,
        )
        activated = client.post(
            "/v1/auth/department-observation-contexts",
            json={"department_id": "product_center"},
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": "observer-product-0001",
            },
        )
        self.assertEqual(201, activated.status_code, activated.text)
        self.assertEqual("product_center", activated.json()["department_id"])
        current = client.get("/v1/auth/me").json()["user"]
        self.assertEqual("company_observer", current["access_mode"])
        self.assertEqual("product_center", current["active_observation_department_ref"])
        self.assertEqual(
            200,
            client.get("/v1/department-cockpit/product_center/bootstrap").status_code,
        )
        self.assertEqual(
            200,
            client.get("/v1/systems?department_id=product_center").status_code,
        )
        self.assertEqual(
            403,
            client.get("/v1/department-cockpit/market_center/bootstrap").status_code,
        )
        self.assertEqual(
            403,
            client.get("/v1/systems?department_id=market_center").status_code,
        )
        self.assertEqual(
            403,
            client.post(
                "/v1/department-cockpit/product_center/sessions",
                json={
                    "message": "合成只读越权尝试",
                    "artifact_refs": [],
                    "idempotency_key": "observer-write-denied-0001",
                },
                headers={
                    "origin": "https://control-plane.lan",
                    CSRF_HEADER: csrf,
                    "Idempotency-Key": "observer-write-denied-0001",
                },
            ).status_code,
        )
        switched = client.post(
            "/v1/auth/department-observation-contexts",
            json={"department_id": "market_center"},
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": "observer-market-0001",
            },
        )
        self.assertEqual(201, switched.status_code, switched.text)
        self.assertEqual(
            403,
            client.get("/v1/department-cockpit/product_center/bootstrap").status_code,
        )
        self.assertEqual(
            200,
            client.get(
                "/v1/department-cockpit/market_center/runtime-status"
            ).status_code,
        )
        self.assertEqual(
            403,
            client.get("/v1/systems?department_id=product_center").status_code,
        )
        self.assertEqual(
            200,
            client.get("/v1/systems?department_id=market_center").status_code,
        )
        with self.database.session() as session:
            contexts = session.scalars(
                select(LanDepartmentObservationContextRow).order_by(
                    LanDepartmentObservationContextRow.created_at
                )
            ).all()
            self.assertEqual(2, len(contexts))
            self.assertIsNotNone(contexts[0].revoked_at)
            self.assertIsNone(contexts[1].revoked_at)
        self.clock.value += timedelta(minutes=15, seconds=1)
        self.assertEqual(
            403,
            client.get("/v1/department-cockpit/market_center/bootstrap").status_code,
        )

    def test_department_runtime_status_keeps_transport_separate_from_execution(
        self,
    ) -> None:
        owner = self._owner()
        self.workloads.create_enrollment_code(
            principal=owner,
            department_id="market_center",
            node_id="node_market_status_001",
            idempotency_key="runtime-status-enrollment-0001",
        )
        governance = GovernanceCatalogService(
            database=self.database,
            repository_root=ROOT,
        )
        governance.bootstrap()
        transport = LangGraphPlanningTransport(
            checkpoint_path=Path(self.temporary.name)
            / "runtime-status-planning.sqlite3"
        )
        self.addCleanup(transport.close)
        app = create_human_app(
            identity=self.identity,
            workloads=self.workloads,
            nodes=self.nodes,
            allowed_origins=("https://control-plane.lan",),
            cockpit=DepartmentCockpitService(
                database=self.database,
                transport=transport,
            ),
            governance_catalogs=governance,
        )
        client = TestClient(app, base_url="https://control-plane.lan")
        login = client.post(
            "/v1/auth/login",
            json={"username": "market.owner", "password": self.password},
            headers={
                "origin": "https://control-plane.lan",
                "Idempotency-Key": "runtime-status-login-0001",
            },
        )
        self.assertEqual(200, login.status_code, login.text)
        status_response = client.get(
            "/v1/department-cockpit/market_center/runtime-status"
        )
        self.assertEqual(200, status_response.status_code, status_response.text)
        value = status_response.json()
        self.assertEqual("missing", value["connection_status"])
        self.assertEqual("node_market_status_001", value["primary_node"]["node_id"])
        self.assertFalse(value["runtime_started"])
        self.assertFalse(value["model_called"])
        self.assertFalse(value["execution_authorized"])
        artifact_projection = value["professional_runtime_artifact"]
        self.assertEqual(
            "ProfessionalRuntimeArtifactProjection",
            artifact_projection["kind"],
        )
        self.assertEqual("hermes", artifact_projection["runtime_family"])
        self.assertEqual("linux/amd64", artifact_projection["target_platform"])
        self.assertEqual("not_assigned", artifact_projection["assignment_status"])
        self.assertEqual(
            ["assigned", "download", "verify", "import", "probe", "complete"],
            [item["stage"] for item in artifact_projection["stages"]],
        )
        self.assertFalse(artifact_projection["qualification_probe_executed"])
        self.assertFalse(
            artifact_projection["professional_task_runtime_started"]
        )

        revision_digest = "sha256:" + "1" * 64
        image_digest = "sha256:" + "2" * 64
        bundle_digest = "sha256:" + "3" * 64
        import_digest = "sha256:" + "4" * 64
        capability_digest = "sha256:" + "5" * 64
        verification = {
            "signature_valid": True,
            "artifact_set_valid": True,
            "manifest_digest_valid": True,
            "source_digest_valid": True,
            "image_digest_valid": True,
            "platform_compatible": True,
            "isolation_compatible": True,
            "artifact_not_revoked": True,
            "probe_passed": True,
        }
        with self.database.session() as session:
            session.add_all(
                [
                    LanArtifactDownloadAssignmentRow(
                        assignment_id="assignment_market_status_001",
                        department_id="market_center",
                        artifact_id="runtime_artifact_market_status_001",
                        revision_digest=revision_digest,
                        bundle_digest=bundle_digest,
                        status="d0_assigned",
                        created_by_ref="human_market_owner_syn",
                        idempotency_key="assignment-market-status-0001",
                        document={},
                        created_at=NOW,
                        revoked_at=None,
                    ),
                    RuntimeArtifactRevisionRow(
                        artifact_id="runtime_artifact_market_status_001",
                        revision_digest=revision_digest,
                        runtime_family="hermes",
                        runtime_source_digest="sha256:" + "6" * 64,
                        runtime_image_digest=image_digest,
                        isolation_profile_digest="sha256:" + "7" * 64,
                        adapter_digest="sha256:" + "8" * 64,
                        target_platform="linux/amd64",
                        bundle_ref="bundle://synthetic/market-status",
                        bundle_digest=bundle_digest,
                        status="qualified_d0",
                        document={"metadata": {"version": "0.21.0"}},
                        recorded_by_ref="human_control_plane_admin_syn",
                        recorded_at=NOW,
                    ),
                    LanArtifactDownloadReceiptRow(
                        receipt_id="download_receipt_market_status_001",
                        node_id="node_market_status_001",
                        department_id="market_center",
                        artifact_id="runtime_artifact_market_status_001",
                        revision_digest=revision_digest,
                        bundle_digest=bundle_digest,
                        etag=bundle_digest,
                        range_start=0,
                        range_end=99,
                        total_size=100,
                        completed=True,
                        idempotency_key="download-market-status-0001",
                        recorded_at=NOW,
                    ),
                    RuntimeArtifactImportReceiptRow(
                        receipt_id="import_receipt_market_status_001",
                        idempotency_key="import-market-status-0001",
                        node_id="node_market_status_001",
                        artifact_id="runtime_artifact_market_status_001",
                        revision_digest=revision_digest,
                        runtime_image_digest=image_digest,
                        capability_report_digest="sha256:" + "9" * 64,
                        outcome="imported",
                        receipt_digest=import_digest,
                        document={"spec": {"verification": verification}},
                        recorded_at=NOW,
                    ),
                    RuntimeNodeCapabilityReportRow(
                        node_id="node_market_status_001",
                        report_digest=capability_digest,
                        idempotency_key="capability-market-status-0001",
                        status="eligible_d0",
                        reason_codes=[],
                        document={
                            "verified_runtime_artifact_digests": [revision_digest],
                            "verified_image_digests": [image_digest],
                            "verified_import_receipt_digests": [import_digest],
                        },
                        observed_at=NOW,
                        recorded_at=NOW,
                    ),
                ]
            )
        completed = client.get(
            "/v1/department-cockpit/market_center/runtime-status"
        ).json()["professional_runtime_artifact"]
        self.assertEqual("0.21.0", completed["version"])
        self.assertEqual("complete", completed["stages"][-1]["stage"])
        self.assertTrue(all(item["status"] == "passed" for item in completed["stages"]))
        self.assertTrue(completed["qualification_probe_executed"])
        self.assertEqual(import_digest, completed["import_receipt_digest"])
        self.assertEqual(capability_digest, completed["capability_report_digest"])
        self.assertFalse(completed["professional_task_runtime_started"])
        self.assertEqual(
            403,
            client.get(
                "/v1/department-cockpit/technology_center/runtime-status"
            ).status_code,
        )

    def test_owner_downloads_only_current_department_device_bundle_with_receipt(
        self,
    ) -> None:
        owner = self._owner()
        lock_digest = "sha256:" + "4" * 64
        content = stage_department_device_bundle(
            self.root,
            department_id="market_center",
            release_lock_digest=lock_digest,
        )
        nodes = LanNodeService(
            self.database,
            department_device_bundle_resolver=FileDepartmentDeviceBundleResolver(
                self.root
            ),
            deployment_release_lock_digest=lock_digest,
            now=self.clock,
        )
        app = create_human_app(
            identity=self.identity,
            workloads=self.workloads,
            nodes=nodes,
            allowed_origins=("https://control-plane.lan",),
        )
        client = TestClient(app, base_url="https://control-plane.lan")
        login = client.post(
            "/v1/auth/login",
            json={"username": "market.owner", "password": self.password},
            headers={
                "origin": "https://control-plane.lan",
                "Idempotency-Key": "device-bundle-owner-login-0001",
            },
        )
        self.assertEqual(200, login.status_code, login.text)
        csrf = login.headers[CSRF_HEADER]
        route = "/v1/department-cockpit/market_center/device-pilot-bundle"
        self.assertEqual(
            403,
            client.post(
                route,
                headers={
                    "origin": "https://control-plane.lan",
                    "Idempotency-Key": "device-bundle-no-csrf-0001",
                },
            ).status_code,
        )
        headers = {
            "origin": "https://control-plane.lan",
            CSRF_HEADER: csrf,
            "Idempotency-Key": "device-bundle-download-0001",
        }
        downloaded = client.post(route, headers=headers)
        self.assertEqual(200, downloaded.status_code, downloaded.text)
        self.assertEqual(content, downloaded.content)
        self.assertEqual("application/zip", downloaded.headers["content-type"])
        self.assertIn(
            "orbit-market-center-lan-d0.zip",
            downloaded.headers["content-disposition"],
        )
        self.assertRegex(
            downloaded.headers["x-orbit-download-receipt"],
            r"^department_device_download_receipt_lan_",
        )
        replay = client.post(route, headers=headers)
        self.assertEqual(
            downloaded.headers["x-orbit-download-receipt"],
            replay.headers["x-orbit-download-receipt"],
        )
        self.assertEqual(
            403,
            client.post(
                "/v1/department-cockpit/technology_center/device-pilot-bundle",
                headers={**headers, "Idempotency-Key": "device-wrong-scope-0001"},
            ).status_code,
        )
        with self.database.session() as session:
            receipt = session.scalar(
                select(ReceiptRow).where(
                    ReceiptRow.receipt_type == "lan_department_device_bundle_download"
                )
            )
            self.assertIsNotNone(receipt)
        self.assertTrue(owner["permissions"]["download_department_device_bundle"])

    def test_p256_csr_binding_caddy_revalidation_revocation_and_scope(self) -> None:
        owner = self._owner()
        enrollment = self.workloads.create_enrollment_code(
            principal=owner,
            department_id="market_center",
            node_id="node_market_001",
            idempotency_key="enroll-p256-0001",
        )
        with self.assertRaisesRegex(LanStage1Error, "lan_csr_key_must_be_p256"):
            self.workloads.enroll(
                enrollment_id=str(enrollment["enrollment_id"]),
                enrollment_code=str(enrollment["enrollment_code"]),
                csr_pem=csr(str(enrollment["expected_uri_san"]), curve=ec.SECP384R1()),
                idempotency_key="bind-wrong-curve-0001",
            )
        certificate = self.workloads.enroll(
            enrollment_id=str(enrollment["enrollment_id"]),
            enrollment_code=str(enrollment["enrollment_code"]),
            csr_pem=csr(str(enrollment["expected_uri_san"])),
            idempotency_key="bind-p256-0001",
        )
        der_b64 = str(certificate["certificate_der_base64"])
        fingerprint = str(certificate["certificate_fingerprint"])
        principal = self.workloads.verify_caddy_forwarded_peer(
            certificate_der_base64=der_b64,
            forwarded_fingerprint=fingerprint,
        )
        self.assertEqual("market_center", principal["department_id"])
        self.assertEqual("node_market_001", principal["node_id"])
        with self.assertRaisesRegex(
            LanStage1Error, "lan_forwarded_fingerprint_mismatch"
        ):
            self.workloads.verify_caddy_forwarded_peer(
                certificate_der_base64=der_b64,
                forwarded_fingerprint="sha256:" + "0" * 64,
            )
        self.workloads.revoke_certificate(
            principal=self.admin,
            fingerprint=fingerprint,
            reason="synthetic node retirement",
            idempotency_key="revoke-cert-0001",
        )
        with self.assertRaisesRegex(
            LanStage1Error, "lan_workload_certificate_not_active"
        ):
            self.workloads.verify_caddy_forwarded_peer(
                certificate_der_base64=der_b64,
                forwarded_fingerprint=fingerprint,
            )
        with self.database.session() as session:
            binding = session.scalar(select(LanCertificateBindingRow))
            assert binding is not None
            self.assertEqual(
                30 * 24 * 60 * 60,
                int(
                    (
                        binding.not_after.replace(tzinfo=timezone.utc)
                        - binding.not_before.replace(tzinfo=timezone.utc)
                    ).total_seconds()
                ),
            )
            self.assertEqual(
                7 * 24 * 60 * 60,
                int(
                    (
                        binding.not_after.replace(tzinfo=timezone.utc)
                        - binding.renewal_after.replace(tzinfo=timezone.utc)
                    ).total_seconds()
                ),
            )

    def test_full_deployment_lock_is_persisted_and_bounds_download_authority(
        self,
    ) -> None:
        artifact_id = "synthetic_runtime_artifact"
        revision_digest = "sha256:" + "d" * 64
        bundle_digest = "sha256:" + "b" * 64
        document = deployment_release_lock(
            artifact_id=artifact_id,
            revision_digest=revision_digest,
        )
        created = self.nodes.create_deployment_release_lock(
            principal=self.admin,
            document=document,
            idempotency_key="deployment-lock-create-0001",
        )
        self.assertEqual(
            document["spec"]["lock_digest"],
            created["deployment_release_lock"]["lock_digest"],
        )
        self.assertFalse(created["deployment_release_lock"]["release_authorization"])
        with self.database.session() as session:
            row = session.scalar(select(LanDeploymentReleaseLockRow))
            assert row is not None
            self.assertEqual("candidate", row.status)
            self.assertEqual("1" * 40, row.architecture_commit)
            session.add(
                DepartmentCockpitObjectRow(
                    object_type="runtime_artifact_selection",
                    object_id="market_center",
                    department_id="market_center",
                    revision=1,
                    document={
                        "department_id": "market_center",
                        "artifact_id": artifact_id,
                        "artifact_revision": revision_digest,
                        "production_authorized": False,
                        "release_authorization": False,
                    },
                    updated_at=self.clock(),
                )
            )
        _, certificate = self._enrolled()
        workload = self.workloads.verify_caddy_forwarded_peer(
            certificate_der_base64=str(certificate["certificate_der_base64"]),
            forwarded_fingerprint=str(certificate["certificate_fingerprint"]),
        )
        self.nodes.heartbeat(
            principal=workload,
            node_id="node_market_001",
            capability_report_digest="sha256:" + "c" * 64,
            status="ready",
            document={
                "synthetic_only": True,
                "production_authorization": False,
                "release_authorization": False,
            },
            idempotency_key="deployment-lock-heartbeat-0001",
        )
        self.nodes.create_artifact_download_assignment(
            principal=self.admin,
            department_id="market_center",
            artifact_id=artifact_id,
            revision_digest=revision_digest,
            bundle_digest=bundle_digest,
            idempotency_key="deployment-lock-assignment-0001",
        )
        authority = DatabaseArtifactDownloadAuthority(
            self.database,
            expected_lock_digest=str(document["spec"]["lock_digest"]),
            now=self.clock,
        )
        authority.authorize_download(
            department_id="market_center",
            node_id="node_market_001",
            artifact_id=artifact_id,
            revision_digest=revision_digest,
            bundle_digest=bundle_digest,
        )
        self.clock.value += timedelta(seconds=61)
        with self.assertRaisesRegex(LanStage1Error, "lan_runtime_node_evidence_stale"):
            authority.authorize_download(
                department_id="market_center",
                node_id="node_market_001",
                artifact_id=artifact_id,
                revision_digest=revision_digest,
                bundle_digest=bundle_digest,
            )
        drifted = deployment_release_lock(
            artifact_id=artifact_id,
            revision_digest=revision_digest,
        )
        drifted["spec"]["repository_commits"][0]["commit_sha"] = "4" * 40
        with self.assertRaisesRegex(
            LanStage1Error, "lan_deployment_release_lock_repository_invalid"
        ):
            self.nodes.create_deployment_release_lock(
                principal=self.admin,
                document=drifted,
                idempotency_key="deployment-lock-drift-0001",
            )
        authority_expanded = deployment_release_lock(
            artifact_id=artifact_id,
            revision_digest=revision_digest,
        )
        authority_expanded["authority_boundary"]["deployment_activated"] = True
        with self.assertRaisesRegex(
            LanStage1Error, "lan_deployment_release_lock_authority_invalid"
        ):
            self.nodes.create_deployment_release_lock(
                principal=self.admin,
                document=authority_expanded,
                idempotency_key="deployment-lock-authority-0001",
            )

    def test_heartbeat_release_lock_range_digest_receipt_and_long_poll(self) -> None:
        _, certificate = self._enrolled()
        workload = self.workloads.verify_caddy_forwarded_peer(
            certificate_der_base64=str(certificate["certificate_der_base64"]),
            forwarded_fingerprint=str(certificate["certificate_fingerprint"]),
        )
        digest = "sha256:" + "a" * 64
        heartbeat = self.nodes.heartbeat(
            principal=workload,
            node_id="node_market_001",
            capability_report_digest=digest,
            status="ready",
            document={
                "synthetic_only": True,
                "production_authorization": False,
                "release_authorization": False,
            },
            idempotency_key="heartbeat-0001",
        )
        replay = self.nodes.heartbeat(
            principal=workload,
            node_id="node_market_001",
            capability_report_digest=digest,
            status="ready",
            document={
                "synthetic_only": True,
                "production_authorization": False,
                "release_authorization": False,
            },
            idempotency_key="heartbeat-0001",
        )
        self.assertEqual(heartbeat["heartbeat_id"], replay["heartbeat_id"])
        next_heartbeat = self.nodes.heartbeat(
            principal=workload,
            node_id="node_market_001",
            capability_report_digest=digest,
            status="ready",
            document={
                "synthetic_only": True,
                "production_authorization": False,
                "release_authorization": False,
            },
            idempotency_key="heartbeat-0002",
        )
        self.assertEqual(1, next_heartbeat["sequence"])
        self.assertNotEqual(heartbeat["heartbeat_id"], next_heartbeat["heartbeat_id"])
        content = b"synthetic-oci-layout-archive"
        bundle_digest = "sha256:" + __import__("hashlib").sha256(content).hexdigest()
        nodes = LanNodeService(
            self.database,
            bundle_resolver=MemoryBundleResolver(content),
            runtime_artifacts=NoWorkRuntimeArtifacts(),
            artifact_download_authority=SyntheticDownloadAuthority(),
            now=self.clock,
        )
        nodes.create_artifact_download_assignment(
            principal=self.admin,
            department_id="market_center",
            artifact_id="runtime_artifact_market_syn",
            revision_digest=digest,
            bundle_digest=bundle_digest,
            idempotency_key="artifact-assignment-0001",
        )
        fail_closed_nodes = LanNodeService(
            self.database,
            bundle_resolver=MemoryBundleResolver(content),
            runtime_artifacts=NoWorkRuntimeArtifacts(),
            now=self.clock,
        )
        with self.assertRaisesRegex(
            LanStage1Error, "lan_deployment_release_lock_required"
        ):
            fail_closed_nodes.download(
                principal=workload,
                node_id="node_market_001",
                artifact_id="runtime_artifact_market_syn",
                revision_digest=digest,
                range_header=None,
                idempotency_key="download-no-deployment-lock-0001",
            )
        downloaded = nodes.download(
            principal=workload,
            node_id="node_market_001",
            artifact_id="runtime_artifact_market_syn",
            revision_digest=digest,
            range_header="bytes=0-8",
            idempotency_key="download-range-0001",
        )
        self.assertEqual(206, downloaded["status_code"])
        self.assertEqual(content[:9], downloaded["content"])
        self.assertEqual(f'"{bundle_digest}"', downloaded["etag"])
        with self.database.session() as session:
            self.assertEqual(
                1, len(tuple(session.scalars(select(LanArtifactDownloadReceiptRow))))
            )
            receipt = session.scalar(
                select(ReceiptRow).where(
                    ReceiptRow.receipt_type == "lan_artifact_download"
                )
            )
            self.assertIsNotNone(receipt)
        other = dict(workload)
        other["department_id"] = "technology_center"
        with self.assertRaisesRegex(LanStage1Error, "lan_artifact_not_authorized"):
            nodes.download(
                principal=other,
                node_id="node_market_001",
                artifact_id="runtime_artifact_market_syn",
                revision_digest=digest,
                range_header=None,
                idempotency_key="download-wrong-dept-0001",
            )
        no_work = LanNodeService(
            self.database, runtime_artifacts=NoWorkRuntimeArtifacts()
        )
        self.assertIsNone(
            no_work.claim_lease_long_poll(
                principal=workload,
                node_id="node_market_001",
                expected_capability_report_digest=digest,
                idempotency_key="lease-longpoll-0001",
                wait_seconds=0,
            )
        )
        with self.assertRaisesRegex(LanStage1Error, "lan_lease_wait_invalid"):
            no_work.claim_lease_long_poll(
                principal=workload,
                node_id="node_market_001",
                expected_capability_report_digest=digest,
                idempotency_key="lease-longpoll-0002",
                wait_seconds=26,
            )

    def test_offline_receipt_spool_is_owner_only_and_fails_closed(self) -> None:
        path = self.root / "spool" / "receipts.jsonl"
        spool = OfflineReceiptSpool(path)
        receipt = {
            "kind": "SyntheticReceipt",
            "production_authorization": False,
            "release_authorization": False,
        }
        spool.append(receipt)
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(receipt, json.loads(lines[0]))
        with self.assertRaisesRegex(
            LanStage1Error, "lan_receipt_spool_authority_invalid"
        ):
            spool.append(
                {"production_authorization": True, "release_authorization": False}
            )
        full = OfflineReceiptSpool(self.root / "full" / "receipts.jsonl")
        full.max_records = 1
        full.append(receipt)
        with self.assertRaisesRegex(
            LanStage1Error, "lan_receipt_spool_capacity_exceeded"
        ):
            full.append(receipt)

    def test_pending_approval_scope_and_admin_cannot_approve_ordinary_user(
        self,
    ) -> None:
        invite = self.identity.create_invite(
            principal=self.admin,
            department_id="technology_center",
            role_ref=ROLE_DEPARTMENT_OWNER,
            idempotency_key="invite-tech-owner-0001",
        )
        pending_owner = self.identity.register(
            invite_code=str(invite["invite_code"]),
            username="tech.owner",
            password=self.password,
            display_name="技术负责人",
            idempotency_key="register-tech-owner-0001",
        )
        with self.assertRaisesRegex(LanStage1Error, "lan_login_invalid"):
            self.identity.login(
                username="tech.owner",
                password=self.password,
                idempotency_key="login-pending-owner-0001",
            )
        self.assertEqual(
            [pending_owner["account_id"]],
            [
                item["account_id"]
                for item in self.identity.pending_accounts(
                    principal=self.admin, department_id="technology_center"
                )
            ],
        )
        self.identity.approve_account(
            principal=self.admin,
            account_id=str(pending_owner["account_id"]),
            idempotency_key="approve-tech-owner-0001",
        )
        tech_owner = pending_owner
        user_invite = self.identity.create_invite(
            principal=tech_owner,
            department_id="technology_center",
            role_ref=ROLE_DEPARTMENT_USER,
            idempotency_key="invite-tech-user-0001",
        )
        pending_user = self.identity.register(
            invite_code=str(user_invite["invite_code"]),
            username="tech.user",
            password=self.password,
            display_name="技术用户",
            idempotency_key="register-tech-user-0001",
        )
        with self.assertRaisesRegex(LanStage1Error, "lan_account_approval_not_allowed"):
            self.identity.approve_account(
                principal=self.admin,
                account_id=str(pending_user["account_id"]),
                idempotency_key="admin-approve-user-0001",
            )
        market_owner = self._owner()
        with self.assertRaisesRegex(LanStage1Error, "lan_department_scope_not_allowed"):
            self.identity.pending_accounts(
                principal=market_owner, department_id="technology_center"
            )
        self.identity.approve_account(
            principal=tech_owner,
            account_id=str(pending_user["account_id"]),
            idempotency_key="owner-approve-user-0001",
        )

    def test_enrollment_bruteforce_exact_human_route_and_mandatory_revalidation(
        self,
    ) -> None:
        owner = self._owner()
        enrollment = self.workloads.create_enrollment_code(
            principal=owner,
            department_id="market_center",
            node_id="node_market_099",
            idempotency_key="enroll-brute-0001",
        )
        csr_pem = csr(str(enrollment["expected_uri_san"]))
        self.assertEqual(
            "spiffe://orbit.local/workload/node_market_099",
            enrollment["expected_uri_san"],
        )
        for attempt in range(5):
            with self.assertRaisesRegex(LanStage1Error, "lan_enrollment_code_invalid"):
                self.workloads.enroll(
                    enrollment_id=str(enrollment["enrollment_id"]),
                    enrollment_code="x" * 32,
                    csr_pem=csr_pem,
                    idempotency_key=f"bad-enrollment-{attempt:04d}",
                )
        with self.assertRaisesRegex(LanStage1Error, "lan_enrollment_code_invalid"):
            self.workloads.enroll(
                enrollment_id=str(enrollment["enrollment_id"]),
                enrollment_code=str(enrollment["enrollment_code"]),
                csr_pem=csr_pem,
                idempotency_key="locked-enrollment-0001",
            )
        enrollment = self.workloads.create_enrollment_code(
            principal=owner,
            department_id="market_center",
            node_id="node_market_100",
            idempotency_key="enroll-exact-0001",
        )
        csr_pem = csr(str(enrollment["expected_uri_san"]))
        app = create_human_app(
            identity=self.identity,
            workloads=self.workloads,
            nodes=self.nodes,
            allowed_origins=("https://control-plane.lan",),
        )
        client = TestClient(app, base_url="https://control-plane.lan")
        response = client.post(
            "/v1/runtime-node-enrollments",
            json={
                "enrollment_id": enrollment["enrollment_id"],
                "enrollment_code": enrollment["enrollment_code"],
                "csr_pem_base64": base64.b64encode(csr_pem).decode(),
            },
            headers={
                "origin": "https://control-plane.lan",
                "Idempotency-Key": "exact-enrollment-0001",
            },
        )
        self.assertEqual(201, response.status_code, response.text)
        unverified = LanWorkloadIdentityService(
            self.database,
            issuer=self.issuer,
            now=self.clock,
        )
        with self.assertRaisesRegex(
            LanStage1Error, "lan_direct_mtls_verifier_unavailable"
        ):
            unverified.verify_caddy_forwarded_peer(
                certificate_der_base64=response.json()["certificate_der_base64"],
                forwarded_fingerprint=response.json()["certificate_fingerprint"],
            )
        source = Path(
            "src/orbit_agent_control_plane/service_runtime/lan_stage1.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn('"password_digest"', source)

    def test_control_projection_matches_cockpit_contract_and_is_admin_only(
        self,
    ) -> None:
        owner = self._owner()
        self.identity.create_invite(
            principal=owner,
            department_id="market_center",
            role_ref=ROLE_DEPARTMENT_USER,
            idempotency_key="control-user-invite-0001",
        )
        self.workloads.create_enrollment_code(
            principal=owner,
            department_id="market_center",
            node_id="node_market_control_001",
            idempotency_key="control-enrollment-0001",
        )
        app = create_human_app(
            identity=self.identity,
            workloads=self.workloads,
            nodes=self.nodes,
            allowed_origins=("https://control-plane.lan",),
        )
        admin_client = TestClient(app, base_url="https://control-plane.lan")
        login = admin_client.post(
            "/v1/auth/login",
            json={
                "username": "company.admin",
                "password": self.password,
            },
            headers={
                "origin": "https://control-plane.lan",
                "Idempotency-Key": "control-login-0001",
            },
        )
        self.assertEqual(200, login.status_code)
        projection = admin_client.get("/v1/control/bootstrap")
        self.assertEqual(200, projection.status_code)
        payload = projection.json()
        self.assertEqual(
            {
                "observed_at",
                "service_mode",
                "connections",
                "invitations",
                "runtime_nodes",
                "department_model_resources",
                "department_accounts",
                "department_readiness",
                "artifact_catalog",
                "release_authorization",
            },
            set(payload),
        )
        self.assertEqual("d0_synthetic_only", payload["service_mode"])
        self.assertFalse(payload["release_authorization"])
        self.assertEqual(3, len(payload["department_readiness"]))
        technology = next(
            row
            for row in payload["department_readiness"]
            if row["department_id"] == "technology_center"
        )
        self.assertEqual(
            {
                "owner_account",
                "planning_model",
                "fixed_node",
                "professional_runtime",
                "evidence_freshness",
            },
            set(technology["cells"]),
        )
        self.assertTrue(
            all(cell["read_only"] for cell in technology["cells"].values())
        )
        self.assertEqual(
            {"control_plane", "identity", "runtime_nodes", "audit"},
            {item["service"] for item in payload["connections"]},
        )
        invitation = next(
            item for item in payload["invitations"] if item["status"] == "available"
        )
        self.assertEqual("role_department_owner", invitation["created_by_role_ref"])
        self.assertTrue(invitation["synthetic_only"])
        self.assertFalse(invitation["production_authorized"])
        node = payload["runtime_nodes"][0]
        self.assertEqual(
            {
                "node_id",
                "display_name",
                "department_ref",
                "enrollment_status",
                "certificate_status",
                "certificate_expires_at",
                "certificate_fingerprint",
                "heartbeat_status",
                "last_heartbeat_at",
                "artifact_stages",
                "current_artifact_digest",
                "evidence_status",
                "runtime_started",
                "model_called",
                "production_authorized",
                "release_authorization",
            },
            set(node),
        )
        self.assertEqual("pending", node["enrollment_status"])
        self.assertEqual("not_issued", node["certificate_status"])
        self.assertEqual(
            ["install", "download", "verify", "import", "probe", "ready"],
            [stage["stage"] for stage in node["artifact_stages"]],
        )
        self.assertEqual(
            {"qualified_count", "candidate_count", "revoked_count"},
            set(payload["artifact_catalog"]),
        )
        document = json.dumps(payload, sort_keys=True)
        for forbidden in (
            "invite_code",
            "token_digest",
            "certificate_der",
            "physical_path",
            "socket",
            "endpoint",
            "secret",
        ):
            self.assertNotIn(forbidden, document.lower())
        token, _, _ = self.identity.login(
            username="market.owner",
            password=self.password,
            idempotency_key="owner-control-login-0001",
        )
        owner_client = TestClient(app, base_url="https://control-plane.lan")
        owner_client.cookies.set(
            "__Host-orbit_session", token, domain="control-plane.lan", path="/"
        )
        self.assertEqual(403, owner_client.get("/v1/control/bootstrap").status_code)
        caddy = Path("deploy/lan-stage1/Caddyfile").read_text(encoding="utf-8")
        self.assertIn("https://control-plane.orbit.local:9443", caddy)
        self.assertIn("bind 192.168.21.22", caddy)
        self.assertNotIn("strict_sni_host insecure_off", caddy)
        self.assertIn("request_header -X-Orbit-Client-Cert-Der", caddy)
        self.assertIn(
            "request_header X-Orbit-Client-Cert-Der {tls_client_certificate_der_base64}",
            caddy,
        )
        self.assertNotIn("X-Orbit-Future-Spoof", caddy)

    def test_same_origin_lan_app_exposes_scoped_cockpit_and_system_routes(self) -> None:
        self._owner()
        governance = GovernanceCatalogService(
            database=self.database,
            repository_root=ROOT,
        )
        governance.bootstrap()
        transport = LangGraphPlanningTransport(
            checkpoint_path=Path(self.temporary.name) / "lan-planning.sqlite3"
        )
        self.addCleanup(transport.close)
        cockpit = DepartmentCockpitService(
            database=self.database,
            transport=transport,
        )
        app = create_human_app(
            identity=self.identity,
            workloads=self.workloads,
            nodes=self.nodes,
            allowed_origins=("https://control-plane.lan",),
            cockpit=cockpit,
            governance_catalogs=governance,
        )
        client = TestClient(app, base_url="https://control-plane.lan")
        login = client.post(
            "/v1/auth/login",
            json={"username": "market.owner", "password": self.password},
            headers={
                "origin": "https://control-plane.lan",
                "Idempotency-Key": "lan-cockpit-login-0001",
            },
        )
        self.assertEqual(200, login.status_code, login.text)
        csrf = login.headers[CSRF_HEADER]
        bootstrap = client.get("/v1/department-cockpit/market_center/bootstrap")
        self.assertEqual(200, bootstrap.status_code, bootstrap.text)
        self.assertEqual(
            "market_center", bootstrap.json()["department"]["department_id"]
        )
        self.assertEqual(
            403,
            client.get("/v1/department-cockpit/product_center/bootstrap").status_code,
        )
        systems = client.get("/v1/systems?department_id=market_center")
        self.assertEqual(200, systems.status_code, systems.text)
        self.assertTrue(
            all(
                item["department_ref"] == "market_center"
                for item in systems.json()["systems"]
            )
        )
        planning = client.post(
            "/v1/department-cockpit/market_center/sessions",
            json={
                "message": "为公开数据设计一项合成市场任务",
                "artifact_refs": [],
                "idempotency_key": "lan-market-planning-0001",
            },
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": "lan-market-planning-0001",
            },
        )
        self.assertEqual(202, planning.status_code, planning.text)
        self.assertIsNotNone(planning.json()["question_card"])
        self.assertFalse(planning.json()["release_authorization"])
        answers = {
            question["question_id"]: question["options"][0]["option_id"]
            for question in planning.json()["question_card"]["questions"]
        }
        package = client.post(
            "/v1/department-cockpit/market_center/sessions/"
            f"{planning.json()['session_id']}/turns",
            json={
                "question_request_id": planning.json()["question_card"]["request_id"],
                "question_revision": planning.json()["question_card"]["revision"],
                "answers": answers,
                "supplement": None,
                "idempotency_key": "lan-market-package-0001",
            },
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": "lan-market-package-0001",
            },
        )
        self.assertEqual(200, package.status_code, package.text)
        task_package = package.json()["task_package"]
        approval = package.json()["task_approval_subject"]
        model_resources = client.get(
            "/v1/department-cockpit/market_center/model-resources"
        )
        self.assertEqual(200, model_resources.status_code, model_resources.text)
        professional = next(
            item
            for item in model_resources.json()["agents"]
            if item["kind"] == "professional"
        )
        candidate_route = next(
            item for item in professional["available_routes"] if not item["selected"]
        )
        model_selection_body = {
            "agent_binding_ref": professional["agent_binding_ref"],
            "route_id": candidate_route["route_id"],
            "route_revision_digest": candidate_route["route_revision_digest"],
            "expected_selection_digest": professional["selection_digest"],
            "idempotency_key": "lan-market-agent-model-before-reauth-0001",
        }
        model_selection_path = (
            "/v1/department-cockpit/market_center/agent-model-route-selections"
        )
        self.assertEqual(
            403,
            client.post(
                model_selection_path,
                json=model_selection_body,
                headers={
                    "origin": "https://control-plane.lan",
                    CSRF_HEADER: csrf,
                    "Idempotency-Key": model_selection_body["idempotency_key"],
                },
            ).status_code,
        )
        confirmation_path = (
            "/v1/department-cockpit/market_center/task-packages/"
            f"{task_package['metadata']['package_id']}/confirm"
        )
        confirmation_body = {
            "task_revision": approval["task_revision"],
            "task_scope_digest": approval["task_scope_digest"],
            "package_digest": approval["package_digest"],
        }
        self.assertEqual(
            403,
            client.post(
                confirmation_path,
                json=confirmation_body,
                headers={
                    "origin": "https://control-plane.lan",
                    CSRF_HEADER: csrf,
                    "Idempotency-Key": "lan-market-confirm-before-reauth-0001",
                },
            ).status_code,
        )
        reauth = client.post(
            "/v1/auth/reauth",
            json={"password": self.password},
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": "lan-market-confirm-reauth-0001",
            },
        )
        self.assertEqual(200, reauth.status_code, reauth.text)
        model_selection_body["idempotency_key"] = (
            "lan-market-agent-model-after-reauth-0001"
        )
        selected_model = client.post(
            model_selection_path,
            json=model_selection_body,
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": model_selection_body["idempotency_key"],
            },
        )
        self.assertEqual(200, selected_model.status_code, selected_model.text)
        self.assertEqual("future_tasks_only", selected_model.json()["effective_for"])
        self.assertFalse(selected_model.json()["execution_grant_issued"])
        confirmed = client.post(
            confirmation_path,
            json=confirmation_body,
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": "lan-market-confirm-after-reauth-0001",
            },
        )
        self.assertEqual(200, confirmed.status_code, confirmed.text)
        self.assertIn("receipt_id", confirmed.json())
        self.assertFalse(confirmed.json()["release_authorization"])

    def test_exact_human_routes_preserve_pending_approval_and_password_security(
        self,
    ) -> None:
        app = create_human_app(
            identity=self.identity,
            workloads=self.workloads,
            nodes=self.nodes,
            allowed_origins=("https://control-plane.lan",),
        )
        admin = TestClient(app, base_url="https://control-plane.lan")
        login = admin.post(
            "/v1/auth/login",
            json={
                "username": "company.admin",
                "password": self.password,
            },
            headers={
                "origin": "https://control-plane.lan",
                "Idempotency-Key": "exact-human-login-0001",
            },
        )
        csrf = login.headers[CSRF_HEADER]
        reauth = admin.post(
            "/v1/auth/reauth",
            json={"password": self.password},
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": "exact-human-reauth-0001",
            },
        )
        self.assertEqual(200, reauth.status_code)
        self.assertIn("reauthenticated_until", reauth.json())
        lock_document = deployment_release_lock()
        release_lock = admin.post(
            "/v1/deployment-release-locks",
            json={"document": lock_document},
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": "exact-human-deployment-lock-0001",
            },
        )
        self.assertEqual(201, release_lock.status_code, release_lock.text)
        self.assertEqual(
            lock_document["spec"]["lock_digest"],
            release_lock.json()["deployment_release_lock"]["lock_digest"],
        )
        self.assertFalse(
            release_lock.json()["deployment_release_lock"]["release_authorization"]
        )
        invitation = admin.post(
            "/v1/auth/invitations",
            json={
                "department_id": "product_center",
                "role_ref": ROLE_DEPARTMENT_OWNER,
            },
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": "exact-human-invite-0001",
            },
        )
        self.assertEqual(201, invitation.status_code, invitation.text)
        self.assertEqual("available", invitation.json()["status"])

        anonymous = TestClient(app, base_url="https://control-plane.lan")
        registered = anonymous.post(
            "/v1/auth/register",
            json={
                "invite_code": invitation.json()["invite_code"],
                "username": "product.owner",
                "password": self.password,
                "display_name": "产品负责人",
            },
            headers={
                "origin": "https://control-plane.lan",
                "Idempotency-Key": "exact-human-register-0001",
            },
        )
        self.assertEqual(201, registered.status_code, registered.text)
        self.assertEqual(
            401,
            anonymous.post(
                "/v1/auth/login",
                json={
                    "username": "product.owner",
                    "password": self.password,
                },
                headers={
                    "origin": "https://control-plane.lan",
                    "Idempotency-Key": "exact-human-pending-login-0001",
                },
            ).status_code,
        )
        pending = admin.get("/v1/auth/pending-accounts")
        self.assertEqual(200, pending.status_code)
        account_id = pending.json()["accounts"][0]["account_id"]
        approved = admin.post(
            f"/v1/auth/accounts/{account_id}/approve",
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: csrf,
                "Idempotency-Key": "exact-human-approve-0001",
            },
        )
        self.assertEqual(200, approved.status_code, approved.text)

        owner = TestClient(app, base_url="https://control-plane.lan")
        owner_login = owner.post(
            "/v1/auth/login",
            json={
                "username": "product.owner",
                "password": self.password,
            },
            headers={
                "origin": "https://control-plane.lan",
                "Idempotency-Key": "exact-owner-login-0001",
            },
        )
        owner_csrf = owner_login.headers[CSRF_HEADER]
        self.assertEqual(
            200,
            owner.post(
                "/v1/auth/reauth",
                json={
                    "password": self.password,
                },
                headers={
                    "origin": "https://control-plane.lan",
                    CSRF_HEADER: owner_csrf,
                    "Idempotency-Key": "exact-owner-reauth-0001",
                },
            ).status_code,
        )
        changed = owner.post(
            "/v1/auth/change-password",
            json={
                "current_password": self.password,
                "new_password": "Stage1-LAN-New-Password!",
            },
            headers={
                "origin": "https://control-plane.lan",
                CSRF_HEADER: owner_csrf,
                "Idempotency-Key": "exact-owner-password-0001",
            },
        )
        self.assertEqual(200, changed.status_code, changed.text)

    def test_exact_workload_routes_require_mtls_and_emit_d0_receipts(self) -> None:
        _, certificate = self._enrolled()
        content = b"synthetic-lan-artifact-bundle"
        bundle_digest = "sha256:" + __import__("hashlib").sha256(content).hexdigest()
        revision_digest = "sha256:" + "b" * 64
        runtimes = NoWorkRuntimeArtifacts()
        nodes = LanNodeService(
            self.database,
            runtime_artifacts=runtimes,
            bundle_resolver=MemoryBundleResolver(content),
            artifact_download_authority=SyntheticDownloadAuthority(),
            now=self.clock,
        )
        nodes.create_artifact_download_assignment(
            principal=self.admin,
            department_id="market_center",
            artifact_id="runtime_artifact_market_exact_syn",
            revision_digest=revision_digest,
            bundle_digest=bundle_digest,
            idempotency_key="exact-workload-assignment-0001",
        )
        app = create_workload_app(workloads=self.workloads, nodes=nodes)
        client = TestClient(app, base_url="https://runtime.control-plane.lan")
        headers = {
            "X-Orbit-Client-Cert-Der": certificate["certificate_der_base64"],
            "X-Orbit-Client-Cert-Fingerprint": certificate["certificate_fingerprint"],
            "Idempotency-Key": "exact-workload-heartbeat-0001",
        }
        self.assertEqual(
            401,
            client.post(
                "/v1/runtime-nodes/node_market_001/heartbeats",
                json={
                    "capability_report_digest": revision_digest,
                    "status": "ready",
                    "document": {
                        "production_authorization": False,
                        "release_authorization": False,
                    },
                },
                headers={"Idempotency-Key": "missing-mtls-heartbeat-0001"},
            ).status_code,
        )
        heartbeat = client.post(
            "/v1/runtime-nodes/node_market_001/heartbeats",
            json={
                "capability_report_digest": revision_digest,
                "status": "ready",
                "document": {
                    "synthetic_only": True,
                    "production_authorization": False,
                    "release_authorization": False,
                },
            },
            headers=headers,
        )
        self.assertEqual(201, heartbeat.status_code, heartbeat.text)

        assignment_headers = {
            key: value
            for key, value in headers.items()
            if key != "Idempotency-Key"
        }
        current_assignment = client.get(
            "/v1/runtime-nodes/node_market_001/"
            "artifact-download-assignments/current",
            headers=assignment_headers,
        )
        self.assertEqual(200, current_assignment.status_code, current_assignment.text)
        assignment_value = current_assignment.json()
        self.assertEqual(
            {
                "node_id",
                "department_id",
                "artifact_id",
                "revision_digest",
                "bundle_digest",
                "download_idempotency",
            },
            set(assignment_value),
        )
        self.assertEqual("node_market_001", assignment_value["node_id"])
        self.assertEqual("market_center", assignment_value["department_id"])
        self.assertEqual(
            "runtime_artifact_market_exact_syn",
            assignment_value["artifact_id"],
        )
        self.assertEqual(revision_digest, assignment_value["revision_digest"])
        self.assertEqual(bundle_digest, assignment_value["bundle_digest"])
        self.assertTrue(
            assignment_value["download_idempotency"]["range_resume_supported"]
        )
        self.assertNotIn("path", str(assignment_value).lower())
        self.assertNotIn("certificate", str(assignment_value).lower())
        self.assertEqual(
            403,
            client.get(
                "/v1/runtime-nodes/node_product_001/"
                "artifact-download-assignments/current",
                headers=assignment_headers,
            ).status_code,
        )

        for suffix, path in (
            ("capability", "/v1/runtime-nodes/node_market_001/capability-reports"),
            ("import", "/v1/runtime-nodes/node_market_001/artifact-import-receipts"),
            ("container", "/v1/runtime-runs/run_market_syn/container-events"),
            ("checkpoint", "/v1/runtime-runs/run_market_syn/checkpoint-receipts"),
            ("cleanup", "/v1/runtime-runs/run_market_syn/cleanup-receipts"),
        ):
            route_headers = dict(headers)
            route_headers["Idempotency-Key"] = f"exact-workload-{suffix}-0001"
            response = client.post(
                path,
                json={
                    "document": {
                        "synthetic_only": True,
                        "production_authorization": False,
                        "release_authorization": False,
                    }
                },
                headers=route_headers,
            )
            self.assertEqual(201, response.status_code, response.text)
            self.assertIn("receipt_id", response.json())

        lease_headers = dict(headers)
        lease_headers["Idempotency-Key"] = "exact-workload-lease-0001"
        lease = client.post(
            "/v1/runtime-nodes/node_market_001/lease-claims?wait_seconds=0",
            json={"expected_capability_report_digest": revision_digest},
            headers=lease_headers,
        )
        self.assertEqual(204, lease.status_code, lease.text)
        download_headers = dict(headers)
        download_headers.update(
            {"Idempotency-Key": "exact-workload-download-0001", "Range": "bytes=0-8"}
        )
        downloaded = client.get(
            f"/v1/runtime-artifacts/runtime_artifact_market_exact_syn/revisions/"
            f"{revision_digest}/bundle/content",
            headers=download_headers,
        )
        self.assertEqual(206, downloaded.status_code, downloaded.text)
        self.assertEqual(content[:9], downloaded.content)
        self.assertEqual(bundle_digest, downloaded.headers["digest"])

    def test_codex_installation_workload_routes_are_node_bound_and_sanitized(
        self,
    ) -> None:
        invite = self.identity.create_invite(
            principal=self.admin,
            department_id="technology_center",
            role_ref=ROLE_DEPARTMENT_OWNER,
            idempotency_key="invite-technology-codex-owner-0001",
        )
        pending = self.identity.register(
            invite_code=str(invite["invite_code"]),
            username="technology.codex.owner",
            password=self.password,
            display_name="技术负责人",
            idempotency_key="register-technology-codex-owner-0001",
        )
        approved = self.identity.approve_account(
            principal=self.admin,
            account_id=str(pending["account_id"]),
            idempotency_key="approve-technology-codex-owner-0001",
        )["account"] | {
            "human_ref": pending["human_ref"],
            "role_refs": pending["role_refs"],
            "department_refs": pending["department_refs"],
            "permissions": pending["permissions"],
        }
        enrollment = self.workloads.create_enrollment_code(
            principal=approved,
            department_id="technology_center",
            node_id="node_technology_001",
            idempotency_key="enroll-technology-codex-node-0001",
        )
        certificate = self.workloads.enroll(
            enrollment_id=str(enrollment["enrollment_id"]),
            enrollment_code=str(enrollment["enrollment_code"]),
            csr_pem=csr(str(enrollment["expected_uri_san"])),
            idempotency_key="bind-technology-codex-node-0001",
        )
        manifest_digest = "sha256:" + "1" * 64
        archive_digest = "sha256:" + "2" * 64
        installation = CodexInstallationService(
            database=self.database,
            approved_release_manifest_digest=manifest_digest,
            approved_archive_digest=archive_digest,
            now=self.clock,
        )
        client = TestClient(
            create_workload_app(
                workloads=self.workloads,
                nodes=self.nodes,
                codex_installation=installation,
            ),
            base_url="https://runtime.control-plane.lan",
        )
        headers = {
            "X-Orbit-Client-Cert-Der": certificate["certificate_der_base64"],
            "X-Orbit-Client-Cert-Fingerprint": certificate[
                "certificate_fingerprint"
            ],
            "Idempotency-Key": "codex-install-event-http-0001",
        }
        document = {
            "event_version": "orbit.codex-installation-stage-event/1",
            "attempt_id": "codex_attempt_http_001",
            "predecessor_attempt_id": None,
            "department_id": "technology_center",
            "codex_cli_version": "0.153.0",
            "target_platform": "x86_64-unknown-linux-musl",
            "release_manifest_digest": manifest_digest,
            "archive_digest": archive_digest,
            "sequence": 1,
            "stage": "download",
            "status": "running",
            "failure_code": None,
            "observed_at": "2026-09-03T08:00:00Z",
            "execution_grant_issued": False,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }
        accepted = client.post(
            "/v1/runtime-nodes/node_technology_001/codex-installation-events",
            json={"document": document},
            headers=headers,
        )
        self.assertEqual(201, accepted.status_code, accepted.text)
        self.assertFalse(accepted.json()["execution_grant_issued"])
        self.assertNotIn("terminal_output", accepted.text)

        wrong_node_headers = dict(headers)
        wrong_node_headers["Idempotency-Key"] = "codex-install-wrong-node-0001"
        wrong_node = client.post(
            "/v1/runtime-nodes/node_product_001/codex-installation-events",
            json={"document": document},
            headers=wrong_node_headers,
        )
        self.assertEqual(403, wrong_node.status_code)
        self.assertNotIn("account", accepted.text.lower())


if __name__ == "__main__":
    unittest.main()

