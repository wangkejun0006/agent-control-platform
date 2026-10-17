"""Fail-closed Stage-1 LAN candidate services.

Nothing in this module opens a socket, starts a Runner, signs a certificate, or
contacts an external provider.  Certificate issuance and artifact bytes are
explicit injected adapters; the defaults are unavailable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import stat
import threading
import time
import zipfile
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar, Protocol

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from sqlalchemy import func, select

from .cockpit_local_identity import (
    DEPARTMENTS,
    ROLE_CONTROL_PLANE_ADMIN,
    ROLE_DEPARTMENT_OWNER,
    ROLE_DEPARTMENT_USER,
    ScryptPasswordHasher,
)
from .database import Database
from .lan_stage1_models import (
    LanArtifactDownloadAssignmentRow,
    LanArtifactDownloadReceiptRow,
    LanAssistedMaintenanceSessionRow,
    LanCertificateBindingRow,
    LanCertificateRevocationRow,
    LanDepartmentObservationContextRow,
    LanDeploymentReleaseLockRow,
    LanEnrollmentCodeRow,
    LanHumanAccountRow,
    LanInviteRow,
    LanMaintenanceJobRow,
    LanMaintenanceReceiptRow,
    LanMutationCommandRow,
    LanNodeHeartbeatRow,
    LanSessionRow,
)
from .models import AuditEventRow, DepartmentCockpitObjectRow, ReceiptRow
from .runtime_artifacts import RuntimeArtifactError, RuntimeArtifactService
from .security import ServiceSecurityError

_USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
_NODE = re.compile(r"^node_[a-z0-9][a-z0-9_-]{2,95}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{8,192}$")
_SESSION_TTL = timedelta(hours=8)
_REAUTH_TTL = timedelta(minutes=15)
_OBSERVATION_CONTEXT_TTL = timedelta(minutes=15)
_INVITE_TTL = timedelta(hours=24)
_ENROLLMENT_TTL = timedelta(minutes=10)
_LOCKOUT_WINDOW = timedelta(minutes=15)
_CERT_TTL = timedelta(days=30)
_CERT_RENEWAL_WINDOW = timedelta(days=7)
_HEARTBEAT_FRESHNESS = timedelta(seconds=60)
_MAINTENANCE_SESSION_MAX = timedelta(minutes=30)
_MAINTENANCE_JOB_MAX = timedelta(minutes=20)
_MAINTENANCE_HANDLERS = {
    "orbit-maintenance-handler/wsl-logind-keepalive-v6":
        "Install-OrbitWslKeepaliveFromLan-v6.ps1",
}
_MAINTENANCE_OUTCOMES = {"succeeded", "failed", "rejected"}


class LanStage1Error(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class CertificateIssuer(Protocol):
    def issue_client_certificate(
        self, *, csr: x509.CertificateSigningRequest, uri_san: str,
        not_before: datetime, not_after: datetime,
    ) -> bytes: ...


class ArtifactBundleResolver(Protocol):
    def read_bundle(
        self, *, artifact_id: str, revision_digest: str, bundle_digest: str
    ) -> bytes: ...


class ArtifactDownloadAuthority(Protocol):
    def authorize_download(
        self, *, department_id: str, node_id: str, artifact_id: str,
        revision_digest: str, bundle_digest: str,
    ) -> None: ...


class DepartmentDeviceBundleResolver(Protocol):
    def read_bundle(
        self, *, department_id: str, deployment_release_lock_digest: str
    ) -> dict[str, Any]: ...


class UnavailableCertificateIssuer:
    def issue_client_certificate(self, **_: Any) -> bytes:
        raise LanStage1Error("lan_certificate_issuer_unavailable")


class UnavailableArtifactBundleResolver:
    def read_bundle(self, **_: Any) -> bytes:
        raise LanStage1Error("lan_artifact_bundle_unavailable")


class UnavailableDepartmentDeviceBundleResolver:
    def read_bundle(self, **_: Any) -> dict[str, Any]:
        raise LanStage1Error("lan_department_device_bundle_unavailable")


class FileArtifactBundleResolver:
    """Resolve digest-bound OCI archives below one owner-only host directory.

    The physical layout is deliberately an implementation detail.  Callers and
    receipts continue to use only logical artifact IDs and SHA-256 digests.
    """

    _MAX_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise LanStage1Error("lan_artifact_root_invalid")
        self.root = root
        self._validate_directory(root, "lan_artifact_root_invalid")
        self._resolved_root = root.resolve(strict=True)

    @staticmethod
    def bundle_path(
        *, root: Path, artifact_id: str, revision_digest: str,
        bundle_digest: str,
    ) -> Path:
        if not re.fullmatch(r"^[a-z][A-Za-z0-9_:-]{2,159}$", artifact_id):
            raise LanStage1Error("lan_artifact_identity_invalid")
        _digest(revision_digest)
        _digest(bundle_digest)
        artifact_key = hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()
        return (
            root
            / artifact_key
            / revision_digest.removeprefix("sha256:")
            / f"{bundle_digest.removeprefix('sha256:')}.oci.tar"
        )

    def read_bundle(
        self, *, artifact_id: str, revision_digest: str, bundle_digest: str
    ) -> bytes:
        path = self.bundle_path(
            root=self.root,
            artifact_id=artifact_id,
            revision_digest=revision_digest,
            bundle_digest=bundle_digest,
        )
        try:
            for directory in (path.parent.parent, path.parent):
                self._validate_directory(directory, "lan_artifact_bundle_path_invalid")
            info = path.lstat()
        except OSError as error:
            raise LanStage1Error("lan_artifact_bundle_not_found") from error
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
        ):
            raise LanStage1Error("lan_artifact_bundle_path_invalid")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise LanStage1Error("lan_artifact_bundle_permissions_invalid")
        if not 1 <= info.st_size <= self._MAX_BUNDLE_BYTES:
            raise LanStage1Error("lan_artifact_bundle_invalid")
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self._resolved_root)
        except (OSError, ValueError) as error:
            raise LanStage1Error("lan_artifact_bundle_path_invalid") from error
        content = path.read_bytes()
        actual = "sha256:" + hashlib.sha256(content).hexdigest()
        if actual != bundle_digest:
            raise LanStage1Error("lan_artifact_bundle_digest_drift")
        return content

    @staticmethod
    def _validate_directory(path: Path, reason_code: str) -> None:
        try:
            info = path.lstat()
        except OSError as error:
            raise LanStage1Error(reason_code) from error
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise LanStage1Error(reason_code)


class FileDepartmentDeviceBundleResolver:
    """Read one department-scoped bootstrap ZIP for the active release lock."""

    _MAX_BUNDLE_BYTES = 64 * 1024 * 1024
    _MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
    _FILENAMES: ClassVar[dict[str, str]] = {
        "product_center": "orbit-product-center-lan-d0.zip",
        "technology_center": "orbit-technology-center-lan-d0.zip",
        "market_center": "orbit-market-center-lan-d0.zip",
    }

    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise LanStage1Error("lan_artifact_root_invalid")
        FileArtifactBundleResolver._validate_directory(
            root, "lan_artifact_root_invalid"
        )
        self.root = root
        self._resolved_root = root.resolve(strict=True)

    @staticmethod
    def bundle_path(
        *, root: Path, department_id: str,
        deployment_release_lock_digest: str,
    ) -> Path:
        _department(department_id)
        _digest(deployment_release_lock_digest)
        return (
            root
            / "department-device"
            / department_id
            / deployment_release_lock_digest.removeprefix("sha256:")
            / "bundle.zip"
        )

    def read_bundle(
        self, *, department_id: str, deployment_release_lock_digest: str
    ) -> dict[str, Any]:
        path = self.bundle_path(
            root=self.root,
            department_id=department_id,
            deployment_release_lock_digest=deployment_release_lock_digest,
        )
        try:
            for directory in (
                path.parent.parent.parent,
                path.parent.parent,
                path.parent,
            ):
                FileArtifactBundleResolver._validate_directory(
                    directory, "lan_department_device_bundle_path_invalid"
                )
            info = path.lstat()
            resolved = path.resolve(strict=True)
            resolved.relative_to(self._resolved_root)
        except (OSError, ValueError) as error:
            raise LanStage1Error(
                "lan_department_device_bundle_path_invalid"
            ) from error
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 1 <= info.st_size <= self._MAX_BUNDLE_BYTES
        ):
            raise LanStage1Error("lan_department_device_bundle_path_invalid")
        content = path.read_bytes()
        bundle_digest = "sha256:" + hashlib.sha256(content).hexdigest()
        manifest_digest = self._validate_archive(
            content,
            department_id=department_id,
            deployment_release_lock_digest=deployment_release_lock_digest,
        )
        return {
            "content": content,
            "bundle_digest": bundle_digest,
            "manifest_digest": manifest_digest,
            "filename": self._FILENAMES[department_id],
        }

    def _validate_archive(
        self, content: bytes, *, department_id: str,
        deployment_release_lock_digest: str,
    ) -> str:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                infos = archive.infolist()
                names = [item.filename for item in infos]
                if (
                    not infos
                    or len(names) != len(set(names))
                    or sum(item.file_size for item in infos)
                    > self._MAX_UNCOMPRESSED_BYTES
                ):
                    raise LanStage1Error(
                        "lan_department_device_bundle_archive_invalid"
                    )
                for item in infos:
                    mode = item.external_attr >> 16
                    if (
                        item.is_dir()
                        or item.flag_bits & 1
                        or item.filename.startswith(("/", "\\"))
                        or "\\" in item.filename
                        or any(part in {"", ".", ".."}
                               for part in item.filename.split("/"))
                        or stat.S_ISLNK(mode)
                    ):
                        raise LanStage1Error(
                            "lan_department_device_bundle_archive_invalid"
                        )
                required = {
                    "artifact-set-manifest.json",
                    "device-config.json",
                    "deployment-layout.json",
                    "START-HERE.md",
                    "Start-OrbitDepartmentPilot.cmd",
                    "Start-OrbitDepartmentPilot.ps1",
                    "Initialize-OrbitWsl.ps1",
                    "Install-OrbitWslRunner.ps1",
                    "Install-OrbitTransportRunnerTask.ps1",
                }
                if not required.issubset(names):
                    raise LanStage1Error(
                        "lan_department_device_bundle_archive_invalid"
                    )
                manifest_raw = archive.read("artifact-set-manifest.json")
                manifest = _strict_json_document(manifest_raw)
                config = _strict_json_document(archive.read("device-config.json"))
                layout = _strict_json_document(archive.read("deployment-layout.json"))
                config_department = config.get("department")
                expected_addons = (
                    ["addons/codex-cli/Start-OrbitCodexCliInstall.cmd"]
                    if department_id == "technology_center" else []
                )
                expected_layout_keys = {
                    "schema_version", "primary_entrypoint", "common_files",
                    "department_files", "department_id", "addons",
                    "excluded_legacy_categories", "runtime_started",
                    "model_called", "production_authorization",
                    "release_authorization",
                }
                expected_manifest_keys = {
                    "schema_version", "algorithm", "department_id", "node_id",
                    "server_address", "human_ca_sha256",
                    "deployment_release_lock_digest", "files", "contains_secret",
                    "runtime_started", "model_called", "production_authorization",
                    "release_authorization",
                }
                if (
                    set(manifest) != expected_manifest_keys
                    or manifest.get("schema_version")
                    != "orbit.department-device-pilot-artifact-set/0.1"
                    or manifest.get("algorithm") != "sha256"
                    or manifest.get("department_id") != department_id
                    or manifest.get("deployment_release_lock_digest")
                    != deployment_release_lock_digest
                    or manifest.get("contains_secret") is not False
                    or manifest.get("runtime_started") is not False
                    or manifest.get("model_called") is not False
                    or manifest.get("production_authorization") is not False
                    or manifest.get("release_authorization") is not False
                    or config.get("schema_version")
                    != "orbit.department-device-pilot/0.1"
                    or not isinstance(config_department, dict)
                    or config_department.get("id") != department_id
                    or config.get("deployment_release_lock_digest")
                    != deployment_release_lock_digest
                    or config.get("contains_secret") is not False
                    or config.get("runtime_started") is not False
                    or config.get("model_called") is not False
                    or config.get("production_authorization") is not False
                    or config.get("release_authorization") is not False
                    or set(layout) != expected_layout_keys
                    or layout.get("schema_version")
                    != "orbit.department-device-delivery-layout/0.1-draft"
                    or layout.get("primary_entrypoint")
                    != "Start-OrbitDepartmentPilot.cmd"
                    or layout.get("department_id") != department_id
                    or layout.get("department_files") != ["device-config.json"]
                    or layout.get("addons") != expected_addons
                    or layout.get("runtime_started") is not False
                    or layout.get("model_called") is not False
                    or layout.get("production_authorization") is not False
                    or layout.get("release_authorization") is not False
                ):
                    raise LanStage1Error(
                        "lan_department_device_bundle_scope_invalid"
                    )
                entries = manifest.get("files")
                if not isinstance(entries, list):
                    raise LanStage1Error(
                        "lan_department_device_bundle_manifest_invalid"
                    )
                manifest_names: set[str] = set()
                for entry in entries:
                    if (
                        not isinstance(entry, dict)
                        or set(entry) != {"path", "sha256", "size"}
                        or not isinstance(entry.get("path"), str)
                        or entry["path"] in manifest_names
                        or entry["path"] not in names
                        or not isinstance(entry.get("size"), int)
                        or entry["size"] < 0
                        or not _is_digest(entry.get("sha256"))
                    ):
                        raise LanStage1Error(
                            "lan_department_device_bundle_manifest_invalid"
                        )
                    raw = archive.read(entry["path"])
                    if (
                        len(raw) != entry["size"]
                        or "sha256:" + hashlib.sha256(raw).hexdigest()
                        != entry["sha256"]
                    ):
                        raise LanStage1Error(
                            "lan_department_device_bundle_digest_drift"
                        )
                    manifest_names.add(entry["path"])
                if set(names) != manifest_names | {"artifact-set-manifest.json"}:
                    raise LanStage1Error(
                        "lan_department_device_bundle_manifest_invalid"
                    )
                for name in (
                    "Start-OrbitDepartmentPilot.ps1",
                    "Initialize-OrbitWsl.ps1",
                    "Install-OrbitWslRunner.ps1",
                ):
                    if not archive.read(name).startswith(b"\xef\xbb\xbf"):
                        raise LanStage1Error(
                            "lan_department_device_bundle_encoding_invalid"
                        )
        except (zipfile.BadZipFile, KeyError, UnicodeError, json.JSONDecodeError) as error:
            raise LanStage1Error(
                "lan_department_device_bundle_archive_invalid"
            ) from error
        return "sha256:" + hashlib.sha256(manifest_raw).hexdigest()


class UnavailableArtifactDownloadAuthority:
    def authorize_download(self, **_: Any) -> None:
        raise LanStage1Error("lan_deployment_release_lock_required")


class DatabaseArtifactDownloadAuthority:
    """Require an exact company lock, department selection, and current node evidence."""

    def __init__(
        self, database: Database, *, expected_lock_digest: str,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        _digest(expected_lock_digest)
        self.database = database
        self.expected_lock_digest = expected_lock_digest
        self.now = now or _now

    def authorize_download(
        self, *, department_id: str, node_id: str, artifact_id: str,
        revision_digest: str, bundle_digest: str,
    ) -> None:
        now = self.now()
        with self.database.session() as session:
            locks = tuple(session.scalars(select(LanDeploymentReleaseLockRow).where(
                LanDeploymentReleaseLockRow.status == "candidate",
                LanDeploymentReleaseLockRow.lock_digest == self.expected_lock_digest,
            )))
            matching_locks = [row for row in locks if _lock_contains_artifact(
                row.document, artifact_id=artifact_id,
                revision_digest=revision_digest,
            )]
            if len(matching_locks) != 1:
                raise LanStage1Error("lan_deployment_release_lock_required")
            selection = session.scalar(select(DepartmentCockpitObjectRow).where(
                DepartmentCockpitObjectRow.object_type == "runtime_artifact_selection",
                DepartmentCockpitObjectRow.object_id == department_id,
                DepartmentCockpitObjectRow.department_id == department_id,
            ))
            if selection is None:
                raise LanStage1Error("lan_department_artifact_selection_required")
            selected = selection.document
            if (
                selected.get("artifact_id") != artifact_id
                or selected.get("artifact_revision") != revision_digest
                or selected.get("release_authorization") is not False
                or selected.get("production_authorized") is not False
            ):
                raise LanStage1Error("lan_department_artifact_selection_drift")
            heartbeat = session.scalar(
                select(LanNodeHeartbeatRow)
                .where(
                    LanNodeHeartbeatRow.node_id == node_id,
                    LanNodeHeartbeatRow.department_id == department_id,
                )
                .order_by(LanNodeHeartbeatRow.id.desc())
                .limit(1)
            )
            if (
                heartbeat is None
                or heartbeat.status not in {"ready", "busy"}
                or _as_utc(heartbeat.recorded_at) + _HEARTBEAT_FRESHNESS <= now
                or heartbeat.document.get("release_authorization") is not False
                or heartbeat.document.get("production_authorization") is not False
            ):
                raise LanStage1Error("lan_runtime_node_evidence_stale")
            assignment = session.scalar(select(LanArtifactDownloadAssignmentRow).where(
                LanArtifactDownloadAssignmentRow.department_id == department_id,
                LanArtifactDownloadAssignmentRow.artifact_id == artifact_id,
                LanArtifactDownloadAssignmentRow.revision_digest == revision_digest,
                LanArtifactDownloadAssignmentRow.bundle_digest == bundle_digest,
                LanArtifactDownloadAssignmentRow.status == "d0_assigned",
                LanArtifactDownloadAssignmentRow.revoked_at.is_(None),
            ))
            if assignment is None:
                raise LanStage1Error("lan_artifact_not_authorized")


class UnavailableDirectMtlsVerifier:
    def verify_mtls_peer(self, **_: Any) -> Mapping[str, Any]:
        raise LanStage1Error("lan_direct_mtls_verifier_unavailable")


class LanCertificateChainVerifier:
    """Directly revalidate a 30-day LAN client cert against public CA certs."""

    def __init__(self, *, ca_certificate_pem: bytes,
                 trust_domain: str = "orbit.local") -> None:
        if trust_domain != "orbit.local":
            raise LanStage1Error("lan_trust_domain_invalid")
        try:
            certificates = x509.load_pem_x509_certificates(ca_certificate_pem)
        except ValueError as error:
            raise LanStage1Error("lan_workload_ca_invalid") from error
        if not 1 <= len(certificates) <= 2:
            raise LanStage1Error("lan_workload_ca_invalid")
        now = _now()
        for certificate in certificates:
            try:
                constraints = certificate.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
                usage = certificate.extensions.get_extension_for_class(
                    x509.KeyUsage
                ).value
            except x509.ExtensionNotFound as error:
                raise LanStage1Error("lan_workload_ca_invalid") from error
            if (not constraints.ca or not usage.key_cert_sign
                    or certificate.not_valid_before_utc > now
                    or certificate.not_valid_after_utc <= now):
                raise LanStage1Error("lan_workload_ca_invalid")
        self.ca_certificates = tuple(certificates)
        self.trust_domain = trust_domain

    def verify_mtls_peer(self, *, peer_certificate: bytes) -> Mapping[str, Any]:
        try:
            certificate = x509.load_der_x509_certificate(peer_certificate)
            constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
            usages = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
        except (ValueError, x509.ExtensionNotFound) as error:
            raise LanStage1Error("lan_mtls_peer_invalid") from error
        now = _now()
        if (constraints.ca or ExtendedKeyUsageOID.CLIENT_AUTH not in usages
                or certificate.not_valid_before_utc > now
                or certificate.not_valid_after_utc <= now
                or certificate.not_valid_after_utc - certificate.not_valid_before_utc
                > _CERT_TTL):
            raise LanStage1Error("lan_mtls_peer_invalid")
        matching = next((ca for ca in self.ca_certificates
                         if ca.subject == certificate.issuer
                         and _certificate_signature_valid(certificate, ca)), None)
        if matching is None:
            raise LanStage1Error("lan_mtls_peer_signature_invalid")
        uri = _only_uri_san(certificate)
        prefix = f"spiffe://{self.trust_domain}/workload/"
        node_id = uri[len(prefix):] if uri.startswith(prefix) else ""
        _node(node_id)
        return {"workload_identity": f"workload_{node_id}", "spiffe_id": uri,
                "certificate_fingerprint": "sha256:"
                + certificate.fingerprint(hashes.SHA256()).hex(),
                "trust_anchor_fingerprint": "sha256:"
                + matching.fingerprint(hashes.SHA256()).hex()}


class LanP256CertificateIssuer:
    """Issue bounded client certificates from injected CA material."""

    def __init__(self, *, ca_certificate_pem: bytes,
                 ca_private_key_pem: bytes) -> None:
        try:
            certificates = x509.load_pem_x509_certificates(ca_certificate_pem)
            key = serialization.load_pem_private_key(
                ca_private_key_pem, password=None
            )
        except (TypeError, ValueError) as error:
            raise LanStage1Error("lan_certificate_issuer_material_invalid") from error
        if len(certificates) != 1 or not isinstance(key, ec.EllipticCurvePrivateKey):
            raise LanStage1Error("lan_certificate_issuer_material_invalid")
        certificate = certificates[0]
        cert_public = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_public = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if cert_public != key_public:
            raise LanStage1Error("lan_certificate_issuer_material_invalid")
        self.certificate = certificate
        self.key = key

    def issue_client_certificate(
        self, *, csr: x509.CertificateSigningRequest, uri_san: str,
        not_before: datetime, not_after: datetime,
    ) -> bytes:
        certificate = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.certificate.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH]
            ), critical=True)
            .add_extension(x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(uri_san)]
            ), critical=True)
            .sign(self.key, hashes.SHA256())
        )
        return certificate.public_bytes(serialization.Encoding.DER)


class LanHumanIdentityService:
    """Invite-only LAN accounts with digest-only credentials and sessions."""

    def __init__(
        self,
        database: Database,
        *,
        password_hasher: ScryptPasswordHasher | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.database = database
        self.password_hasher = password_hasher or ScryptPasswordHasher()
        if self.password_hasher.n < 2**12:
            raise LanStage1Error("lan_scrypt_cost_too_low")
        self.now = now or _now
        self._lock = threading.RLock()
        self._dummy_hash = self.password_hasher.hash(
            "D0-LAN-dummy-password-never-valid"
        )

    def public_status(self) -> dict[str, Any]:
        with self.database.session() as session:
            count = session.scalar(select(func.count(LanHumanAccountRow.id))) or 0
        return {"bootstrap_required": count == 0,
                "registration_mode": "invitation_and_approval",
                "bootstrap_mode": "cli_only", "session_ttl_seconds": 28800,
                "reauth_ttl_seconds": 900,
                "password_kdf": "scrypt_log_n_12_or_higher",
                "identity_authority": "lan_stage1_local_account_only",
                "production_authorized": False,
                "production_authorization": False,
                "release_authorization": False}

    def bootstrap_admin_cli_only(
        self, *, username: str, password: str, display_name: str
    ) -> dict[str, Any]:
        """Create the first admin; this method is intentionally not routed."""
        normalized = _username(username)
        _password(password)
        display = _display_name(display_name)
        now = self.now()
        with self._lock, self.database.session() as session:
            if (session.scalar(select(func.count(LanHumanAccountRow.id))) or 0) != 0:
                raise LanStage1Error("lan_bootstrap_already_completed")
            row = _new_account(
                username=normalized,
                display_name=display,
                password_hash=self.password_hasher.hash(password),
                role_ref=ROLE_CONTROL_PLANE_ADMIN,
                department_id=None,
                status="active",
                approved_by_ref="cli_bootstrap",
                now=now,
            )
            session.add(row)
            session.flush()
            _audit(session, "lan_bootstrap_admin_created", row.account_id,
                   row.human_ref, {"cli_only": True}, now)
            return self._principal(row)

    def create_invite(
        self, *, principal: Mapping[str, Any], department_id: str,
        role_ref: str, idempotency_key: str,
    ) -> dict[str, Any]:
        _department(department_id)
        _idempotency(idempotency_key)
        role = _single_role(principal)
        if role == ROLE_CONTROL_PLANE_ADMIN:
            if role_ref != ROLE_DEPARTMENT_OWNER:
                raise LanStage1Error("lan_invite_role_not_allowed")
        elif role == ROLE_DEPARTMENT_OWNER:
            if department_id not in principal.get("department_refs", ()):
                raise LanStage1Error("lan_department_scope_not_allowed")
            if role_ref != ROLE_DEPARTMENT_USER:
                raise LanStage1Error("lan_invite_role_not_allowed")
        else:
            raise LanStage1Error("lan_invite_not_allowed")
        request = {
            "department_id": department_id,
            "role_ref": role_ref,
            "actor_ref": principal["human_ref"],
        }
        digest = _canonical_digest(request)
        now = self.now()
        with self._lock, self.database.session() as session:
            replay = _command_replay(session, idempotency_key, "create_invite", digest)
            if replay is not None:
                # Raw codes are never persisted and therefore cannot be replayed.
                return {**replay, "invite_code": None, "replayed": True}
            raw = secrets.token_urlsafe(32)
            invite_id = _stable_id("invite_lan", raw)
            response = {
                "invite_id": invite_id,
                "invite_code": raw,
                "department_id": department_id,
                "role_ref": role_ref,
                "expires_at": _time(now + _INVITE_TTL),
                "single_use": True,
                "status": "available",
                "created_by_role_ref": role,
                "synthetic_only": True,
                "replayed": False,
                "production_authorized": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            session.add(LanInviteRow(
                invite_id=invite_id, token_digest=_secret_digest(raw),
                department_id=department_id, role_ref=role_ref,
                invited_by_ref=str(principal["human_ref"]),
                idempotency_key=idempotency_key, created_at=now,
                expires_at=now + _INVITE_TTL, consumed_at=None,
                consumed_by_ref=None,
            ))
            _record_command(session, idempotency_key, "create_invite", digest,
                            {key: value for key, value in response.items() if key != "invite_code"},
                            str(principal["human_ref"]), now)
            return response

    def register(
        self, *, invite_code: str, username: str, password: str,
        display_name: str, idempotency_key: str,
    ) -> dict[str, Any]:
        _idempotency(idempotency_key)
        normalized = _username(username)
        _password(password)
        display = _display_name(display_name)
        now = self.now()
        if not isinstance(invite_code, str) or not 20 <= len(invite_code) <= 128:
            raise LanStage1Error("lan_invite_invalid")
        request_digest = _canonical_digest({
            "invite_digest": _secret_digest(invite_code), "username": normalized,
            "display_name": display,
        })
        with self._lock, self.database.session() as session:
            replay = _command_replay(session, idempotency_key, "register_account", request_digest)
            if replay is not None:
                return {**replay, "replayed": True}
            invite = session.scalar(select(LanInviteRow).where(
                LanInviteRow.token_digest == _secret_digest(invite_code)
            ).with_for_update())
            if (invite is None or invite.consumed_at is not None
                    or _as_utc(invite.expires_at) <= now):
                raise LanStage1Error("lan_invite_invalid")
            if session.scalar(select(LanHumanAccountRow).where(
                LanHumanAccountRow.username == normalized
            )) is not None:
                raise LanStage1Error("lan_username_unavailable")
            row = _new_account(
                username=normalized, display_name=display,
                password_hash=self.password_hasher.hash(password),
                role_ref=invite.role_ref, department_id=invite.department_id,
                status="pending_approval", approved_by_ref=None, now=now,
            )
            session.add(row)
            session.flush()
            invite.consumed_at = now
            invite.consumed_by_ref = row.human_ref
            _audit(session, "lan_invite_consumed", invite.invite_id,
                   row.human_ref, {"department_id": invite.department_id}, now)
            response = {**self._principal(row), "replayed": False}
            _record_command(session, idempotency_key, "register_account", request_digest,
                            response, row.human_ref, now)
            return response

    def approve_account(
        self, *, principal: Mapping[str, Any], account_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        _idempotency(idempotency_key)
        role = _single_role(principal)
        request_digest = _canonical_digest({"account_id": account_id})
        now = self.now()
        with self.database.session() as session:
            replay = _command_replay(
                session, idempotency_key, "approve_account", request_digest,
                actor_ref=str(principal["human_ref"]),
            )
            if replay is not None:
                return {**replay, "replayed": True}
            row = session.scalar(select(LanHumanAccountRow).where(
                LanHumanAccountRow.account_id == account_id
            ).with_for_update())
            if row is None:
                raise LanStage1Error("lan_account_not_found")
            if row.status != "pending_approval" or row.department_id is None:
                raise LanStage1Error("lan_account_not_pending")
            if role == ROLE_DEPARTMENT_OWNER:
                if row.department_id not in principal.get("department_refs", ()):
                    raise LanStage1Error("lan_department_scope_not_allowed")
                if row.role_ref != ROLE_DEPARTMENT_USER:
                    raise LanStage1Error("lan_account_approval_not_allowed")
            elif role == ROLE_CONTROL_PLANE_ADMIN:
                if row.role_ref != ROLE_DEPARTMENT_OWNER:
                    raise LanStage1Error("lan_account_approval_not_allowed")
            else:
                raise LanStage1Error("lan_account_approval_not_allowed")
            row.status = "active"
            row.approved_by_ref = str(principal["human_ref"])
            row.approved_at = now
            response = {"account": self._public_account(row), "replayed": False,
                        "production_authorization": False,
                        "release_authorization": False}
            _record_command(session, idempotency_key, "approve_account", request_digest,
                            response, str(principal["human_ref"]), now)
            _audit(session, "lan_account_approved", account_id,
                   str(principal["human_ref"]),
                   {"department_id": row.department_id, "role_ref": row.role_ref}, now)
            return response

    def pending_accounts(
        self, *, principal: Mapping[str, Any], department_id: str | None,
    ) -> list[dict[str, Any]]:
        role = _single_role(principal)
        with self.database.session() as session:
            statement = select(LanHumanAccountRow).where(
                LanHumanAccountRow.status == "pending_approval"
            )
            if role == ROLE_CONTROL_PLANE_ADMIN:
                if department_id is not None:
                    _department(department_id)
                    statement = statement.where(
                        LanHumanAccountRow.department_id == department_id
                    )
                statement = statement.where(
                    LanHumanAccountRow.role_ref == ROLE_DEPARTMENT_OWNER
                )
            elif role == ROLE_DEPARTMENT_OWNER:
                own_department = str(principal["department_refs"][0])
                if department_id not in {None, own_department}:
                    raise LanStage1Error("lan_department_scope_not_allowed")
                statement = statement.where(
                    LanHumanAccountRow.department_id == own_department,
                    LanHumanAccountRow.role_ref == ROLE_DEPARTMENT_USER,
                )
            else:
                raise LanStage1Error("lan_account_approval_not_allowed")
            rows = tuple(session.scalars(statement.order_by(LanHumanAccountRow.id)))
        return [self._public_account(row) for row in rows]

    def change_password(
        self, *, principal: Mapping[str, Any], current_password: str,
        new_password: str, idempotency_key: str,
    ) -> dict[str, Any]:
        _idempotency(idempotency_key)
        _password(current_password)
        _password(new_password)
        request_digest = _canonical_digest({
            "account_id": principal["account_id"],
        })
        now = self.now()
        with self.database.session() as session:
            replay = _command_replay(session, idempotency_key, "change_password", request_digest)
            if replay is not None:
                return {**replay, "replayed": True}
            row = session.scalar(select(LanHumanAccountRow).where(
                LanHumanAccountRow.account_id == principal["account_id"]
            ).with_for_update())
            if row is None or not self.password_hasher.verify(current_password, row.password_hash):
                raise LanStage1Error("lan_current_password_invalid")
            if self.password_hasher.verify(new_password, row.password_hash):
                raise LanStage1Error("lan_new_password_unchanged")
            row.password_hash = self.password_hasher.hash(new_password)
            sessions = tuple(session.scalars(select(LanSessionRow).where(
                LanSessionRow.account_id == row.account_id,
                LanSessionRow.revoked_at.is_(None),
            )))
            for session_row in sessions:
                session_row.revoked_at = now
            response = {"changed": True, "sessions_revoked": len(sessions),
                        "replayed": False, "production_authorization": False,
                        "release_authorization": False}
            _record_command(session, idempotency_key, "change_password", request_digest,
                            response, str(principal["human_ref"]), now)
            return response

    def login(self, *, username: str, password: str,
              idempotency_key: str) -> tuple[str, str, dict[str, Any]]:
        _idempotency(idempotency_key)
        normalized = _username(username)
        _password(password)
        now = self.now()
        rejected = False
        request_digest = _canonical_digest({"username": normalized})
        with self._lock, self.database.session() as session:
            replay = session.scalar(select(LanSessionRow).where(
                LanSessionRow.login_idempotency_key == idempotency_key
            ))
            if replay is not None:
                if replay.login_request_digest != request_digest:
                    raise LanStage1Error("lan_idempotency_conflict")
                raise LanStage1Error("lan_login_already_completed")
            row = session.scalar(select(LanHumanAccountRow).where(
                LanHumanAccountRow.username == normalized
            ).with_for_update())
            encoded = self._dummy_hash if row is None else row.password_hash
            valid = self.password_hasher.verify(password, encoded)
            locked = row is not None and _future(row.locked_until, now)
            if row is None or not valid or row.status != "active" or locked:
                if row is not None and not locked:
                    start = _as_utc(row.failed_window_started_at) if row.failed_window_started_at else None
                    if start is None or start + _LOCKOUT_WINDOW <= now:
                        row.failed_window_started_at = now
                        row.failed_login_count = 1
                    else:
                        row.failed_login_count += 1
                    if row.failed_login_count >= 5:
                        row.locked_until = now + _LOCKOUT_WINDOW
                rejected = True
            else:
                row.failed_login_count = 0
                row.failed_window_started_at = None
                row.locked_until = None
                token = secrets.token_urlsafe(32)
                csrf = _csrf_for_session(token)
                session.add(LanSessionRow(
                    session_id=_stable_id("session_lan", token),
                    session_digest=_secret_digest(token), csrf_digest=_secret_digest(csrf),
                    account_id=row.account_id, login_idempotency_key=idempotency_key,
                    login_request_digest=request_digest,
                    created_at=now, authenticated_at=now,
                    reauthenticated_at=None, expires_at=now + _SESSION_TTL,
                    revoked_at=None,
                ))
                result = (token, csrf, self._principal(row))
        if rejected:
            raise LanStage1Error("lan_login_invalid")
        return result

    def authenticate(
        self, token: str | None, *, csrf_token: str | None = None,
        unsafe: bool = False, require_recent_reauth: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(token, str) or not 20 <= len(token) <= 128:
            raise LanStage1Error("lan_session_required")
        now = self.now()
        with self.database.session() as session:
            session_row = session.scalar(select(LanSessionRow).where(
                LanSessionRow.session_digest == _secret_digest(token)
            ))
            if (session_row is None or session_row.revoked_at is not None
                    or _as_utc(session_row.expires_at) <= now):
                raise LanStage1Error("lan_session_invalid")
            if unsafe and (not isinstance(csrf_token, str) or not hmac.compare_digest(
                _secret_digest(csrf_token), session_row.csrf_digest
            )):
                raise LanStage1Error("lan_csrf_invalid")
            if require_recent_reauth and (
                session_row.reauthenticated_at is None
                or _as_utc(session_row.reauthenticated_at) + _REAUTH_TTL <= now
            ):
                raise LanStage1Error("lan_recent_reauth_required")
            account = session.scalar(select(LanHumanAccountRow).where(
                LanHumanAccountRow.account_id == session_row.account_id
            ))
            if account is None or account.status != "active":
                raise LanStage1Error("lan_session_invalid")
            principal = self._principal(account)
            principal["session_id"] = session_row.session_id
            principal["csrf_token"] = _csrf_for_session(token)
            context = session.scalar(
                select(LanDepartmentObservationContextRow)
                .where(
                    LanDepartmentObservationContextRow.session_id
                    == session_row.session_id,
                    LanDepartmentObservationContextRow.revoked_at.is_(None),
                )
                .order_by(LanDepartmentObservationContextRow.id.desc())
                .limit(1)
            )
            active_context = (
                context
                if context is not None and _as_utc(context.expires_at) > now
                else None
            )
            if ROLE_CONTROL_PLANE_ADMIN in principal["role_refs"]:
                principal["access_mode"] = (
                    "company_observer"
                    if active_context is not None
                    else "company_control"
                )
                principal["active_observation_department_ref"] = (
                    None if active_context is None else active_context.department_id
                )
                principal["observation_expires_at"] = (
                    None
                    if active_context is None
                    else _time(_as_utc(active_context.expires_at))
                )
                principal["allowed_observation_department_refs"] = list(DEPARTMENTS)
            else:
                principal["access_mode"] = "department_member"
                principal["active_observation_department_ref"] = None
                principal["observation_expires_at"] = None
                principal["allowed_observation_department_refs"] = []
            return principal

    def activate_department_observation(
        self,
        *,
        token: str | None,
        department_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        _department(department_id)
        _idempotency(idempotency_key)
        principal = self.authenticate(token, require_recent_reauth=True)
        if _single_role(principal) != ROLE_CONTROL_PLANE_ADMIN:
            raise LanStage1Error("lan_department_observation_admin_required")
        now = self.now()
        request_digest = _canonical_digest(
            {
                "session_id": principal["session_id"],
                "department_id": department_id,
            }
        )
        with self.database.session() as session:
            replay = _command_replay(
                session,
                idempotency_key,
                "activate_department_observation",
                request_digest,
            )
            if replay is not None:
                return {**replay, "replayed": True}
            active = tuple(
                session.scalars(
                    select(LanDepartmentObservationContextRow).where(
                        LanDepartmentObservationContextRow.session_id
                        == principal["session_id"],
                        LanDepartmentObservationContextRow.revoked_at.is_(None),
                    )
                )
            )
            for row in active:
                row.revoked_at = now
                row.revoke_reason = "replaced"
            context_id = _stable_id(
                "department_observation",
                f"{principal['session_id']}:{department_id}:{idempotency_key}",
            )
            expires_at = now + _OBSERVATION_CONTEXT_TTL
            session.add(
                LanDepartmentObservationContextRow(
                    context_id=context_id,
                    session_id=str(principal["session_id"]),
                    department_id=department_id,
                    actor_ref=str(principal["human_ref"]),
                    idempotency_key=idempotency_key,
                    created_at=now,
                    expires_at=expires_at,
                    revoked_at=None,
                    revoke_reason=None,
                )
            )
            response = {
                "context_id": context_id,
                "department_id": department_id,
                "access_mode": "company_observer",
                "read_only": True,
                "expires_at": _time(expires_at),
                "replayed": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            _record_command(
                session,
                idempotency_key,
                "activate_department_observation",
                request_digest,
                response,
                str(principal["human_ref"]),
                now,
            )
            _audit(
                session,
                "department_observation_activated",
                context_id,
                str(principal["human_ref"]),
                {
                    "department_id": department_id,
                    "read_only": True,
                    "expires_at": _time(expires_at),
                },
                now,
            )
            return response

    def clear_department_observation(
        self, *, token: str | None, idempotency_key: str
    ) -> dict[str, Any]:
        _idempotency(idempotency_key)
        principal = self.authenticate(token)
        if _single_role(principal) != ROLE_CONTROL_PLANE_ADMIN:
            raise LanStage1Error("lan_department_observation_admin_required")
        now = self.now()
        request_digest = _canonical_digest({"session_id": principal["session_id"]})
        with self.database.session() as session:
            replay = _command_replay(
                session,
                idempotency_key,
                "clear_department_observation",
                request_digest,
            )
            if replay is not None:
                return {**replay, "replayed": True}
            active = tuple(
                session.scalars(
                    select(LanDepartmentObservationContextRow).where(
                        LanDepartmentObservationContextRow.session_id
                        == principal["session_id"],
                        LanDepartmentObservationContextRow.revoked_at.is_(None),
                    )
                )
            )
            cleared = [row.context_id for row in active]
            for row in active:
                row.revoked_at = now
                row.revoke_reason = "cleared"
            response = {
                "cleared": bool(cleared),
                "context_ids": cleared,
                "access_mode": "company_control",
                "replayed": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            _record_command(
                session,
                idempotency_key,
                "clear_department_observation",
                request_digest,
                response,
                str(principal["human_ref"]),
                now,
            )
            for context_id in cleared:
                _audit(
                    session,
                    "department_observation_cleared",
                    context_id,
                    str(principal["human_ref"]),
                    {"read_only": True, "reason": "cleared"},
                    now,
                )
            return response

    def reauthentication_status(self, token: str | None) -> dict[str, Any]:
        """Read the current session deadline without renewing it or granting access."""
        self.authenticate(token)
        now = self.now()
        with self.database.session() as session:
            row = session.scalar(select(LanSessionRow).where(
                LanSessionRow.session_digest == _secret_digest(str(token))
            ))
            if row is None or row.revoked_at is not None or _as_utc(row.expires_at) <= now:
                raise LanStage1Error("lan_session_invalid")
            deadline = None if row.reauthenticated_at is None else min(
                _as_utc(row.reauthenticated_at) + _REAUTH_TTL, _as_utc(row.expires_at)
            )
            return {"reauthenticated_until": _time(deadline) if deadline and deadline > now else None,
                    "observed_at": _time(now)}

    def reauthenticate(self, *, token: str | None, password: str,
                       idempotency_key: str) -> dict[str, Any]:
        _idempotency(idempotency_key)
        _password(password)
        principal = self.authenticate(token)
        now = self.now()
        request_digest = _canonical_digest({"session_id": principal["session_id"]})
        with self.database.session() as session:
            replay = _command_replay(session, idempotency_key, "reauthenticate", request_digest)
            if replay is not None:
                return {**replay, "csrf_token": _csrf_for_session(str(token)),
                        "replayed": True}
            account = session.scalar(select(LanHumanAccountRow).where(
                LanHumanAccountRow.account_id == principal["account_id"]
            ))
            if account is None or not self.password_hasher.verify(password, account.password_hash):
                raise LanStage1Error("lan_reauth_invalid")
            session_row = session.scalar(select(LanSessionRow).where(
                LanSessionRow.session_digest == _secret_digest(str(token))
            ))
            assert session_row is not None
            session_row.reauthenticated_at = now
            response = {**principal, "replayed": False}
            _record_command(session, idempotency_key, "reauthenticate", request_digest,
                            {key: value for key, value in response.items()
                             if key != "csrf_token"},
                            str(principal["human_ref"]), now)
        return response

    def logout(self, *, token: str | None, csrf_token: str | None,
               idempotency_key: str) -> dict[str, Any]:
        _idempotency(idempotency_key)
        if not isinstance(token, str):
            raise LanStage1Error("lan_session_required")
        request_digest = _canonical_digest({"session_digest": _secret_digest(token)})
        with self.database.session() as session:
            replay = _command_replay(session, idempotency_key, "logout", request_digest)
            if replay is not None:
                return {**replay, "replayed": True}
            row = session.scalar(select(LanSessionRow).where(
                LanSessionRow.session_digest == _secret_digest(token)
            ))
            if (row is None or row.revoked_at is not None
                    or not isinstance(csrf_token, str)
                    or not hmac.compare_digest(row.csrf_digest,
                                               _secret_digest(csrf_token))):
                raise LanStage1Error("lan_session_invalid")
            now = self.now()
            row.revoked_at = now
            active_contexts = tuple(
                session.scalars(
                    select(LanDepartmentObservationContextRow).where(
                        LanDepartmentObservationContextRow.session_id == row.session_id,
                        LanDepartmentObservationContextRow.revoked_at.is_(None),
                    )
                )
            )
            for context in active_contexts:
                context.revoked_at = now
                context.revoke_reason = "logout"
            response = {"logged_out": True, "replayed": False,
                        "production_authorization": False,
                        "release_authorization": False}
            _record_command(session, idempotency_key, "logout", request_digest,
                            response, row.account_id, now)
            return response

    @staticmethod
    def _principal(row: LanHumanAccountRow) -> dict[str, Any]:
        departments = list(DEPARTMENTS) if row.role_ref == ROLE_CONTROL_PLANE_ADMIN else [row.department_id]
        return {
            "account_id": row.account_id, "human_ref": row.human_ref,
            "username": row.username, "display_name": row.display_name,
            "role_refs": [row.role_ref], "department_refs": [item for item in departments if item],
            "permissions": {
                "view_all_departments": row.role_ref == ROLE_CONTROL_PLANE_ADMIN,
                "confirm_tasks": row.role_ref == ROLE_DEPARTMENT_OWNER,
                "select_department_model_route": row.role_ref == ROLE_DEPARTMENT_OWNER,
                "select_department_runtime_artifact": row.role_ref == ROLE_DEPARTMENT_OWNER,
                "approve_department_users": row.role_ref == ROLE_DEPARTMENT_OWNER,
                "assign_department_owner": row.role_ref == ROLE_CONTROL_PLANE_ADMIN,
                "manage_company_model_routes": row.role_ref == ROLE_CONTROL_PLANE_ADMIN,
                "manage_company_access": row.role_ref == ROLE_CONTROL_PLANE_ADMIN,
                "issue_runtime_enrollment_codes": row.role_ref == ROLE_DEPARTMENT_OWNER,
                "download_department_device_bundle": row.role_ref == ROLE_DEPARTMENT_OWNER,
            },
            "identity_evidence": "lan_stage1_local_account_mapping",
            "production_authorized": False,
            "production_authorization": False, "release_authorization": False,
        }

    @staticmethod
    def _public_account(row: LanHumanAccountRow) -> dict[str, Any]:
        return {"account_id": row.account_id, "username": row.username,
                "display_name": row.display_name, "role_ref": row.role_ref,
                "department_id": row.department_id, "status": row.status,
                "created_at": _time(_as_utc(row.created_at)),
                "approved_at": None if row.approved_at is None else _time(_as_utc(row.approved_at)),
                "identity_authority": "lan_stage1_local_account_only",
                "production_authorized": False}


class LanWorkloadIdentityService:
    """Enrollment and Caddy-forwarded certificate binding verification."""

    def __init__(
        self, database: Database, *, trust_domain: str = "orbit.local",
        issuer: CertificateIssuer | None = None,
        direct_mtls_verifier: Any | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if trust_domain != "orbit.local":
            raise LanStage1Error("lan_trust_domain_invalid")
        self.database = database
        self.trust_domain = trust_domain
        self.issuer = issuer or UnavailableCertificateIssuer()
        self.direct_mtls_verifier = direct_mtls_verifier or UnavailableDirectMtlsVerifier()
        self.now = now or _now

    def create_enrollment_code(
        self, *, principal: Mapping[str, Any], department_id: str,
        node_id: str, idempotency_key: str,
    ) -> dict[str, Any]:
        _department(department_id)
        _node(node_id)
        _idempotency(idempotency_key)
        if _single_role(principal) != ROLE_DEPARTMENT_OWNER:
            raise LanStage1Error("lan_node_enrollment_owner_required")
        if department_id not in principal.get("department_refs", ()):
            raise LanStage1Error("lan_department_scope_not_allowed")
        now = self.now()
        raw = secrets.token_urlsafe(32)
        uri = self._uri(department_id, node_id)
        request_digest = _canonical_digest({"department_id": department_id, "node_id": node_id})
        with self.database.session() as session:
            replay = _command_replay(session, idempotency_key, "create_enrollment", request_digest)
            if replay is not None:
                return {**replay, "enrollment_code": None, "replayed": True}
            enrollment_id = _stable_id("enrollment_lan", raw)
            response = {
                "enrollment_id": enrollment_id, "enrollment_code": raw,
                "node_id": node_id, "department_id": department_id,
                "expected_uri_san": uri,
                "expires_at": _time(now + _ENROLLMENT_TTL), "single_use": True,
                "replayed": False, "production_authorized": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            session.add(LanEnrollmentCodeRow(
                enrollment_id=enrollment_id, code_digest=_secret_digest(raw),
                node_id=node_id, department_id=department_id, expected_uri_san=uri,
                created_by_ref=str(principal["human_ref"]), idempotency_key=idempotency_key,
                created_at=now, expires_at=now + _ENROLLMENT_TTL, consumed_at=None,
                failed_attempt_count=0, failed_window_started_at=None,
                locked_until=None,
            ))
            _record_command(session, idempotency_key, "create_enrollment", request_digest,
                            {key: value for key, value in response.items() if key != "enrollment_code"},
                            str(principal["human_ref"]), now)
            return response

    def enroll(self, *, enrollment_id: str, enrollment_code: str,
               csr_pem: bytes, idempotency_key: str) -> dict[str, Any]:
        _idempotency(idempotency_key)
        if not isinstance(enrollment_code, str) or not 20 <= len(enrollment_code) <= 128:
            raise LanStage1Error("lan_enrollment_code_invalid")
        now = self.now()
        rejected = False
        request_digest = _canonical_digest({"enrollment_id": enrollment_id,
            "code_digest": _secret_digest(enrollment_code),
            "csr_digest": "sha256:" + hashlib.sha256(csr_pem).hexdigest()})
        with self.database.session() as session:
            replay = _command_replay(session, idempotency_key,
                                     "runtime_node_enrollment", request_digest)
            if replay is not None:
                if replay.get("outcome") == "rejected":
                    rejected = True
                    result = None
                else:
                    return {**replay, "replayed": True}
            row = session.scalar(select(LanEnrollmentCodeRow).where(
                LanEnrollmentCodeRow.enrollment_id == enrollment_id
            ).with_for_update())
            if not rejected and (row is None or row.consumed_at is not None
                    or _as_utc(row.expires_at) <= now or _future(row.locked_until, now)):
                raise LanStage1Error("lan_enrollment_code_invalid")
            if not rejected and not hmac.compare_digest(row.code_digest, _secret_digest(enrollment_code)):
                start = _as_utc(row.failed_window_started_at) if row.failed_window_started_at else None
                if start is None or start + _LOCKOUT_WINDOW <= now:
                    row.failed_window_started_at = now
                    row.failed_attempt_count = 1
                else:
                    row.failed_attempt_count += 1
                if row.failed_attempt_count >= 5:
                    row.locked_until = now + _LOCKOUT_WINDOW
                rejected = True
                _record_command(session, idempotency_key, "runtime_node_enrollment",
                                request_digest, {"outcome": "rejected"},
                                f"enrollment_{enrollment_id}", now)
            if rejected:
                result = None
            else:
                row.failed_attempt_count = 0
                row.failed_window_started_at = None
                csr = _validate_p256_csr(csr_pem)
                result = self._complete_enrollment(session=session, row=row, csr=csr, now=now)
                result["outcome"] = "bound"
                result["replayed"] = False
                _record_command(session, idempotency_key, "runtime_node_enrollment",
                                request_digest, result,
                                f"workload_{row.node_id}", now)
        if rejected:
            raise LanStage1Error("lan_enrollment_code_invalid")
        assert result is not None
        return result

    def _complete_enrollment(
        self, *, session: Any, row: LanEnrollmentCodeRow,
        csr: x509.CertificateSigningRequest, now: datetime,
    ) -> dict[str, Any]:
            csr_uri = _only_uri_san(csr)
            if csr_uri != row.expected_uri_san:
                raise LanStage1Error("lan_csr_uri_san_binding_drift")
            certificate_der = self.issuer.issue_client_certificate(
                csr=csr, uri_san=row.expected_uri_san,
                not_before=now, not_after=now + _CERT_TTL,
            )
            cert = _validate_issued_certificate(
                certificate_der, csr=csr, uri_san=row.expected_uri_san,
                now=now,
            )
            fingerprint = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
            existing = session.scalar(select(LanCertificateBindingRow).where(
                LanCertificateBindingRow.fingerprint == fingerprint
            ))
            if existing is not None:
                raise LanStage1Error("lan_certificate_binding_conflict")
            public_der = cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            binding_id = _stable_id("cert_binding_lan", fingerprint)
            session.add(LanCertificateBindingRow(
                binding_id=binding_id, node_id=row.node_id,
                department_id=row.department_id, uri_san=row.expected_uri_san,
                fingerprint=fingerprint, serial_number=format(cert.serial_number, "x"),
                certificate_der=certificate_der,
                public_key_digest="sha256:" + hashlib.sha256(public_der).hexdigest(),
                status="active", issued_at=now,
                not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc,
                renewal_after=cert.not_valid_after_utc - _CERT_RENEWAL_WINDOW,
            ))
            row.consumed_at = now
            _audit(session, "lan_node_certificate_bound", binding_id,
                   f"workload_{row.node_id}", {"node_id": row.node_id,
                   "department_id": row.department_id, "fingerprint": fingerprint}, now)
            return {
                "binding_id": binding_id, "node_id": row.node_id,
                "department_id": row.department_id, "uri_san": row.expected_uri_san,
                "certificate_der_base64": base64.b64encode(certificate_der).decode("ascii"),
                "certificate_fingerprint": fingerprint,
                "not_after": _time(cert.not_valid_after_utc),
                "renewal_after": _time(cert.not_valid_after_utc - _CERT_RENEWAL_WINDOW),
                "production_authorized": False,
                "production_authorization": False, "release_authorization": False,
            }

    def renew_certificate(
        self, *, principal: Mapping[str, Any], node_id: str,
        csr_pem: bytes, idempotency_key: str,
    ) -> dict[str, Any]:
        _node_actor(principal, node_id)
        _idempotency(idempotency_key)
        csr_value = _validate_p256_csr(csr_pem)
        now = self.now()
        request_digest = _canonical_digest({"node_id": node_id,
            "csr_digest": "sha256:" + hashlib.sha256(csr_pem).hexdigest()})
        with self.database.session() as session:
            replay = _command_replay(session, idempotency_key, "renew_certificate", request_digest)
            if replay is not None:
                return {**replay, "replayed": True}
            current = session.scalar(select(LanCertificateBindingRow).where(
                LanCertificateBindingRow.fingerprint == principal["certificate_fingerprint"],
                LanCertificateBindingRow.node_id == node_id,
                LanCertificateBindingRow.status == "active",
            ).with_for_update())
            if current is None:
                raise LanStage1Error("lan_certificate_binding_not_found")
            if _as_utc(current.renewal_after) > now:
                raise LanStage1Error("lan_certificate_renewal_too_early")
            synthetic_row = LanEnrollmentCodeRow(
                enrollment_id="renewal_only", code_digest=_secret_digest("renewal_only"),
                node_id=current.node_id, department_id=current.department_id,
                expected_uri_san=current.uri_san, created_by_ref=str(principal["workload_identity"]),
                idempotency_key=idempotency_key, created_at=now,
                expires_at=now + timedelta(minutes=1), consumed_at=None,
                failed_attempt_count=0, failed_window_started_at=None, locked_until=None,
            )
            response = self._complete_enrollment(session=session, row=synthetic_row,
                                                 csr=csr_value, now=now)
            current.status = "superseded"
            response["superseded_fingerprint"] = current.fingerprint
            response["replayed"] = False
            _record_command(session, idempotency_key, "renew_certificate", request_digest,
                            response, str(principal["workload_identity"]), now)
            return response

    def verify_caddy_forwarded_peer(
        self, *, certificate_der_base64: str | None,
        forwarded_fingerprint: str | None,
    ) -> dict[str, Any]:
        if not isinstance(certificate_der_base64, str) or len(certificate_der_base64) > 64 * 1024:
            raise LanStage1Error("lan_forwarded_certificate_required")
        try:
            der = base64.b64decode(certificate_der_base64, validate=True)
            cert = x509.load_der_x509_certificate(der)
        except (ValueError, TypeError) as error:
            raise LanStage1Error("lan_forwarded_certificate_invalid") from error
        fingerprint = "sha256:" + cert.fingerprint(hashes.SHA256()).hex()
        normalized_forwarded = forwarded_fingerprint.lower() if isinstance(forwarded_fingerprint, str) else ""
        if re.fullmatch(r"[0-9a-f]{64}", normalized_forwarded):
            normalized_forwarded = "sha256:" + normalized_forwarded
        if not hmac.compare_digest(
            fingerprint, normalized_forwarded
        ):
            raise LanStage1Error("lan_forwarded_fingerprint_mismatch")
        now = self.now()
        with self.database.session() as session:
            binding = session.scalar(select(LanCertificateBindingRow).where(
                LanCertificateBindingRow.fingerprint == fingerprint
            ))
            revoked = session.scalar(select(LanCertificateRevocationRow).where(
                LanCertificateRevocationRow.fingerprint == fingerprint
            ))
            if (binding is None or binding.status != "active" or revoked is not None
                    or binding.certificate_der != der
                    or _as_utc(binding.not_before) > now
                    or _as_utc(binding.not_after) <= now
                    or _only_uri_san(cert) != binding.uri_san
                    or binding.uri_san != self._uri(binding.department_id, binding.node_id)):
                raise LanStage1Error("lan_workload_certificate_not_active")
        try:
            verified = self.direct_mtls_verifier.verify_mtls_peer(
                peer_certificate=der
            )
        except ServiceSecurityError as error:
            raise LanStage1Error(error.reason_code) from error
        if (verified.get("spiffe_id") != binding.uri_san
                or verified.get("certificate_fingerprint") != fingerprint):
            raise LanStage1Error("lan_direct_mtls_binding_drift")
        return {
            "workload_identity": f"workload_{binding.node_id}",
            "node_id": binding.node_id, "department_id": binding.department_id,
            "spiffe_id": binding.uri_san, "certificate_fingerprint": fingerprint,
            "not_after": _time(_as_utc(binding.not_after)),
            "production_authorization": False, "release_authorization": False,
        }

    def revoke_certificate(
        self, *, principal: Mapping[str, Any], fingerprint: str,
        reason: str, idempotency_key: str,
    ) -> dict[str, Any]:
        _digest(fingerprint)
        _idempotency(idempotency_key)
        if _single_role(principal) != ROLE_CONTROL_PLANE_ADMIN:
            raise LanStage1Error("lan_certificate_revocation_admin_required")
        if not 8 <= len(reason.strip()) <= 500:
            raise LanStage1Error("lan_reason_invalid")
        now = self.now()
        request_digest = _canonical_digest({"fingerprint": fingerprint, "reason": reason.strip()})
        with self.database.session() as session:
            replay = _command_replay(session, idempotency_key, "revoke_certificate", request_digest)
            if replay is not None:
                return {**replay, "replayed": True}
            binding = session.scalar(select(LanCertificateBindingRow).where(
                LanCertificateBindingRow.fingerprint == fingerprint
            ))
            if binding is None:
                raise LanStage1Error("lan_certificate_binding_not_found")
            revocation_id = _stable_id("cert_revocation_lan", idempotency_key)
            response = {"revocation_id": revocation_id, "fingerprint": fingerprint,
                        "revoked_at": _time(now), "replayed": False,
                        "production_authorization": False, "release_authorization": False}
            session.add(LanCertificateRevocationRow(
                revocation_id=revocation_id, fingerprint=fingerprint,
                reason=reason.strip(), revoked_by_ref=str(principal["human_ref"]),
                idempotency_key=idempotency_key, revoked_at=now,
            ))
            binding.status = "revoked"
            _record_command(session, idempotency_key, "revoke_certificate", request_digest,
                            response, str(principal["human_ref"]), now)
            return response

    def _uri(self, department_id: str, node_id: str) -> str:
        del department_id
        return f"spiffe://{self.trust_domain}/workload/{node_id}"


class LanNodeService:
    def __init__(
        self, database: Database, *, runtime_artifacts: RuntimeArtifactService | None = None,
        bundle_resolver: ArtifactBundleResolver | None = None,
        artifact_download_authority: ArtifactDownloadAuthority | None = None,
        department_device_bundle_resolver: DepartmentDeviceBundleResolver | None = None,
        deployment_release_lock_digest: str | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.database = database
        self.runtime_artifacts = runtime_artifacts
        self.bundle_resolver = bundle_resolver or UnavailableArtifactBundleResolver()
        self.artifact_download_authority = (
            artifact_download_authority or UnavailableArtifactDownloadAuthority()
        )
        self.department_device_bundle_resolver = (
            department_device_bundle_resolver
            or UnavailableDepartmentDeviceBundleResolver()
        )
        if deployment_release_lock_digest is not None:
            _digest(deployment_release_lock_digest)
        self.deployment_release_lock_digest = deployment_release_lock_digest
        self.now = now or _now

    def download_department_device_bundle(
        self, *, principal: Mapping[str, Any], department_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        _department(department_id)
        _idempotency(idempotency_key)
        if (
            _single_role(principal) != ROLE_DEPARTMENT_OWNER
            or principal.get("department_refs") != [department_id]
            or not isinstance(principal.get("human_ref"), str)
        ):
            raise LanStage1Error("lan_department_device_bundle_scope_not_allowed")
        if self.deployment_release_lock_digest is None:
            raise LanStage1Error("lan_deployment_release_lock_required")
        package = self.department_device_bundle_resolver.read_bundle(
            department_id=department_id,
            deployment_release_lock_digest=self.deployment_release_lock_digest,
        )
        metadata = {
            "department_id": department_id,
            "deployment_release_lock_digest": self.deployment_release_lock_digest,
            "bundle_digest": package["bundle_digest"],
            "manifest_digest": package["manifest_digest"],
            "filename": package["filename"],
            "contains_secret": False,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }
        request_digest = _canonical_digest(metadata)
        now = self.now()
        with self.database.session() as session:
            replay = _command_replay(
                session, idempotency_key,
                "download_department_device_bundle", request_digest,
            )
            if replay is None:
                receipt_id = _stable_id(
                    "department_device_download_receipt_lan", idempotency_key
                )
                receipt_document = {
                    **metadata,
                    "receipt_id": receipt_id,
                    "requested_by_ref": str(principal["human_ref"]),
                }
                response = {**metadata, "receipt_id": receipt_id}
                _record_command(
                    session, idempotency_key,
                    "download_department_device_bundle", request_digest,
                    response, str(principal["human_ref"]), now,
                )
                _receipt(
                    session, "lan_department_device_bundle_download",
                    receipt_id,
                    "artifact://department-device-pilot/"
                    f"{department_id}/{package['bundle_digest'].removeprefix('sha256:')}",
                    receipt_document, now,
                )
                _audit(
                    session, "department_device_bundle.downloaded",
                    receipt_id, str(principal["human_ref"]),
                    receipt_document, now,
                )
            else:
                response = replay
                receipt_id = str(replay["receipt_id"])
        return {
            **response,
            "receipt_id": receipt_id,
            "content": package["content"],
        }

    def heartbeat(
        self, *, principal: Mapping[str, Any], node_id: str,
        capability_report_digest: str, status: str,
        document: Mapping[str, Any], idempotency_key: str,
    ) -> dict[str, Any]:
        _node_actor(principal, node_id)
        _digest(capability_report_digest)
        _idempotency(idempotency_key)
        if status not in {"ready", "busy", "degraded", "offline_spooling"}:
            raise LanStage1Error("lan_heartbeat_status_invalid")
        normalized = _normalize(document)
        if normalized.get("production_authorization") is not False or normalized.get("release_authorization") is not False:
            raise LanStage1Error("lan_heartbeat_authority_invalid")
        request_digest = _canonical_digest({"node_id": node_id, "capability_report_digest": capability_report_digest, "status": status, "document": normalized})
        now = self.now()
        with self.database.session() as session:
            replay = _command_replay(session, idempotency_key, "node_heartbeat", request_digest)
            if replay is not None:
                return {**replay, "replayed": True}
            maximum = session.scalar(
                select(func.max(LanNodeHeartbeatRow.sequence)).where(
                    LanNodeHeartbeatRow.node_id == node_id
                )
            )
            sequence = (-1 if maximum is None else int(maximum)) + 1
            heartbeat_id = _stable_id("heartbeat_lan", f"{node_id}:{sequence}")
            response = {"heartbeat_id": heartbeat_id, "sequence": sequence,
                        "recorded_at": _time(now), "replayed": False,
                        "production_authorization": False, "release_authorization": False}
            session.add(LanNodeHeartbeatRow(
                heartbeat_id=heartbeat_id, node_id=node_id,
                department_id=str(principal["department_id"]), sequence=sequence,
                capability_report_digest=capability_report_digest, status=status,
                document=normalized, idempotency_key=idempotency_key, recorded_at=now,
            ))
            _record_command(session, idempotency_key, "node_heartbeat", request_digest,
                            response, str(principal["workload_identity"]), now)
            _receipt(session, "lan_node_heartbeat", heartbeat_id,
                     f"runtime-node://{node_id}", response, now)
            return response

    def open_assisted_maintenance_session(
        self, *, principal: Mapping[str, Any], node_id: str,
        requested_handler_ids: list[str], duration_seconds: int,
        local_user_initiated: bool, idempotency_key: str,
    ) -> dict[str, Any]:
        """Open a node-initiated, outbound-only maintenance window."""
        _node_actor(principal, node_id)
        _idempotency(idempotency_key)
        if local_user_initiated is not True:
            raise LanStage1Error("lan_maintenance_local_initiation_required")
        if not isinstance(duration_seconds, int) or isinstance(duration_seconds, bool) or not 60 <= duration_seconds <= 1800:
            raise LanStage1Error("lan_maintenance_duration_invalid")
        if (
            not isinstance(requested_handler_ids, list)
            or not requested_handler_ids
            or len(requested_handler_ids) > 16
            or len(set(requested_handler_ids)) != len(requested_handler_ids)
            or any(item not in _MAINTENANCE_HANDLERS for item in requested_handler_ids)
        ):
            raise LanStage1Error("lan_maintenance_handler_not_allowed")
        now = self.now()
        expires_at = now + timedelta(seconds=duration_seconds)
        request = {
            "node_id": node_id,
            "department_id": str(principal["department_id"]),
            "certificate_fingerprint": str(principal["certificate_fingerprint"]),
            "allowed_handler_ids": sorted(requested_handler_ids),
            "duration_seconds": duration_seconds,
            "local_user_initiated": True,
        }
        request_digest = _canonical_digest(request)
        with self.database.session() as session:
            replay = _command_replay(
                session, idempotency_key,
                "open_assisted_maintenance_session", request_digest,
            )
            if replay is not None:
                return {**replay, "replayed": True}
            existing = session.scalar(select(LanAssistedMaintenanceSessionRow).where(
                LanAssistedMaintenanceSessionRow.node_id == node_id,
                LanAssistedMaintenanceSessionRow.closed_at.is_(None),
                LanAssistedMaintenanceSessionRow.expires_at > now,
            ))
            if existing is not None:
                if (
                    existing.department_id != principal["department_id"]
                    or existing.certificate_fingerprint
                    != principal["certificate_fingerprint"]
                ):
                    raise LanStage1Error("lan_maintenance_session_already_active")
                if (
                    existing.allowed_handler_ids.get("items")
                    == sorted(requested_handler_ids)
                ):
                    remaining_seconds = max(
                        1,
                        min(
                            duration_seconds,
                            int(
                                (
                                    _as_utc(existing.expires_at) - now
                                ).total_seconds()
                            ),
                        ),
                    )
                    response = {
                        "session_id": existing.session_id,
                        "session_digest": existing.session_digest,
                        "node_id": node_id,
                        "department_id": existing.department_id,
                        "allowed_handler_ids": existing.allowed_handler_ids["items"],
                        "started_at": _time(_as_utc(existing.created_at)),
                        "expires_at": _time(_as_utc(existing.expires_at)),
                        "duration_seconds": int(
                            (_as_utc(existing.expires_at) - _as_utc(existing.created_at)).total_seconds()
                        ),
                        "remaining_seconds": remaining_seconds,
                        "resumed": True, "replayed": False,
                        "runtime_started": False, "model_called": False,
                        "production_authorization": False,
                        "release_authorization": False,
                    }
                    _record_command(
                        session, idempotency_key,
                        "open_assisted_maintenance_session", request_digest,
                        response, str(principal["workload_identity"]), now,
                    )
                    return response
                existing.closed_at = now
                existing.close_reason = "superseded_by_local_user"
                superseded = {
                    "session_id": existing.session_id,
                    "node_id": node_id,
                    "department_id": existing.department_id,
                    "closed_at": _time(now),
                    "close_reason": existing.close_reason,
                    "successor_handler_ids": sorted(requested_handler_ids),
                    "runtime_started": False,
                    "model_called": False,
                    "production_authorization": False,
                    "release_authorization": False,
                }
                _receipt(
                    session, "lan_assisted_maintenance_session_superseded",
                    _stable_id(
                        "receipt_lan",
                        f"{existing.session_id}:superseded:{_time(now)}",
                    ),
                    f"runtime-node://{node_id}",
                    superseded, now,
                )
                _audit(
                    session, "runtime_node.maintenance_session_superseded",
                    existing.session_id,
                    str(principal["workload_identity"]), superseded, now,
                )
            session_id = _stable_id("maintenance_session_lan", idempotency_key)
            session_document = {
                **request,
                "session_id": session_id,
                "started_at": _time(now),
                "expires_at": _time(expires_at),
                "transport": {
                    "direction": "node_outbound_only",
                    "tls_mode": "mutual_tls",
                    "port": 9443,
                    "windows_inbound_listener": False,
                },
                "runtime_started": False,
                "model_called": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            session_digest = _canonical_digest(session_document)
            session.add(LanAssistedMaintenanceSessionRow(
                session_id=session_id, session_digest=session_digest,
                node_id=node_id, department_id=str(principal["department_id"]),
                certificate_fingerprint=str(principal["certificate_fingerprint"]),
                allowed_handler_ids={"items": sorted(requested_handler_ids)},
                idempotency_key=idempotency_key, created_at=now,
                expires_at=expires_at, closed_at=None, close_reason=None,
            ))
            response = {
                "session_id": session_id,
                "session_digest": session_digest,
                "node_id": node_id,
                "department_id": str(principal["department_id"]),
                "allowed_handler_ids": sorted(requested_handler_ids),
                "started_at": _time(now), "expires_at": _time(expires_at),
                "duration_seconds": duration_seconds,
                "remaining_seconds": duration_seconds,
                "resumed": False, "replayed": False,
                "runtime_started": False, "model_called": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            _record_command(
                session, idempotency_key,
                "open_assisted_maintenance_session", request_digest,
                response, str(principal["workload_identity"]), now,
            )
            _receipt(
                session, "lan_assisted_maintenance_session_opened",
                session_id, f"runtime-node://{node_id}", response, now,
            )
            _audit(
                session, "runtime_node.maintenance_session_opened",
                session_id, str(principal["workload_identity"]), response, now,
            )
            return response

    def enqueue_maintenance_job(
        self, *, node_id: str, handler_id: str, asset_name: str,
        asset_digest: str, idempotency_key: str, actor_ref: str,
    ) -> dict[str, Any]:
        """Local Control Plane operator action; never accepts command/args."""
        _node(node_id)
        _digest(asset_digest)
        _idempotency(idempotency_key)
        if not re.fullmatch(r"human_[a-z0-9_:-]{3,150}|operator_[a-z0-9_:-]{3,147}", actor_ref):
            raise LanStage1Error("lan_maintenance_actor_invalid")
        if _MAINTENANCE_HANDLERS.get(handler_id) != asset_name:
            raise LanStage1Error("lan_maintenance_handler_not_allowed")
        now = self.now()
        request = {
            "node_id": node_id, "handler_id": handler_id,
            "asset_name": asset_name, "asset_digest": asset_digest,
        }
        request_digest = _canonical_digest(request)
        with self.database.session() as session:
            replay = _command_replay(
                session, idempotency_key,
                "enqueue_maintenance_job", request_digest,
            )
            if replay is not None:
                return {**replay, "replayed": True}
            active = session.scalar(
                select(LanAssistedMaintenanceSessionRow).where(
                    LanAssistedMaintenanceSessionRow.node_id == node_id,
                    LanAssistedMaintenanceSessionRow.closed_at.is_(None),
                    LanAssistedMaintenanceSessionRow.expires_at > now,
                ).order_by(LanAssistedMaintenanceSessionRow.id.desc())
            )
            if active is None:
                raise LanStage1Error("lan_maintenance_session_not_active")
            allowed = active.allowed_handler_ids.get("items", [])
            if handler_id not in allowed:
                raise LanStage1Error("lan_maintenance_handler_not_allowed")
            expires_at = min(_as_utc(active.expires_at), now + _MAINTENANCE_JOB_MAX)
            nonce_digest = _secret_digest(secrets.token_urlsafe(32))
            job_id = _stable_id("maintenance_job_lan", idempotency_key)
            job_document = {
                "job_id": job_id, "session_id": active.session_id,
                "node_id": node_id, "department_id": active.department_id,
                "handler_id": handler_id, "asset_name": asset_name,
                "asset_ref": f"artifact://lan-bootstrap/{asset_name}",
                "asset_digest": asset_digest, "nonce_digest": nonce_digest,
                "created_at": _time(now), "expires_at": _time(expires_at),
                "synthetic_only": True, "runtime_started": False,
                "model_called": False, "production_authorization": False,
                "release_authorization": False,
            }
            job_digest = _canonical_digest(job_document)
            session.add(LanMaintenanceJobRow(
                job_id=job_id, job_digest=job_digest,
                session_id=active.session_id, node_id=node_id,
                department_id=active.department_id, handler_id=handler_id,
                asset_name=asset_name, asset_digest=asset_digest,
                nonce_digest=nonce_digest, status="queued",
                actor_ref=actor_ref, idempotency_key=idempotency_key,
                created_at=now, expires_at=expires_at,
                claimed_at=None, claimed_by_identity=None,
            ))
            response = {**job_document, "job_digest": job_digest, "replayed": False}
            _record_command(
                session, idempotency_key, "enqueue_maintenance_job",
                request_digest, response, actor_ref, now,
            )
            _audit(
                session, "runtime_node.maintenance_job_enqueued",
                job_id, actor_ref, response, now,
            )
            return response

    def claim_maintenance_job_long_poll(
        self, *, principal: Mapping[str, Any], node_id: str,
        session_id: str, idempotency_key: str, wait_seconds: float,
    ) -> dict[str, Any] | None:
        _node_actor(principal, node_id)
        _idempotency(idempotency_key)
        if not re.fullmatch(r"maintenance_session_lan_[a-f0-9]{32}", session_id):
            raise LanStage1Error("lan_maintenance_session_invalid")
        if not 0 <= wait_seconds <= 25:
            raise LanStage1Error("lan_maintenance_wait_invalid")
        request_digest = _canonical_digest({
            "node_id": node_id, "session_id": session_id,
            "certificate_fingerprint": principal["certificate_fingerprint"],
        })
        deadline = time.monotonic() + wait_seconds
        while True:
            now = self.now()
            with self.database.session() as session:
                replay = _command_replay(
                    session, idempotency_key,
                    "claim_maintenance_job", request_digest,
                )
                if replay is not None:
                    return {**replay, "replayed": True}
                active = session.scalar(select(LanAssistedMaintenanceSessionRow).where(
                    LanAssistedMaintenanceSessionRow.session_id == session_id,
                    LanAssistedMaintenanceSessionRow.node_id == node_id,
                    LanAssistedMaintenanceSessionRow.department_id == principal["department_id"],
                    LanAssistedMaintenanceSessionRow.certificate_fingerprint == principal["certificate_fingerprint"],
                    LanAssistedMaintenanceSessionRow.closed_at.is_(None),
                    LanAssistedMaintenanceSessionRow.expires_at > now,
                ))
                if active is None:
                    raise LanStage1Error("lan_maintenance_session_not_active")
                job = session.scalar(
                    select(LanMaintenanceJobRow).where(
                        LanMaintenanceJobRow.session_id == session_id,
                        LanMaintenanceJobRow.node_id == node_id,
                        LanMaintenanceJobRow.status == "queued",
                        LanMaintenanceJobRow.expires_at > now,
                    ).order_by(LanMaintenanceJobRow.id).with_for_update(skip_locked=True)
                )
                if job is not None:
                    job.status = "claimed"
                    job.claimed_at = now
                    job.claimed_by_identity = str(principal["workload_identity"])
                    response = self._maintenance_job_projection(job)
                    _receipt(
                        session, "lan_maintenance_job_claimed", job.job_id,
                        f"runtime-node://{node_id}", response, now,
                    )
                    _record_command(
                        session, idempotency_key, "claim_maintenance_job",
                        request_digest, response,
                        str(principal["workload_identity"]), now,
                    )
                    return response
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(0.25, remaining))

    def record_maintenance_receipt(
        self, *, principal: Mapping[str, Any], node_id: str,
        job_id: str, document: Mapping[str, Any], idempotency_key: str,
    ) -> dict[str, Any]:
        _node_actor(principal, node_id)
        _idempotency(idempotency_key)
        normalized = _normalize(document)
        required = {
            "session_id", "job_digest", "handler_id", "asset_digest",
            "started_at", "completed_at", "outcome", "reason_code",
            "sanitized_summary", "output_digest", "output_truncated",
            "runtime_started", "model_called", "production_authorization",
            "release_authorization",
        }
        _exact_keys(normalized, required, "lan_maintenance_receipt_invalid")
        started_at = _parse_date_time(normalized["started_at"])
        completed_at = _parse_date_time(normalized["completed_at"])
        if (
            normalized["outcome"] not in _MAINTENANCE_OUTCOMES
            or not re.fullmatch(r"[a-z][a-z0-9_]{2,95}", str(normalized["reason_code"]))
            or not isinstance(normalized["sanitized_summary"], str)
            or not 1 <= len(normalized["sanitized_summary"]) <= 2000
            or any(token in normalized["sanitized_summary"].lower() for token in (
                "-----begin", "enrollment code", "api_key", "authorization:",
                "c:\\users\\", "/home/", "sk-",
            ))
            or re.search(
                r"[A-Za-z]:\\|/(?:home|opt|Users)/",
                normalized["sanitized_summary"], re.IGNORECASE,
            ) is not None
            or normalized["output_truncated"] not in {True, False}
            or normalized["runtime_started"] is not False
            or normalized["model_called"] is not False
            or normalized["production_authorization"] is not False
            or normalized["release_authorization"] is not False
            or started_at is None
            or completed_at is None
        ):
            raise LanStage1Error("lan_maintenance_receipt_invalid")
        for field in ("job_digest", "asset_digest", "output_digest"):
            _digest(str(normalized[field]))
        request_digest = _canonical_digest({"node_id": node_id, "job_id": job_id, "document": normalized})
        now = self.now()
        with self.database.session() as session:
            replay = _command_replay(
                session, idempotency_key,
                "record_maintenance_receipt", request_digest,
            )
            if replay is not None:
                return {**replay, "replayed": True}
            job = session.scalar(select(LanMaintenanceJobRow).where(
                LanMaintenanceJobRow.job_id == job_id
            ))
            if (
                job is None or job.status != "claimed"
                or job.node_id != node_id
                or job.department_id != principal["department_id"]
                or job.session_id != normalized["session_id"]
                or job.job_digest != normalized["job_digest"]
                or job.handler_id != normalized["handler_id"]
                or job.asset_digest != normalized["asset_digest"]
                or job.claimed_by_identity != principal["workload_identity"]
            ):
                raise LanStage1Error("lan_maintenance_receipt_binding_drift")
            clock_skew = timedelta(minutes=5)
            if (
                started_at < _as_utc(job.created_at) - clock_skew
                or started_at > _as_utc(job.expires_at) + clock_skew
                or completed_at < started_at
                or completed_at > _as_utc(job.expires_at) + clock_skew
                or completed_at > now + clock_skew
            ):
                raise LanStage1Error("lan_maintenance_receipt_time_invalid")
            if session.scalar(select(LanMaintenanceReceiptRow).where(
                LanMaintenanceReceiptRow.job_id == job_id
            )) is not None:
                raise LanStage1Error("lan_maintenance_receipt_conflict")
            receipt_id = _stable_id("maintenance_receipt_lan", idempotency_key)
            receipt_document = {
                **normalized, "receipt_id": receipt_id, "job_id": job_id,
                "node_id": node_id, "department_id": job.department_id,
                "recorded_at": _time(now),
            }
            receipt_digest = _canonical_digest(receipt_document)
            receipt_document["receipt_digest"] = receipt_digest
            session.add(LanMaintenanceReceiptRow(
                receipt_id=receipt_id, receipt_digest=receipt_digest,
                session_id=job.session_id, job_id=job_id,
                job_digest=job.job_digest, node_id=node_id,
                department_id=job.department_id, handler_id=job.handler_id,
                asset_digest=job.asset_digest, outcome=str(normalized["outcome"]),
                reason_code=str(normalized["reason_code"]),
                sanitized_summary=str(normalized["sanitized_summary"]),
                output_digest=str(normalized["output_digest"]),
                output_truncated=bool(normalized["output_truncated"]),
                document=receipt_document, idempotency_key=idempotency_key,
                recorded_at=now,
            ))
            job.status = "completed" if normalized["outcome"] == "succeeded" else "failed"
            response = {
                "receipt_id": receipt_id, "receipt_digest": receipt_digest,
                "job_id": job_id, "outcome": normalized["outcome"],
                "reason_code": normalized["reason_code"], "replayed": False,
                "runtime_started": False, "model_called": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            _record_command(
                session, idempotency_key, "record_maintenance_receipt",
                request_digest, response, str(principal["workload_identity"]), now,
            )
            _receipt(
                session, "lan_maintenance_job_result", receipt_id,
                f"runtime-node://{node_id}", receipt_document, now,
            )
            _audit(
                session, "runtime_node.maintenance_job_recorded",
                receipt_id, str(principal["workload_identity"]),
                receipt_document, now,
            )
            return response

    def maintenance_status(self, *, node_id: str | None = None) -> dict[str, Any]:
        if node_id is not None:
            _node(node_id)
        now = self.now()
        with self.database.session() as session:
            session_query = select(LanAssistedMaintenanceSessionRow)
            job_query = select(LanMaintenanceJobRow)
            receipt_query = select(LanMaintenanceReceiptRow)
            if node_id is not None:
                session_query = session_query.where(LanAssistedMaintenanceSessionRow.node_id == node_id)
                job_query = job_query.where(LanMaintenanceJobRow.node_id == node_id)
                receipt_query = receipt_query.where(LanMaintenanceReceiptRow.node_id == node_id)
            sessions = tuple(session.scalars(session_query.order_by(LanAssistedMaintenanceSessionRow.id.desc()).limit(20)))
            jobs = tuple(session.scalars(job_query.order_by(LanMaintenanceJobRow.id.desc()).limit(50)))
            receipts = tuple(session.scalars(receipt_query.order_by(LanMaintenanceReceiptRow.id.desc()).limit(50)))
        return {
            "observed_at": _time(now),
            "sessions": [
                {
                    "session_id": row.session_id, "session_digest": row.session_digest,
                    "node_id": row.node_id, "department_id": row.department_id,
                    "allowed_handler_ids": row.allowed_handler_ids.get("items", []),
                    "created_at": _time(_as_utc(row.created_at)),
                    "expires_at": _time(_as_utc(row.expires_at)),
                    "active": row.closed_at is None and _as_utc(row.expires_at) > now,
                }
                for row in sessions
            ],
            "jobs": [self._maintenance_job_projection(row) | {"status": row.status} for row in jobs],
            "receipts": [dict(row.document) for row in receipts],
            "runtime_started": False, "model_called": False,
            "production_authorization": False, "release_authorization": False,
        }

    @staticmethod
    def _maintenance_job_projection(row: LanMaintenanceJobRow) -> dict[str, Any]:
        return {
            "job_id": row.job_id, "job_digest": row.job_digest,
            "session_id": row.session_id, "node_id": row.node_id,
            "department_id": row.department_id, "handler_id": row.handler_id,
            "asset_name": row.asset_name,
            "asset_ref": f"artifact://lan-bootstrap/{row.asset_name}",
            "asset_digest": row.asset_digest, "nonce_digest": row.nonce_digest,
            "created_at": _time(_as_utc(row.created_at)),
            "expires_at": _time(_as_utc(row.expires_at)),
            "synthetic_only": True, "runtime_started": False,
            "model_called": False, "production_authorization": False,
            "release_authorization": False,
        }

    def create_deployment_release_lock(
        self, *, principal: Mapping[str, Any], document: Mapping[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        if _single_role(principal) != ROLE_CONTROL_PLANE_ADMIN:
            raise LanStage1Error("lan_deployment_release_lock_admin_required")
        _idempotency(idempotency_key)
        normalized = _validate_deployment_release_lock(document)
        metadata = normalized["metadata"]
        spec = normalized["spec"]
        commits = {
            item["repository_role"]: item["commit_sha"]
            for item in spec["repository_commits"]
        }
        request_digest = _canonical_digest(normalized)
        now = self.now()
        with self.database.session() as session:
            replay = _command_replay(
                session, idempotency_key,
                "create_deployment_release_lock", request_digest,
            )
            if replay is not None:
                return {**replay, "replayed": True}
            if session.scalar(select(LanDeploymentReleaseLockRow).where(
                (LanDeploymentReleaseLockRow.lock_id == metadata["lock_id"])
                | (LanDeploymentReleaseLockRow.lock_digest == spec["lock_digest"])
            )) is not None:
                raise LanStage1Error("lan_deployment_release_lock_conflict")
            row = LanDeploymentReleaseLockRow(
                lock_id=metadata["lock_id"], lock_digest=spec["lock_digest"],
                architecture_commit=commits["architecture"],
                control_plane_commit=commits["control_plane"],
                department_cockpit_commit=commits["department_cockpit"],
                semantic_authority_release_id=spec["architecture_authority"]["release_id"],
                semantic_authority_manifest_digest=spec["architecture_authority"]["release_manifest_digest"],
                status="candidate", document=normalized,
                created_by_ref=str(principal["human_ref"]),
                idempotency_key=idempotency_key, created_at=now,
            )
            session.add(row)
            response = {
                "deployment_release_lock": {
                    "lock_id": metadata["lock_id"],
                    "lock_digest": spec["lock_digest"],
                    "status": "candidate",
                    "authority_claim": "none",
                    "deployment_activated": False,
                    "release_authorization": False,
                },
                "replayed": False,
            }
            _record_command(
                session, idempotency_key, "create_deployment_release_lock",
                request_digest, response, str(principal["human_ref"]), now,
            )
            _receipt(
                session, "lan_deployment_release_lock_candidate",
                metadata["lock_id"],
                f"deployment-release-lock://{metadata['lock_id']}",
                response["deployment_release_lock"], now,
            )
            return response

    def create_artifact_download_assignment(
        self, *, principal: Mapping[str, Any], department_id: str,
        artifact_id: str, revision_digest: str, bundle_digest: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        if _single_role(principal) != ROLE_CONTROL_PLANE_ADMIN:
            raise LanStage1Error("lan_artifact_assignment_admin_required")
        _department(department_id)
        _digest(revision_digest)
        _digest(bundle_digest)
        _idempotency(idempotency_key)
        if not re.fullmatch(r"[a-z][a-z0-9_-]{2,159}", artifact_id):
            raise LanStage1Error("lan_artifact_id_invalid")
        request = {"department_id": department_id, "artifact_id": artifact_id,
                   "revision_digest": revision_digest, "bundle_digest": bundle_digest}
        request_digest = _canonical_digest(request)
        now = self.now()
        with self.database.session() as session:
            replay = _command_replay(session, idempotency_key, "create_artifact_assignment", request_digest)
            if replay is not None:
                return {**replay, "replayed": True}
            existing = session.scalar(select(LanArtifactDownloadAssignmentRow).where(
                LanArtifactDownloadAssignmentRow.department_id == department_id,
                LanArtifactDownloadAssignmentRow.artifact_id == artifact_id,
                LanArtifactDownloadAssignmentRow.revision_digest == revision_digest,
            ))
            if existing is not None:
                raise LanStage1Error("lan_artifact_assignment_conflict")
            lock_id = _stable_id("artifact_assignment_lan", idempotency_key)
            document = {**request, "assignment_id": lock_id, "status": "d0_assigned",
                        "is_deployment_release_lock": False,
                        "synthetic_only": True, "production_authorization": False,
                        "release_authorization": False}
            response = {"artifact_download_assignment": document, "replayed": False}
            session.add(LanArtifactDownloadAssignmentRow(
                assignment_id=lock_id, department_id=department_id, artifact_id=artifact_id,
                revision_digest=revision_digest, bundle_digest=bundle_digest,
                status="d0_assigned", created_by_ref=str(principal["human_ref"]),
                idempotency_key=idempotency_key, document=document,
                created_at=now, revoked_at=None,
            ))
            _record_command(session, idempotency_key, "create_artifact_assignment", request_digest,
                            response, str(principal["human_ref"]), now)
            _receipt(session, "lan_artifact_download_assignment", lock_id,
                     f"runtime-artifact://{artifact_id}/{revision_digest}", document, now)
            return response

    def current_artifact_download_assignment(
        self, *, principal: Mapping[str, Any], node_id: str
    ) -> dict[str, Any] | None:
        """Return the latest active, qualified assignment for one mTLS node.

        The response is deliberately smaller than the administrator record. It
        contains no creator identity, host path, provider detail, certificate
        material, or release-lock internals. The download authority is checked
        here as well as on the byte endpoint so an offline or drifted node never
        learns a usable assignment and only then fails at download time.
        """

        _node_actor(principal, node_id)
        department_id = str(principal["department_id"])
        with self.database.session() as session:
            assignment = session.scalar(
                select(LanArtifactDownloadAssignmentRow)
                .where(
                    LanArtifactDownloadAssignmentRow.department_id
                    == department_id,
                    LanArtifactDownloadAssignmentRow.status == "d0_assigned",
                    LanArtifactDownloadAssignmentRow.revoked_at.is_(None),
                )
                .order_by(LanArtifactDownloadAssignmentRow.id.desc())
                .limit(1)
            )
        if assignment is None:
            return None
        if self.runtime_artifacts is None:
            raise LanStage1Error("lan_runtime_artifact_qualification_required")
        try:
            revision = self.runtime_artifacts.revision(
                artifact_id=assignment.artifact_id,
                revision_digest=assignment.revision_digest,
            )
        except RuntimeArtifactError as error:
            raise LanStage1Error(error.reason_code) from error
        if (
            revision.get("status") != "qualified_d0"
            or revision.get("revoked") is not False
        ):
            raise LanStage1Error("lan_runtime_artifact_not_qualified")
        self.artifact_download_authority.authorize_download(
            department_id=department_id,
            node_id=node_id,
            artifact_id=assignment.artifact_id,
            revision_digest=assignment.revision_digest,
            bundle_digest=assignment.bundle_digest,
        )
        return {
            "node_id": node_id,
            "department_id": department_id,
            "artifact_id": assignment.artifact_id,
            "revision_digest": assignment.revision_digest,
            "bundle_digest": assignment.bundle_digest,
            "download_idempotency": {
                "required": True,
                "key_prefix": (
                    f"artifact-download:{assignment.assignment_id}:{node_id}"
                ),
                "range_resume_supported": True,
                "etag": assignment.bundle_digest,
            },
        }

    def download(
        self, *, principal: Mapping[str, Any], node_id: str, artifact_id: str,
        revision_digest: str, range_header: str | None,
        idempotency_key: str,
    ) -> dict[str, Any]:
        _node_actor(principal, node_id)
        _digest(revision_digest)
        _idempotency(idempotency_key)
        department_id = str(principal["department_id"])
        with self.database.session() as session:
            lock = session.scalar(select(LanArtifactDownloadAssignmentRow).where(
                LanArtifactDownloadAssignmentRow.department_id == department_id,
                LanArtifactDownloadAssignmentRow.artifact_id == artifact_id,
                LanArtifactDownloadAssignmentRow.revision_digest == revision_digest,
                LanArtifactDownloadAssignmentRow.status == "d0_assigned",
                LanArtifactDownloadAssignmentRow.revoked_at.is_(None),
            ))
            if lock is None:
                raise LanStage1Error("lan_artifact_not_authorized")
            bundle_digest = lock.bundle_digest
        if self.runtime_artifacts is None:
            raise LanStage1Error("lan_runtime_artifact_qualification_required")
        try:
            revision = self.runtime_artifacts.revision(
                artifact_id=artifact_id, revision_digest=revision_digest
            )
        except RuntimeArtifactError as error:
            raise LanStage1Error(error.reason_code) from error
        if revision.get("status") != "qualified_d0" or revision.get("revoked") is not False:
            raise LanStage1Error("lan_runtime_artifact_not_qualified")
        self.artifact_download_authority.authorize_download(
            department_id=department_id, node_id=node_id,
            artifact_id=artifact_id, revision_digest=revision_digest,
            bundle_digest=bundle_digest,
        )
        content = self.bundle_resolver.read_bundle(
            artifact_id=artifact_id, revision_digest=revision_digest,
            bundle_digest=bundle_digest,
        )
        if not isinstance(content, bytes) or not content:
            raise LanStage1Error("lan_artifact_bundle_invalid")
        actual = "sha256:" + hashlib.sha256(content).hexdigest()
        if actual != bundle_digest:
            raise LanStage1Error("lan_artifact_bundle_digest_drift")
        start, end, partial = _byte_range(range_header, len(content))
        selected = content[start:end + 1]
        etag = f'"{bundle_digest}"'
        request_digest = _canonical_digest({"node_id": node_id, "artifact_id": artifact_id,
            "revision_digest": revision_digest, "range_start": start, "range_end": end})
        now = self.now()
        with self.database.session() as session:
            replay = session.scalar(select(LanArtifactDownloadReceiptRow).where(
                LanArtifactDownloadReceiptRow.idempotency_key == idempotency_key
            ))
            if replay is not None:
                if replay.node_id != node_id or replay.artifact_id != artifact_id or replay.revision_digest != revision_digest or replay.range_start != start or replay.range_end != end:
                    raise LanStage1Error("lan_download_idempotency_conflict")
                receipt_id = replay.receipt_id
            else:
                receipt_id = _stable_id("download_receipt_lan", idempotency_key)
                session.add(LanArtifactDownloadReceiptRow(
                    receipt_id=receipt_id, node_id=node_id, department_id=department_id,
                    artifact_id=artifact_id, revision_digest=revision_digest,
                    bundle_digest=bundle_digest, etag=etag, range_start=start,
                    range_end=end, total_size=len(content), completed=not partial,
                    idempotency_key=idempotency_key, recorded_at=now,
                ))
                document = {"receipt_id": receipt_id, "node_id": node_id,
                    "artifact_id": artifact_id, "revision_digest": revision_digest,
                    "bundle_digest": bundle_digest, "range_start": start,
                    "range_end": end, "total_size": len(content),
                    "completed": not partial, "request_digest": request_digest,
                    "production_authorization": False, "release_authorization": False}
                _receipt(session, "lan_artifact_download", receipt_id,
                         f"runtime-artifact://{artifact_id}/{revision_digest}", document, now)
        return {"content": selected, "status_code": 206 if partial else 200,
                "etag": etag, "content_range": f"bytes {start}-{end}/{len(content)}" if partial else None,
                "total_size": len(content), "receipt_id": receipt_id,
                "bundle_digest": bundle_digest}

    def claim_lease_long_poll(
        self, *, principal: Mapping[str, Any], node_id: str,
        expected_capability_report_digest: str, idempotency_key: str,
        wait_seconds: float,
    ) -> dict[str, Any] | None:
        _node_actor(principal, node_id)
        if self.runtime_artifacts is None:
            raise LanStage1Error("lan_runtime_queue_unavailable")
        if not 0 <= wait_seconds <= 25:
            raise LanStage1Error("lan_lease_wait_invalid")
        deadline = time.monotonic() + wait_seconds
        attempt = 0
        while True:
            try:
                result = self.runtime_artifacts.claim_lease(
                    node_id=node_id,
                    expected_capability_report_digest=expected_capability_report_digest,
                    idempotency_key=idempotency_key,
                    workload_identity=str(principal["workload_identity"]),
                )
            except RuntimeArtifactError as error:
                raise LanStage1Error(error.reason_code) from error
            if result.get("claimed"):
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(0.25, remaining))
            attempt += 1


class OfflineReceiptSpool:
    """Owner-only JSONL spool with hard record and byte caps."""

    def __init__(self, path: Path, *, max_records: int = 1000,
                 max_bytes: int = 10 * 1024 * 1024) -> None:
        if not path.is_absolute() or max_records != 1000 or max_bytes != 10 * 1024 * 1024:
            raise LanStage1Error("lan_receipt_spool_configuration_invalid")
        self.path = path
        self.max_records = max_records
        self.max_bytes = max_bytes

    def append(self, receipt: Mapping[str, Any]) -> None:
        normalized = _normalize(receipt)
        if normalized.get("production_authorization") is not False or normalized.get("release_authorization") is not False:
            raise LanStage1Error("lan_receipt_spool_authority_invalid")
        encoded = json.dumps(normalized, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode() + b"\n"
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        if self.path.exists():
            info = self.path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise LanStage1Error("lan_receipt_spool_file_invalid")
            current = self.path.read_bytes()
        else:
            current = b""
        count = current.count(b"\n")
        if count >= self.max_records or len(current) + len(encoded) > self.max_bytes:
            raise LanStage1Error("lan_receipt_spool_capacity_exceeded")
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _new_account(*, username: str, display_name: str, password_hash: str,
                 role_ref: str, department_id: str | None, status: str,
                 approved_by_ref: str | None,
                 now: datetime) -> LanHumanAccountRow:
    suffix = hashlib.sha256(username.encode()).hexdigest()[:24]
    return LanHumanAccountRow(
        account_id=f"acct_lan_{suffix}_syn", username=username,
        display_name=display_name, human_ref=f"human_lan_{suffix}_syn",
        password_hash=password_hash, role_ref=role_ref,
        department_id=department_id, status=status, failed_login_count=0,
        failed_window_started_at=None, locked_until=None, created_at=now,
        approved_by_ref=approved_by_ref,
        approved_at=now if approved_by_ref is not None else None,
    )


def _validate_p256_csr(value: bytes) -> x509.CertificateSigningRequest:
    if not isinstance(value, bytes) or not 1 <= len(value) <= 64 * 1024:
        raise LanStage1Error("lan_csr_invalid")
    try:
        csr = x509.load_pem_x509_csr(value)
    except ValueError as error:
        raise LanStage1Error("lan_csr_invalid") from error
    if not csr.is_signature_valid:
        raise LanStage1Error("lan_csr_signature_invalid")
    key = csr.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise LanStage1Error("lan_csr_key_must_be_p256")
    _only_uri_san(csr)
    return csr


def _validate_issued_certificate(
    value: bytes, *, csr: x509.CertificateSigningRequest,
    uri_san: str, now: datetime,
) -> x509.Certificate:
    try:
        cert = x509.load_der_x509_certificate(value)
        usages = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except (ValueError, x509.ExtensionNotFound) as error:
        raise LanStage1Error("lan_issued_certificate_invalid") from error
    cert_key = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    csr_key = csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if (cert_key != csr_key or _only_uri_san(cert) != uri_san or constraints.ca
            or ExtendedKeyUsageOID.CLIENT_AUTH not in usages
            or cert.not_valid_before_utc > now + timedelta(minutes=1)
            or cert.not_valid_after_utc <= now
            or cert.not_valid_after_utc - cert.not_valid_before_utc > _CERT_TTL):
        raise LanStage1Error("lan_issued_certificate_binding_invalid")
    return cert


def _certificate_signature_valid(
    certificate: x509.Certificate, ca: x509.Certificate
) -> bool:
    key = ca.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes,
                       padding.PKCS1v15(), certificate.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes,
                       ec.ECDSA(certificate.signature_hash_algorithm))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes)
        else:
            return False
    except InvalidSignature:
        return False
    return True


def _only_uri_san(value: Any) -> str:
    try:
        names = value.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as error:
        raise LanStage1Error("lan_uri_san_required") from error
    uris = tuple(str(item) for item in names.get_values_for_type(x509.UniformResourceIdentifier))
    if len(uris) != 1 or len(names) != 1:
        raise LanStage1Error("lan_uri_san_invalid")
    return uris[0]


def _byte_range(value: str | None, size: int) -> tuple[int, int, bool]:
    if value is None:
        return 0, size - 1, False
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value)
    if match is None or (not match.group(1) and not match.group(2)):
        raise LanStage1Error("lan_artifact_range_invalid")
    if not match.group(1):
        length = int(match.group(2))
        if not 1 <= length <= size:
            raise LanStage1Error("lan_artifact_range_unsatisfiable")
        start, end = size - length, size - 1
    else:
        start = int(match.group(1))
        end = size - 1 if not match.group(2) else int(match.group(2))
        if start >= size or end < start or end >= size:
            raise LanStage1Error("lan_artifact_range_unsatisfiable")
    return start, end, True


def _node_actor(principal: Mapping[str, Any], node_id: str) -> None:
    _node(node_id)
    if principal.get("node_id") != node_id or principal.get("workload_identity") != f"workload_{node_id}" or principal.get("department_id") not in DEPARTMENTS:
        raise LanStage1Error("lan_node_scope_not_allowed")


def _record_command(session: Any, key: str, operation: str, digest: str,
                    response: Mapping[str, Any], actor: str, now: datetime) -> None:
    session.add(LanMutationCommandRow(
        idempotency_key=key, operation=operation, request_digest=digest,
        response_document=dict(response), actor_ref=actor, recorded_at=now,
    ))


def _command_replay(session: Any, key: str, operation: str,
                    digest: str, *, actor_ref: str | None = None) -> dict[str, Any] | None:
    row = session.scalar(select(LanMutationCommandRow).where(
        LanMutationCommandRow.idempotency_key == key
    ))
    if row is None:
        return None
    if (row.operation != operation or row.request_digest != digest
            or (actor_ref is not None and row.actor_ref != actor_ref)):
        raise LanStage1Error("lan_idempotency_conflict")
    return dict(row.response_document)


def _receipt(session: Any, receipt_type: str, receipt_id: str,
             subject_ref: str, document: Mapping[str, Any], now: datetime) -> None:
    session.add(ReceiptRow(receipt_id=receipt_id, receipt_type=receipt_type,
        receipt_digest=_canonical_digest(document), subject_ref=subject_ref,
        document=dict(document), recorded_at=now))


def _audit(session: Any, event_type: str, correlation_id: str,
           actor_ref: str, payload: Mapping[str, Any], now: datetime) -> None:
    document = {**dict(payload), "production_authorization": False,
                "release_authorization": False}
    session.add(AuditEventRow(
        audit_id=_stable_id("audit_lan", f"{event_type}:{correlation_id}:{actor_ref}:{_time(now)}"),
        correlation_id=correlation_id, event_type=event_type,
        actor_ref=actor_ref, payload=document, recorded_at=now,
    ))


def _normalize(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError) as error:
        raise LanStage1Error("lan_document_invalid") from error


def _strict_json_document(raw: bytes) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise LanStage1Error("lan_department_device_bundle_duplicate_key")
            value[key] = item
        return value

    def reject_constant(_: str) -> None:
        raise LanStage1Error("lan_department_device_bundle_json_constant_invalid")

    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
    )
    if not isinstance(value, dict):
        raise LanStage1Error("lan_department_device_bundle_manifest_invalid")
    return value


def _validate_deployment_release_lock(value: Mapping[str, Any]) -> dict[str, Any]:
    document = _normalize(value)
    _exact_keys(
        document,
        {"api_version", "kind", "metadata", "spec", "authority_boundary"},
        "lan_deployment_release_lock_invalid",
    )
    if (
        document.get("api_version") != "company-ai-os/v1alpha3-draft"
        or document.get("kind") != "DeploymentReleaseLock"
    ):
        raise LanStage1Error("lan_deployment_release_lock_invalid")
    metadata = document.get("metadata")
    spec = document.get("spec")
    boundary = document.get("authority_boundary")
    if not all(isinstance(item, dict) for item in (metadata, spec, boundary)):
        raise LanStage1Error("lan_deployment_release_lock_invalid")
    _exact_keys(
        metadata,
        {"lock_id", "version", "revision", "status", "evidence_status", "synthetic_only", "created_at"},
        "lan_deployment_release_lock_invalid",
    )
    if (
        not isinstance(metadata["lock_id"], str)
        or not re.fullmatch(r"[a-z][a-z0-9_:-]{2,127}", metadata["lock_id"])
        or not isinstance(metadata["version"], str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", metadata["version"])
        or not isinstance(metadata["revision"], int)
        or isinstance(metadata["revision"], bool)
        or metadata["revision"] < 1
        or metadata["status"] != "candidate"
        or metadata["evidence_status"] not in {"architecture_reference", "synthetic_d0"}
        or metadata["synthetic_only"] is not True
        or not _date_time(metadata["created_at"])
    ):
        raise LanStage1Error("lan_deployment_release_lock_invalid")
    _exact_keys(
        spec,
        {
            "architecture_authority", "repository_commits", "build_bundle",
            "installer_bundle", "lan_service_profile_ref",
            "lan_service_profile_digest", "runtime_artifacts", "lock_digest",
        },
        "lan_deployment_release_lock_invalid",
    )
    architecture = spec["architecture_authority"]
    _exact_keys(
        architecture,
        {"release_id", "release_manifest_ref", "release_manifest_digest", "repository_commit"},
        "lan_deployment_release_lock_invalid",
    )
    if (
        not re.fullmatch(
            r"semantic-authority-v[0-9]+\.[0-9]+\.[0-9]+-alpha\.[0-9]+",
            str(architecture["release_id"]),
        )
        or not _artifact_ref(architecture["release_manifest_ref"])
        or not _is_digest(architecture["release_manifest_digest"])
        or not _is_commit(architecture["repository_commit"])
    ):
        raise LanStage1Error("lan_deployment_release_lock_invalid")
    repositories = spec["repository_commits"]
    if not isinstance(repositories, list) or len(repositories) != 3:
        raise LanStage1Error("lan_deployment_release_lock_repository_invalid")
    repository_roles: dict[str, dict[str, Any]] = {}
    for item in repositories:
        _exact_keys(
            item,
            {"repository_role", "repository_id", "commit_sha", "source_tree_digest"},
            "lan_deployment_release_lock_repository_invalid",
        )
        role = item["repository_role"]
        if (
            role not in {"architecture", "control_plane", "department_cockpit"}
            or role in repository_roles
            or not isinstance(item["repository_id"], str)
            or not re.fullmatch(r"[a-z][a-z0-9_:-]{2,127}", item["repository_id"])
            or not _is_commit(item["commit_sha"])
            or not _is_digest(item["source_tree_digest"])
        ):
            raise LanStage1Error("lan_deployment_release_lock_repository_invalid")
        repository_roles[role] = item
    if (
        set(repository_roles) != {"architecture", "control_plane", "department_cockpit"}
        or repository_roles["architecture"]["commit_sha"] != architecture["repository_commit"]
        or len({item["commit_sha"] for item in repositories}) != 3
        or len({item["source_tree_digest"] for item in repositories}) != 3
    ):
        raise LanStage1Error("lan_deployment_release_lock_repository_invalid")
    _validate_bundle(spec["build_bundle"], build=True)
    _validate_bundle(spec["installer_bundle"], build=False)
    profile_ref = spec["lan_service_profile_ref"]
    _validate_versioned_ref(profile_ref)
    if (
        not _is_digest(spec["lan_service_profile_digest"])
        or profile_ref["digest"] != spec["lan_service_profile_digest"]
    ):
        raise LanStage1Error("lan_deployment_release_lock_profile_invalid")
    artifacts = spec["runtime_artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise LanStage1Error("lan_deployment_release_lock_artifact_invalid")
    artifact_keys: set[tuple[str, str]] = set()
    for item in artifacts:
        _exact_keys(
            item,
            {
                "runtime_family", "runtime_artifact_ref",
                "runtime_artifact_manifest_digest", "runtime_source_digest",
                "runtime_image_manifest_digest",
            },
            "lan_deployment_release_lock_artifact_invalid",
        )
        reference = item["runtime_artifact_ref"]
        _validate_versioned_ref(reference)
        digests = (
            item["runtime_artifact_manifest_digest"],
            item["runtime_source_digest"], item["runtime_image_manifest_digest"],
        )
        key = (reference["id"], reference["digest"])
        if (
            item["runtime_family"] not in {"hermes", "codex"}
            or not all(_is_digest(digest) for digest in digests)
            or reference["digest"] != item["runtime_artifact_manifest_digest"]
            or len(set(digests)) != 3
            or key in artifact_keys
        ):
            raise LanStage1Error("lan_deployment_release_lock_artifact_invalid")
        artifact_keys.add(key)
    _exact_keys(
        boundary,
        {
            "approval_created", "execution_grant_issued", "worker_lease_issued",
            "qualification_conferred", "deployment_activated", "runtime_started",
            "contract_published", "production_authorized", "release_authorization",
        },
        "lan_deployment_release_lock_authority_invalid",
    )
    if any(item is not False for item in boundary.values()):
        raise LanStage1Error("lan_deployment_release_lock_authority_invalid")
    if not _is_digest(spec["lock_digest"]):
        raise LanStage1Error("lan_deployment_release_lock_digest_invalid")
    critical_digests = [
        architecture["release_manifest_digest"],
        *(item["source_tree_digest"] for item in repositories),
        spec["build_bundle"]["bundle_digest"],
        spec["build_bundle"]["manifest_digest"],
        spec["build_bundle"]["provenance_digest"],
        spec["installer_bundle"]["bundle_digest"],
        spec["installer_bundle"]["manifest_digest"],
        spec["lan_service_profile_digest"],
        *(
            digest
            for item in artifacts
            for digest in (
                item["runtime_artifact_manifest_digest"],
                item["runtime_source_digest"],
                item["runtime_image_manifest_digest"],
            )
        ),
        spec["lock_digest"],
    ]
    if len(set(critical_digests)) != len(critical_digests):
        raise LanStage1Error("lan_deployment_release_lock_digest_role_reused")
    digest_candidate = json.loads(json.dumps(document))
    del digest_candidate["spec"]["lock_digest"]
    if not hmac.compare_digest(
        spec["lock_digest"], _canonical_digest(digest_candidate)
    ):
        raise LanStage1Error("lan_deployment_release_lock_digest_invalid")
    return document


def _lock_contains_artifact(
    document: Mapping[str, Any], *, artifact_id: str, revision_digest: str,
) -> bool:
    try:
        validated = _validate_deployment_release_lock(document)
    except LanStage1Error:
        return False
    return any(
        item["runtime_artifact_ref"]["id"] == artifact_id
        and item["runtime_artifact_manifest_digest"] == revision_digest
        for item in validated["spec"]["runtime_artifacts"]
    )


def _validate_bundle(value: Any, *, build: bool) -> None:
    required = (
        {"manifest_ref", "bundle_digest", "manifest_digest", "provenance_digest"}
        if build
        else {"bundle_ref", "bundle_digest", "manifest_digest"}
    )
    _exact_keys(value, required, "lan_deployment_release_lock_bundle_invalid")
    reference_key = "manifest_ref" if build else "bundle_ref"
    digest_keys = required - {reference_key}
    if not _artifact_ref(value[reference_key]) or not all(
        _is_digest(value[key]) for key in digest_keys
    ):
        raise LanStage1Error("lan_deployment_release_lock_bundle_invalid")


def _validate_versioned_ref(value: Any) -> None:
    _exact_keys(
        value, {"id", "version", "digest"},
        "lan_deployment_release_lock_reference_invalid",
    )
    if (
        not isinstance(value["id"], str)
        or not re.fullmatch(r"[a-z][a-z0-9_:-]{2,127}", value["id"])
        or not isinstance(value["version"], str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", value["version"])
        or not _is_digest(value["digest"])
    ):
        raise LanStage1Error("lan_deployment_release_lock_reference_invalid")


def _exact_keys(value: Any, expected: set[str], reason: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise LanStage1Error(reason)


def _artifact_ref(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"artifact://[a-z0-9][a-z0-9._/-]{2,190}", value
    ) is not None


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _is_commit(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _parse_date_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _date_time(value: Any) -> bool:
    return _parse_date_time(value) is not None


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _secret_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _csrf_for_session(token: str) -> str:
    return base64.urlsafe_b64encode(
        hmac.new(token.encode(), b"orbit-lan-csrf-v1", hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")


def _stable_id(prefix: str, value: str) -> str:
    return f"{prefix}_{hashlib.sha256(value.encode()).hexdigest()[:32]}"


def _username(value: str) -> str:
    normalized = value.strip().lower() if isinstance(value, str) else ""
    if not _USERNAME.fullmatch(normalized):
        raise LanStage1Error("lan_username_invalid")
    return normalized


def _display_name(value: str) -> str:
    normalized = " ".join(value.split()) if isinstance(value, str) else ""
    if not 2 <= len(normalized) <= 40:
        raise LanStage1Error("lan_display_name_invalid")
    return normalized


def _password(value: str) -> None:
    if not isinstance(value, str) or not 12 <= len(value) <= 128:
        raise LanStage1Error("lan_password_invalid")
    if len(value.encode("utf-8")) > 512:
        raise LanStage1Error("lan_password_invalid")


def _department(value: str) -> None:
    if value not in DEPARTMENTS:
        raise LanStage1Error("lan_department_invalid")


def _node(value: str) -> None:
    if not isinstance(value, str) or not _NODE.fullmatch(value):
        raise LanStage1Error("lan_node_id_invalid")


def _digest(value: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise LanStage1Error("lan_digest_invalid")


def _idempotency(value: str) -> None:
    if not isinstance(value, str) or not _IDEMPOTENCY.fullmatch(value):
        raise LanStage1Error("lan_idempotency_key_invalid")


def _single_role(principal: Mapping[str, Any]) -> str:
    roles = principal.get("role_refs")
    if not isinstance(roles, list) or len(roles) != 1:
        raise LanStage1Error("lan_principal_role_invalid")
    return str(roles[0])


def _future(value: datetime | None, now: datetime) -> bool:
    return value is not None and _as_utc(value) > now


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _time(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)

