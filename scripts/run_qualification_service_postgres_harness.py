#!/usr/bin/env python3
"""Run a bounded local synthetic service check against ephemeral PostgreSQL."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import jwt
import psycopg
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient
from sqlalchemy import select

from alembic import command
from orbit_agent_control_plane.qualification import (
    LocalPolicyActivationLedger,
    canonical_digest,
)
from orbit_agent_control_plane.qualification.automation import ReceiptArtifact
from orbit_agent_control_plane.service_runtime.api import (
    create_app,
    load_service_runtime,
)
from orbit_agent_control_plane.service_runtime.config import ServiceSettings
from orbit_agent_control_plane.service_runtime.model_route import (
    ModelRouteReconciler,
    ModelRouteStore,
    OwnerOnlyFileSecretProvider,
)
from orbit_agent_control_plane.service_runtime.models import WorkerLeaseRow
from orbit_agent_control_plane.service_runtime.repositories import (
    SqlAuditExporter,
    SqlOutboxPublisher,
)
from orbit_agent_control_plane.service_runtime.security import (
    Ed25519EvaluationGrantSigner,
    FileSecretReferenceResolver,
    MtlsWorkloadIdentityVerifier,
    OidcHumanIdentityVerifier,
    ServiceSecurityError,
)

POLICY = ROOT / (
    "evidence/disease-agent-r2/2026-08-27-automation-policy-alpha2/"
    "automation-policy.disease-r2.synthetic.json"
)
REVIEW = ROOT / (
    "evidence/disease-agent-r2/2026-08-27-automation-policy-alpha2/"
    "automation-policy-review-package.json"
)
PROFILE = ROOT / "references/qualification-service-profile.candidate.json"
ACTIVATION_STATE = ROOT / (
    ".local-state/qualification-automation/disease-r2-policy-alpha2"
)
POSTGRES_DATABASE = "orbit_control_plane"
POSTGRES_USER = "orbit_control_plane"
EXPECTED_POLICY_DIGEST = (
    "sha256:52e70ed2eb9116f190b9d95400952863631998a764f85efd4722a4632a18fd43"
)


class HarnessFailure(RuntimeError):
    pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--postgres-image", default="postgres:17-alpine")
    parser.add_argument("--expected-image-id")
    args = parser.parse_args()
    evidence = run_harness(
        postgres_image=args.postgres_image,
        expected_image_id=args.expected_image_id,
    )
    source = _render(evidence)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.read_text(encoding="utf-8") != source:
        raise HarnessFailure("service_runtime_evidence_conflict")
    output.write_text(source, encoding="utf-8")
    print(source, end="")
    return 0 if evidence["status"] == "PASS" else 1


def run_harness(
    *, postgres_image: str, expected_image_id: str | None
) -> dict[str, Any]:
    started_at = _now()
    checks: list[dict[str, Any]] = []
    container = "orbit-cp-pg-" + uuid.uuid4().hex[:12]
    network = "orbit-cp-net-" + uuid.uuid4().hex[:12]
    image_id = _image_id(postgres_image)
    if expected_image_id is not None and image_id != expected_image_id:
        raise HarnessFailure("postgres_image_id_drift")
    port = _free_port()
    password = secrets.token_urlsafe(32)
    container_started = False
    network_created = False
    verified_roles: set[str] = set()
    activation_receipt_digest: str | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="orbit-cp-service-") as temporary:
            temporary_root = Path(temporary)
            password_path = temporary_root / "postgres-password"
            password_path.write_text(password + "\n", encoding="utf-8")
            os.chmod(password_path, 0o600)
            _docker("network", "create", network)
            network_created = True
            _start_postgres(
                container=container,
                image=postgres_image,
                network=network,
                port=port,
                password_path=password_path,
            )
            container_started = True
            _wait_postgres(container)
            inspect = _docker_json("inspect", container)[0]
            restricted = _container_restricted(inspect, network=network, port=port)
            checks.append(_check("postgres_container_restrictions", restricted))
            if not restricted:
                raise HarnessFailure("postgres_container_restrictions_failed")

            database_url = _database_url(password=password, port=port)
            _wait_host_postgres(database_url)
            url_path = temporary_root / "database-url"
            url_path.write_text(database_url + "\n", encoding="utf-8")
            os.chmod(url_path, 0o600)
            environment = _service_environment(url_path)
            with _environment(environment):
                _migrate("head")
                _migrate("head")
                checks.append(_check("migration_rehearsal", True))
                verified_roles.add("schema_migrations")

                settings = ServiceSettings.from_environment(environment)
                runtime = load_service_runtime(
                    settings=settings,
                    repository_root=ROOT,
                )
                if not runtime.database.ping():
                    raise HarnessFailure("database_ping_failed")
                checks.append(_check("authoritative_store_ping", True))

                activation_receipt_digest = _record_activation(runtime)
                replayed = runtime.policy_activations.get_by_policy_digest(
                    EXPECTED_POLICY_DIGEST
                )
                intake_ok = (
                    replayed is not None
                    and replayed["receipt_digest"] == activation_receipt_digest
                )
                checks.append(_check("explicit_policy_activation_intake", intake_ok))
                verified_roles.add("authoritative_store")

                published: list[dict[str, Any]] = []
                publisher = SqlOutboxPublisher(runtime.database, published.append)
                first_publish = publisher.publish_pending(limit=20)
                second_publish = publisher.publish_pending(limit=20)
                outbox_ok = first_publish == 1 and second_publish == 0
                checks.append(_check("transactional_outbox_replay", outbox_ok))
                if outbox_ok:
                    verified_roles.add("transactional_outbox")

                revocation_ok = _revocation_probe(runtime)
                checks.append(_check("grant_revocation_propagation", revocation_ok))
                if revocation_ok:
                    verified_roles.add("grant_revocation")

                lease_ok = _lease_reclaim_probe(runtime)
                checks.append(_check("worker_lease_reclaim", lease_ok))
                if lease_ok:
                    verified_roles.add("worker_lease")

                audit_ok = _audit_probe(runtime)
                checks.append(_check("audit_correlation", audit_ok))
                if audit_ok:
                    verified_roles.add("audit_export")

                model_route_secret = temporary_root / "model-route-wemeta-secret"
                model_route_secret.write_text("synthetic-secret\n", encoding="utf-8")
                os.chmod(model_route_secret, 0o600)
                model_route_bindings = temporary_root / "model-route-bindings.json"
                model_route_bindings.write_text(
                    json.dumps(
                        {
                            "binding_version": "orbit.model-route-secret-bindings/1",
                            "bindings": {
                                "secret://local/wemeta/current": {
                                    "path": str(model_route_secret),
                                    "version": "postgres-harness-v1",
                                }
                            },
                        },
                        sort_keys=True,
                    ),
                    encoding="utf-8",
                )
                os.chmod(model_route_bindings, 0o600)
                route_id, route_snapshot_digest = _model_route_probe(
                    runtime.database,
                    bindings_path=model_route_bindings,
                )
                checks.append(_check("model_route_postgres_snapshot", True))

                with TestClient(create_app(runtime)) as client:
                    live = client.get("/health/live")
                    ready = client.get("/health/ready")
                    adapter = client.get(
                        "/v1/runtime-adapters/"
                        "runtime_adapter_framework_neutral_disease_r2_syn"
                    )
                observability_ok = (
                    live.status_code == 200
                    and ready.status_code == 503
                    and adapter.status_code == 200
                    and adapter.json()["transport"]["status"] == "not_configured"
                )
                checks.append(
                    _check("health_and_runtime_adapter_fail_closed", observability_ok)
                )
                if observability_ok:
                    verified_roles.add("observability")
                runtime.database.dispose()

                restarted = load_service_runtime(
                    settings=settings,
                    repository_root=ROOT,
                )
                recovered = restarted.policy_activations.get_by_policy_digest(
                    EXPECTED_POLICY_DIGEST
                )
                restart_ok = (
                    restarted.database.ping()
                    and recovered is not None
                    and recovered["receipt_digest"] == activation_receipt_digest
                )
                restarted_route = ModelRouteReconciler(
                    store=ModelRouteStore(restarted.database),
                    secret_provider=OwnerOnlyFileSecretProvider(
                        model_route_bindings
                    ),
                ).status(route_id)
                model_route_restart_ok = (
                    restarted_route["snapshot_digest"] == route_snapshot_digest
                    and restarted_route["snapshot_status"] == "ready"
                )
                restarted.database.dispose()
                checks.append(_check("restart_recovery", restart_ok))
                checks.append(
                    _check("model_route_postgres_restart_replay", model_route_restart_ok)
                )

                identity = _identity_and_secret_probe(temporary_root)
                checks.append(_check("identity_and_secret_negative_probes", identity))
                if identity:
                    verified_roles.update(
                        {
                            "human_identity",
                            "workload_identity",
                            "grant_signer",
                            "secret_resolver",
                        }
                    )

                backup_ok = _backup_restore_probe(
                    container=container,
                    password=password,
                    port=port,
                    environment=environment,
                    activation_receipt_digest=activation_receipt_digest,
                )
                checks.append(_check("backup_restore_replay", backup_ok))
                if backup_ok:
                    verified_roles.add("backup_restore")

                rollback_environment = {
                    **environment,
                    "ORBIT_SERVICE_DATABASE_URL": _database_url(
                        password=password,
                        port=port,
                        database="orbit_restore",
                    ),
                }
                rollback_environment.pop("ORBIT_SERVICE_DATABASE_URL_FILE")
                with _environment(rollback_environment):
                    _migrate("base", downgrade=True)
                    _migrate("head")
                checks.append(_check("migration_rollback_plan", True))
    except Exception as error:  # noqa: BLE001 - evidence must close on every failure
        checks.append(
            _check(
                "harness_terminal",
                False,
                type(error).__name__,
                detail=_sanitize_error(error, password=password),
            )
        )
    finally:
        password = ""
        if container_started:
            _docker_optional("rm", "--force", container)
        if network_created:
            _docker_optional("network", "rm", network)

    passed = all(check["status"] == "pass" for check in checks)
    if passed and verified_roles != _required_roles():
        checks.append(
            _check("adapter_role_coverage", False, "verified_roles_incomplete")
        )
        passed = False
    else:
        checks.append(_check("adapter_role_coverage", passed))
    return {
        "evidence_version": "orbit.qualification-service-runtime-evidence/1",
        "status": "PASS" if passed else "FAIL",
        "evidence_status": "synthetic",
        "started_at": started_at,
        "completed_at": _now(),
        "postgres_image": postgres_image,
        "postgres_image_id": image_id,
        "postgres_network_egress_blocked": False,
        "postgres_host_binding": "loopback_ephemeral",
        "checks": checks,
        "verified_adapter_roles": sorted(verified_roles),
        "policy_digest": EXPECTED_POLICY_DIGEST,
        "activation_receipt_digest": activation_receipt_digest,
        "database_content_classification": "synthetic",
        "database_state_persisted": False,
        "external_network_accessed_by_harness": False,
        "model_called": False,
        "nas_accessed": False,
        "runtime_worker_started": False,
        "formal_registry_written": False,
        "preproduction_authorized": False,
        "production_authorized": False,
        "release_authorization": False,
    }


def _start_postgres(
    *,
    container: str,
    image: str,
    network: str,
    port: int,
    password_path: Path,
) -> None:
    _docker(
        "run",
        "--detach",
        "--rm",
        "--name",
        container,
        "--network",
        network,
        "--publish",
        f"127.0.0.1:{port}:5432",
        "--read-only",
        "--user",
        "70:70",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "128",
        "--memory",
        "384m",
        "--cpus",
        "1",
        "--tmpfs",
        "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=192m,mode=0700,uid=70,gid=70",
        "--tmpfs",
        "/var/run/postgresql:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=70,gid=70",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
        "--mount",
        f"type=bind,src={password_path},dst=/run/secrets/postgres_password,readonly",
        "--env",
        f"POSTGRES_DB={POSTGRES_DATABASE}",
        "--env",
        f"POSTGRES_USER={POSTGRES_USER}",
        "--env",
        "POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password",
        "--env",
        "PGDATA=/var/lib/postgresql/data/pgdata",
        "--pull",
        "never",
        image,
    )


def _wait_postgres(container: str) -> None:
    for _ in range(60):
        completed = _docker_optional(
            "exec",
            container,
            "pg_isready",
            "-U",
            POSTGRES_USER,
            "-d",
            POSTGRES_DATABASE,
        )
        if completed.returncode == 0:
            return
        time.sleep(0.5)
    logs = _docker_optional("logs", "--tail", "30", container)
    raise HarnessFailure("postgres_not_ready:" + logs.stderr[-200:])


def _wait_host_postgres(database_url: str) -> None:
    psycopg_url = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    for _ in range(60):
        try:
            with (
                psycopg.connect(psycopg_url, connect_timeout=1) as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute("SELECT 1")
                if cursor.fetchone() == (1,):
                    return
        except psycopg.Error:
            time.sleep(0.5)
    raise HarnessFailure("postgres_host_port_not_ready")


def _container_restricted(value: dict[str, Any], *, network: str, port: int) -> bool:
    host = value.get("HostConfig", {})
    settings = value.get("NetworkSettings", {})
    networks = settings.get("Networks", {})
    bindings = host.get("PortBindings", {}).get("5432/tcp")
    mounts = value.get("Mounts", [])
    return (
        value.get("Config", {}).get("User") == "70:70"
        and host.get("ReadonlyRootfs") is True
        and host.get("CapDrop") == ["ALL"]
        and "no-new-privileges:true" in host.get("SecurityOpt", [])
        and host.get("PidsLimit") == 128
        and host.get("Memory") == 384 * 1024 * 1024
        and host.get("NanoCpus") == 1_000_000_000
        and set(networks) == {network}
        and bindings == [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
        and all(
            mount.get("Source") != str(ROOT)
            and not str(mount.get("Source", "")).startswith(str(Path.home()))
            for mount in mounts
        )
    )


def _record_activation(runtime) -> str:
    ledger_state = LocalPolicyActivationLedger(
        ACTIVATION_STATE / "activation-ledger.jsonl"
    ).replay()
    approval = _read_json(ACTIVATION_STATE / "approval-decision.json")
    receipt_value = _read_json(ACTIVATION_STATE / "activation-receipt.json")
    receipt = ReceiptArtifact(
        receipt_value["schema_id"],
        receipt_value["document"],
        receipt_value["digest"],
    )
    if (
        ledger_state.policy_digest != EXPECTED_POLICY_DIGEST
        or ledger_state.receipt_digest != receipt.digest
        or ledger_state.approval_digest != canonical_digest(approval)
    ):
        raise HarnessFailure("policy_activation_state_drift")
    runtime.policy_activations.record(
        policy=runtime.policy,
        policy_digest=runtime.policy_digest,
        approval_decision=approval,
        receipt=receipt,
    )
    return receipt.digest


def _revocation_probe(runtime) -> bool:
    revision = runtime.grant_revocations.revoke(
        grant_id="grant_service_harness_revocation_syn",
        reason_code="synthetic_harness_revoke",
        revoked_by_ref="human_orbit_platform_owner",
    )
    return runtime.grant_revocations.is_revoked(
        grant_id="grant_service_harness_revocation_syn",
        minimum_revision=revision,
    ) and not runtime.grant_revocations.is_revoked(
        grant_id="grant_service_harness_revocation_syn",
        minimum_revision=revision + 1,
    )


def _lease_reclaim_probe(runtime) -> bool:
    first = runtime.worker_leases.claim(
        run_id="run_service_harness_lease_syn",
        worker_identity="workload_service_harness_a",
        ttl_seconds=30,
    )
    runtime.worker_leases.heartbeat(
        lease_id=first,
        worker_identity="workload_service_harness_a",
    )
    with runtime.database.session() as session:
        row = session.scalar(
            select(WorkerLeaseRow).where(WorkerLeaseRow.lease_id == first)
        )
        if row is None:
            return False
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    second = runtime.worker_leases.claim(
        run_id="run_service_harness_lease_syn",
        worker_identity="workload_service_harness_b",
        ttl_seconds=30,
    )
    runtime.worker_leases.close(
        lease_id=second,
        worker_identity="workload_service_harness_b",
        outcome="cancelled",
    )
    status = runtime.worker_leases.status(second)
    return first != second and status is not None and status["status"] == "closed"


def _audit_probe(runtime) -> bool:
    exporter = SqlAuditExporter(runtime.database)
    first = exporter.record(
        correlation_id="corr_service_harness_syn",
        event_type="synthetic_service_probe",
        actor_ref="workload_service_harness",
        payload={"synthetic_only": True, "release_authorization": False},
    )
    second = exporter.record(
        correlation_id="corr_service_harness_syn",
        event_type="synthetic_service_probe",
        actor_ref="workload_service_harness",
        payload={"synthetic_only": True, "release_authorization": False},
    )
    return first == second


def _model_route_probe(database, *, bindings_path: Path) -> tuple[str, str]:
    route = json.loads(
        (
            ROOT
            / "references/model-route-revisions/"
            "disease-r2-wemeta-gpt-5.6-sol.public.json"
        ).read_text(encoding="utf-8")
    )
    observation = json.loads(
        (
            ROOT
            / "evidence/model-route/2026-08-28/"
            "wemeta-gpt-5.6-sol-observation.public.json"
        ).read_text(encoding="utf-8")
    )
    observed_at = datetime.now(timezone.utc).replace(microsecond=0)
    observation["observed_at"] = observed_at.isoformat().replace("+00:00", "Z")
    observation["expires_at"] = (
        observed_at + timedelta(hours=6)
    ).isoformat().replace("+00:00", "Z")
    observation["source_kind"] = "deterministic_fixture"
    observation["source"] = "fixture://postgres-harness/model-route"
    store = ModelRouteStore(database)
    store.record_route(route)
    store.record_observation(observation)
    result = ModelRouteReconciler(
        store=store,
        secret_provider=OwnerOnlyFileSecretProvider(bindings_path),
    ).reconcile(route["route_id"])
    if result["status"] != "ready":
        raise HarnessFailure("model_route_postgres_snapshot_blocked")
    return route["route_id"], result["snapshot_digest"]


def _identity_and_secret_probe(root: Path) -> bool:
    now = datetime.now(timezone.utc)
    oidc_key = ed25519.Ed25519PrivateKey.generate()
    oidc_public = oidc_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    oidc = OidcHumanIdentityVerifier(
        issuer="https://identity.synthetic.orbit.local",
        audience="orbit_control_plane",
        public_key_pem=oidc_public,
        required_key_id="oidc_harness_2026_08",
        allowed_subject_digests=(
            "sha256:" + hashlib.sha256(b"synthetic-owner").hexdigest(),
        ),
    )
    token = jwt.encode(
        {
            "iss": "https://identity.synthetic.orbit.local",
            "aud": "orbit_control_plane",
            "sub": "synthetic-owner",
            "jti": "synthetic-service-harness",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "roles": ["control_plane_admin"],
        },
        oidc_key,
        algorithm="EdDSA",
        headers={"kid": "oidc_harness_2026_08"},
    )
    principal = oidc.verify_oidc_assertion(
        token=token,
        expected_audience="orbit_control_plane",
    )
    try:
        oidc.verify_oidc_assertion(token=token, expected_audience="wrong_audience")
    except ServiceSecurityError:
        oidc_negative = True
    else:
        oidc_negative = False

    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, algorithm=None)
    )
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "runner")]))
        .issuer_name(ca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=55))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("spiffe://orbit.local/workload/runner")]
            ),
            critical=False,
        )
        .sign(ca_key, algorithm=None)
    )
    mtls = MtlsWorkloadIdentityVerifier(
        ca_certificate_pem=ca.public_bytes(serialization.Encoding.PEM),
        trust_domain="orbit.local",
        allowed_workload_names=("runner",),
    )
    workload = mtls.verify_mtls_peer(
        peer_certificate=leaf.public_bytes(serialization.Encoding.DER)
    )

    signing_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = signing_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path = root / "grant-signing-key"
    key_path.write_bytes(private_pem)
    os.chmod(key_path, 0o600)
    resolver = FileSecretReferenceResolver(
        {"secret://control-plane/grant-signing-key": key_path},
        access_policy={
            "secret://control-plane/grant-signing-key": (
                "workload_control_plane_service",
            )
        },
    )
    resolved = resolver.resolve_for_workload(
        logical_ref="secret://control-plane/grant-signing-key",
        workload_identity="workload_control_plane_service",
    )
    signer = Ed25519EvaluationGrantSigner(
        private_key_pem=resolved,
        key_id="grant_signer_synthetic",
    )
    canonical_grant = json.dumps(
        {
            "api_version": "company-ai-os/v1alpha1",
            "kind": "ExecutionGrant",
            "metadata": {
                "evidence_status": "synthetic",
                "expires_at": "2026-08-28T01:10:00Z",
                "issued_at": "2026-08-28T01:00:00Z",
                "status": "active",
                "synthetic_only": True,
            },
            "spec": {},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    signature = signer.sign_grant(
        canonical_grant=canonical_grant,
        key_id="grant_signer_synthetic",
    )
    return (
        principal["role_refs"] == ["role_control_plane_admin"]
        and oidc_negative
        and workload["workload_identity"] == "workload_runner"
        and bool(signature)
    )


def _backup_restore_probe(
    *,
    container: str,
    password: str,
    port: int,
    environment: dict[str, str],
    activation_receipt_digest: str,
) -> bool:
    dump = _docker_bytes(
        "exec",
        container,
        "pg_dump",
        "-U",
        POSTGRES_USER,
        "-Fc",
        POSTGRES_DATABASE,
    )
    _docker("exec", container, "createdb", "-U", POSTGRES_USER, "orbit_restore")
    _docker_with_input(
        dump,
        "exec",
        "-i",
        container,
        "pg_restore",
        "-U",
        POSTGRES_USER,
        "--no-owner",
        "--no-privileges",
        "-d",
        "orbit_restore",
    )
    restore_environment = {
        **environment,
        "ORBIT_SERVICE_DATABASE_URL": _database_url(
            password=password,
            port=port,
            database="orbit_restore",
        ),
    }
    restore_environment.pop("ORBIT_SERVICE_DATABASE_URL_FILE")
    restored = load_service_runtime(
        settings=ServiceSettings.from_environment(restore_environment),
        repository_root=ROOT,
    )
    activation = restored.policy_activations.get_by_policy_digest(
        EXPECTED_POLICY_DIGEST
    )
    result = (
        restored.database.ping()
        and activation is not None
        and activation["receipt_digest"] == activation_receipt_digest
    )
    restored.database.dispose()
    return result


def _migrate(target: str, *, downgrade: bool = False) -> None:
    config = Config(str(ROOT / "alembic.ini"))
    if downgrade:
        command.downgrade(config, target)
    else:
        command.upgrade(config, target)


def _service_environment(database_url_file: Path) -> dict[str, str]:
    return {
        "ORBIT_SERVICE_MODE": "local_synthetic",
        "ORBIT_SERVICE_DATABASE_URL_FILE": str(database_url_file.resolve()),
        "ORBIT_SERVICE_POLICY_PATH": str(POLICY.resolve()),
        "ORBIT_SERVICE_REVIEW_PACKAGE_PATH": str(REVIEW.resolve()),
        "ORBIT_SERVICE_PROFILE_PATH": str(PROFILE.resolve()),
        "ORBIT_SERVICE_MUTATIONS_ENABLED": "false",
        "ORBIT_SERVICE_HOST": "127.0.0.1",
        "ORBIT_SERVICE_PORT": "8431",
    }


@contextmanager
def _environment(values: dict[str, str]):
    previous = os.environ.copy()
    for key in tuple(os.environ):
        if key.startswith("ORBIT_SERVICE_"):
            del os.environ[key]
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


def _database_url(
    *, password: str, port: int, database: str = POSTGRES_DATABASE
) -> str:
    return (
        f"postgresql+psycopg://{POSTGRES_USER}:{quote(password, safe='')}"
        f"@127.0.0.1:{port}/{database}"
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _image_id(image: str) -> str:
    value = _docker_json("image", "inspect", image)
    if not isinstance(value, list) or len(value) != 1:
        raise HarnessFailure("postgres_image_not_available")
    image_id = value[0].get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
        raise HarnessFailure("postgres_image_id_invalid")
    return image_id


def _docker(*args: str) -> str:
    completed = subprocess.run(
        ["docker", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise HarnessFailure("docker_command_failed:" + completed.stderr[-300:])
    return completed.stdout.strip()


def _docker_optional(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def _docker_json(*args: str) -> Any:
    return json.loads(_docker(*args))


def _docker_bytes(*args: str) -> bytes:
    completed = subprocess.run(
        ["docker", *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise HarnessFailure("docker_command_failed")
    return completed.stdout


def _docker_with_input(source: bytes, *args: str) -> None:
    completed = subprocess.run(
        ["docker", *args],
        input=source,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise HarnessFailure("docker_command_failed")


def _read_json(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or info.st_size > 1024 * 1024
    ):
        raise HarnessFailure("activation_input_invalid")
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=lambda _: _reject_constant(),
    )
    if not isinstance(value, dict):
        raise HarnessFailure("activation_input_invalid")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise HarnessFailure("json_duplicate_key")
        value[key] = item
    return value


def _reject_constant() -> None:
    raise HarnessFailure("json_nonfinite_number")


def _required_roles() -> set[str]:
    return {
        "authoritative_store",
        "schema_migrations",
        "transactional_outbox",
        "human_identity",
        "workload_identity",
        "grant_signer",
        "grant_revocation",
        "worker_lease",
        "secret_resolver",
        "audit_export",
        "backup_restore",
        "observability",
    }


def _check(
    identifier: str,
    passed: bool,
    reason: str | None = None,
    *,
    detail: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "id": identifier,
        "status": "pass" if passed else "fail",
    }
    if reason is not None:
        value["reason_code"] = reason
    if detail is not None:
        value["detail"] = detail
    return value


def _sanitize_error(error: Exception, *, password: str) -> str:
    value = str(error)
    for sensitive in (password, str(ROOT), str(Path.home())):
        if sensitive:
            value = value.replace(sensitive, "[redacted]")
    return " ".join(value.split())[:500]


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _render(value: Any) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    )


if __name__ == "__main__":
    raise SystemExit(main())

