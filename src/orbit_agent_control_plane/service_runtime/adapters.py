"""Adapter manifest generation for fail-closed service readiness."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..qualification.automation import canonical_digest
from ..qualification.service import REQUIRED_ADAPTER_ROLES

_ROLE_COMPONENTS = {
    "authoritative_store": (
        "component_postgresql_qualification_store",
        "src/orbit_agent_control_plane/service_runtime/repositories.py",
    ),
    "schema_migrations": (
        "component_alembic_schema_migrations",
        "alembic/versions/20260828_0001_service_core.py",
    ),
    "transactional_outbox": (
        "component_postgresql_transactional_outbox",
        "src/orbit_agent_control_plane/service_runtime/repositories.py",
    ),
    "human_identity": (
        "component_oidc_human_identity",
        "src/orbit_agent_control_plane/service_runtime/security.py",
    ),
    "workload_identity": (
        "component_mtls_workload_identity",
        "src/orbit_agent_control_plane/service_runtime/security.py",
    ),
    "grant_signer": (
        "component_ed25519_grant_signer",
        "src/orbit_agent_control_plane/service_runtime/security.py",
    ),
    "grant_revocation": (
        "component_postgresql_grant_revocation",
        "src/orbit_agent_control_plane/service_runtime/repositories.py",
    ),
    "worker_lease": (
        "component_postgresql_worker_lease",
        "src/orbit_agent_control_plane/service_runtime/repositories.py",
    ),
    "secret_resolver": (
        "component_file_secret_reference_resolver",
        "src/orbit_agent_control_plane/service_runtime/security.py",
    ),
    "audit_export": (
        "component_postgresql_audit_export",
        "src/orbit_agent_control_plane/service_runtime/repositories.py",
    ),
    "backup_restore": (
        "component_postgresql_backup_restore_harness",
        "scripts/run_qualification_service_postgres_harness.py",
    ),
    "observability": (
        "component_fastapi_service_health",
        "src/orbit_agent_control_plane/service_runtime/api.py",
    ),
}

_IMPLEMENTED_CAPABILITIES = {
    "authoritative_store": (
        "serializable_append",
        "idempotency_unique_constraint",
        "row_locking",
        "strict_replay",
    ),
    "schema_migrations": (
        "forward_migration",
        "rollback_plan",
        "migration_lock",
    ),
    "transactional_outbox": (
        "same_transaction_enqueue",
        "at_least_once_publish",
        "deduplicated_consume",
    ),
    "human_identity": (
        "oidc_signature_validation",
        "issuer_audience_check",
        "role_claim_mapping",
        "subject_allowlist",
        "token_lifetime_limit",
    ),
    "workload_identity": (
        "certificate_rotation",
        "mtls_peer_validation",
        "service_identity_mapping",
        "workload_allowlist",
    ),
    "grant_signer": (
        "asymmetric_signature",
        "key_id_binding",
        "short_lived_grant",
    ),
    "grant_revocation": ("revisioned_revocation",),
    "worker_lease": ("exclusive_claim", "heartbeat", "expiry_reclaim"),
    "secret_resolver": ("logical_reference_only", "workload_scoped_fetch"),
    "audit_export": ("correlation_id",),
    "backup_restore": ("restore_replay_check",),
    "observability": ("health_readiness",),
}


def build_adapter_bindings(
    *, repository_root: Path, runtime_evidence: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    verified_roles = _verified_roles(runtime_evidence)
    bindings: list[dict[str, Any]] = []
    for role in REQUIRED_ADAPTER_ROLES:
        component_id, source = _ROLE_COMPONENTS[role]
        path = repository_root / source
        digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        bindings.append(
            {
                "role": role,
                "component_id": component_id,
                "version": "0.1.0",
                "digest": digest,
                "evidence_status": "synthetic",
                "capabilities": sorted(_IMPLEMENTED_CAPABILITIES[role]),
                "synthetic_only": True,
                "runtime_verified": role in verified_roles,
            }
        )
    return bindings


def adapter_manifest(
    *, repository_root: Path, runtime_evidence: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    bindings = build_adapter_bindings(
        repository_root=repository_root,
        runtime_evidence=runtime_evidence,
    )
    return {
        "manifest_version": "orbit.qualification-service-adapters/1",
        "evidence_status": "synthetic",
        "adapters": bindings,
        "runtime_evidence_digest": (
            canonical_digest(runtime_evidence) if runtime_evidence is not None else None
        ),
        "authority_boundary": {
            "authoritative_state_migrated": False,
            "preproduction_authorized": False,
            "production_authorized": False,
            "release_authorization": False,
        },
    }


def load_runtime_evidence(path: Path | None) -> Mapping[str, Any] | None:
    if path is None:
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError("adapter_runtime_evidence_invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("adapter_runtime_evidence_invalid") from error
    if not isinstance(value, dict):
        raise TypeError("adapter_runtime_evidence_invalid")
    return value


def _verified_roles(value: Mapping[str, Any] | None) -> frozenset[str]:
    if value is None:
        return frozenset()
    if (
        value.get("evidence_version")
        != "orbit.qualification-service-runtime-evidence/1"
        or value.get("status") != "PASS"
        or value.get("evidence_status") != "synthetic"
        or value.get("production_authorized") is not False
        or value.get("release_authorization") is not False
    ):
        raise ValueError("adapter_runtime_evidence_invalid")
    roles = value.get("verified_adapter_roles")
    if not isinstance(roles, list) or any(
        role not in REQUIRED_ADAPTER_ROLES for role in roles
    ):
        raise ValueError("adapter_runtime_evidence_invalid")
    return frozenset(roles)

