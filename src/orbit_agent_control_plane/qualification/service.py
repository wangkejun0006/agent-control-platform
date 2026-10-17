"""Production-service ports and fail-closed readiness assessment.

This module deliberately contains no database, identity-provider, secret, or
network implementation.  It defines the replaceable boundaries that a formal
Control Plane service must satisfy before local synthetic state can be replaced
by authoritative service state.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .automation import canonical_digest
from .ledger import QualificationAppendResult, QualificationReplay

SERVICE_PROFILE_VERSION = "orbit.qualification-service-profile/1"
TARGET_CONTRACT_RELEASE = "contract-v0.1.0-alpha.2"
REQUIRED_ADAPTER_ROLES = (
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
)
REQUIRED_CAPABILITIES = {
    "authoritative_store": frozenset(
        {
            "serializable_append",
            "idempotency_unique_constraint",
            "row_locking",
            "strict_replay",
        }
    ),
    "schema_migrations": frozenset(
        {"forward_migration", "rollback_plan", "migration_lock"}
    ),
    "transactional_outbox": frozenset(
        {"same_transaction_enqueue", "at_least_once_publish", "deduplicated_consume"}
    ),
    "human_identity": frozenset(
        {"oidc_signature_validation", "issuer_audience_check", "role_claim_mapping"}
    ),
    "workload_identity": frozenset(
        {"mtls_peer_validation", "service_identity_mapping", "certificate_rotation"}
    ),
    "grant_signer": frozenset(
        {"asymmetric_signature", "short_lived_grant", "key_id_binding"}
    ),
    "grant_revocation": frozenset(
        {"revisioned_revocation", "runner_enforcement", "bounded_propagation"}
    ),
    "worker_lease": frozenset(
        {"exclusive_claim", "heartbeat", "expiry_reclaim", "cancel_cleanup"}
    ),
    "secret_resolver": frozenset(
        {"logical_reference_only", "workload_scoped_fetch", "redacted_audit"}
    ),
    "audit_export": frozenset(
        {"immutable_sequence", "correlation_id", "retention_policy"}
    ),
    "backup_restore": frozenset(
        {"encrypted_backup", "point_in_time_restore", "restore_replay_check"}
    ),
    "observability": frozenset(
        {"health_readiness", "metrics", "tracing", "alert_route"}
    ),
}

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")


class QualificationServiceError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class TransactionalQualificationStore(Protocol):
    """Authoritative store boundary; JSONL does not implement this port."""

    def append_with_outbox(
        self,
        *,
        record_type: str,
        run_id: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        outbox_events: Sequence[Mapping[str, Any]],
    ) -> QualificationAppendResult: ...

    def replay(self) -> QualificationReplay: ...

    def claim_reconciliation_work(
        self, *, worker_identity: str, limit: int
    ) -> tuple[str, ...]: ...


class HumanIdentityVerifier(Protocol):
    def verify_oidc_assertion(
        self, *, token: str, expected_audience: str
    ) -> Mapping[str, Any]: ...


class WorkloadIdentityVerifier(Protocol):
    def verify_mtls_peer(self, *, peer_certificate: bytes) -> Mapping[str, Any]: ...


class EvaluationGrantSigner(Protocol):
    def sign_grant(self, *, canonical_grant: bytes, key_id: str) -> str: ...


class GrantRevocationRegistry(Protocol):
    def revision(self) -> int: ...

    def is_revoked(self, *, grant_id: str, minimum_revision: int) -> bool: ...


class WorkerLeaseCoordinator(Protocol):
    def claim(self, *, run_id: str, worker_identity: str, ttl_seconds: int) -> str: ...

    def heartbeat(self, *, lease_id: str, worker_identity: str) -> None: ...

    def close(self, *, lease_id: str, outcome: str) -> None: ...


class SecretReferenceResolver(Protocol):
    def resolve_for_workload(
        self, *, logical_ref: str, workload_identity: str
    ) -> bytes: ...


class OutboxPublisher(Protocol):
    def publish_pending(self, *, limit: int) -> int: ...


@dataclass(frozen=True)
class ServiceAdapterBinding:
    role: str
    component_id: str
    version: str
    digest: str
    evidence_status: str
    capabilities: tuple[str, ...]
    synthetic_only: bool
    runtime_verified: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ServiceAdapterBinding:
        fields = {
            "role",
            "component_id",
            "version",
            "digest",
            "evidence_status",
            "capabilities",
            "synthetic_only",
            "runtime_verified",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise QualificationServiceError("service_adapter_binding_invalid")
        role = _token(value["role"])
        component_id = _token(value["component_id"])
        version = value["version"]
        digest = value["digest"]
        evidence_status = value["evidence_status"]
        capabilities = _unique_tokens(value["capabilities"])
        if (
            role not in REQUIRED_ADAPTER_ROLES
            or not isinstance(version, str)
            or not _VERSION.fullmatch(version)
            or not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
            or evidence_status
            not in {"architecture_reference", "synthetic", "verified_runtime"}
            or type(value["synthetic_only"]) is not bool
            or type(value["runtime_verified"]) is not bool
        ):
            raise QualificationServiceError("service_adapter_binding_invalid")
        return cls(
            role,
            component_id,
            version,
            digest,
            evidence_status,
            capabilities,
            value["synthetic_only"],
            value["runtime_verified"],
        )


@dataclass(frozen=True)
class ProductionReadinessAssessment:
    ready: bool
    status: str
    profile_digest: str
    blocker_codes: tuple[str, ...]
    verified_adapter_roles: tuple[str, ...]
    release_authorization: bool = False


def validate_service_profile(profile: Mapping[str, Any]) -> None:
    """Validate a non-secret, non-effective target service profile."""
    expected = {
        "profile_version",
        "profile_id",
        "status",
        "evidence_status",
        "contract_release",
        "service_stack",
        "authoritative_state",
        "local_state_boundary",
        "required_adapter_roles",
        "api_surfaces",
        "security_boundaries",
        "deployment_evidence_required",
        "authority_boundary",
    }
    if not isinstance(profile, Mapping) or set(profile) != expected:
        raise QualificationServiceError("service_profile_invalid")
    if (
        profile["profile_version"] != SERVICE_PROFILE_VERSION
        or _token(profile["profile_id"]) != profile["profile_id"]
        or profile["status"] != "proposed-not-effective"
        or profile["evidence_status"] != "architecture_reference"
        or profile["contract_release"] != TARGET_CONTRACT_RELEASE
        or profile["authoritative_state"] != "postgresql_transactional_store"
        or profile["local_state_boundary"]
        != "jsonl_synthetic_evidence_never_promoted_to_authority"
        or tuple(profile["required_adapter_roles"]) != REQUIRED_ADAPTER_ROLES
    ):
        raise QualificationServiceError("service_profile_invalid")
    stack = _unique_tokens(profile["service_stack"])
    if not {
        "fastapi",
        "postgresql",
        "sqlalchemy",
        "psycopg",
        "alembic",
    }.issubset(stack):
        raise QualificationServiceError("service_profile_stack_incomplete")
    surfaces = _unique_tokens(profile["api_surfaces"])
    if not {
        "policy",
        "qualification_run",
        "receipt",
        "grant_revocation",
        "worker_lease",
        "audit",
        "health",
    }.issubset(surfaces):
        raise QualificationServiceError("service_profile_api_incomplete")
    security = _unique_tokens(profile["security_boundaries"])
    if not {
        "oidc_human_identity",
        "mtls_workload_identity",
        "short_lived_signed_grants",
        "logical_secret_refs_only",
        "agent_has_no_direct_network_or_credentials",
    }.issubset(security):
        raise QualificationServiceError("service_profile_security_incomplete")
    evidence = _unique_tokens(profile["deployment_evidence_required"])
    if not {
        "migration_rehearsal",
        "restart_recovery",
        "backup_restore",
        "revocation_propagation",
        "lease_reclaim",
        "outbox_replay",
        "identity_negative_probes",
    }.issubset(evidence):
        raise QualificationServiceError("service_profile_evidence_incomplete")
    authority = profile["authority_boundary"]
    if not isinstance(authority, Mapping) or set(authority) != {
        "service_deployed",
        "authoritative_state_migrated",
        "preproduction_authorized",
        "production_authorized",
        "release_authorization",
    } or any(value is not False for value in authority.values()):
        raise QualificationServiceError("service_profile_authority_invalid")


def assess_production_readiness(
    *, profile: Mapping[str, Any], adapters: Sequence[Mapping[str, Any]]
) -> ProductionReadinessAssessment:
    """Require exact, runtime-verified adapters for every production role."""
    validate_service_profile(profile)
    normalized = tuple(ServiceAdapterBinding.from_mapping(item) for item in adapters)
    seen: dict[str, ServiceAdapterBinding] = {}
    blockers: list[str] = []
    for binding in normalized:
        if binding.role in seen:
            blockers.append(f"duplicate_adapter_role_{binding.role}")
            continue
        seen[binding.role] = binding
    for role in REQUIRED_ADAPTER_ROLES:
        binding = seen.get(role)
        if binding is None:
            blockers.append(f"missing_adapter_{role}")
            continue
        missing = REQUIRED_CAPABILITIES[role].difference(binding.capabilities)
        if missing:
            blockers.append(f"adapter_capabilities_incomplete_{role}")
        if (
            binding.evidence_status != "verified_runtime"
            or binding.synthetic_only
            or not binding.runtime_verified
        ):
            blockers.append(f"adapter_runtime_evidence_missing_{role}")
    if (
        seen.get("human_identity") is not None
        and seen.get("workload_identity") is not None
        and seen["human_identity"].component_id
        == seen["workload_identity"].component_id
    ):
        blockers.append("human_workload_identity_not_separated")
    if (
        seen.get("grant_signer") is not None
        and seen.get("grant_revocation") is not None
        and seen["grant_signer"].component_id
        == seen["grant_revocation"].component_id
    ):
        blockers.append("grant_signing_revocation_not_separated")
    unique_blockers = tuple(dict.fromkeys(blockers))
    ready = not unique_blockers
    return ProductionReadinessAssessment(
        ready=ready,
        status="ready_for_preproduction_review" if ready else "not_ready",
        profile_digest=canonical_digest(profile),
        blocker_codes=unique_blockers,
        verified_adapter_roles=tuple(
            role
            for role in REQUIRED_ADAPTER_ROLES
            if role in seen
            and seen[role].runtime_verified
            and not seen[role].synthetic_only
            and seen[role].evidence_status == "verified_runtime"
        ),
    )


def _token(value: Any) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise QualificationServiceError("service_profile_token_invalid")
    return value


def _unique_tokens(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise QualificationServiceError("service_profile_tokens_invalid")
    result = tuple(_token(item) for item in value)
    if len(result) != len(set(result)):
        raise QualificationServiceError("service_profile_tokens_invalid")
    return result

