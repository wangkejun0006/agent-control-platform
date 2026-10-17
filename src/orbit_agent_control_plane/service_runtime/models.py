"""SQLAlchemy schema for authoritative service-mode state."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JSON_DOCUMENT = JSON().with_variant(JSONB, "postgresql")
IDENTITY = BigInteger().with_variant(Integer, "sqlite")


class Base(DeclarativeBase):
    pass


class StreamHeadRow(Base):
    __tablename__ = "control_plane_stream_heads"

    stream_name: Mapped[str] = mapped_column(String(96), primary_key=True)
    next_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_record_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)


class QualificationEventRow(Base):
    __tablename__ = "control_plane_qualification_events"
    __table_args__ = (
        UniqueConstraint("stream_name", "sequence", name="uq_qualification_sequence"),
        UniqueConstraint("idempotency_key", name="uq_qualification_idempotency"),
        UniqueConstraint("record_id", name="uq_qualification_record_id"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    stream_name: Mapped[str] = mapped_column(String(96), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    record_id: Mapped[str] = mapped_column(String(96), nullable=False)
    record_type: Mapped[str] = mapped_column(String(64), nullable=False)
    run_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    previous_record_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    record_hash: Mapped[str] = mapped_column(String(71), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class OutboxEventRow(Base):
    __tablename__ = "control_plane_outbox_events"
    __table_args__ = (UniqueConstraint("event_id", name="uq_outbox_event_id"),)

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(96), nullable=False)
    topic: Mapped[str] = mapped_column(String(128), nullable=False)
    aggregate_ref: Mapped[str] = mapped_column(String(240), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class PolicyActivationRow(Base):
    __tablename__ = "control_plane_policy_activations"
    __table_args__ = (
        UniqueConstraint("policy_digest", name="uq_policy_activation_digest"),
        UniqueConstraint("receipt_id", name="uq_policy_activation_receipt"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    approval_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    receipt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    approval_document: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    receipt_document: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    evidence_status: Mapped[str] = mapped_column(String(32), nullable=False)
    synthetic_only: Mapped[bool] = mapped_column(Boolean, nullable=False)


class ReceiptRow(Base):
    __tablename__ = "control_plane_receipts"
    __table_args__ = (
        UniqueConstraint("receipt_id", name="uq_receipt_id"),
        UniqueConstraint("receipt_digest", name="uq_receipt_digest"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    receipt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    receipt_type: Mapped[str] = mapped_column(String(96), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    subject_ref: Mapped[str] = mapped_column(String(240), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class GrantRevocationRow(Base):
    __tablename__ = "control_plane_grant_revocations"
    __table_args__ = (UniqueConstraint("grant_id", name="uq_grant_revocation_grant"),)

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    grant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(96), nullable=False)
    revoked_by_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class WorkerLeaseRow(Base):
    __tablename__ = "control_plane_worker_leases"
    __table_args__ = (
        UniqueConstraint("lease_id", name="uq_worker_lease_id"),
        UniqueConstraint("run_id", name="uq_worker_lease_run"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    lease_id: Mapped[str] = mapped_column(String(128), nullable=False)
    run_id: Mapped[str] = mapped_column(String(128), nullable=False)
    worker_identity: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    claimed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    outcome: Mapped[str | None] = mapped_column(String(48), nullable=True)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)


class AuditEventRow(Base):
    __tablename__ = "control_plane_audit_events"
    __table_args__ = (UniqueConstraint("audit_id", name="uq_audit_id"),)

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(String(128), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(96), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ReconciliationClaimRow(Base):
    __tablename__ = "control_plane_reconciliation_claims"
    __table_args__ = (UniqueConstraint("run_id", name="uq_reconciliation_run"),)

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(128), nullable=False)
    worker_identity: Mapped[str] = mapped_column(String(160), nullable=False)
    claimed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class AdapterEvidenceRow(Base):
    __tablename__ = "control_plane_adapter_evidence"
    __table_args__ = (UniqueConstraint("role", name="uq_adapter_evidence_role"),)

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    role: Mapped[str] = mapped_column(String(96), nullable=False)
    component_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    digest: Mapped[str] = mapped_column(String(71), nullable=False)
    evidence_status: Mapped[str] = mapped_column(String(32), nullable=False)
    capabilities: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    synthetic_only: Mapped[bool] = mapped_column(Boolean, nullable=False)
    runtime_verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    evidence_ref: Mapped[str] = mapped_column(Text, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ManagedComponentRow(Base):
    """Versioned registration of an internal Control Plane implementation."""

    __tablename__ = "control_plane_managed_components"
    __table_args__ = (
        UniqueConstraint(
            "component_id",
            "version",
            name="uq_managed_component_version",
        ),
        UniqueConstraint(
            "descriptor_digest",
            name="uq_managed_component_descriptor_digest",
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    component_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    descriptor_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    descriptor: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    term_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    concept_refs: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    authority_claim: Mapped[str] = mapped_column(String(32), nullable=False)
    creates_human_checkpoint: Mapped[bool] = mapped_column(Boolean, nullable=False)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class AutomationSupervisorEventRow(Base):
    """Append-only cross-run supervision event within one approved Pilot scope."""

    __tablename__ = "control_plane_automation_supervisor_events"
    __table_args__ = (
        UniqueConstraint(
            "scope_ref",
            "sequence",
            name="uq_automation_supervisor_scope_sequence",
        ),
        UniqueConstraint(
            "idempotency_key",
            name="uq_automation_supervisor_idempotency",
        ),
        UniqueConstraint(
            "event_digest",
            name="uq_automation_supervisor_event_digest",
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    scope_ref: Mapped[str] = mapped_column(String(240), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    event_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class SignedGrantRow(Base):
    __tablename__ = "control_plane_signed_grants"
    __table_args__ = (
        UniqueConstraint("grant_id", name="uq_signed_grant_id"),
        UniqueConstraint("grant_digest", name="uq_signed_grant_digest"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    grant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    grant_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    key_id: Mapped[str] = mapped_column(String(96), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)


class RuntimeRunRow(Base):
    __tablename__ = "control_plane_runtime_runs"
    __table_args__ = (
        UniqueConstraint("run_id", name="uq_runtime_run_id"),
        UniqueConstraint("idempotency_key", name="uq_runtime_run_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(128), nullable=False)
    task_id: Mapped[str] = mapped_column(String(128), nullable=False)
    grant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    grant_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    composition_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    runtime_source_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    runtime_artifact_digest: Mapped[str | None] = mapped_column(
        String(71), nullable=True
    )
    runtime_image_digest: Mapped[str | None] = mapped_column(String(71), nullable=True)
    isolation_profile_digest: Mapped[str | None] = mapped_column(
        String(71), nullable=True
    )
    input_snapshot_refs: Mapped[list[str] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    invocation_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    invocation: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    worker_identity: Mapped[str | None] = mapped_column(String(160), nullable=True)
    cancel_reason_code: Mapped[str | None] = mapped_column(String(96), nullable=True)
    failure_reason_code: Mapped[str | None] = mapped_column(String(96), nullable=True)
    result_document: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    result_digest: Mapped[str | None] = mapped_column(String(71), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)


class RuntimeEventRow(Base):
    __tablename__ = "control_plane_runtime_events"
    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_runtime_event_sequence"),
        UniqueConstraint("event_digest", name="uq_runtime_event_digest"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(96), nullable=False)
    event_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ModelRouteRevisionRow(Base):
    """Immutable, non-secret Model Route configuration revision."""

    __tablename__ = "control_plane_model_route_revisions"
    __table_args__ = (
        UniqueConstraint("revision_digest", name="uq_model_route_revision_digest"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    route_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    provider: Mapped[str] = mapped_column(String(96), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    requested_model: Mapped[str] = mapped_column(String(160), nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    data_classification: Mapped[str] = mapped_column(String(48), nullable=False)
    budget_policy: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    resolution_mode: Mapped[str] = mapped_column(String(48), nullable=False)
    secret_ref: Mapped[str | None] = mapped_column(String(240), nullable=True)
    route_version: Mapped[str | None] = mapped_column(String(96), nullable=True)
    authentication: Mapped[dict[str, Any] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    credential_scope: Mapped[str | None] = mapped_column(String(48), nullable=True)
    authorized_node_refs: Mapped[list[str] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    qualification_evidence_refs: Mapped[list[str] | None] = mapped_column(
        JSON_DOCUMENT, nullable=True
    )
    budget_control_mode: Mapped[str | None] = mapped_column(
        String(48), nullable=True
    )
    approved_scope: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    runtime_binding: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    policy_binding: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ProviderObservationRow(Base):
    """Sanitized provider/model/price observation without raw provider data."""

    __tablename__ = "control_plane_provider_observations"
    __table_args__ = (
        UniqueConstraint("observation_digest", name="uq_provider_observation_digest"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    requested_model: Mapped[str] = mapped_column(String(160), nullable=False)
    resolved_model_id: Mapped[str] = mapped_column(String(192), nullable=False)
    input_usd_per_million_tokens: Mapped[str] = mapped_column(
        String(48), nullable=False
    )
    output_usd_per_million_tokens: Mapped[str] = mapped_column(
        String(48), nullable=False
    )
    cached_input_usd_per_million_tokens: Mapped[str] = mapped_column(
        String(48), nullable=False
    )
    source: Mapped[str] = mapped_column(String(512), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(48), nullable=False)
    regression_status: Mapped[str] = mapped_column(String(32), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    observation_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ModelRouteSnapshotRow(Base):
    """Immutable deployment preflight snapshot over one Route and Observation."""

    __tablename__ = "control_plane_model_route_snapshots"
    __table_args__ = (
        UniqueConstraint("snapshot_digest", name="uq_model_route_snapshot_digest"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    route_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    route_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    observation_digest: Mapped[str | None] = mapped_column(
        String(71), nullable=True
    )
    secret_ref: Mapped[str | None] = mapped_column(String(240), nullable=True)
    secret_binding_version: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    requested_model: Mapped[str] = mapped_column(String(160), nullable=False)
    resolved_model_id: Mapped[str | None] = mapped_column(
        String(192), nullable=True
    )
    endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    budget_policy: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    worst_case_cost: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    runtime_binding: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    policy_binding: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    snapshot_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class SemanticAuthorityReleaseRow(Base):
    """Verified read-only import of one Architecture semantic release."""

    __tablename__ = "control_plane_semantic_authority_releases"
    __table_args__ = (
        UniqueConstraint("release_id", name="uq_semantic_authority_release_id"),
        UniqueConstraint(
            "manifest_digest", name="uq_semantic_authority_manifest_digest"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    release_id: Mapped[str] = mapped_column(String(160), nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    authority_lock_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    architecture_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    source_digests: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    authority_claim: Mapped[str] = mapped_column(String(32), nullable=False)
    release_authorization: Mapped[bool] = mapped_column(Boolean, nullable=False)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class SemanticTermRow(Base):
    """Control Plane projection of a stable Architecture Term."""

    __tablename__ = "control_plane_semantic_terms"
    __table_args__ = (
        UniqueConstraint(
            "release_id", "term_id", name="uq_semantic_term_release_id"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    release_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    term_id: Mapped[str] = mapped_column(String(192), nullable=False, index=True)
    term_zh: Mapped[str] = mapped_column(String(160), nullable=False)
    term_en: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    publication_status: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_status: Mapped[str] = mapped_column(String(48), nullable=False)
    definition: Mapped[str] = mapped_column(Text, nullable=False)
    mapped_concept_refs: Mapped[list[str]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    depends_on_term_refs: Mapped[list[str]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    not_a: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    invariants: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    operator_exposure: Mapped[str] = mapped_column(String(48), nullable=False)
    authority_claim: Mapped[str] = mapped_column(String(32), nullable=False)
    creates_human_checkpoint: Mapped[bool] = mapped_column(Boolean, nullable=False)
    source_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ToolSemanticScopeRow(Base):
    """Registered operation-level Tool semantic scope without activation power."""

    __tablename__ = "control_plane_tool_semantic_scopes"
    __table_args__ = (
        UniqueConstraint("scope_id", name="uq_tool_semantic_scope_id"),
        UniqueConstraint(
            "tool_id",
            "tool_version",
            "operation_id",
            name="uq_tool_semantic_scope_operation",
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    scope_id: Mapped[str] = mapped_column(String(160), nullable=False)
    tool_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    operation_id: Mapped[str] = mapped_column(String(160), nullable=False)
    capability: Mapped[str] = mapped_column(String(160), nullable=False)
    domain: Mapped[str] = mapped_column(String(96), nullable=False)
    resource_kind: Mapped[str] = mapped_column(String(96), nullable=False)
    action: Mapped[str] = mapped_column(String(96), nullable=False)
    side_effect_class: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_scope_key: Mapped[str] = mapped_column(String(384), nullable=False)
    relationship_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    target_scope_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_status: Mapped[str] = mapped_column(String(48), nullable=False)
    owner_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    source_release_id: Mapped[str] = mapped_column(String(160), nullable=False)
    registration_only: Mapped[bool] = mapped_column(Boolean, nullable=False)
    activation_authorization: Mapped[bool] = mapped_column(Boolean, nullable=False)
    production_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class SystemRegistryRow(Base):
    """Logical system ownership projection; never a physical-migration receipt."""

    __tablename__ = "control_plane_system_registry"
    __table_args__ = (
        UniqueConstraint(
            "system_id", "system_version", name="uq_system_registry_version"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    system_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    system_version: Mapped[str] = mapped_column(String(32), nullable=False)
    display_name: Mapped[str] = mapped_column(String(192), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(32), nullable=False)
    ownership_status: Mapped[str] = mapped_column(String(48), nullable=False)
    department_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    responsible_role_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    composition_ref: Mapped[str] = mapped_column(String(384), nullable=False)
    source_locations: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    migration_status: Mapped[str] = mapped_column(String(48), nullable=False)
    decision_refs: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    evidence_status: Mapped[str] = mapped_column(String(48), nullable=False)
    runtime_effective: Mapped[bool] = mapped_column(Boolean, nullable=False)
    production_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False)
    source_release_id: Mapped[str] = mapped_column(String(160), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ControlledArtifactRow(Base):
    """Department-scoped document bytes behind an opaque Artifact reference."""

    __tablename__ = "control_plane_controlled_artifacts"
    __table_args__ = (
        UniqueConstraint("artifact_ref", name="uq_controlled_artifact_ref"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    artifact_ref: Mapped[str] = mapped_column(String(384), nullable=False)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(192), nullable=False)
    media_type: Mapped[str] = mapped_column(String(128), nullable=False)
    byte_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    data_classification: Mapped[str] = mapped_column(String(48), nullable=False)
    scan_status: Mapped[str] = mapped_column(String(48), nullable=False)
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    uploaded_by_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class DepartmentCockpitObjectRow(Base):
    """Durable D0 cockpit object projection keyed by immutable business ID."""

    __tablename__ = "control_plane_department_cockpit_objects"
    __table_args__ = (
        UniqueConstraint(
            "object_type", "object_id", name="uq_department_cockpit_object"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    object_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    object_id: Mapped[str] = mapped_column(String(160), nullable=False)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class PlanningSessionAuthorityRow(Base):
    """Authoritative planning-session binding; checkpoints are not authority."""

    __tablename__ = "control_plane_planning_sessions"
    __table_args__ = (
        UniqueConstraint("session_id", name="uq_planning_session_id"),
        UniqueConstraint("parent_task_id", name="uq_planning_parent_task"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(160), nullable=False)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    parent_task_id: Mapped[str] = mapped_column(String(160), nullable=False)
    professional_task_id: Mapped[str | None] = mapped_column(
        String(160), nullable=True, unique=True
    )
    predecessor_session_id: Mapped[str | None] = mapped_column(
        String(160), nullable=True
    )
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(48), nullable=False)
    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    round_count: Mapped[int] = mapped_column(Integer, nullable=False)
    route_id: Mapped[str] = mapped_column(String(160), nullable=False)
    route_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    route_selection_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    grant_id: Mapped[str] = mapped_column(String(160), nullable=False)
    grant_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PlanningTurnRow(Base):
    """Immutable question request and idempotent human answer command."""

    __tablename__ = "control_plane_planning_turns"
    __table_args__ = (
        UniqueConstraint("turn_id", name="uq_planning_turn_id"),
        UniqueConstraint("idempotency_key", name="uq_planning_turn_idempotency"),
        UniqueConstraint(
            "session_id", "round_number", name="uq_planning_turn_round"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    turn_id: Mapped[str] = mapped_column(String(160), nullable=False)
    session_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    round_number: Mapped[int] = mapped_column(Integer, nullable=False)
    question_request_id: Mapped[str] = mapped_column(String(160), nullable=False)
    question_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    question_document: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    answer_document: Mapped[dict[str, Any]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PlanningCommandRow(Base):
    """Idempotent resource command for create, retry, successor and stop."""

    __tablename__ = "control_plane_planning_commands"
    __table_args__ = (
        UniqueConstraint("command_id", name="uq_planning_command_id"),
        UniqueConstraint("idempotency_key", name="uq_planning_command_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    command_id: Mapped[str] = mapped_column(String(160), nullable=False)
    session_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    command_kind: Mapped[str] = mapped_column(String(48), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    result_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PlanningInvocationEvidenceRow(Base):
    """Immutable, redacted model invocation evidence for planning only."""

    __tablename__ = "control_plane_planning_invocation_evidence"
    __table_args__ = (
        UniqueConstraint("invocation_id", name="uq_planning_invocation_id"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    invocation_id: Mapped[str] = mapped_column(String(160), nullable=False)
    session_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    round_number: Mapped[int] = mapped_column(Integer, nullable=False)
    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    route_id: Mapped[str] = mapped_column(String(160), nullable=False)
    route_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    grant_id: Mapped[str] = mapped_column(String(160), nullable=False)
    provider_request_id: Mapped[str | None] = mapped_column(String(192), nullable=True)
    returned_model_id: Mapped[str | None] = mapped_column(String(192), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    cost_cny_micros: Mapped[int] = mapped_column(BigInteger, nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    response_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    schema_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status: Mapped[str] = mapped_column(String(48), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# Keep the shared SQLAlchemy registry complete for Alembic and callers that
# intentionally import only Base before invoking metadata.create_all().  The
# imported module defines tables only; it performs no I/O or runtime startup.
from . import lan_stage1_models as _lan_stage1_models  # noqa: F401
from . import runtime_artifact_models as _runtime_artifact_models  # noqa: F401

