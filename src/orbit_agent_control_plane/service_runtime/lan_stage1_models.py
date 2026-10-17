"""Persistent D0 records for the Stage-1 LAN candidate.

The tables deliberately store only credential digests and certificate public
material.  They do not contain a CA private key, model credential, Execution
Grant, or production authorization.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .models import IDENTITY, JSON_DOCUMENT, Base


class LanHumanAccountRow(Base):
    __tablename__ = "control_plane_lan_human_accounts"
    __table_args__ = (
        UniqueConstraint("account_id", name="uq_lan_human_account_id"),
        UniqueConstraint("username", name="uq_lan_human_username"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    account_id: Mapped[str] = mapped_column(String(96), nullable=False)
    username: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(96), nullable=False)
    human_ref: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role_ref: Mapped[str] = mapped_column(String(96), nullable=False)
    department_id: Mapped[str | None] = mapped_column(String(96), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    failed_login_count: Mapped[int] = mapped_column(nullable=False)
    failed_window_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LanInviteRow(Base):
    __tablename__ = "control_plane_lan_invites"
    __table_args__ = (
        UniqueConstraint("invite_id", name="uq_lan_invite_id"),
        UniqueConstraint("token_digest", name="uq_lan_invite_token_digest"),
        UniqueConstraint("idempotency_key", name="uq_lan_invite_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    invite_id: Mapped[str] = mapped_column(String(128), nullable=False)
    token_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    role_ref: Mapped[str] = mapped_column(String(96), nullable=False)
    invited_by_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_by_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)


class LanSessionRow(Base):
    __tablename__ = "control_plane_lan_sessions"
    __table_args__ = (
        UniqueConstraint("session_id", name="uq_lan_session_id"),
        UniqueConstraint("session_digest", name="uq_lan_session_digest"),
        UniqueConstraint("login_idempotency_key", name="uq_lan_session_login_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    session_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    csrf_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    account_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    login_idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    login_request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    authenticated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reauthenticated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LanDepartmentObservationContextRow(Base):
    """Short-lived, read-only company-admin department observation context."""

    __tablename__ = "control_plane_lan_department_observation_contexts"
    __table_args__ = (
        UniqueConstraint("context_id", name="uq_lan_department_observation_context_id"),
        UniqueConstraint(
            "idempotency_key",
            name="uq_lan_department_observation_context_idempotency",
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    context_id: Mapped[str] = mapped_column(String(128), nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)


class LanEnrollmentCodeRow(Base):
    __tablename__ = "control_plane_lan_enrollment_codes"
    __table_args__ = (
        UniqueConstraint("enrollment_id", name="uq_lan_enrollment_id"),
        UniqueConstraint("code_digest", name="uq_lan_enrollment_code_digest"),
        UniqueConstraint("idempotency_key", name="uq_lan_enrollment_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    enrollment_id: Mapped[str] = mapped_column(String(128), nullable=False)
    code_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False)
    expected_uri_san: Mapped[str] = mapped_column(String(384), nullable=False)
    created_by_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_attempt_count: Mapped[int] = mapped_column(nullable=False)
    failed_window_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LanCertificateBindingRow(Base):
    __tablename__ = "control_plane_lan_certificate_bindings"
    __table_args__ = (
        UniqueConstraint("binding_id", name="uq_lan_cert_binding_id"),
        UniqueConstraint("fingerprint", name="uq_lan_cert_fingerprint"),
        UniqueConstraint("serial_number", name="uq_lan_cert_serial"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    binding_id: Mapped[str] = mapped_column(String(128), nullable=False)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False)
    uri_san: Mapped[str] = mapped_column(String(384), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(71), nullable=False)
    serial_number: Mapped[str] = mapped_column(String(96), nullable=False)
    certificate_der: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    public_key_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    renewal_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LanCertificateRevocationRow(Base):
    __tablename__ = "control_plane_lan_certificate_revocations"
    __table_args__ = (
        UniqueConstraint("revocation_id", name="uq_lan_cert_revocation_id"),
        UniqueConstraint("fingerprint", name="uq_lan_cert_revoked_fingerprint"),
        UniqueConstraint("idempotency_key", name="uq_lan_cert_revocation_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    revocation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(71), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    revoked_by_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LanNodeHeartbeatRow(Base):
    __tablename__ = "control_plane_lan_node_heartbeats"
    __table_args__ = (
        UniqueConstraint("heartbeat_id", name="uq_lan_heartbeat_id"),
        UniqueConstraint("node_id", "sequence", name="uq_lan_heartbeat_sequence"),
        UniqueConstraint("idempotency_key", name="uq_lan_heartbeat_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    heartbeat_id: Mapped[str] = mapped_column(String(128), nullable=False)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    capability_report_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LanCodexInstallationAttemptRow(Base):
    """Authoritative installation attempt projection; never a Runtime run."""

    __tablename__ = "control_plane_lan_codex_installation_attempts"
    __table_args__ = (
        UniqueConstraint("attempt_id", name="uq_lan_codex_install_attempt_id"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    attempt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    predecessor_attempt_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    codex_cli_version: Mapped[str] = mapped_column(String(32), nullable=False)
    target_platform: Mapped[str] = mapped_column(String(96), nullable=False)
    release_manifest_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    archive_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    latest_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    current_stage: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    intermediate_events_available: Mapped[bool] = mapped_column(Boolean, nullable=False)
    resource_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LanCodexInstallationEventRow(Base):
    """Append-only, sanitized device installation stage evidence."""

    __tablename__ = "control_plane_lan_codex_installation_events"
    __table_args__ = (
        UniqueConstraint("event_id", name="uq_lan_codex_install_event_id"),
        UniqueConstraint(
            "attempt_id", "sequence", name="uq_lan_codex_install_event_sequence"
        ),
        UniqueConstraint(
            "idempotency_key", name="uq_lan_codex_install_event_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    document_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LanCodexInstallationReceiptRow(Base):
    """Immutable terminal Receipt evidence for one exact Codex CLI release."""

    __tablename__ = "control_plane_lan_codex_installation_receipts"
    __table_args__ = (
        UniqueConstraint("receipt_id", name="uq_lan_codex_install_receipt_id"),
        UniqueConstraint("attempt_id", name="uq_lan_codex_install_receipt_attempt"),
        UniqueConstraint(
            "idempotency_key", name="uq_lan_codex_install_receipt_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    receipt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    codex_cli_version: Mapped[str] = mapped_column(String(32), nullable=False)
    target_platform: Mapped[str] = mapped_column(String(96), nullable=False)
    release_manifest_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    archive_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    evidence_source: Mapped[str] = mapped_column(String(48), nullable=False)
    intermediate_events_available: Mapped[bool] = mapped_column(Boolean, nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LanArtifactDownloadAssignmentRow(Base):
    """Department artifact download assignment; never a release authority."""
    __tablename__ = "control_plane_lan_artifact_download_assignments"
    __table_args__ = (
        UniqueConstraint("assignment_id", name="uq_lan_artifact_assignment_id"),
        UniqueConstraint(
            "department_id", "artifact_id", "revision_digest",
            name="uq_lan_artifact_assignment_subject",
        ),
        UniqueConstraint(
            "idempotency_key", name="uq_lan_artifact_assignment_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    assignment_id: Mapped[str] = mapped_column(String(128), nullable=False)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    artifact_id: Mapped[str] = mapped_column(String(160), nullable=False)
    revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    bundle_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_by_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LanDeploymentReleaseLockRow(Base):
    """Immutable cross-repository deployment candidate; never an authority grant."""

    __tablename__ = "control_plane_lan_deployment_release_locks"
    __table_args__ = (
        UniqueConstraint("lock_id", name="uq_lan_deployment_release_lock_id"),
        UniqueConstraint("lock_digest", name="uq_lan_deployment_release_lock_digest"),
        UniqueConstraint(
            "idempotency_key", name="uq_lan_deployment_release_lock_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    lock_id: Mapped[str] = mapped_column(String(128), nullable=False)
    lock_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    architecture_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    control_plane_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    department_cockpit_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    semantic_authority_release_id: Mapped[str] = mapped_column(
        String(96), nullable=False
    )
    semantic_authority_manifest_digest: Mapped[str] = mapped_column(
        String(71), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    created_by_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LanArtifactDownloadReceiptRow(Base):
    __tablename__ = "control_plane_lan_artifact_download_receipts"
    __table_args__ = (
        UniqueConstraint("receipt_id", name="uq_lan_download_receipt_id"),
        UniqueConstraint("idempotency_key", name="uq_lan_download_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    receipt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False)
    artifact_id: Mapped[str] = mapped_column(String(160), nullable=False)
    revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    bundle_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    etag: Mapped[str] = mapped_column(String(96), nullable=False)
    range_start: Mapped[int] = mapped_column(BigInteger, nullable=False)
    range_end: Mapped[int] = mapped_column(BigInteger, nullable=False)
    total_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    completed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LanMutationCommandRow(Base):
    __tablename__ = "control_plane_lan_mutation_commands"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_lan_mutation_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    operation: Mapped[str] = mapped_column(String(96), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    response_document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LanAssistedMaintenanceSessionRow(Base):
    """Locally initiated, short-lived node maintenance window; never a Grant."""

    __tablename__ = "control_plane_lan_assisted_maintenance_sessions"
    __table_args__ = (
        UniqueConstraint("session_id", name="uq_lan_maintenance_session_id"),
        UniqueConstraint("session_digest", name="uq_lan_maintenance_session_digest"),
        UniqueConstraint("idempotency_key", name="uq_lan_maintenance_session_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    session_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False)
    certificate_fingerprint: Mapped[str] = mapped_column(String(71), nullable=False)
    allowed_handler_ids: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    close_reason: Mapped[str | None] = mapped_column(String(96), nullable=True)


class LanMaintenanceJobRow(Base):
    """Digest-pinned allowlisted maintenance job; contains no command surface."""

    __tablename__ = "control_plane_lan_maintenance_jobs"
    __table_args__ = (
        UniqueConstraint("job_id", name="uq_lan_maintenance_job_id"),
        UniqueConstraint("job_digest", name="uq_lan_maintenance_job_digest"),
        UniqueConstraint("idempotency_key", name="uq_lan_maintenance_job_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(128), nullable=False)
    job_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False)
    handler_id: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_name: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    nonce_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_by_identity: Mapped[str | None] = mapped_column(String(192), nullable=True)


class LanMaintenanceReceiptRow(Base):
    """Append-only sanitized maintenance evidence."""

    __tablename__ = "control_plane_lan_maintenance_receipts"
    __table_args__ = (
        UniqueConstraint("receipt_id", name="uq_lan_maintenance_receipt_id"),
        UniqueConstraint("job_id", name="uq_lan_maintenance_receipt_job"),
        UniqueConstraint("idempotency_key", name="uq_lan_maintenance_receipt_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    receipt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    job_id: Mapped[str] = mapped_column(String(128), nullable=False)
    job_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False)
    handler_id: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(96), nullable=False)
    sanitized_summary: Mapped[str] = mapped_column(Text, nullable=False)
    output_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    output_truncated: Mapped[bool] = mapped_column(Boolean, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

