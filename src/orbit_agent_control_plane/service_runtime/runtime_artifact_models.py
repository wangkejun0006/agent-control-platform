"""Persistence rows for D0 Runtime Artifact and container-run evidence.

These rows are deliberately separate from Agent Registry and Task authority.
They record immutable candidates, node observations, and append-only receipts;
none of them activates an Agent or grants execution authority.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .models import IDENTITY, JSON_DOCUMENT, Base


class RuntimeArtifactRevisionRow(Base):
    __tablename__ = "control_plane_runtime_artifact_revisions"
    __table_args__ = (
        UniqueConstraint("revision_digest", name="uq_runtime_artifact_revision_digest"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    artifact_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    runtime_family: Mapped[str] = mapped_column(String(96), nullable=False)
    runtime_source_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    runtime_image_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    isolation_profile_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    adapter_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    target_platform: Mapped[str] = mapped_column(String(64), nullable=False)
    bundle_ref: Mapped[str] = mapped_column(String(384), nullable=False)
    bundle_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    recorded_by_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuntimeArtifactRevocationRow(Base):
    __tablename__ = "control_plane_runtime_artifact_revocations"
    __table_args__ = (
        UniqueConstraint(
            "artifact_id", "revision_digest", name="uq_runtime_artifact_revocation"
        ),
        UniqueConstraint(
            "idempotency_key", name="uq_runtime_artifact_revocation_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    revocation_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    artifact_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    revoked_by_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    receipt_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuntimeNodeCapabilityReportRow(Base):
    __tablename__ = "control_plane_runtime_node_capability_reports"
    __table_args__ = (
        UniqueConstraint("report_digest", name="uq_runtime_node_capability_digest"),
        UniqueConstraint(
            "idempotency_key", name="uq_runtime_node_capability_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    report_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuntimeArtifactImportReceiptRow(Base):
    __tablename__ = "control_plane_runtime_artifact_import_receipts"
    __table_args__ = (
        UniqueConstraint("receipt_id", name="uq_runtime_artifact_import_receipt"),
        UniqueConstraint(
            "idempotency_key", name="uq_runtime_artifact_import_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    receipt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    artifact_id: Mapped[str] = mapped_column(String(160), nullable=False)
    revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    runtime_image_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    capability_report_digest: Mapped[str | None] = mapped_column(
        String(71), nullable=True
    )
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuntimeNodeLeaseClaimRow(Base):
    __tablename__ = "control_plane_runtime_node_lease_claims"
    __table_args__ = (
        UniqueConstraint("lease_id", name="uq_runtime_node_lease_claim_lease"),
        UniqueConstraint("run_id", name="uq_runtime_node_lease_claim_run"),
        UniqueConstraint(
            "idempotency_key", name="uq_runtime_node_lease_claim_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    lease_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    run_id: Mapped[str] = mapped_column(String(128), nullable=False)
    invocation_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    capability_report_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RuntimeContainerEvidenceRow(Base):
    __tablename__ = "control_plane_runtime_container_evidence"
    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_runtime_container_sequence"),
        UniqueConstraint("evidence_digest", name="uq_runtime_container_digest"),
        UniqueConstraint(
            "idempotency_key", name="uq_runtime_container_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    evidence_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ModelGatewayTokenExchangeRow(Base):
    __tablename__ = "control_plane_model_gateway_token_exchanges"
    __table_args__ = (
        UniqueConstraint(
            "idempotency_key", name="uq_model_gateway_exchange_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    attempt_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False)
    task_id: Mapped[str] = mapped_column(String(160), nullable=False)
    grant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    run_id: Mapped[str] = mapped_column(String(128), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(96), nullable=False)
    token_issued: Mapped[bool] = mapped_column(Boolean, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DepartmentTaskDecisionRow(Base):
    __tablename__ = "control_plane_department_task_decisions"
    __table_args__ = (
        UniqueConstraint("decision_id", name="uq_department_task_decision_id"),
        UniqueConstraint("decision_digest", name="uq_department_task_decision_digest"),
        UniqueConstraint(
            "idempotency_key", name="uq_department_task_decision_idempotency"
        ),
        UniqueConstraint(
            "task_id", "task_revision", name="uq_department_task_decision_subject"
        ),
        UniqueConstraint("receipt_id", name="uq_department_task_decision_receipt"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(String(128), nullable=False)
    decision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    task_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    task_scope_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    package_id: Mapped[str] = mapped_column(String(160), nullable=False)
    package_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    actor_role_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    receipt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

