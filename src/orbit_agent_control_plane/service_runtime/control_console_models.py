"""SQL rows owned by the company Control Plane console vertical slice."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .models import IDENTITY, JSON_DOCUMENT, Base


class ModelRouteDecisionRow(Base):
    """Immutable company decision over one exact Model Route revision."""

    __tablename__ = "control_plane_model_route_decisions"
    __table_args__ = (
        UniqueConstraint("decision_id", name="uq_model_route_decision_id"),
        UniqueConstraint("decision_digest", name="uq_model_route_decision_digest"),
        UniqueConstraint(
            "idempotency_key", name="uq_model_route_decision_idempotency"
        ),
        UniqueConstraint("receipt_id", name="uq_model_route_decision_receipt"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(String(128), nullable=False)
    decision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    route_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    route_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    snapshot_digest: Mapped[str | None] = mapped_column(String(71), nullable=True)
    source_decision_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    actor_role_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    receipt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class TaskScopeAuditRow(Base):
    """Evidence-only deterministic audit of one immutable Department Task revision."""

    __tablename__ = "control_plane_task_scope_audits"
    __table_args__ = (
        UniqueConstraint("audit_record_id", name="uq_task_scope_audit_record_id"),
        UniqueConstraint(
            "idempotency_key", name="uq_task_scope_audit_idempotency"
        ),
        UniqueConstraint("receipt_id", name="uq_task_scope_audit_receipt"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    audit_record_id: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    task_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    task_revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    task_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON_DOCUMENT, nullable=False)
    grant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    grant_action: Mapped[str] = mapped_column(String(32), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    receipt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ControlConsoleCommandRow(Base):
    """Idempotency ledger for every company-console mutation command."""

    __tablename__ = "control_plane_console_commands"
    __table_args__ = (
        UniqueConstraint(
            "idempotency_key", name="uq_control_console_command_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    command_kind: Mapped[str] = mapped_column(String(96), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(240), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ModelRouteCredentialBindingRow(Base):
    """Non-secret binding and qualification state for one authentication route."""

    __tablename__ = "control_plane_model_route_credential_bindings"
    __table_args__ = (
        UniqueConstraint("binding_id", name="uq_model_route_credential_binding_id"),
        UniqueConstraint(
            "idempotency_key", name="uq_model_route_credential_binding_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    binding_id: Mapped[str] = mapped_column(String(160), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    route_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    route_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    authentication_mode: Mapped[str] = mapped_column(String(48), nullable=False)
    credential_binding_ref: Mapped[str] = mapped_column(String(240), nullable=False)
    credential_scope: Mapped[str] = mapped_column(String(48), nullable=False)
    authorized_node_refs: Mapped[list[str]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    qualification_evidence_refs: Mapped[list[str]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    status: Mapped[str] = mapped_column(String(48), nullable=False)
    secret_fingerprint: Mapped[str | None] = mapped_column(String(71), nullable=True)
    secret_version: Mapped[str | None] = mapped_column(String(96), nullable=True)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ModelRouteRetirementRow(Base):
    """Append-only retirement evidence; route history remains readable."""

    __tablename__ = "control_plane_model_route_retirements"
    __table_args__ = (
        UniqueConstraint("retirement_id", name="uq_model_route_retirement_id"),
        UniqueConstraint(
            "idempotency_key", name="uq_model_route_retirement_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    retirement_id: Mapped[str] = mapped_column(String(160), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    route_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    route_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    receipt_id: Mapped[str] = mapped_column(String(160), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class RuntimeAdapterCapabilityReportRow(Base):
    """Sanitized node evidence for a fixed runtime adapter revision."""

    __tablename__ = "control_plane_runtime_adapter_capability_reports"
    __table_args__ = (
        UniqueConstraint("report_id", name="uq_runtime_adapter_capability_report_id"),
        UniqueConstraint(
            "idempotency_key", name="uq_runtime_adapter_capability_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    report_id: Mapped[str] = mapped_column(String(160), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    node_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    adapter_id: Mapped[str] = mapped_column(String(160), nullable=False)
    adapter_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    authentication_modes: Mapped[list[str]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    capability_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    status: Mapped[str] = mapped_column(String(48), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

