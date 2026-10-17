"""Durable rows for company model catalog and department Agent proposals.

These rows are evidence and proposal records.  They do not express an
ApprovalDecision, Agent activation, ExecutionGrant, RuntimeComposition, or
WorkerLease.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .models import IDENTITY, JSON_DOCUMENT, Base


class ProviderModelDiscoveryRow(Base):
    __tablename__ = "control_plane_provider_model_discoveries"
    __table_args__ = (
        UniqueConstraint("discovery_id", name="uq_provider_model_discovery_id"),
        UniqueConstraint("discovery_digest", name="uq_provider_model_discovery_digest"),
        UniqueConstraint(
            "idempotency_key", name="uq_provider_model_discovery_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    discovery_id: Mapped[str] = mapped_column(String(160), nullable=False)
    discovery_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    provider_preset_id: Mapped[str] = mapped_column(
        String(160), nullable=False, index=True
    )
    provider_preset_revision_digest: Mapped[str] = mapped_column(
        String(71), nullable=False
    )
    region_id: Mapped[str] = mapped_column(String(96), nullable=False)
    connection_alias: Mapped[str] = mapped_column(String(160), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ProviderOnboardingProposalRow(Base):
    __tablename__ = "control_plane_provider_onboarding_proposals"
    __table_args__ = (
        UniqueConstraint("proposal_id", name="uq_provider_onboarding_proposal_id"),
        UniqueConstraint("idempotency_key", name="uq_provider_onboarding_idempotency"),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    proposal_id: Mapped[str] = mapped_column(String(160), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ModelCatalogEntryRow(Base):
    __tablename__ = "control_plane_model_catalog_entries"
    __table_args__ = (
        UniqueConstraint(
            "entry_revision_digest", name="uq_model_catalog_entry_revision"
        ),
        UniqueConstraint(
            "entry_id", "revision", name="uq_model_catalog_subject_revision"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    entry_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    entry_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    provider_preset_id: Mapped[str] = mapped_column(String(160), nullable=False)
    discovery_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(48), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    created_by_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ModelCatalogCredentialBindingRow(Base):
    __tablename__ = "control_plane_model_catalog_credential_bindings"
    __table_args__ = (
        UniqueConstraint("binding_id", name="uq_model_catalog_credential_binding_id"),
        UniqueConstraint(
            "idempotency_key", name="uq_model_catalog_credential_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    binding_id: Mapped[str] = mapped_column(String(160), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    entry_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    entry_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    authentication_mode: Mapped[str] = mapped_column(String(48), nullable=False)
    binding_version: Mapped[str | None] = mapped_column(String(160), nullable=True)
    credential_binding_ref: Mapped[str] = mapped_column(String(240), nullable=False)
    qualification_evidence_refs: Mapped[list[str]] = mapped_column(
        JSON_DOCUMENT, nullable=False
    )
    status: Mapped[str] = mapped_column(String(48), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ModelCatalogLifecycleReceiptRow(Base):
    __tablename__ = "control_plane_model_catalog_lifecycle_receipts"
    __table_args__ = (
        UniqueConstraint("receipt_id", name="uq_model_catalog_lifecycle_receipt_id"),
        UniqueConstraint(
            "receipt_digest", name="uq_model_catalog_lifecycle_receipt_digest"
        ),
        UniqueConstraint(
            "idempotency_key", name="uq_model_catalog_lifecycle_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    receipt_id: Mapped[str] = mapped_column(String(160), nullable=False)
    receipt_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    entry_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    entry_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    transition: Mapped[str] = mapped_column(String(64), nullable=False)
    from_state: Mapped[str] = mapped_column(String(48), nullable=False)
    to_state: Mapped[str] = mapped_column(String(48), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class DepartmentAgentProposalRow(Base):
    __tablename__ = "control_plane_department_agent_proposals"
    __table_args__ = (
        UniqueConstraint("package_digest", name="uq_department_agent_proposal_package"),
        UniqueConstraint(
            "proposal_id", "revision", name="uq_agent_proposal_subject_revision"
        ),
        UniqueConstraint(
            "idempotency_key", name="uq_department_agent_proposal_idempotency"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    proposal_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    package_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    supersedes_package_digest: Mapped[str | None] = mapped_column(
        String(71), nullable=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    department_id: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    selected_catalog_entry_id: Mapped[str] = mapped_column(String(160), nullable=False)
    selected_catalog_entry_revision_digest: Mapped[str] = mapped_column(
        String(71), nullable=False
    )
    agent_definition_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    agent_binding_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    model_route_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    model_route_revision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    submitted_by_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class DepartmentAgentProposalDecisionRow(Base):
    """Exact human decision for the existing agent_activation scope."""

    __tablename__ = "control_plane_department_agent_proposal_decisions"
    __table_args__ = (
        UniqueConstraint(
            "decision_id", name="uq_department_agent_proposal_decision_id"
        ),
        UniqueConstraint(
            "decision_digest", name="uq_department_agent_proposal_decision_digest"
        ),
        UniqueConstraint(
            "idempotency_key", name="uq_department_agent_proposal_decision_idempotency"
        ),
        UniqueConstraint(
            "package_digest", name="uq_department_agent_proposal_terminal_decision"
        ),
    )

    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(String(160), nullable=False)
    decision_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    proposal_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    package_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    agent_definition_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    decision_scope: Mapped[str] = mapped_column(String(48), nullable=False)
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ModelCatalogCommandRow(Base):
    __tablename__ = "control_plane_model_catalog_commands"
    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    idempotency_key: Mapped[str] = mapped_column(
        String(192), nullable=False, unique=True
    )
    operation: Mapped[str] = mapped_column(String(96), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(160), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(71), nullable=False)
    response: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class ProviderOnboardingReviewRow(Base):
    __tablename__ = "control_plane_provider_onboarding_reviews"
    __table_args__ = (
        UniqueConstraint(
            "proposal_id", "revision", name="uq_provider_onboarding_review_revision"
        ),
    )
    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    proposal_id: Mapped[str] = mapped_column(String(160), nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    review_digest: Mapped[str] = mapped_column(String(71), nullable=False, unique=True)
    document: Mapped[dict[str, Any]] = mapped_column(JSON_DOCUMENT, nullable=False)

