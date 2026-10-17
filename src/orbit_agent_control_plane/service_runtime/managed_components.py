"""Durable registration for internal Control Plane implementation components.

These records classify and inventory code that implements existing architecture
concepts.  They are not Agent/Tool Registry entries, do not create authority,
and cannot replace an ExecutionGrant or a human checkpoint.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from ..ids import deterministic_id
from ..qualification.automation import canonical_digest
from .database import Database
from .models import (
    AuditEventRow,
    ManagedComponentRow,
    OutboxEventRow,
)
from .repositories import ServiceRepositoryError

GOVERNED_RELEASE_PIPELINE_COMPONENT_ID = "component_governed_release_pipeline"
GOVERNED_RELEASE_PIPELINE_VERSION = "0.3.2"
SEMANTIC_AUTHORITY_LOCK_DIGEST = (
    "sha256:ecf2f5d2e165addde44c9349edc01a52bbc3efa6c27ead5c8ce36a1c33d65407"
)
CONCEPT_CATALOG_DIGEST = (
    "sha256:d862c4f81ada477f6b8a60622a5f7803f7d85e261eba890027ab22ced96e6921"
)
TERM_REGISTRY_DIGEST = (
    "sha256:344f7c68ebcca2f1175d5a662dc2a36a97fd78b7a4c14d7a455332f227878b7e"
)
GOVERNED_RELEASE_PIPELINE_TERM = "orbit.term/governed-release-pipeline"
GOVERNED_RELEASE_PIPELINE_CONCEPTS = (
    "orbit.concept/agent-control-plane",
    "orbit.concept/automation-policy",
    "orbit.concept/task",
    "orbit.concept/execution-grant",
    "orbit.concept/runtime-composition",
    "orbit.concept/evaluation-report",
    "orbit.concept/receipt",
    "orbit.concept/audit-event",
)
_SOURCE_REFS = (
    "src/orbit_agent_control_plane/service_runtime/automation_supervisor.py",
    "src/orbit_agent_control_plane/service_runtime/pipeline.py",
    "src/orbit_agent_control_plane/service_runtime/model_route.py",
    "src/orbit_agent_control_plane/service_runtime/public_pilot_execution.py",
    "src/orbit_agent_control_plane/service_runtime/dataset_public_execution.py",
)


def build_governed_release_pipeline_descriptor(
    repository_root: Path,
) -> dict[str, Any]:
    """Build the non-secret descriptor for the resident Pipeline/Supervisor."""
    source_set = []
    for relative in _SOURCE_REFS:
        path = repository_root / relative
        if not path.is_file():
            path = Path(__file__).resolve().parent / Path(relative).name
        if not path.is_file():
            raise ServiceRepositoryError("managed_component_source_missing")
        source_set.append(
            {
                "source_ref": relative,
                "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    descriptor: dict[str, Any] = {
        "descriptor_version": "orbit.control-plane-managed-component/1",
        "component_id": GOVERNED_RELEASE_PIPELINE_COMPONENT_ID,
        "version": GOVERNED_RELEASE_PIPELINE_VERSION,
        "implementation_kind": "implementation_component",
        "implementation": {
            "pipeline": (
                "orbit_agent_control_plane.service_runtime.pipeline."
                "GovernedReleasePipeline"
            ),
            "supervisor": (
                "orbit_agent_control_plane.service_runtime.automation_supervisor."
                "AutomationSupervisor"
            ),
            "lifecycle": "resident_control_plane_service",
        },
        "architecture_mapping": {
            "semantic_authority_lock_digest": SEMANTIC_AUTHORITY_LOCK_DIGEST,
            "term_ref": GOVERNED_RELEASE_PIPELINE_TERM,
            "term_registry_digest": TERM_REGISTRY_DIGEST,
            "concept_refs": list(GOVERNED_RELEASE_PIPELINE_CONCEPTS),
            "concept_catalog_digest": CONCEPT_CATALOG_DIGEST,
        },
        "capabilities": [
            "failure_classification",
            "policy_subset_enforcement",
            "model_route_deploy_preflight",
            "same_runtime_family_remediation_guard",
            "attempt_budget_enforcement",
            "cross_run_supervision_replay",
            "terminal_state_reconciliation",
        ],
        "source_set": source_set,
        "authority_boundary": {
            "authority_claim": "none",
            "creates_human_checkpoint": False,
            "execution_grant_is_only_task_authority": True,
            "may_issue_execution_grant": False,
            "may_activate_agent_or_tool": False,
            "release_authorization": False,
        },
        "data_classification": "non_secret_control_metadata",
        "status": "registered",
    }
    descriptor["descriptor_digest"] = canonical_digest(descriptor)
    return descriptor


class ManagedComponentRegistry:
    """Persistent, idempotent inventory of internal implementation components."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def register(self, descriptor: Mapping[str, Any]) -> bool:
        normalized = _validate_descriptor(descriptor)
        component_id = normalized["component_id"]
        version = normalized["version"]
        descriptor_digest = normalized["descriptor_digest"]
        with self.database.session() as session:
            existing = session.scalar(
                select(ManagedComponentRow).where(
                    ManagedComponentRow.component_id == component_id,
                    ManagedComponentRow.version == version,
                )
            )
            if existing is not None:
                if (
                    existing.descriptor_digest != descriptor_digest
                    or existing.descriptor != normalized
                ):
                    raise ServiceRepositoryError("managed_component_version_conflict")
                return False
            registered_at = datetime.now(timezone.utc)
            mapping = normalized["architecture_mapping"]
            boundary = normalized["authority_boundary"]
            session.add(
                ManagedComponentRow(
                    component_id=component_id,
                    version=version,
                    descriptor_digest=descriptor_digest,
                    descriptor=normalized,
                    status=normalized["status"],
                    term_ref=mapping["term_ref"],
                    concept_refs=mapping["concept_refs"],
                    authority_claim=boundary["authority_claim"],
                    creates_human_checkpoint=boundary["creates_human_checkpoint"],
                    registered_at=registered_at,
                )
            )
            audit_id = deterministic_id(
                "audit", "managed-component", component_id, version
            )
            session.add(
                AuditEventRow(
                    audit_id=audit_id,
                    correlation_id=component_id,
                    event_type="managed_component_registered",
                    actor_ref="component_control_plane_service_bootstrap",
                    payload={
                        "component_id": component_id,
                        "version": version,
                        "descriptor_digest": descriptor_digest,
                        "authority_claim": "none",
                        "release_authorization": False,
                    },
                    recorded_at=registered_at,
                )
            )
            session.add(
                OutboxEventRow(
                    event_id=deterministic_id(
                        "outbox", "managed-component", component_id, version
                    ),
                    topic="control-plane.managed-component.registered",
                    aggregate_ref=f"managed-component://{component_id}/{version}",
                    payload={
                        "component_id": component_id,
                        "version": version,
                        "descriptor_digest": descriptor_digest,
                        "authority_claim": "none",
                        "release_authorization": False,
                    },
                    status="pending",
                    attempts=0,
                    created_at=registered_at,
                    published_at=None,
                )
            )
        return True

    def current(self, component_id: str) -> dict[str, Any] | None:
        with self.database.session() as session:
            row = session.scalar(
                select(ManagedComponentRow)
                .where(ManagedComponentRow.component_id == component_id)
                .order_by(ManagedComponentRow.id.desc())
                .limit(1)
            )
            return None if row is None else _projection(row)

    def all(self) -> tuple[dict[str, Any], ...]:
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(ManagedComponentRow).order_by(
                        ManagedComponentRow.component_id,
                        ManagedComponentRow.id.desc(),
                    )
                )
            )
        return tuple(_projection(row) for row in rows)


def _validate_descriptor(descriptor: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(descriptor)
    expected = {
        "descriptor_version",
        "component_id",
        "version",
        "implementation_kind",
        "implementation",
        "architecture_mapping",
        "capabilities",
        "source_set",
        "authority_boundary",
        "data_classification",
        "status",
        "descriptor_digest",
    }
    if set(normalized) != expected:
        raise ServiceRepositoryError("managed_component_descriptor_invalid")
    mapping = normalized.get("architecture_mapping")
    boundary = normalized.get("authority_boundary")
    claimed_digest = normalized.pop("descriptor_digest", None)
    computed_digest = canonical_digest(normalized)
    normalized["descriptor_digest"] = claimed_digest
    if (
        normalized["descriptor_version"]
        != "orbit.control-plane-managed-component/1"
        or normalized["implementation_kind"] != "implementation_component"
        or normalized["status"] != "registered"
        or normalized["data_classification"] != "non_secret_control_metadata"
        or not isinstance(mapping, dict)
        or mapping.get("term_ref") != GOVERNED_RELEASE_PIPELINE_TERM
        or mapping.get("semantic_authority_lock_digest")
        != SEMANTIC_AUTHORITY_LOCK_DIGEST
        or mapping.get("term_registry_digest") != TERM_REGISTRY_DIGEST
        or mapping.get("concept_catalog_digest") != CONCEPT_CATALOG_DIGEST
        or mapping.get("concept_refs") != list(GOVERNED_RELEASE_PIPELINE_CONCEPTS)
        or not isinstance(boundary, dict)
        or boundary.get("authority_claim") != "none"
        or boundary.get("creates_human_checkpoint") is not False
        or boundary.get("execution_grant_is_only_task_authority") is not True
        or boundary.get("may_issue_execution_grant") is not False
        or boundary.get("may_activate_agent_or_tool") is not False
        or boundary.get("release_authorization") is not False
        or claimed_digest != computed_digest
    ):
        raise ServiceRepositoryError("managed_component_descriptor_invalid")
    return normalized


def _projection(row: ManagedComponentRow) -> dict[str, Any]:
    return {
        "component_id": row.component_id,
        "version": row.version,
        "descriptor_digest": row.descriptor_digest,
        "status": row.status,
        "term_ref": row.term_ref,
        "concept_refs": list(row.concept_refs),
        "authority_claim": row.authority_claim,
        "creates_human_checkpoint": row.creates_human_checkpoint,
        "descriptor": dict(row.descriptor),
        "registered_at": row.registered_at.isoformat(),
        "release_authorization": False,
    }

