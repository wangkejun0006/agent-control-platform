"""Company semantic, Tool scope, and logical System registry projections."""

from __future__ import annotations

import hashlib
import json
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
    SemanticAuthorityReleaseRow,
    SemanticTermRow,
    SystemRegistryRow,
    ToolSemanticScopeRow,
)
from .semantic_authority import (
    SemanticAuthorityBundle,
    SemanticAuthorityError,
    load_semantic_authority_bundle,
)


class GovernanceCatalogError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class GovernanceCatalogService:
    """Read-only Architecture projection plus governed CP registrations."""

    def __init__(self, *, database: Database, repository_root: Path) -> None:
        self.database = database
        self.repository_root = repository_root
        try:
            self.bundle = load_semantic_authority_bundle(repository_root)
        except SemanticAuthorityError as error:
            raise GovernanceCatalogError(error.reason_code) from error
        self.scope_seed = _read_json(
            repository_root / "references/company-tool-semantic-scopes.json"
        )
        self.system_seed = _read_json(
            repository_root / "references/company-system-registry.seed.json"
        )
        self.tool_profile = _read_json(
            repository_root / "references/dataset-tool-intake-profile.json"
        )
        _validate_seed_documents(
            bundle=self.bundle,
            scope_seed=self.scope_seed,
            system_seed=self.system_seed,
            tool_profile=self.tool_profile,
        )

    def bootstrap(self) -> dict[str, Any]:
        """Import exact released bytes and idempotently seed governed projections."""

        now = _utcnow()
        with self.database.session() as session:
            release = session.scalar(
                select(SemanticAuthorityReleaseRow).where(
                    SemanticAuthorityReleaseRow.release_id == self.bundle.release_id
                )
            )
            if release is None:
                release = SemanticAuthorityReleaseRow(
                    release_id=self.bundle.release_id,
                    manifest_digest=self.bundle.manifest_digest,
                    authority_lock_digest=self.bundle.authority_lock_digest,
                    architecture_commit=self.bundle.architecture_commit,
                    source_digests=self.bundle.source_digests,
                    status="released_internal_alpha",
                    authority_claim="projection_only",
                    release_authorization=False,
                    imported_at=now,
                )
                session.add(release)
                for term in self.bundle.terms:
                    session.add(
                        SemanticTermRow(
                            release_id=self.bundle.release_id,
                            term_id=term["id"],
                            term_zh=term["term_zh"],
                            term_en=term["term_en"],
                            kind=term["kind"],
                            publication_status=term["publication_stage"],
                            evidence_status=term["evidence_status"],
                            definition=term["definition"],
                            mapped_concept_refs=term["maps_to_concepts"],
                            depends_on_term_refs=term["depends_on_terms"],
                            not_a=term["not_a"],
                            invariants=term["invariants"],
                            operator_exposure=term["operator_exposure"],
                            authority_claim=term["authority_claim"],
                            creates_human_checkpoint=term[
                                "creates_human_checkpoint"
                            ],
                            source_digest=self.bundle.source_digests[
                                "term_registry"
                            ],
                            imported_at=now,
                        )
                    )
                _add_audit(
                    session,
                    event_type="semantic_authority_release_imported",
                    correlation_id=self.bundle.release_id,
                    actor_ref="workload_control_plane_bootstrap",
                    payload={
                        "release_id": self.bundle.release_id,
                        "manifest_digest": self.bundle.manifest_digest,
                        "term_count": len(self.bundle.terms),
                        "authority_claim": "projection_only",
                        "release_authorization": False,
                    },
                    recorded_at=now,
                )
            else:
                _require_release_match(release, self.bundle)
                term_count = len(
                    tuple(
                        session.scalars(
                            select(SemanticTermRow).where(
                                SemanticTermRow.release_id
                                == self.bundle.release_id
                            )
                        )
                    )
                )
                if term_count != len(self.bundle.terms):
                    raise GovernanceCatalogError("semantic_projection_incomplete")

            for system in self.system_seed["systems"]:
                _seed_system(
                    session,
                    system=system,
                    release_id=self.bundle.release_id,
                    recorded_at=now,
                )
            for scope in self.scope_seed["scopes"]:
                _seed_tool_scope(
                    session,
                    scope=scope,
                    release_id=self.bundle.release_id,
                    recorded_at=now,
                )
            session.flush()
        return {
            "semantic_release_id": self.bundle.release_id,
            "term_count": len(self.bundle.terms),
            "tool_scope_count": len(self.scope_seed["scopes"]),
            "system_count": len(self.system_seed["systems"]),
            "authority_claim": "projection_only",
            "release_authorization": False,
        }

    def terms(self) -> dict[str, Any]:
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(SemanticTermRow)
                    .where(SemanticTermRow.release_id == self.bundle.release_id)
                    .order_by(SemanticTermRow.term_id)
                )
            )
        return {
            "semantic_release_id": self.bundle.release_id,
            "terms": [_term_document(row) for row in rows],
            "authority_claim": "projection_only",
            "release_authorization": False,
        }

    def term(self, term_id: str) -> dict[str, Any]:
        with self.database.session() as session:
            row = session.scalar(
                select(SemanticTermRow).where(
                    SemanticTermRow.release_id == self.bundle.release_id,
                    SemanticTermRow.term_id == term_id,
                )
            )
        if row is None:
            raise GovernanceCatalogError("semantic_term_not_found")
        return {
            "semantic_release_id": self.bundle.release_id,
            "term": _term_document(row),
            "authority_claim": "projection_only",
            "release_authorization": False,
        }

    def tools(self) -> dict[str, Any]:
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(ToolSemanticScopeRow).order_by(
                        ToolSemanticScopeRow.tool_id,
                        ToolSemanticScopeRow.tool_version,
                        ToolSemanticScopeRow.operation_id,
                    )
                )
            )
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for row in rows:
            key = (row.tool_id, row.tool_version)
            document = grouped.setdefault(
                key,
                {
                    "tool_id": row.tool_id,
                    "version": row.tool_version,
                    "manifest_digest": row.manifest_digest,
                    "operations": [],
                    "registration_only": True,
                    "activation_authorization": False,
                    "production_authorized": False,
                },
            )
            if document["manifest_digest"] != row.manifest_digest:
                raise GovernanceCatalogError("tool_manifest_digest_drift")
            document["operations"].append(_tool_scope_document(row))
        return {
            "tools": list(grouped.values()),
            "semantic_authority_release_id": self.bundle.release_id,
            "release_authorization": False,
        }

    def tool(self, *, tool_id: str, tool_version: str) -> dict[str, Any]:
        values = self.tools()
        for tool in values["tools"]:
            if tool["tool_id"] == tool_id and tool["version"] == tool_version:
                return {**tool, "release_authorization": False}
        raise GovernanceCatalogError("tool_registration_not_found")

    def register_tool_scope(
        self, *, candidate: Mapping[str, Any], actor_ref: str
    ) -> dict[str, Any]:
        normalized = _validate_tool_scope_candidate(
            candidate, release_id=self.bundle.release_id
        )
        now = _utcnow()
        with self.database.session() as session:
            existing = session.scalar(
                select(ToolSemanticScopeRow).where(
                    ToolSemanticScopeRow.tool_id == normalized["tool_id"],
                    ToolSemanticScopeRow.tool_version
                    == normalized["tool_version"],
                    ToolSemanticScopeRow.operation_id
                    == normalized["operation_id"],
                )
            )
            if existing is not None:
                existing_document = _tool_scope_document(existing)
                if _candidate_comparison(existing_document) != _candidate_comparison(
                    normalized
                ):
                    raise GovernanceCatalogError("tool_operation_registration_conflict")
                return {
                    "appended": False,
                    "scope": existing_document,
                    "release_authorization": False,
                }

            same_key = tuple(
                session.scalars(
                    select(ToolSemanticScopeRow).where(
                        ToolSemanticScopeRow.canonical_scope_key
                        == normalized["canonical_scope_key"]
                    )
                )
            )
            relationship = normalized["relationship"]
            target = None
            if relationship["mode"] == "canonical":
                if any(row.status == "registered" for row in same_key):
                    raise GovernanceCatalogError("tool_semantic_scope_collision")
            else:
                target = session.scalar(
                    select(ToolSemanticScopeRow).where(
                        ToolSemanticScopeRow.scope_id
                        == relationship["target_scope_id"]
                    )
                )
                if (
                    target is None
                    or target.canonical_scope_key
                    != normalized["canonical_scope_key"]
                ):
                    raise GovernanceCatalogError(
                        "tool_semantic_scope_relationship_invalid"
                    )
                if relationship["mode"] == "supersedes":
                    target.status = "superseded"

            row = _tool_scope_row(
                normalized,
                release_id=self.bundle.release_id,
                recorded_at=now,
            )
            session.add(row)
            _add_audit(
                session,
                event_type="tool_semantic_scope_registered",
                correlation_id=normalized["scope_id"],
                actor_ref=actor_ref,
                payload={
                    "scope_id": normalized["scope_id"],
                    "tool_id": normalized["tool_id"],
                    "tool_version": normalized["tool_version"],
                    "operation_id": normalized["operation_id"],
                    "canonical_scope_key": normalized["canonical_scope_key"],
                    "relationship": relationship,
                    "activation_authorization": False,
                    "production_authorized": False,
                },
                recorded_at=now,
            )
            session.flush()
            return {
                "appended": True,
                "scope": _tool_scope_document(row),
                "release_authorization": False,
            }

    def systems(self, *, department_id: str | None = None) -> dict[str, Any]:
        with self.database.session() as session:
            statement = select(SystemRegistryRow).order_by(SystemRegistryRow.system_id)
            if department_id is not None:
                statement = statement.where(
                    SystemRegistryRow.department_ref == department_id
                )
            rows = tuple(session.scalars(statement))
        return {
            "systems": [_system_document(row) for row in rows],
            "semantic_authority_release_id": self.bundle.release_id,
            "release_authorization": False,
        }

    def system(self, system_id: str) -> dict[str, Any]:
        with self.database.session() as session:
            row = session.scalar(
                select(SystemRegistryRow)
                .where(SystemRegistryRow.system_id == system_id)
                .order_by(SystemRegistryRow.id.desc())
            )
        if row is None:
            raise GovernanceCatalogError("system_registry_record_not_found")
        return {"system": _system_document(row), "release_authorization": False}


def _validate_seed_documents(
    *,
    bundle: SemanticAuthorityBundle,
    scope_seed: dict[str, Any],
    system_seed: dict[str, Any],
    tool_profile: dict[str, Any],
) -> None:
    if (
        scope_seed.get("registry_version")
        != "orbit.control-plane-tool-semantic-scopes/1"
        or scope_seed.get("status") != "synthetic_registration_only"
        or scope_seed.get("semantic_authority_release_id") != bundle.release_id
        or system_seed.get("registry_version")
        != "orbit.control-plane-system-registry-seed/1"
        or system_seed.get("status") != "human_confirmed_projection"
        or system_seed.get("semantic_authority_release_id") != bundle.release_id
    ):
        raise GovernanceCatalogError("governance_seed_boundary_invalid")
    profile_tools: dict[tuple[str, str], dict[str, Any]] = {}
    for tool in _list(tool_profile.get("tools"), "tool_intake_profile_invalid"):
        item = _mapping(tool, "tool_intake_profile_invalid")
        key = (
            _string(item.get("tool_id"), "tool_intake_profile_invalid"),
            _string(item.get("version"), "tool_intake_profile_invalid"),
        )
        profile_tools[key] = item
    scopes = _list(scope_seed.get("scopes"), "tool_scope_seed_invalid")
    seen_scopes: set[str] = set()
    seen_operations: set[tuple[str, str, str]] = set()
    seen_canonical_keys: set[str] = set()
    for scope in scopes:
        normalized = _validate_tool_scope_candidate(scope, release_id=bundle.release_id)
        scope_id = normalized["scope_id"]
        operation_key = (
            normalized["tool_id"],
            normalized["tool_version"],
            normalized["operation_id"],
        )
        if (
            scope_id in seen_scopes
            or operation_key in seen_operations
            or normalized["canonical_scope_key"] in seen_canonical_keys
            or normalized["relationship"]["mode"] != "canonical"
        ):
            raise GovernanceCatalogError("tool_scope_seed_duplicate")
        seen_scopes.add(scope_id)
        seen_operations.add(operation_key)
        seen_canonical_keys.add(normalized["canonical_scope_key"])
        profile = profile_tools.get(operation_key[:2])
        if (
            profile is None
            or profile.get("manifest_sha256") != normalized["manifest_digest"]
            or normalized["operation_id"]
            not in profile.get("d0_allowed_operation_ids", [])
            or normalized["capability"] not in profile.get("capabilities", [])
        ):
            raise GovernanceCatalogError("tool_scope_seed_profile_drift")
    expected_operations = {
        (tool_id, version, operation)
        for (tool_id, version), profile in profile_tools.items()
        for operation in profile.get("d0_allowed_operation_ids", [])
    }
    if seen_operations != expected_operations:
        raise GovernanceCatalogError("tool_scope_seed_incomplete")

    systems = _list(system_seed.get("systems"), "system_registry_seed_invalid")
    if {item.get("system_id") for item in systems if isinstance(item, dict)} != {
        "sys_orbit_health",
        "sys_smart_jewelry_ai_growth",
    }:
        raise GovernanceCatalogError("system_registry_seed_invalid")
    for value in systems:
        system = _validate_system(value)
        if system["runtime_effective"] or system["production_authorized"]:
            raise GovernanceCatalogError("system_registry_authority_boundary_invalid")


def _validate_tool_scope_candidate(
    value: Mapping[str, Any], *, release_id: str
) -> dict[str, Any]:
    candidate = dict(value)
    scope = _mapping(candidate.get("semantic_scope"), "tool_semantic_scope_invalid")
    relationship = _mapping(
        candidate.get("relationship"), "tool_semantic_scope_invalid"
    )
    normalized = {
        "scope_id": _string(candidate.get("scope_id"), "tool_semantic_scope_invalid"),
        "tool_id": _string(candidate.get("tool_id"), "tool_semantic_scope_invalid"),
        "tool_version": _string(
            candidate.get("tool_version"), "tool_semantic_scope_invalid"
        ),
        "manifest_digest": _digest(
            candidate.get("manifest_digest"), "tool_semantic_scope_invalid"
        ),
        "operation_id": _string(
            candidate.get("operation_id"), "tool_semantic_scope_invalid"
        ),
        "capability": _string(
            candidate.get("capability"), "tool_semantic_scope_invalid"
        ),
        "semantic_scope": {
            field: _string(scope.get(field), "tool_semantic_scope_invalid")
            for field in ("domain", "resource_kind", "action", "side_effect_class")
        },
        "canonical_scope_key": _string(
            candidate.get("canonical_scope_key"), "tool_semantic_scope_invalid"
        ),
        "relationship": {
            "mode": _string(
                relationship.get("mode"), "tool_semantic_scope_invalid"
            ),
            "target_scope_id": relationship.get("target_scope_id"),
        },
        "status": _string(candidate.get("status"), "tool_semantic_scope_invalid"),
        "evidence_status": _string(
            candidate.get("evidence_status"), "tool_semantic_scope_invalid"
        ),
        "owner_ref": _string(
            candidate.get("owner_ref"), "tool_semantic_scope_invalid"
        ),
        "source_release_id": candidate.get("source_release_id", release_id),
        "registration_only": candidate.get("registration_only"),
        "activation_authorization": candidate.get("activation_authorization"),
        "production_authorized": candidate.get("production_authorized"),
    }
    expected_key = ":".join(normalized["semantic_scope"].values())
    mode = normalized["relationship"]["mode"]
    target = normalized["relationship"]["target_scope_id"]
    if (
        normalized["canonical_scope_key"] != expected_key
        or mode not in {"canonical", "alias", "supersedes"}
        or (mode == "canonical" and target is not None)
        or (
            mode != "canonical"
            and (not isinstance(target, str) or not target)
        )
        or normalized["status"] != "registered"
        or normalized["source_release_id"] != release_id
        or normalized["registration_only"] is not True
        or normalized["activation_authorization"] is not False
        or normalized["production_authorized"] is not False
    ):
        raise GovernanceCatalogError("tool_semantic_scope_boundary_invalid")
    return normalized


def _validate_system(value: Any) -> dict[str, Any]:
    system = _mapping(value, "system_registry_seed_invalid")
    required = (
        "system_id",
        "system_version",
        "display_name",
        "lifecycle_status",
        "ownership_status",
        "department_ref",
        "responsible_role_ref",
        "composition_ref",
        "migration_status",
        "evidence_status",
    )
    for field in required:
        _string(system.get(field), "system_registry_seed_invalid")
    for field in ("source_locations", "decision_refs"):
        values = _list(system.get(field), "system_registry_seed_invalid")
        if not values or not all(isinstance(item, str) and item for item in values):
            raise GovernanceCatalogError("system_registry_seed_invalid")
    for field in ("runtime_effective", "production_authorized"):
        if not isinstance(system.get(field), bool):
            raise GovernanceCatalogError("system_registry_seed_invalid")
    return dict(system)


def _seed_system(
    session: Any,
    *,
    system: Mapping[str, Any],
    release_id: str,
    recorded_at: datetime,
) -> None:
    normalized = _validate_system(system)
    existing = session.scalar(
        select(SystemRegistryRow).where(
            SystemRegistryRow.system_id == normalized["system_id"],
            SystemRegistryRow.system_version == normalized["system_version"],
        )
    )
    expected = {**normalized, "source_release_id": release_id}
    if existing is not None:
        if _system_seed_comparison(
            _system_document(existing)
        ) != _system_seed_comparison(expected):
            raise GovernanceCatalogError("system_registry_seed_drift")
        return
    row = SystemRegistryRow(
        **normalized,
        source_release_id=release_id,
        recorded_at=recorded_at,
    )
    session.add(row)
    _add_audit(
        session,
        event_type="system_registry_record_seeded",
        correlation_id=normalized["system_id"],
        actor_ref="workload_control_plane_bootstrap",
        payload={
            "system_id": normalized["system_id"],
            "department_ref": normalized["department_ref"],
            "migration_status": normalized["migration_status"],
            "runtime_effective": False,
            "production_authorized": False,
        },
        recorded_at=recorded_at,
    )


def _seed_tool_scope(
    session: Any,
    *,
    scope: Mapping[str, Any],
    release_id: str,
    recorded_at: datetime,
) -> None:
    normalized = _validate_tool_scope_candidate(scope, release_id=release_id)
    existing = session.scalar(
        select(ToolSemanticScopeRow).where(
            ToolSemanticScopeRow.scope_id == normalized["scope_id"]
        )
    )
    if existing is not None:
        if _tool_seed_comparison(
            _tool_scope_document(existing)
        ) != _tool_seed_comparison(normalized):
            raise GovernanceCatalogError("tool_scope_seed_drift")
        return
    collision = session.scalar(
        select(ToolSemanticScopeRow).where(
            ToolSemanticScopeRow.canonical_scope_key
            == normalized["canonical_scope_key"],
            ToolSemanticScopeRow.status == "registered",
        )
    )
    if collision is not None:
        raise GovernanceCatalogError("tool_semantic_scope_collision")
    session.add(
        _tool_scope_row(normalized, release_id=release_id, recorded_at=recorded_at)
    )
    _add_audit(
        session,
        event_type="tool_semantic_scope_seeded",
        correlation_id=normalized["scope_id"],
        actor_ref="workload_control_plane_bootstrap",
        payload={
            "scope_id": normalized["scope_id"],
            "tool_id": normalized["tool_id"],
            "operation_id": normalized["operation_id"],
            "canonical_scope_key": normalized["canonical_scope_key"],
            "activation_authorization": False,
            "production_authorized": False,
        },
        recorded_at=recorded_at,
    )


def _tool_scope_row(
    value: Mapping[str, Any], *, release_id: str, recorded_at: datetime
) -> ToolSemanticScopeRow:
    semantic_scope = value["semantic_scope"]
    relationship = value["relationship"]
    return ToolSemanticScopeRow(
        scope_id=value["scope_id"],
        tool_id=value["tool_id"],
        tool_version=value["tool_version"],
        manifest_digest=value["manifest_digest"],
        operation_id=value["operation_id"],
        capability=value["capability"],
        domain=semantic_scope["domain"],
        resource_kind=semantic_scope["resource_kind"],
        action=semantic_scope["action"],
        side_effect_class=semantic_scope["side_effect_class"],
        canonical_scope_key=value["canonical_scope_key"],
        relationship_mode=relationship["mode"],
        target_scope_id=relationship["target_scope_id"],
        status=value["status"],
        evidence_status=value["evidence_status"],
        owner_ref=value["owner_ref"],
        source_release_id=release_id,
        registration_only=True,
        activation_authorization=False,
        production_authorized=False,
        recorded_at=recorded_at,
    )


def _term_document(row: SemanticTermRow) -> dict[str, Any]:
    return {
        "term_id": row.term_id,
        "term_zh": row.term_zh,
        "term_en": row.term_en,
        "kind": row.kind,
        "publication_status": row.publication_status,
        "evidence_status": row.evidence_status,
        "definition": row.definition,
        "mapped_concept_refs": row.mapped_concept_refs,
        "depends_on_term_refs": row.depends_on_term_refs,
        "not_a": row.not_a,
        "invariants": row.invariants,
        "operator_exposure": row.operator_exposure,
        "authority_claim": row.authority_claim,
        "creates_human_checkpoint": row.creates_human_checkpoint,
        "source_digest": row.source_digest,
    }


def _tool_scope_document(row: ToolSemanticScopeRow) -> dict[str, Any]:
    return {
        "scope_id": row.scope_id,
        "tool_id": row.tool_id,
        "tool_version": row.tool_version,
        "manifest_digest": row.manifest_digest,
        "operation_id": row.operation_id,
        "capability": row.capability,
        "semantic_scope": {
            "domain": row.domain,
            "resource_kind": row.resource_kind,
            "action": row.action,
            "side_effect_class": row.side_effect_class,
        },
        "canonical_scope_key": row.canonical_scope_key,
        "relationship": {
            "mode": row.relationship_mode,
            "target_scope_id": row.target_scope_id,
        },
        "status": row.status,
        "evidence_status": row.evidence_status,
        "owner_ref": row.owner_ref,
        "source_release_id": row.source_release_id,
        "registration_only": row.registration_only,
        "activation_authorization": row.activation_authorization,
        "production_authorized": row.production_authorized,
    }


def _system_document(row: SystemRegistryRow) -> dict[str, Any]:
    return {
        "system_id": row.system_id,
        "system_version": row.system_version,
        "display_name": row.display_name,
        "lifecycle_status": row.lifecycle_status,
        "ownership_status": row.ownership_status,
        "department_ref": row.department_ref,
        "responsible_role_ref": row.responsible_role_ref,
        "composition_ref": row.composition_ref,
        "source_locations": row.source_locations,
        "migration_status": row.migration_status,
        "decision_refs": row.decision_refs,
        "evidence_status": row.evidence_status,
        "runtime_effective": row.runtime_effective,
        "production_authorized": row.production_authorized,
        "source_release_id": row.source_release_id,
        "recorded_at": row.recorded_at.isoformat(),
    }


def _candidate_comparison(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in (
            "scope_id",
            "tool_id",
            "tool_version",
            "manifest_digest",
            "operation_id",
            "capability",
            "semantic_scope",
            "canonical_scope_key",
            "relationship",
            "status",
            "evidence_status",
            "owner_ref",
            "source_release_id",
            "registration_only",
            "activation_authorization",
            "production_authorized",
        )
    }


def _system_comparison(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in (
            "system_id",
            "system_version",
            "display_name",
            "lifecycle_status",
            "ownership_status",
            "department_ref",
            "responsible_role_ref",
            "composition_ref",
            "source_locations",
            "migration_status",
            "decision_refs",
            "evidence_status",
            "runtime_effective",
            "production_authorized",
            "source_release_id",
        )
    }


def _tool_seed_comparison(value: Mapping[str, Any]) -> dict[str, Any]:
    """Compare immutable seed meaning while retaining predecessor provenance."""

    return {
        key: item
        for key, item in _candidate_comparison(value).items()
        if key != "source_release_id"
    }


def _system_seed_comparison(value: Mapping[str, Any]) -> dict[str, Any]:
    """Compare immutable seed meaning while retaining predecessor provenance."""

    return {
        key: item
        for key, item in _system_comparison(value).items()
        if key != "source_release_id"
    }


def _require_release_match(
    row: SemanticAuthorityReleaseRow, bundle: SemanticAuthorityBundle
) -> None:
    if (
        row.manifest_digest != bundle.manifest_digest
        or row.authority_lock_digest != bundle.authority_lock_digest
        or row.architecture_commit != bundle.architecture_commit
        or row.source_digests != bundle.source_digests
        or row.authority_claim != "projection_only"
        or row.release_authorization is not False
    ):
        raise GovernanceCatalogError("semantic_projection_release_drift")


def _add_audit(
    session: Any,
    *,
    event_type: str,
    correlation_id: str,
    actor_ref: str,
    payload: dict[str, Any],
    recorded_at: datetime,
) -> None:
    digest = canonical_digest(payload)
    audit_id = deterministic_id("audit", event_type, correlation_id, digest)
    existing = session.scalar(
        select(AuditEventRow).where(AuditEventRow.audit_id == audit_id)
    )
    if existing is None:
        session.add(
            AuditEventRow(
                audit_id=audit_id,
                correlation_id=correlation_id,
                event_type=event_type,
                actor_ref=actor_ref,
                payload=payload,
                recorded_at=recorded_at,
            )
        )


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise GovernanceCatalogError("governance_reference_invalid")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: _reject_constant(),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GovernanceCatalogError("governance_reference_invalid") from error
    return _mapping(value, "governance_reference_invalid")


def _mapping(value: Any, reason_code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GovernanceCatalogError(reason_code)
    return value


def _list(value: Any, reason_code: str) -> list[Any]:
    if not isinstance(value, list):
        raise GovernanceCatalogError(reason_code)
    return value


def _string(value: Any, reason_code: str) -> str:
    if not isinstance(value, str) or not value:
        raise GovernanceCatalogError(reason_code)
    return value


def _digest(value: Any, reason_code: str) -> str:
    digest = _string(value, reason_code)
    if len(digest) != 71 or not digest.startswith("sha256:"):
        raise GovernanceCatalogError(reason_code)
    try:
        bytes.fromhex(digest[7:])
    except ValueError as error:
        raise GovernanceCatalogError(reason_code) from error
    return digest


def _file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise GovernanceCatalogError("governance_json_duplicate_key")
        value[key] = item
    return value


def _reject_constant() -> None:
    raise GovernanceCatalogError("governance_json_constant_invalid")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

