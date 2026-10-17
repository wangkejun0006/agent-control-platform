"""Strict registration-only intake for independently released Tool manifests.

The Tool Registry is separate from the Agent Registry.  This module consumes
published Company Schema bytes through the same verifier used by Agent
registration, verifies domain release bytes, and returns immutable local D0
candidate records.  It does not activate a Tool, issue a Grant, or authorize
network, storage, Registry, or production side effects.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .registration import (
    DEFAULT_COMPANY_LOCK,
    DEFAULT_CONTRACT_BUNDLE,
    RegistrationError,
    _SchemaValidator,
    _digest,
    _exact_keys,
    _load_json_bytes,
    _load_verified_company_schemas,
    _read_local_regular_file,
    _read_safe_file,
    _safe_relative_path,
    _strict_mapping,
    _unique_index,
    _validate_digest,
    _validate_source_root,
)


DEFAULT_DATASET_TOOL_INTAKE_PROFILE = (
    Path(__file__).resolve().parents[2]
    / "references"
    / "dataset-tool-intake-profile.json"
)
TOOL_MANIFEST_SCHEMA_ID = "urn:company-ai-os:schema:tool-manifest:0.3"
_CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{2,127}$")
_OPERATION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")


class ToolRegistryError(ValueError):
    """Fail-closed Tool candidate intake error with a stable reason code."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class ToolRegistryCandidate:
    tool_id: str
    version: str
    release_digest: str
    manifest_digest: str
    source_release_id: str
    source_release_manifest_digest: str
    owner_human_ref: str
    capabilities: tuple[str, ...]
    operation_ids: tuple[str, ...]
    d0_allowed_operation_ids: tuple[str, ...]
    allowed_data_classifications: tuple[str, ...]
    risk_classes: tuple[str, ...]
    source_manifest_status: str
    registry_status: str = "draft"
    evidence_status: str = "synthetic"
    synthetic_only: bool = True
    company_authoritative: bool = False

    def registry_document(self) -> dict[str, object]:
        return {
            "tool_id": self.tool_id,
            "version": self.version,
            "release_digest": self.release_digest,
            "manifest_digest": self.manifest_digest,
            "source_release_id": self.source_release_id,
            "owner_human_ref": self.owner_human_ref,
            "capabilities": list(self.capabilities),
            "operation_ids": list(self.operation_ids),
            "d0_allowed_operation_ids": list(self.d0_allowed_operation_ids),
            "allowed_data_classifications": list(
                self.allowed_data_classifications
            ),
            "risk_classes": list(self.risk_classes),
            "status": self.registry_status,
            "evidence_status": self.evidence_status,
            "synthetic_only": self.synthetic_only,
            "company_authoritative": self.company_authoritative,
            "activation_authorized": False,
            "production_authorized": False,
        }


@dataclass(frozen=True)
class ToolCandidateBundle:
    profile_id: str
    source_release_id: str
    source_release_manifest_digest: str
    company_contract_release_id: str
    candidates: tuple[ToolRegistryCandidate, ...]

    def candidate(self, tool_id: str) -> ToolRegistryCandidate:
        matches = tuple(item for item in self.candidates if item.tool_id == tool_id)
        if len(matches) != 1:
            raise ToolRegistryError(
                "tool_candidate_not_unique",
                "Tool candidate is absent or ambiguous",
            )
        return matches[0]

    def document(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "source_release_id": self.source_release_id,
            "source_release_manifest_digest": self.source_release_manifest_digest,
            "company_contract_release_id": self.company_contract_release_id,
            "candidates": [asdict(item) for item in self.candidates],
            "registration_only": True,
            "activation_authorized": False,
            "production_authorized": False,
        }


def load_tool_candidate_bundle(
    source_root: Path | str,
    release_manifest: Path | str,
    *,
    intake_profile_path: Path | str = DEFAULT_DATASET_TOOL_INTAKE_PROFILE,
    company_lock_path: Path | str = DEFAULT_COMPANY_LOCK,
    contract_bundle_root: Path | str = DEFAULT_CONTRACT_BUNDLE,
) -> ToolCandidateBundle:
    """Verify exact Tool release bytes and return draft local candidates."""

    try:
        root = _validate_source_root(source_root)
        release_relative = _safe_relative_path(
            release_manifest, "Tool release manifest"
        )
        release_source = _read_safe_file(root, release_relative)
        release = _load_json_bytes(release_source, "Tool release manifest")
        profile = _load_json_bytes(
            _read_local_regular_file(
                Path(intake_profile_path), "Tool intake profile"
            ),
            "Tool intake profile",
        )
        return _load_verified_bundle(
            root,
            release,
            release_source,
            profile,
            Path(company_lock_path),
            Path(contract_bundle_root),
        )
    except ToolRegistryError:
        raise
    except RegistrationError as error:
        raise ToolRegistryError(error.reason_code, str(error)) from error


def _load_verified_bundle(
    root: Path,
    release: Mapping[str, Any],
    release_source: bytes,
    profile: Mapping[str, Any],
    company_lock_path: Path,
    contract_bundle_root: Path,
) -> ToolCandidateBundle:
    _validate_profile(profile)
    _validate_release(release)
    profile_release = _strict_mapping(
        profile["source_release"], "Tool intake source release"
    )
    release_digest = _digest(release_source)
    if (
        release_digest != profile_release["manifest_sha256"]
        or release["release_id"] != profile_release["release_id"]
        or release["company_contract_release_ref"]
        != profile["contract_release_id"]
    ):
        raise ToolRegistryError(
            "tool_release_not_reviewed",
            "Tool release bytes or authority differ from the intake profile",
        )

    schemas, company_authority, _ = _load_verified_company_schemas(
        company_lock_path,
        contract_bundle_root,
        required_schema_ids={TOOL_MANIFEST_SCHEMA_ID},
    )
    if (
        company_authority["contract_release_id"]
        != profile["contract_release_id"]
    ):
        raise ToolRegistryError(
            "company_contract_identity_mismatch",
            "Tool intake profile differs from the Company Contract release",
        )
    validator = _SchemaValidator(schemas)

    release_tools = _unique_index(
        release["tool_manifests"], "tool_id", "Tool release manifests"
    )
    profile_tools = _unique_index(
        profile["tools"], "tool_id", "Tool intake candidates"
    )
    if set(release_tools) != set(profile_tools):
        raise ToolRegistryError(
            "tool_candidate_set_mismatch",
            "Tool release and reviewed intake profile contain different Tools",
        )
    _verify_domain_schemas(root, release["domain_schemas"])

    candidates = []
    for tool_id in sorted(release_tools):
        source_entry = release_tools[tool_id]
        profile_entry = profile_tools[tool_id]
        _validate_profile_tool(profile_entry)
        manifest_relative = _safe_relative_path(
            source_entry.get("path"), "Tool manifest"
        )
        manifest_source = _read_safe_file(root, manifest_relative)
        manifest_digest = _digest(manifest_source)
        for declared in (
            source_entry.get("sha256"),
            profile_entry.get("manifest_sha256"),
        ):
            _validate_digest(declared, "Tool manifest digest")
            if declared != manifest_digest:
                raise ToolRegistryError(
                    "tool_manifest_digest_mismatch",
                    "Tool manifest raw bytes differ from a locked digest",
                )
        manifest = _load_json_bytes(manifest_source, "Tool manifest")
        validator.validate(manifest, TOOL_MANIFEST_SCHEMA_ID)
        candidate = _candidate_from_manifest(
            manifest,
            manifest_digest,
            release,
            release_digest,
            profile_entry,
        )
        if candidate.tool_id != tool_id:
            raise ToolRegistryError(
                "tool_manifest_identity_mismatch",
                "Tool manifest identity differs from release index",
            )
        candidates.append(candidate)

    return ToolCandidateBundle(
        profile_id=profile["profile_id"],
        source_release_id=release["release_id"],
        source_release_manifest_digest=release_digest,
        company_contract_release_id=profile["contract_release_id"],
        candidates=tuple(candidates),
    )


def _validate_profile(profile: Mapping[str, Any]) -> None:
    _exact_keys(
        profile,
        {
            "profile_version",
            "profile_id",
            "evidence_status",
            "company_authoritative",
            "contract_release_id",
            "source_release",
            "tools",
            "boundary",
        },
        "Tool intake profile",
    )
    boundary = _strict_mapping(profile["boundary"], "Tool intake boundary")
    if (
        profile["profile_version"] != "orbit.synthetic-tool-intake-profile/1"
        or profile["evidence_status"] != "synthetic"
        or profile["company_authoritative"] is not False
        or not isinstance(profile["tools"], list)
        or boundary
        != {
            "registration_only": True,
            "activation_authorized": False,
            "production_authorized": False,
            "real_network_authorized": False,
            "real_storage_authorized": False,
            "real_registry_authorized": False,
        }
    ):
        raise ToolRegistryError(
            "tool_intake_profile_invalid",
            "Tool intake profile exceeds the synthetic registration boundary",
        )
    source_release = _strict_mapping(
        profile["source_release"], "Tool intake source release"
    )
    _exact_keys(
        source_release,
        {"release_id", "manifest_sha256"},
        "Tool intake source release",
    )
    _validate_digest(source_release["manifest_sha256"], "source release digest")


def _validate_profile_tool(value: Mapping[str, Any]) -> None:
    _exact_keys(
        value,
        {
            "tool_id",
            "version",
            "manifest_sha256",
            "capabilities",
            "d0_allowed_operation_ids",
        },
        "Tool intake candidate",
    )
    _validate_digest(value["manifest_sha256"], "Tool manifest digest")
    capabilities = _string_list(
        value["capabilities"], "Tool capabilities", _CAPABILITY_PATTERN
    )
    operations = _string_list(
        value["d0_allowed_operation_ids"],
        "D0 allowed operations",
        _OPERATION_PATTERN,
    )
    if not capabilities or not operations:
        raise ToolRegistryError(
            "tool_intake_scope_empty",
            "Tool intake capabilities and D0 operations must be non-empty",
        )


def _validate_release(release: Mapping[str, Any]) -> None:
    _exact_keys(
        release,
        {
            "manifest_version",
            "release_id",
            "source_code_ref",
            "company_contract_release_ref",
            "minimum_control_plane_revision_ref",
            "status",
            "tool_manifests",
            "domain_schemas",
            "agent_visible_boundary",
        },
        "Tool release manifest",
    )
    if (
        release["manifest_version"] != "orbit.dataset-tool-release/1"
        or release["status"] != "evaluation"
        or not isinstance(release["tool_manifests"], list)
        or not release["tool_manifests"]
        or not isinstance(release["domain_schemas"], list)
        or not release["domain_schemas"]
        or release["agent_visible_boundary"]
        != {
            "logical_references_only": True,
            "physical_paths_visible": False,
            "credentials_visible": False,
            "nas_handles_visible": False,
        }
    ):
        raise ToolRegistryError(
            "tool_release_boundary_invalid",
            "Tool release is outside the reviewed registration boundary",
        )
    for entry in release["tool_manifests"]:
        _exact_keys(entry, {"tool_id", "path", "sha256"}, "Tool release entry")
        _validate_digest(entry["sha256"], "Tool release entry digest")


def _verify_domain_schemas(root: Path, entries: Any) -> None:
    indexed = _unique_index(entries, "schema_id", "Tool domain schemas")
    for schema_id, entry in indexed.items():
        _exact_keys(entry, {"schema_id", "path", "sha256"}, "domain schema")
        _validate_digest(entry["sha256"], "domain schema digest")
        source = _read_safe_file(
            root, _safe_relative_path(entry["path"], "domain schema")
        )
        if _digest(source) != entry["sha256"]:
            raise ToolRegistryError(
                "domain_schema_digest_mismatch",
                "Tool domain Schema bytes differ from the release manifest",
            )
        schema = _load_json_bytes(source, "Tool domain Schema")
        if schema.get("$id") != schema_id:
            raise ToolRegistryError(
                "domain_schema_id_mismatch",
                "Tool domain Schema identifier differs",
            )


def _candidate_from_manifest(
    manifest: Mapping[str, Any],
    manifest_digest: str,
    release: Mapping[str, Any],
    release_digest: str,
    profile_entry: Mapping[str, Any],
) -> ToolRegistryCandidate:
    if (
        manifest["tool_id"] != profile_entry["tool_id"]
        or manifest["version"] != profile_entry["version"]
        or manifest["status"] != "evaluation"
        or manifest["runtime_constraints"]
        != {"allowed_environments": ["test", "staging"], "sandbox_required": True}
    ):
        raise ToolRegistryError(
            "tool_manifest_boundary_invalid",
            "Tool manifest identity or D0 runtime boundary differs",
        )
    operations = _unique_index(
        manifest["operations"], "operation_id", "Tool operations"
    )
    allowed_operations = tuple(profile_entry["d0_allowed_operation_ids"])
    if not set(allowed_operations).issubset(operations):
        raise ToolRegistryError(
            "tool_operation_scope_invalid",
            "Reviewed D0 operations are absent from the Tool manifest",
        )
    for operation_id in allowed_operations:
        operation = operations[operation_id]
        if (
            operation["network_egress"]["mode"] != "deny_all"
            or operation["credential_policy"]["agent_visible"] is not False
            or "public" not in operation["data_policy"]["allowed_classifications"]
            or operation["idempotency"] != "required"
        ):
            raise ToolRegistryError(
                "tool_d0_operation_boundary_invalid",
                "Reviewed D0 Tool operation violates network, credential, data, or idempotency gates",
            )
    classifications = sorted(
        {
            classification
            for operation_id in allowed_operations
            for classification in operations[operation_id]["data_policy"][
                "allowed_classifications"
            ]
        }
    )
    risks = sorted({operation["risk_class"] for operation in operations.values()})
    return ToolRegistryCandidate(
        tool_id=manifest["tool_id"],
        version=manifest["version"],
        release_digest=manifest_digest,
        manifest_digest=manifest_digest,
        source_release_id=release["release_id"],
        source_release_manifest_digest=release_digest,
        owner_human_ref=manifest["owner"]["human_id"],
        capabilities=tuple(profile_entry["capabilities"]),
        operation_ids=tuple(operations),
        d0_allowed_operation_ids=allowed_operations,
        allowed_data_classifications=tuple(classifications),
        risk_classes=tuple(risks),
        source_manifest_status=manifest["status"],
    )


def _string_list(value: Any, label: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not pattern.fullmatch(item) for item in value)
        or len(set(value)) != len(value)
    ):
        raise ToolRegistryError(
            "tool_intake_profile_invalid", f"{label} are invalid"
        )
    return tuple(value)

