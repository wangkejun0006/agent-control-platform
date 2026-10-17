"""Strict read-only consumption of the published company concept catalog profile."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROFILE_PATH = REPOSITORY_ROOT / "references/company-concept-profile.json"
PROFILE_VERSION = "orbit.control-plane-concept-profile/1"
CONCEPT_BINDINGS_VERSION = "orbit.lifecycle-review-concept-bindings/1"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


class ConceptProfileError(ValueError):
    """Raised when a concept consumer lock or review binding drifts."""


@dataclass(frozen=True)
class CompanyConceptProfile:
    profile_version: str
    profile_sha256: str
    source: Mapping[str, str]
    concept_ids: tuple[str, ...]
    authority_semantics: Mapping[str, tuple[str, ...]]
    required_by_manifest_type: Mapping[str, tuple[str, ...]]
    required_by_scope_kind: Mapping[str, tuple[str, ...]]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConceptProfileError(f"concept_profile_duplicate_key:{key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ConceptProfileError(f"concept_profile_invalid_constant:{value}")


def _exact_fields(value: Mapping[str, Any], expected: set[str], reason: str) -> None:
    if set(value) != expected:
        raise ConceptProfileError(reason)


def _string_list(value: Any, reason: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ConceptProfileError(reason)
    return tuple(value)


def _mapping_of_string_lists(value: Any, reason: str) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, Mapping) or not value:
        raise ConceptProfileError(reason)
    result: dict[str, tuple[str, ...]] = {}
    for key, items in value.items():
        if not isinstance(key, str) or not key:
            raise ConceptProfileError(reason)
        result[key] = _string_list(items, reason)
    return result


def load_company_concept_profile(
    path: Path = DEFAULT_PROFILE_PATH,
) -> CompanyConceptProfile:
    raw = path.read_bytes()
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConceptProfileError("concept_profile_json_invalid") from error
    if not isinstance(document, Mapping):
        raise ConceptProfileError("concept_profile_not_object")
    _exact_fields(
        document,
        {
            "profile_version",
            "source",
            "concept_ids",
            "authority_semantics",
            "required_by_manifest_type",
            "required_by_scope_kind",
            "status",
            "authority_claim",
        },
        "concept_profile_fields_invalid",
    )
    source = document["source"]
    if not isinstance(source, Mapping):
        raise ConceptProfileError("concept_profile_source_invalid")
    _exact_fields(
        source,
        {
            "repository",
            "commit",
            "catalog_path",
            "catalog_version",
            "catalog_sha256",
            "validation_schema_path",
            "validation_schema_sha256",
        },
        "concept_profile_source_fields_invalid",
    )
    if (
        document["profile_version"] != PROFILE_VERSION
        or document["status"] != "read_only_consumer_lock"
        or document["authority_claim"] != "none"
        or not _COMMIT.fullmatch(str(source["commit"]))
        or not _DIGEST.fullmatch(str(source["catalog_sha256"]))
        or not _DIGEST.fullmatch(str(source["validation_schema_sha256"]))
    ):
        raise ConceptProfileError("concept_profile_identity_invalid")
    concepts = _string_list(document["concept_ids"], "concept_profile_ids_invalid")
    if any(not item.startswith("orbit.concept/") for item in concepts):
        raise ConceptProfileError("concept_profile_id_invalid")
    concept_set = set(concepts)
    semantics = _mapping_of_string_lists(
        document["authority_semantics"], "concept_profile_semantics_invalid"
    )
    manifest_requirements = _mapping_of_string_lists(
        document["required_by_manifest_type"],
        "concept_profile_manifest_requirements_invalid",
    )
    scope_requirements = _mapping_of_string_lists(
        document["required_by_scope_kind"],
        "concept_profile_scope_requirements_invalid",
    )
    referenced = {
        item
        for mapping in (semantics, manifest_requirements, scope_requirements)
        for items in mapping.values()
        for item in items
    }
    if not referenced <= concept_set:
        raise ConceptProfileError("concept_profile_reference_unknown")
    if semantics.get("effective_task_authority") != (
        "orbit.concept/execution-grant",
    ):
        raise ConceptProfileError("concept_profile_effective_authority_invalid")
    return CompanyConceptProfile(
        profile_version=PROFILE_VERSION,
        profile_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
        source={key: str(value) for key, value in source.items()},
        concept_ids=concepts,
        authority_semantics=semantics,
        required_by_manifest_type=manifest_requirements,
        required_by_scope_kind=scope_requirements,
    )


def validate_review_concept_bindings(
    value: Any,
    *,
    manifest_type: str,
    scope_kinds: set[str],
    profile: CompanyConceptProfile | None = None,
) -> tuple[str, ...]:
    profile = profile or load_company_concept_profile()
    if not isinstance(value, Mapping):
        raise ConceptProfileError("concept_bindings_invalid")
    _exact_fields(
        value,
        {
            "binding_version",
            "profile_version",
            "profile_sha256",
            "architecture_commit",
            "catalog_sha256",
            "concept_ids",
        },
        "concept_bindings_fields_invalid",
    )
    if (
        value["binding_version"] != CONCEPT_BINDINGS_VERSION
        or value["profile_version"] != profile.profile_version
        or value["profile_sha256"] != profile.profile_sha256
        or value["architecture_commit"] != profile.source["commit"]
        or value["catalog_sha256"] != profile.source["catalog_sha256"]
    ):
        raise ConceptProfileError("concept_bindings_source_drift")
    concept_ids = _string_list(value["concept_ids"], "concept_bindings_ids_invalid")
    if tuple(sorted(concept_ids)) != concept_ids:
        raise ConceptProfileError("concept_bindings_ids_not_sorted")
    unknown = set(concept_ids) - set(profile.concept_ids)
    if unknown:
        raise ConceptProfileError("concept_bindings_unknown_id")
    required = set(profile.required_by_manifest_type.get(manifest_type, ()))
    for scope_kind in scope_kinds:
        required.update(profile.required_by_scope_kind.get(scope_kind, ()))
    if not required <= set(concept_ids):
        raise ConceptProfileError("concept_bindings_required_id_missing")
    return concept_ids


def build_review_concept_bindings(
    *,
    manifest_type: str,
    scope_kinds: set[str],
    additional_concept_ids: set[str] | None = None,
    profile: CompanyConceptProfile | None = None,
) -> dict[str, Any]:
    """Build the minimal deterministic concept binding for a new Artifact Set v3."""

    profile = profile or load_company_concept_profile()
    concepts = set(profile.required_by_manifest_type.get(manifest_type, ()))
    for scope_kind in scope_kinds:
        concepts.update(profile.required_by_scope_kind.get(scope_kind, ()))
    concepts.update(additional_concept_ids or set())
    unknown = concepts - set(profile.concept_ids)
    if unknown:
        raise ConceptProfileError("concept_bindings_unknown_id")
    binding: dict[str, Any] = {
        "binding_version": CONCEPT_BINDINGS_VERSION,
        "profile_version": profile.profile_version,
        "profile_sha256": profile.profile_sha256,
        "architecture_commit": profile.source["commit"],
        "catalog_sha256": profile.source["catalog_sha256"],
        "concept_ids": sorted(concepts),
    }
    validate_review_concept_bindings(
        binding,
        manifest_type=manifest_type,
        scope_kinds=scope_kinds,
        profile=profile,
    )
    return binding


def concept_profile_status(path: Path = DEFAULT_PROFILE_PATH) -> dict[str, Any]:
    profile = load_company_concept_profile(path)
    return {
        "status": "verified_read_only_consumer_lock",
        "profile_version": profile.profile_version,
        "profile_sha256": profile.profile_sha256,
        "architecture_commit": profile.source["commit"],
        "catalog_version": profile.source["catalog_version"],
        "catalog_sha256": profile.source["catalog_sha256"],
        "concept_count": len(profile.concept_ids),
        "effective_task_authority": list(
            profile.authority_semantics["effective_task_authority"]
        ),
        "authority_claim": "none",
    }

