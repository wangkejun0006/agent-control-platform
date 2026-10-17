"""Fail-closed consumer for the released Architecture semantic authority bundle."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SemanticAuthorityError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class SemanticAuthorityBundle:
    release_id: str
    manifest_digest: str
    authority_lock_digest: str
    architecture_commit: str
    source_digests: dict[str, str]
    terms: tuple[dict[str, Any], ...]


_BUNDLE_DIRECTORY = "semantic-authority-v0.1.0-alpha.7"
_EXPECTED_TERM_COUNT = 43
_SOURCE_FILES = {
    "concept_catalog": "concept-catalog.json",
    "term_registry": "term-classification.json",
    "state_catalog": "state-catalog.json",
    "contract_enum_index": "contract-enum-index.json",
}


def load_semantic_authority_bundle(repository_root: Path) -> SemanticAuthorityBundle:
    """Verify an exact release projection without redefining Architecture terms."""

    references = repository_root / "references"
    consumer_lock = _read_json(references / "semantic-authority-lock.json")
    authority = _mapping(consumer_lock.get("authority"), "semantic_consumer_lock_invalid")
    release_id = _string(
        authority.get("semantic_authority_release_id"),
        "semantic_consumer_lock_invalid",
    )
    if release_id != _BUNDLE_DIRECTORY:
        raise SemanticAuthorityError("semantic_release_not_supported")
    if authority.get("publication_stage") != "release":
        raise SemanticAuthorityError("semantic_release_not_released")

    bundle_root = references / _BUNDLE_DIRECTORY
    manifest_path = bundle_root / "manifest.json"
    manifest_digest = _file_digest(manifest_path)
    if manifest_digest != authority.get("semantic_authority_release_manifest_sha256"):
        raise SemanticAuthorityError("semantic_manifest_digest_drift")
    manifest = _read_json(manifest_path)
    approval = _mapping(manifest.get("approval"), "semantic_manifest_invalid")
    if (
        manifest.get("release_id") != release_id
        or manifest.get("status") != "approved"
        or manifest.get("distribution_scope") != "company_internal"
        or approval.get("production_authorization") is not False
        or approval.get("orbit_write_authorization") is not False
    ):
        raise SemanticAuthorityError("semantic_manifest_boundary_invalid")

    artifacts = _mapping(manifest.get("artifacts"), "semantic_manifest_invalid")
    lock_artifact = _mapping(
        artifacts.get("authority_lock"), "semantic_manifest_invalid"
    )
    authority_lock_path = bundle_root / "semantic-authority-lock.json"
    authority_lock_digest = _file_digest(authority_lock_path)
    if (
        authority_lock_digest != lock_artifact.get("sha256")
        or authority_lock_digest
        != authority.get("semantic_authority_lock_sha256")
    ):
        raise SemanticAuthorityError("semantic_authority_lock_digest_drift")
    authority_lock = _read_json(authority_lock_path)
    if (
        authority_lock.get("lock_version") != "orbit.semantic-authority-lock/1"
        or authority_lock.get("publication_stage") != "release"
        or authority_lock.get("definition_authority")
        != "orbit-agent-architecture"
    ):
        raise SemanticAuthorityError("semantic_authority_lock_invalid")

    manifest_sources = _source_index(
        artifacts.get("sources"), reason_code="semantic_manifest_invalid"
    )
    locked_sources = _source_index(
        authority_lock.get("sources"), reason_code="semantic_authority_lock_invalid"
    )
    consumer_sources = _mapping(
        consumer_lock.get("sources"), "semantic_consumer_lock_invalid"
    )
    source_digests: dict[str, str] = {}
    documents: dict[str, dict[str, Any]] = {}
    for role, filename in _SOURCE_FILES.items():
        actual_digest = _file_digest(bundle_root / filename)
        manifest_source = manifest_sources.get(role)
        locked_source = locked_sources.get(role)
        consumer_source = _mapping(
            consumer_sources.get(role), "semantic_consumer_lock_invalid"
        )
        if (
            manifest_source is None
            or locked_source is None
            or actual_digest != manifest_source.get("sha256")
            or actual_digest != locked_source.get("sha256")
            or actual_digest != consumer_source.get("sha256")
            or manifest_source.get("version") != locked_source.get("version")
            or manifest_source.get("version") != consumer_source.get("version")
        ):
            raise SemanticAuthorityError("semantic_source_digest_drift")
        source_digests[role] = actual_digest
        documents[role] = _read_json(bundle_root / filename)

    terms_document = documents["term_registry"]
    if (
        terms_document.get("registry_version")
        != "orbit.architecture-term-classification/2"
        or terms_document.get("status") != "human_confirmed"
        or terms_document.get("definition_authority")
        != "orbit-agent-architecture"
    ):
        raise SemanticAuthorityError("semantic_term_registry_invalid")
    raw_terms = terms_document.get("terms")
    if not isinstance(raw_terms, list) or len(raw_terms) != _EXPECTED_TERM_COUNT:
        raise SemanticAuthorityError("semantic_term_registry_invalid")
    terms = tuple(_validate_term(item) for item in raw_terms)
    term_ids = {term["id"] for term in terms}
    if len(term_ids) != len(terms):
        raise SemanticAuthorityError("semantic_term_id_duplicate")
    for term in terms:
        if any(ref not in term_ids for ref in term["depends_on_terms"]):
            raise SemanticAuthorityError("semantic_term_dependency_unknown")

    return SemanticAuthorityBundle(
        release_id=release_id,
        manifest_digest=manifest_digest,
        authority_lock_digest=authority_lock_digest,
        architecture_commit=_string(
            authority.get("architecture_commit"), "semantic_consumer_lock_invalid"
        ),
        source_digests=source_digests,
        terms=terms,
    )


def _validate_term(value: Any) -> dict[str, Any]:
    term = _mapping(value, "semantic_term_invalid")
    required_strings = (
        "id",
        "term_zh",
        "term_en",
        "kind",
        "definition",
        "authority_claim",
        "operator_exposure",
        "publication_stage",
        "evidence_status",
    )
    for field in required_strings:
        _string(term.get(field), "semantic_term_invalid")
    if (
        not term["id"].startswith("orbit.term/")
        or term["authority_claim"] != "none"
        or term.get("creates_human_checkpoint") is not False
    ):
        raise SemanticAuthorityError("semantic_term_authority_boundary_invalid")
    for field in (
        "not_a",
        "maps_to_concepts",
        "depends_on_terms",
        "declared_in",
        "invariants",
    ):
        values = term.get(field)
        if not isinstance(values, list) or not all(
            isinstance(item, str) and item for item in values
        ):
            raise SemanticAuthorityError("semantic_term_invalid")
    if not term["maps_to_concepts"] or not all(
        item.startswith("orbit.concept/") for item in term["maps_to_concepts"]
    ):
        raise SemanticAuthorityError("semantic_term_concept_mapping_invalid")
    return dict(term)


def _source_index(value: Any, *, reason_code: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        raise SemanticAuthorityError(reason_code)
    result: dict[str, dict[str, Any]] = {}
    for item in value:
        source = _mapping(item, reason_code)
        role = _string(source.get("role"), reason_code)
        if role in result:
            raise SemanticAuthorityError(reason_code)
        result[role] = source
    return result


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SemanticAuthorityError("semantic_artifact_invalid")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: _reject_constant(),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SemanticAuthorityError("semantic_artifact_invalid") from error
    return _mapping(value, "semantic_artifact_invalid")


def _mapping(value: Any, reason_code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SemanticAuthorityError(reason_code)
    return value


def _string(value: Any, reason_code: str) -> str:
    if not isinstance(value, str) or not value:
        raise SemanticAuthorityError(reason_code)
    return value


def _file_digest(path: Path) -> str:
    try:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise SemanticAuthorityError("semantic_artifact_invalid") from error


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SemanticAuthorityError("semantic_json_duplicate_key")
        value[key] = item
    return value


def _reject_constant() -> None:
    raise SemanticAuthorityError("semantic_json_constant_invalid")

