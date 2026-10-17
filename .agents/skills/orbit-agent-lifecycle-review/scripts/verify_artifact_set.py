#!/usr/bin/env python3
"""Strictly verify Orbit lifecycle-review artifact manifests and raw bytes."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

ALGORITHM = "sha256"
CANONICALIZATION = "orbit.canonical-json/1.0"
ARTIFACT_SET_V1 = "orbit.lifecycle-review-artifact-set/1"
ARTIFACT_SET_V2 = "orbit.lifecycle-review-artifact-set/2"
ARTIFACT_SET_V3 = "orbit.lifecycle-review-artifact-set/3"
CONCEPT_BINDINGS_VERSION = "orbit.lifecycle-review-concept-bindings/1"
CONTROL_PLANE_ROOT = Path(__file__).resolve().parents[4]
CONCEPT_PROFILE_PATH = CONTROL_PLANE_ROOT / "references/company-concept-profile.json"
SCOPE_KINDS = {
    "automation_policy_activation",
    "agent_activation",
    "tool_activation",
    "model_route_approval",
    "corpus_acquisition_approval",
    "r2_execution",
}
FORBIDDEN_TRUE_KEYS = {
    "release_authorization",
    "activation_authorized",
    "runtime_started",
    "effective",
}
_DIGEST = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")


class ReviewError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReviewError(f"duplicate_json_key:{key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ReviewError(f"invalid_json_constant:{value}")


def safe_relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ReviewError("artifact_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ReviewError(f"artifact_path_unsafe:{value}")
    return path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_regular(root: Path, relative: PurePosixPath) -> Path:
    current = root
    for part in relative.parts:
        current = current / part
        if os.path.lexists(current) and stat.S_ISLNK(os.lstat(current).st_mode):
            raise ReviewError(f"artifact_symlink_forbidden:{relative}")
    if not current.is_file():
        raise ReviewError(f"artifact_missing:{relative}")
    return current


def expected_hex(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ReviewError("artifact_digest_invalid")
    return value.removeprefix("sha256:")


def _exact_fields(value: Mapping[str, Any], expected: set[str], reason: str) -> None:
    if set(value) != expected:
        raise ReviewError(reason)


def _reject_authority_widening(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in FORBIDDEN_TRUE_KEYS and item is True:
                raise ReviewError(f"authority_widening_forbidden:{key}")
            _reject_authority_widening(item)
    elif isinstance(value, list):
        for item in value:
            _reject_authority_widening(item)


def _validate_descriptor(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReviewError(f"{label}_descriptor_invalid")
    _exact_fields(
        value,
        {"algorithm", "canonicalization", "value"},
        f"{label}_descriptor_fields_invalid",
    )
    if value["algorithm"] != ALGORITHM:
        raise ReviewError(f"{label}_algorithm_invalid")
    if value["canonicalization"] != CANONICALIZATION:
        raise ReviewError(f"{label}_canonicalization_invalid")
    expected_hex(value["value"])
    return value


def _validate_v2_digest_bindings(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise ReviewError("digest_bindings_invalid")
    _exact_fields(
        value,
        {"subjects", "approval_receipts", "pending_approval_scopes"},
        "digest_bindings_fields_invalid",
    )
    subjects = value["subjects"]
    receipts = value["approval_receipts"]
    pending = value["pending_approval_scopes"]
    if not isinstance(subjects, list) or not subjects:
        raise ReviewError("digest_subjects_invalid")
    subject_by_scope: dict[str, str] = {}
    for item in subjects:
        if not isinstance(item, Mapping):
            raise ReviewError("digest_subject_invalid")
        _exact_fields(
            item,
            {"scope_kind", "subject_id", "subject_digest"},
            "digest_subject_fields_invalid",
        )
        scope = item["scope_kind"]
        if (
            scope not in SCOPE_KINDS
            or scope in subject_by_scope
            or not isinstance(item["subject_id"], str)
            or not item["subject_id"]
        ):
            raise ReviewError("digest_subject_invalid")
        expected_hex(item["subject_digest"])
        subject_by_scope[scope] = item["subject_digest"]
    if not isinstance(receipts, list):
        raise ReviewError("approval_receipts_invalid")
    receipt_scopes: set[str] = set()
    for item in receipts:
        if not isinstance(item, Mapping):
            raise ReviewError("approval_receipt_invalid")
        _exact_fields(
            item,
            {
                "scope_kind",
                "subject_digest",
                "approval_receipt_digest",
                "ledger_revision",
                "approval_action",
                "current_status",
                "expires_at",
                "consumption_status",
            },
            "approval_receipt_fields_invalid",
        )
        scope = item["scope_kind"]
        subject_digest = item["subject_digest"]
        receipt_digest = item["approval_receipt_digest"]
        expires_at = item["expires_at"]
        if (
            scope not in subject_by_scope
            or scope in receipt_scopes
            or subject_by_scope[scope] != subject_digest
            or not isinstance(item["ledger_revision"], int)
            or isinstance(item["ledger_revision"], bool)
            or item["ledger_revision"] < 1
            or not isinstance(item["approval_action"], str)
            or not item["approval_action"]
            or not isinstance(item["current_status"], str)
            or not item["current_status"]
            or (expires_at is not None and not isinstance(expires_at, str))
            or item["consumption_status"]
            not in {"not_applicable", "unconsumed", "consumed", "blocked", "expired"}
        ):
            raise ReviewError("approval_receipt_invalid")
        expected_hex(subject_digest)
        expected_hex(receipt_digest)
        if subject_digest == receipt_digest:
            raise ReviewError("subject_digest_used_as_approval_receipt")
        receipt_scopes.add(scope)
    if (
        not isinstance(pending, list)
        or any(scope not in subject_by_scope for scope in pending)
        or len(set(pending)) != len(pending)
        or set(pending) & receipt_scopes
        or receipt_scopes | set(pending) != set(subject_by_scope)
    ):
        raise ReviewError("pending_approval_scopes_invalid")


def _string_list(value: Any, reason: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ReviewError(reason)
    return tuple(value)


def _load_concept_profile() -> tuple[dict[str, Any], str]:
    try:
        raw = CONCEPT_PROFILE_PATH.read_bytes()
        profile = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReviewError("concept_profile_unavailable") from error
    if not isinstance(profile, dict):
        raise ReviewError("concept_profile_invalid")
    _exact_fields(
        profile,
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
    source = profile["source"]
    if not isinstance(source, Mapping):
        raise ReviewError("concept_profile_source_invalid")
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
    concepts = _string_list(profile["concept_ids"], "concept_profile_ids_invalid")
    if (
        profile["profile_version"] != "orbit.control-plane-concept-profile/1"
        or profile["status"] != "read_only_consumer_lock"
        or profile["authority_claim"] != "none"
        or source.get("catalog_version")
        != "orbit.architecture-concept-catalog/2"
        or not _DIGEST.fullmatch(str(source.get("catalog_sha256", "")))
        or not _DIGEST.fullmatch(
            str(source.get("validation_schema_sha256", ""))
        )
        or not re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit", "")))
        or any(not item.startswith("orbit.concept/") for item in concepts)
    ):
        raise ReviewError("concept_profile_identity_invalid")
    semantics = profile["authority_semantics"]
    manifest_requirements = profile["required_by_manifest_type"]
    scope_requirements = profile["required_by_scope_kind"]
    if (
        not isinstance(semantics, Mapping)
        or not isinstance(manifest_requirements, Mapping)
        or not isinstance(scope_requirements, Mapping)
        or semantics.get("effective_task_authority")
        != ["orbit.concept/execution-grant"]
    ):
        raise ReviewError("concept_profile_effective_authority_invalid")
    referenced: set[str] = set()
    for mapping in (semantics, manifest_requirements, scope_requirements):
        for values in mapping.values():
            referenced.update(_string_list(values, "concept_profile_reference_invalid"))
    if not referenced <= set(concepts):
        raise ReviewError("concept_profile_reference_unknown")
    return profile, "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_v3_concept_bindings(
    value: Any, *, manifest_type: str, digest_bindings: Mapping[str, Any]
) -> tuple[str, ...]:
    if not isinstance(value, Mapping):
        raise ReviewError("concept_bindings_invalid")
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
    profile, profile_sha256 = _load_concept_profile()
    source = profile["source"]
    if (
        value["binding_version"] != CONCEPT_BINDINGS_VERSION
        or value["profile_version"] != profile["profile_version"]
        or value["profile_sha256"] != profile_sha256
        or value["architecture_commit"] != source["commit"]
        or value["catalog_sha256"] != source["catalog_sha256"]
    ):
        raise ReviewError("concept_bindings_source_drift")
    concept_ids = _string_list(value["concept_ids"], "concept_bindings_ids_invalid")
    if tuple(sorted(concept_ids)) != concept_ids:
        raise ReviewError("concept_bindings_ids_not_sorted")
    if not set(concept_ids) <= set(profile["concept_ids"]):
        raise ReviewError("concept_bindings_unknown_id")
    required = set(profile["required_by_manifest_type"].get(manifest_type, []))
    for subject in digest_bindings["subjects"]:
        required.update(
            profile["required_by_scope_kind"].get(subject["scope_kind"], [])
        )
    if not required <= set(concept_ids):
        raise ReviewError("concept_bindings_required_id_missing")
    return concept_ids


def validate_manifest_profile(manifest: dict[str, Any]) -> str:
    _reject_authority_widening(manifest)
    version = manifest.get("manifest_version")
    if version == ARTIFACT_SET_V1:
        _exact_fields(
            manifest,
            {
                "manifest_version",
                "artifacts",
                "release_authorization",
                "activation_authorized",
            },
            "artifact_set_v1_fields_invalid",
        )
        if (
            manifest["release_authorization"] is not False
            or manifest["activation_authorized"] is not False
        ):
            raise ReviewError("artifact_set_v1_authority_invalid")
        return "lifecycle_artifact_set_v1_legacy"
    if version == ARTIFACT_SET_V2:
        _exact_fields(
            manifest,
            {
                "manifest_version",
                "manifest_type",
                "algorithm",
                "canonicalization",
                "evidence_status",
                "artifacts",
                "digest_bindings",
                "release_authorization",
                "activation_authorized",
                "runtime_started",
                "effective",
            },
            "artifact_set_v2_fields_invalid",
        )
        if manifest["manifest_type"] not in {
            "lifecycle_review",
            "runtime_execution_review",
        }:
            raise ReviewError("artifact_set_manifest_type_invalid")
        if manifest["algorithm"] != ALGORITHM:
            raise ReviewError("artifact_set_algorithm_invalid")
        if manifest["canonicalization"] != CANONICALIZATION:
            raise ReviewError("artifact_set_canonicalization_invalid")
        if manifest["evidence_status"] not in {"static", "synthetic", "public"}:
            raise ReviewError("artifact_set_evidence_status_invalid")
        for field in FORBIDDEN_TRUE_KEYS:
            if manifest[field] is not False:
                raise ReviewError(f"artifact_set_authority_invalid:{field}")
        _validate_v2_digest_bindings(manifest["digest_bindings"])
        return "lifecycle_artifact_set_v2"
    if version == ARTIFACT_SET_V3:
        _exact_fields(
            manifest,
            {
                "manifest_version",
                "manifest_type",
                "algorithm",
                "canonicalization",
                "evidence_status",
                "artifacts",
                "digest_bindings",
                "concept_bindings",
                "release_authorization",
                "activation_authorized",
                "runtime_started",
                "effective",
            },
            "artifact_set_v3_fields_invalid",
        )
        if manifest["manifest_type"] not in {
            "lifecycle_review",
            "runtime_execution_review",
        }:
            raise ReviewError("artifact_set_manifest_type_invalid")
        if manifest["algorithm"] != ALGORITHM:
            raise ReviewError("artifact_set_algorithm_invalid")
        if manifest["canonicalization"] != CANONICALIZATION:
            raise ReviewError("artifact_set_canonicalization_invalid")
        if manifest["evidence_status"] not in {"static", "synthetic", "public"}:
            raise ReviewError("artifact_set_evidence_status_invalid")
        for field in FORBIDDEN_TRUE_KEYS:
            if manifest[field] is not False:
                raise ReviewError(f"artifact_set_authority_invalid:{field}")
        _validate_v2_digest_bindings(manifest["digest_bindings"])
        _validate_v3_concept_bindings(
            manifest["concept_bindings"],
            manifest_type=manifest["manifest_type"],
            digest_bindings=manifest["digest_bindings"],
        )
        return "lifecycle_artifact_set_v3"
    if not isinstance(
        manifest.get("schema_version")
        or manifest.get("manifest_version")
        or manifest.get("review_version")
        or manifest.get("kind"),
        str,
    ):
        raise ReviewError("manifest_type_missing")
    return "typed_candidate_or_handoff"


def artifact_entries(manifest: dict[str, Any], profile: str) -> list[dict[str, Any]]:
    if isinstance(manifest.get("artifacts"), list):
        entries = manifest["artifacts"]
    else:
        entries = []
        for key in ("tool_manifests", "domain_schemas", "registration_artifacts"):
            value = manifest.get(key)
            if isinstance(value, list):
                entries.extend(value)
    if not entries:
        raise ReviewError("artifact_set_missing")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReviewError("artifact_entry_invalid")
        allowed = {frozenset({"path", "sha256"})}
        if profile == "typed_candidate_or_handoff":
            allowed.add(frozenset({"kind", "path", "sha256"}))
        if frozenset(entry) not in allowed:
            raise ReviewError("artifact_entry_fields_invalid")
    return entries


def canonical_candidate_digest(manifest: dict[str, Any]) -> str | None:
    descriptor = manifest.get("candidate_set_digest")
    if descriptor is None:
        return None
    descriptor = _validate_descriptor(descriptor, "candidate")
    canonical = copy.deepcopy(manifest)
    del canonical["candidate_set_digest"]["value"]
    source = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    actual = hashlib.sha256(source).hexdigest()
    if actual != expected_hex(descriptor["value"]):
        raise ReviewError("candidate_digest_mismatch")
    return actual


def canonical_handoff_digest(manifest: dict[str, Any]) -> str | None:
    descriptor = manifest.get("handoff_digest")
    if descriptor is None:
        return None
    descriptor = _validate_descriptor(descriptor, "handoff")
    canonical = copy.deepcopy(manifest)
    del canonical["handoff_digest"]["value"]
    source = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    actual = hashlib.sha256(source).hexdigest()
    if actual != expected_hex(descriptor["value"]):
        raise ReviewError("handoff_digest_mismatch")
    return actual


def verify(root: Path, manifest_relative: PurePosixPath) -> dict[str, Any]:
    root = root.resolve(strict=True)
    manifest_path = read_regular(root, manifest_relative)
    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    if not isinstance(manifest, dict):
        raise ReviewError("manifest_not_object")
    profile = validate_manifest_profile(manifest)
    checked: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in artifact_entries(manifest, profile):
        relative = safe_relative(entry["path"])
        if str(relative) in seen:
            raise ReviewError(f"artifact_path_duplicated:{relative}")
        seen.add(str(relative))
        path = read_regular(root, relative)
        actual = digest(path)
        if actual != expected_hex(entry["sha256"]):
            raise ReviewError(f"artifact_digest_mismatch:{relative}")
        checked.append({"path": str(relative), "sha256": f"sha256:{actual}"})
    candidate_digest = canonical_candidate_digest(manifest)
    handoff_digest = canonical_handoff_digest(manifest)
    document = {
        "status": "PASS",
        "evidence_status": "static_digest_review",
        "manifest": str(manifest_relative),
        "manifest_profile": profile,
        "manifest_sha256": f"sha256:{digest(manifest_path)}",
        "artifacts_checked": checked,
        "candidate_set_digest": (
            None if candidate_digest is None else f"sha256:{candidate_digest}"
        ),
        "release_authorization": False,
        "activation_authorized": False,
        "runtime_started": False,
        "effective": False,
    }
    if handoff_digest is not None:
        document["handoff_digest"] = f"sha256:{handoff_digest}"
    if profile == "lifecycle_artifact_set_v3":
        document["concept_bindings"] = {
            "architecture_commit": manifest["concept_bindings"][
                "architecture_commit"
            ],
            "catalog_sha256": manifest["concept_bindings"]["catalog_sha256"],
            "concept_ids": manifest["concept_bindings"]["concept_ids"],
        }
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    try:
        document = verify(args.root, safe_relative(args.manifest))
        exit_code = 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ReviewError) as error:
        document = {
            "status": "FAIL",
            "reason": str(error),
            "release_authorization": False,
            "activation_authorized": False,
            "runtime_started": False,
            "effective": False,
        }
        exit_code = 1
    print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

