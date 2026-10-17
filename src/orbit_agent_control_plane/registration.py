"""Strict registration-only intake for approved D0 synthetic Agent handoffs.

This module verifies immutable source bytes and writes minimal local evidence.
It does not activate an Agent, create a Company Registry record, or grant any
runtime, task, model, network, filesystem, database, or NAS authority.
"""

from __future__ import annotations

import copy
import fcntl
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

from .ids import deterministic_id

LEGACY_REGISTRATION_LEDGER_VERSION = "orbit.synthetic-agent-registration-ledger/1"
REGISTRATION_LEDGER_VERSION = "orbit.synthetic-agent-registration-ledger/2"
REGISTRATION_GENESIS_HASH = "sha256:" + ("0" * 64)
REGISTRATION_INTAKE_PROFILE = "orbit.synthetic-agent-registration-intake/1"
REGISTRATION_INTAKE_OPERATIONS = ("apply", "status", "replay")
REGISTRATION_APPROVAL_SEMANTICS = (
    "批准精确 handoff 与 manifest 摘要用于 local synthetic registration-only intake；"
    "不批准正式 Registry、激活、Runtime、Task、Grant、模型、网络、文件系统、NAS、"
    "真实数据、预产或生产。"
)
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
MAX_REGISTRATION_LEDGER_BYTES = 16 * 1024 * 1024
MAX_REGISTRATION_RECORD_BYTES = 64 * 1024

_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_APPROVAL_LOCK = (
    _REPO_ROOT / "references" / "agent-registration-approved-inputs.json"
)
DEFAULT_COMPANY_LOCK = _REPO_ROOT / "references" / "company-contract-lock.json"
DEFAULT_CONTRACT_BUNDLE = (
    _REPO_ROOT
    / "packages"
    / "agent-authoring-toolkit"
    / "contract-bundles"
    / "contract-v0.1.0-alpha.2"
)
HISTORICAL_ALPHA1_COMPANY_LOCK = (
    _REPO_ROOT / "references" / "company-contract-lock.alpha.1.history.json"
)
HISTORICAL_ALPHA1_CONTRACT_BUNDLE = (
    _REPO_ROOT
    / "packages"
    / "agent-authoring-toolkit"
    / "contract-bundles"
    / "contract-v0.1.0-alpha.1"
)

_REQUIRED_SCHEMA_IDS = {
    "definition": "urn:company-ai-os:schema:agent-definition:0.1",
    "binding": "urn:company-ai-os:schema:agent-binding:0.1",
    "template": "urn:company-ai-os:schema:agent-template:0.1",
    "registry": "urn:company-ai-os:schema:agent-registry:0.3",
    "approval": "urn:company-ai-os:schema:approval-decision:0.1",
    "audit": "urn:company-ai-os:schema:audit-event:0.1",
}
_COMMON_SCHEMA_ID = "urn:company-ai-os:schema:agent-common:0.1"
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")
_YAML_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_LEDGER_RECORD_KEYS = {
    "ledger_version",
    "sequence",
    "record_id",
    "record_type",
    "idempotency_key",
    "previous_record_hash",
    "payload",
    "record_hash",
}
_LEDGER_PAYLOAD_KEYS = {
    "handoff_id",
    "agent_id",
    "agent_version",
    "candidate_digest",
    "handoff_digest",
    "handoff_manifest_sha256",
    "definition_ref",
    "definition_digest",
    "binding_ref",
    "binding_digest",
    "template_ref",
    "template_digest",
    "registry_record_digest",
    "owner_role_ref",
    "hierarchy_node_ref",
    "registry_record_ref",
    "registration_approval_ref",
    "registration_audit_ref",
    "registration_status",
    "evidence_status",
    "company_authoritative",
    "synthetic_registration_evidence_written",
    "company_registry_write_applied",
    "formal_registry_record_exists",
    "activation_authorized",
    "active",
    "task_execution_authorized",
}
_LEGACY_LEDGER_PAYLOAD_KEYS = {
    "handoff_id",
    "candidate_digest",
    "handoff_digest",
    "handoff_manifest_sha256",
    "registry_record_ref",
    "registration_approval_ref",
    "registration_audit_ref",
    "registration_status",
    "evidence_status",
    "company_authoritative",
    "synthetic_registration_evidence_written",
    "company_registry_write_applied",
    "formal_registry_record_exists",
    "activation_authorized",
    "active",
    "task_execution_authorized",
}
_LEAK_PATTERNS = (
    re.compile(r"opaque_storage_ref", re.IGNORECASE),
    re.compile(r"opaque://", re.IGNORECASE),
    re.compile(r"/Users/", re.IGNORECASE),
    re.compile(r"/Volumes/", re.IGNORECASE),
    re.compile(r"(?:file|smb)://", re.IGNORECASE),
    re.compile(r"secret[ _-]?ref(?:erence)?", re.IGNORECASE),
    re.compile(r"api[ _-]?key", re.IGNORECASE),
    re.compile(r"endpoint", re.IGNORECASE),
)


class RegistrationError(ValueError):
    """Fail-closed registration intake error with a stable reason code."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class VerifiedRegistrationHandoff:
    handoff_id: str
    agent_id: str
    agent_version: str
    candidate_digest: str
    handoff_digest: str
    handoff_manifest_sha256: str
    definition_ref: str
    definition_digest: str
    binding_ref: str
    binding_digest: str
    template_ref: str
    template_digest: str
    registry_record_digest: str
    owner_role_ref: str
    hierarchy_node_ref: str
    registry_record_ref: str
    registration_approval_ref: str
    registration_audit_ref: str

    def ledger_payload(self) -> dict[str, object]:
        return {
            **asdict(self),
            "registration_status": "draft",
            "evidence_status": "synthetic",
            "company_authoritative": False,
            "synthetic_registration_evidence_written": True,
            "company_registry_write_applied": False,
            "formal_registry_record_exists": False,
            "activation_authorized": False,
            "active": False,
            "task_execution_authorized": False,
        }


@dataclass(frozen=True)
class RegistrationAppendResult:
    record_id: str
    sequence: int
    record_hash: str
    appended: bool


@dataclass(frozen=True)
class RegistrationReplay:
    records_checked: int
    last_record_hash: str
    registrations: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class _RegistrationRecord:
    sequence: int
    record_id: str
    idempotency_key: str
    previous_record_hash: str
    payload: Mapping[str, Any]
    record_hash: str


@dataclass(frozen=True)
class _YamlLine:
    indent: int
    text: str
    number: int


def apply_registration_handoff(
    source_root: Path | str,
    handoff_manifest: Path | str,
    ledger_path: Path | str,
    *,
    approval_lock_path: Path | str = DEFAULT_APPROVAL_LOCK,
    company_lock_path: Path | str = DEFAULT_COMPANY_LOCK,
    contract_bundle_root: Path | str = DEFAULT_CONTRACT_BUNDLE,
) -> tuple[VerifiedRegistrationHandoff, RegistrationAppendResult]:
    verified = verify_registration_handoff(
        source_root,
        handoff_manifest,
        approval_lock_path=approval_lock_path,
        company_lock_path=company_lock_path,
        contract_bundle_root=contract_bundle_root,
    )
    result = SyntheticAgentRegistrationLedger(ledger_path).append_registration(
        verified.ledger_payload(),
        idempotency_key=(
            f"registration:{verified.handoff_id}:"
            f"{verified.handoff_digest.removeprefix('sha256:')}"
        ),
    )
    return verified, result


def verify_registration_handoff(
    source_root: Path | str,
    handoff_manifest: Path | str,
    *,
    approval_lock_path: Path | str = DEFAULT_APPROVAL_LOCK,
    company_lock_path: Path | str = DEFAULT_COMPANY_LOCK,
    contract_bundle_root: Path | str = DEFAULT_CONTRACT_BUNDLE,
) -> VerifiedRegistrationHandoff:
    """Verify one approved registration handoff without writing any state."""

    root = _validate_source_root(source_root)
    manifest_relative = _safe_relative_path(handoff_manifest, "handoff manifest")
    manifest_bytes = _read_safe_file(root, manifest_relative)
    handoff = _load_json_bytes(manifest_bytes, "handoff manifest")
    _validate_handoff_shape(handoff)

    handoff_digest = _canonical_digest_without(
        handoff, ("handoff_digest", "value")
    )
    if handoff_digest != handoff["handoff_digest"]["value"]:
        raise RegistrationError(
            "handoff_digest_mismatch", "handoff canonical digest differs"
        )
    handoff_digest_prefixed = f"sha256:{handoff_digest}"
    manifest_sha256 = _digest(manifest_bytes)
    approved = _approved_handoff(
        Path(approval_lock_path), handoff["handoff_id"]
    )
    expected_approval = {
        "manifest_sha256": manifest_sha256,
        "candidate_digest": handoff["candidate_set_ref"]["digest"],
        "handoff_digest": handoff_digest_prefixed,
    }
    for field, actual in expected_approval.items():
        if approved[field] != actual:
            raise RegistrationError(
                "registration_input_not_approved",
                "registration input differs from the reviewed approval lock",
            )
    if (
        not approved["registration_only"]
        or approved["activation_authorized"]
        or approved["task_execution_authorized"]
    ):
        raise RegistrationError(
            "approval_scope_invalid", "approval lock exceeds registration-only scope"
        )

    schemas, company_authority, schema_digests = _load_verified_company_schemas(
        Path(company_lock_path), Path(contract_bundle_root)
    )
    for field in ("contract_release_id", "contract_git_tag", "contract_git_commit"):
        if approved[field] != company_authority[field]:
            raise RegistrationError(
                "company_contract_identity_mismatch",
                "approval lock differs from the Company Contract release",
            )

    registration_entries = _artifact_index(
        handoff["registration_artifacts"],
        "registration artifacts",
    )
    if set(registration_entries) != {
        "CompanyRegistrationContractLock",
        "AgentRegistryRecord",
        "ApprovalDecision",
        "AuditEvent",
    }:
        raise RegistrationError(
            "registration_artifact_set_invalid",
            "registration artifact set is incomplete or unsupported",
        )
    registration_sources = _read_hashed_artifacts(root, registration_entries)
    registration_lock = _load_json_bytes(
        registration_sources["CompanyRegistrationContractLock"],
        "registration Company Contract lock",
    )
    _validate_registration_contract_lock(
        registration_lock,
        company_authority,
        schema_digests,
        approved["registration_intake_profile"],
    )

    candidate_refs = _strict_mapping(
        handoff["candidate_artifact_refs"], "candidate artifact refs"
    )
    if set(candidate_refs) != {"definition", "binding", "template"}:
        raise RegistrationError(
            "candidate_artifact_set_invalid", "candidate artifact refs are incomplete"
        )
    for name, reference in candidate_refs.items():
        _validate_versioned_ref(reference, f"candidate {name} ref")
    registration_version_root = manifest_relative.parent
    if (
        registration_version_root.parent.name != "registration"
        or registration_version_root.parent.parent == PurePosixPath(".")
    ):
        raise RegistrationError(
            "handoff_manifest_location_invalid",
            "handoff manifest is outside the expected registration version directory",
        )
    agent_root = registration_version_root.parent.parent
    candidate_manifest_path = (
        agent_root
        / "candidates"
        / handoff["candidate_set_ref"]["version"]
        / "candidate-review-manifest.json"
    )
    candidate_manifest_bytes = _read_safe_file(root, candidate_manifest_path)
    candidate_manifest = _load_json_bytes(
        candidate_manifest_bytes, "candidate review manifest"
    )
    _validate_candidate_manifest_shape(candidate_manifest)
    candidate_digest = _canonical_digest_without(
        candidate_manifest, ("candidate_set_digest", "value")
    )
    candidate_digest_prefixed = f"sha256:{candidate_digest}"
    if candidate_digest != candidate_manifest["candidate_set_digest"]["value"]:
        raise RegistrationError(
            "candidate_digest_mismatch", "candidate canonical digest differs"
        )
    if (
        candidate_digest_prefixed != handoff["candidate_set_ref"]["digest"]
        or candidate_manifest["candidate_set_id"]
        != handoff["candidate_set_ref"]["id"]
        or candidate_manifest["version"] != handoff["candidate_set_ref"]["version"]
    ):
        raise RegistrationError(
            "candidate_reference_mismatch", "handoff candidate reference differs"
        )

    candidate_entries = _artifact_index(
        candidate_manifest["artifacts"], "candidate manifest artifacts"
    )
    for required_kind in ("AgentDefinition", "AgentBinding", "AgentTemplate"):
        if required_kind not in candidate_entries:
            raise RegistrationError(
                "candidate_artifact_set_invalid", "required candidate artifact is missing"
            )
    candidate_sources = _read_hashed_artifacts(root, candidate_entries)
    for entry in candidate_manifest["supporting_contracts"]:
        _read_and_verify_declared_file(root, entry, "supporting contract")
    _read_and_verify_declared_file(
        root, candidate_manifest["review_guide"], "candidate review guide"
    )
    candidate_company_lock_source = _read_and_verify_declared_file(
        root,
        {
            "path": candidate_manifest["company_contract"]["lock_path"],
            "sha256": candidate_manifest["company_contract"]["lock_sha256"],
        },
        "candidate Company Contract lock",
    )
    candidate_company_lock = _load_json_bytes(
        candidate_company_lock_source, "candidate Company Contract lock"
    )
    _validate_candidate_contract_lock(
        candidate_company_lock, company_authority, schema_digests
    )
    if (
        candidate_manifest["company_contract"]["git_tag"]
        != company_authority["contract_git_tag"]
        or candidate_manifest["company_contract"]["git_commit"]
        != company_authority["contract_git_commit"]
    ):
        raise RegistrationError(
            "company_contract_identity_mismatch",
            "candidate manifest Contract identity differs",
        )

    for name, kind in (
        ("definition", "AgentDefinition"),
        ("binding", "AgentBinding"),
        ("template", "AgentTemplate"),
    ):
        declared_path = _safe_relative_path(candidate_entries[kind]["path"], kind)
        if declared_path.parent != candidate_manifest_path.parent:
            raise RegistrationError(
                "candidate_artifact_path_mismatch",
                "candidate artifact path differs from its version directory",
            )
        expected_digest = f"sha256:{_sha256(candidate_sources[kind])}"
        if handoff["candidate_artifact_refs"][name]["digest"] != expected_digest:
            raise RegistrationError(
                "candidate_artifact_digest_mismatch",
                "candidate artifact bytes differ from handoff reference",
            )

    definition = _load_strict_yaml_bytes(candidate_sources["AgentDefinition"])
    binding = _load_strict_yaml_bytes(candidate_sources["AgentBinding"])
    template = _load_strict_yaml_bytes(candidate_sources["AgentTemplate"])
    registry_record = _load_strict_yaml_bytes(
        registration_sources["AgentRegistryRecord"]
    )
    approval = _load_strict_yaml_bytes(registration_sources["ApprovalDecision"])
    audit = _load_strict_yaml_bytes(registration_sources["AuditEvent"])

    validator = _SchemaValidator(schemas)
    for instance, schema_id in (
        (definition, _REQUIRED_SCHEMA_IDS["definition"]),
        (binding, _REQUIRED_SCHEMA_IDS["binding"]),
        (template, _REQUIRED_SCHEMA_IDS["template"]),
        (registry_record, _REQUIRED_SCHEMA_IDS["registry"]),
        (approval, _REQUIRED_SCHEMA_IDS["approval"]),
        (audit, _REQUIRED_SCHEMA_IDS["audit"]),
    ):
        validator.validate(instance, schema_id)

    _validate_candidate_and_registration_refs(
        handoff,
        definition,
        binding,
        template,
        registry_record,
        approval,
        audit,
        candidate_digest_prefixed,
    )
    deferred_source = _read_and_verify_declared_file(
        root, handoff["deferred_activation_test_ref"], "deferred activation test"
    )
    if not deferred_source:
        raise RegistrationError(
            "deferred_activation_evidence_empty",
            "deferred activation evidence must not be empty",
        )
    _validate_gate_state(handoff)
    _scan_for_leaks([registry_record, approval, audit])

    return VerifiedRegistrationHandoff(
        handoff_id=handoff["handoff_id"],
        agent_id=definition["metadata"]["agent_id"],
        agent_version=definition["metadata"]["version"],
        candidate_digest=candidate_digest_prefixed,
        handoff_digest=handoff_digest_prefixed,
        handoff_manifest_sha256=manifest_sha256,
        definition_ref=definition["metadata"]["agent_id"],
        definition_digest=handoff["candidate_artifact_refs"]["definition"]["digest"],
        binding_ref=binding["metadata"]["binding_id"],
        binding_digest=handoff["candidate_artifact_refs"]["binding"]["digest"],
        template_ref=template["metadata"]["template_id"],
        template_digest=handoff["candidate_artifact_refs"]["template"]["digest"],
        registry_record_digest=_digest(registration_sources["AgentRegistryRecord"]),
        owner_role_ref=registry_record["spec"]["owner_role_ref"],
        hierarchy_node_ref=registry_record["spec"]["hierarchy_node_ref"],
        registry_record_ref=registry_record["metadata"]["record_id"],
        registration_approval_ref=approval["metadata"]["decision_id"],
        registration_audit_ref=audit["metadata"]["audit_event_id"],
    )


class SyntheticAgentRegistrationLedger:
    """Owner-only append-only evidence ledger; never a Company Registry."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def append_registration(
        self, payload: Mapping[str, Any], *, idempotency_key: str
    ) -> RegistrationAppendResult:
        normalized = _normalize_json(payload)
        _validate_ledger_payload(normalized)
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY_PATTERN.fullmatch(
            idempotency_key
        ):
            raise RegistrationError(
                "invalid_idempotency_key", "registration idempotency key is invalid"
            )
        fd = self._open(create=True, exclusive=True)
        try:
            records = self._read_records(fd)
            matching = tuple(
                record for record in records if record.idempotency_key == idempotency_key
            )
            if matching:
                if len(matching) != 1 or _canonical_json(matching[0].payload) != _canonical_json(
                    normalized
                ):
                    raise RegistrationError(
                        "idempotency_conflict",
                        "registration idempotency key is bound to different content",
                    )
                existing = matching[0]
                return RegistrationAppendResult(
                    existing.record_id,
                    existing.sequence,
                    existing.record_hash,
                    False,
                )
            previous_hash = records[-1].record_hash if records else REGISTRATION_GENESIS_HASH
            payload_digest = _digest(_canonical_json(normalized).encode("utf-8"))
            record_id = deterministic_id(
                "registration", idempotency_key, payload_digest
            )
            content = {
                "ledger_version": REGISTRATION_LEDGER_VERSION,
                "sequence": len(records),
                "record_id": record_id,
                "record_type": "synthetic_registration_evidence",
                "idempotency_key": idempotency_key,
                "previous_record_hash": previous_hash,
                "payload": normalized,
            }
            record_hash = _digest(_canonical_json(content).encode("utf-8"))
            document = {**content, "record_hash": record_hash}
            _record_from_document(document, len(records), previous_hash)
            encoded = (_canonical_json(document) + "\n").encode("utf-8")
            if len(encoded) > MAX_REGISTRATION_RECORD_BYTES:
                raise RegistrationError(
                    "record_too_large", "registration record exceeds size limit"
                )
            if os.fstat(fd).st_size + len(encoded) > MAX_REGISTRATION_LEDGER_BYTES:
                raise RegistrationError(
                    "ledger_too_large", "registration ledger exceeds size limit"
                )
            written = os.write(fd, encoded)
            if written != len(encoded):
                raise RegistrationError(
                    "ledger_short_write", "registration ledger append was incomplete"
                )
            os.fsync(fd)
            return RegistrationAppendResult(
                record_id, len(records), record_hash, True
            )
        finally:
            self._close(fd)

    def replay(self) -> RegistrationReplay:
        fd = self._open(create=False, exclusive=False)
        try:
            records = self._read_records(fd)
        finally:
            self._close(fd)
        return RegistrationReplay(
            records_checked=len(records),
            last_record_hash=(
                records[-1].record_hash if records else REGISTRATION_GENESIS_HASH
            ),
            registrations=tuple(record.payload for record in records),
        )

    def _open(self, *, create: bool, exclusive: bool) -> int:
        if os.path.lexists(self.path):
            if stat.S_ISLNK(os.lstat(self.path).st_mode):
                raise RegistrationError(
                    "ledger_symlink_forbidden", "registration ledger may not be a symlink"
                )
        elif not create:
            raise RegistrationError(
                "ledger_not_found", "registration ledger does not exist"
            )
        if create:
            _ensure_owner_only_parent(self.path.parent)
        elif not self.path.parent.is_dir():
            raise RegistrationError(
                "ledger_parent_missing", "registration ledger parent is unavailable"
            )
        flags = os.O_RDONLY if not create else os.O_RDWR | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileNotFoundError as error:
            raise RegistrationError(
                "ledger_not_found", "registration ledger does not exist"
            ) from error
        except OSError as error:
            raise RegistrationError(
                "ledger_open_failed", "registration ledger could not be opened"
            ) from error
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise RegistrationError(
                    "ledger_not_regular_file", "registration ledger must be a regular file"
                )
            if metadata.st_uid != os.geteuid():
                raise RegistrationError(
                    "ledger_owner_mismatch", "registration ledger owner differs"
                )
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise RegistrationError(
                    "ledger_permissions_too_broad", "registration ledger must be 0600"
                )
            fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            return fd
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _close(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    @staticmethod
    def _read_records(fd: int) -> list[_RegistrationRecord]:
        size = os.fstat(fd).st_size
        if size > MAX_REGISTRATION_LEDGER_BYTES:
            raise RegistrationError(
                "ledger_too_large", "registration ledger exceeds size limit"
            )
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                raise RegistrationError(
                    "ledger_read_incomplete", "registration ledger read stopped"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        source = b"".join(chunks)
        if not source:
            return []
        if not source.endswith(b"\n"):
            raise RegistrationError(
                "truncated_record", "registration ledger record is truncated"
            )
        records: list[_RegistrationRecord] = []
        previous_hash = REGISTRATION_GENESIS_HASH
        idempotency_keys: set[str] = set()
        for sequence, line in enumerate(source.splitlines()):
            if not line:
                raise RegistrationError(
                    "blank_record", "registration ledger contains a blank record"
                )
            if len(line) + 1 > MAX_REGISTRATION_RECORD_BYTES:
                raise RegistrationError(
                    "record_too_large", "registration record exceeds size limit"
                )
            document = _load_json_bytes(line, "registration ledger record")
            record = _record_from_document(document, sequence, previous_hash)
            if record.idempotency_key in idempotency_keys:
                raise RegistrationError(
                    "duplicate_idempotency_record",
                    "registration ledger repeats an idempotency key",
                )
            idempotency_keys.add(record.idempotency_key)
            records.append(record)
            previous_hash = record.record_hash
        return records


def registration_result_document(
    verified: VerifiedRegistrationHandoff,
    result: RegistrationAppendResult,
) -> dict[str, object]:
    document = {
        "status": "verified",
        "evidence_status": "synthetic",
        "company_authoritative": False,
        "synthetic_registration_evidence_written": True,
        "candidate_digest": verified.candidate_digest,
        "handoff_digest": verified.handoff_digest,
        "registry_record_ref": verified.registry_record_ref,
        "registration_approval_ref": verified.registration_approval_ref,
        "registration_audit_ref": verified.registration_audit_ref,
        "local_ledger_record_id": result.record_id,
        "local_ledger_record_hash": result.record_hash,
        "local_revision": result.sequence,
        "sequence": result.sequence,
        "ledger_appended": result.appended,
        "company_registry_write_applied": False,
        "formal_registry_record_exists": False,
        "activation_authorized": False,
        "active": False,
        "task_execution_authorized": False,
    }
    _scan_for_leaks([document])
    return document


def registration_replay_document(replay: RegistrationReplay) -> dict[str, object]:
    if replay.records_checked == 0:
        raise RegistrationError(
            "ledger_empty", "registration ledger contains no records"
        )
    document = {
        "status": "verified",
        "evidence_status": "synthetic",
        "company_authoritative": False,
        "records_checked": replay.records_checked,
        "last_record_hash": replay.last_record_hash,
        "registrations": list(replay.registrations),
        "company_registry_write_applied": False,
        "formal_registry_record_exists": False,
        "activation_authorized": False,
        "active": False,
        "task_execution_authorized": False,
    }
    _scan_for_leaks([document])
    return document


def _validate_handoff_shape(value: Any) -> None:
    handoff = _strict_mapping(value, "handoff manifest")
    _exact_keys(
        handoff,
        {
            "schema_version",
            "handoff_id",
            "status",
            "evidence_status",
            "synthetic_only",
            "handoff_digest",
            "requested_operation",
            "candidate_set_ref",
            "candidate_artifact_refs",
            "registration_artifacts",
            "target_authority",
            "deferred_activation_test_ref",
            "gate_state",
            "required_application_sequence",
            "evidence_boundary",
        },
        "handoff manifest",
    )
    if (
        handoff["schema_version"] != "orbit.agent-registration-handoff-manifest/1.0"
        or handoff["status"] != "validated-registration-request-not-applied"
        or handoff["evidence_status"] != "synthetic"
        or handoff["synthetic_only"] is not True
        or handoff["requested_operation"] != "register-draft-agent-candidate"
    ):
        raise RegistrationError(
            "handoff_boundary_invalid", "handoff is not an expected synthetic draft registration"
        )
    _validate_digest_descriptor(handoff["handoff_digest"], "handoff digest")
    _validate_versioned_ref(handoff["candidate_set_ref"], "candidate set ref")
    _validate_handoff_target_authority(handoff["target_authority"])
    if not isinstance(handoff["registration_artifacts"], list):
        raise RegistrationError(
            "handoff_structure_invalid", "registration artifacts must be a list"
        )


def _validate_candidate_manifest_shape(value: Any) -> None:
    manifest = _strict_mapping(value, "candidate review manifest")
    _exact_keys(
        manifest,
        {
            "schema_version",
            "candidate_set_id",
            "version",
            "status",
            "evidence_status",
            "synthetic_only",
            "candidate_set_digest",
            "company_contract",
            "artifacts",
            "supporting_contracts",
            "review_guide",
            "human_roles",
            "activation_blockers",
            "gate_state",
            "evidence_boundary",
        },
        "candidate review manifest",
    )
    if (
        manifest["schema_version"] != "orbit.agent-candidate-review-manifest/1.0"
        or manifest["evidence_status"] != "synthetic"
        or manifest["synthetic_only"] is not True
    ):
        raise RegistrationError(
            "candidate_boundary_invalid", "candidate manifest is outside the synthetic boundary"
        )
    _validate_digest_descriptor(
        manifest["candidate_set_digest"], "candidate set digest"
    )
    if not isinstance(manifest["artifacts"], list) or not isinstance(
        manifest["supporting_contracts"], list
    ):
        raise RegistrationError(
            "candidate_structure_invalid", "candidate artifact lists are invalid"
        )


def _validate_candidate_and_registration_refs(
    handoff: Mapping[str, Any],
    definition: Mapping[str, Any],
    binding: Mapping[str, Any],
    template: Mapping[str, Any],
    registry_record: Mapping[str, Any],
    approval: Mapping[str, Any],
    audit: Mapping[str, Any],
    candidate_digest: str,
) -> None:
    candidate_refs = handoff["candidate_artifact_refs"]
    expected_definition = {
        "id": definition["metadata"]["agent_id"],
        "version": definition["metadata"]["version"],
        "digest": candidate_refs["definition"]["digest"],
    }
    expected_binding = {
        "id": binding["metadata"]["binding_id"],
        "version": binding["metadata"]["version"],
        "digest": candidate_refs["binding"]["digest"],
    }
    expected_template = {
        "id": template["metadata"]["template_id"],
        "version": template["metadata"]["version"],
        "digest": candidate_refs["template"]["digest"],
    }
    if candidate_refs != {
        "definition": expected_definition,
        "binding": expected_binding,
        "template": expected_template,
    }:
        raise RegistrationError(
            "candidate_identity_mismatch", "candidate artifact identity differs"
        )
    if (
        binding["spec"]["definition_ref"] != expected_definition
        or template["spec"]["child_definition_ref"] != expected_definition
    ):
        raise RegistrationError(
            "candidate_reference_mismatch", "candidate Definition references do not close"
        )
    if (
        registry_record["spec"]["definition_ref"] != expected_definition
        or registry_record["spec"]["binding_refs"] != [expected_binding]
        or registry_record["metadata"]["agent_id"] != expected_definition["id"]
    ):
        raise RegistrationError(
            "registry_candidate_reference_mismatch",
            "Registry record does not reference the exact candidate",
        )
    for document, label in (
        (definition, "Definition"),
        (binding, "Binding"),
        (template, "Template"),
        (registry_record, "Registry record"),
        (approval, "ApprovalDecision"),
        (audit, "AuditEvent"),
    ):
        metadata = document["metadata"]
        if metadata.get("evidence_status") != "synthetic" or metadata.get(
            "synthetic_only"
        ) is not True:
            raise RegistrationError(
                "registration_not_synthetic", f"{label} is outside the synthetic boundary"
            )
    if registry_record["metadata"]["status"] != "draft":
        raise RegistrationError(
            "registry_status_invalid", "Registry record must remain draft"
        )
    if (
        approval["spec"]["decision"] != "approve"
        or not approval["spec"]["scope_ref"].endswith("/registration-only")
        or approval["spec"]["scope_digest"] != candidate_digest
    ):
        raise RegistrationError(
            "approval_scope_digest_mismatch",
            "registration ApprovalDecision scope differs from the candidate",
        )
    audit_id = audit["metadata"]["audit_event_id"]
    scope_base = approval["spec"]["scope_ref"].removesuffix("/registration-only")
    if (
        approval["spec"]["audit_event_refs"] != [audit_id]
        or audit["spec"]["actor"]["id"]
        != approval["spec"]["decided_by_human_ref"]
        or audit["spec"]["task_ref"] != approval["metadata"]["task_id"]
        or audit["spec"]["action"] != "agent.registration.approve"
        or audit["spec"]["decision"] != "allow"
        or audit["spec"]["outcome"] != "succeeded"
        or audit["spec"]["resource"]["ref"] != scope_base
        or audit["spec"]["payload_ref"] != scope_base
    ):
        raise RegistrationError(
            "registration_audit_reference_mismatch",
            "ApprovalDecision and AuditEvent references do not close",
        )
    event_digest = _canonical_digest_without(
        audit, ("spec", "integrity", "event_digest")
    )
    if audit["spec"]["integrity"]["event_digest"] != f"sha256:{event_digest}":
        raise RegistrationError(
            "audit_integrity_digest_mismatch", "AuditEvent integrity digest differs"
        )
    if (
        audit["metadata"]["sequence"] != 0
        or audit["spec"]["integrity"]["previous_event_digest"] is not None
    ):
        raise RegistrationError(
            "audit_integrity_boundary_invalid", "registration AuditEvent must start its synthetic chain"
        )


def _validate_gate_state(handoff: Mapping[str, Any]) -> None:
    gate = _strict_mapping(handoff["gate_state"], "handoff gate state")
    required_false = {
        "company_registry_write_applied",
        "formal_registry_record_exists",
        "agent_release_manifest_created",
        "runtime_selected",
        "effective_grant_created",
        "activation_authorized",
        "active",
        "task_execution_authorized",
    }
    if any(gate.get(field) is not False for field in required_false):
        raise RegistrationError(
            "activation_boundary_violated",
            "registration handoff claims activation, execution, or formal Registry state",
        )
    required_true = {
        "candidate_digest_human_approved_for_registration",
        "company_schema_validated",
        "registration_digest_closure_validated",
        "registration_application_authorized",
    }
    if any(gate.get(field) is not True for field in required_true):
        raise RegistrationError(
            "registration_gate_incomplete", "registration handoff Gate is incomplete"
        )
    deferred = handoff["deferred_activation_test_ref"]
    if (
        deferred.get("id") != "E4-DRTA-001"
        or deferred.get("blocks_registration") is not False
        or deferred.get("blocks_activation") is not True
    ):
        raise RegistrationError(
            "deferred_activation_gate_invalid", "deferred E4 boundary differs"
        )


def _approved_handoff(lock_path: Path, handoff_id: str) -> Mapping[str, Any]:
    source = _read_local_regular_file(lock_path, "registration approval lock")
    lock = _load_json_bytes(source, "registration approval lock")
    _exact_keys(
        lock,
        {
            "lock_version",
            "status",
            "evidence_status",
            "company_authoritative",
            "review_requests",
            "approved_handoffs",
        },
        "registration approval lock",
    )
    if (
        lock["lock_version"]
        != "orbit.synthetic-agent-registration-approval-lock/2"
        or lock["status"]
        not in {"awaiting-human-review", "local-synthetic-registration-only"}
        or lock["evidence_status"] != "synthetic"
        or lock["company_authoritative"] is not False
        or not isinstance(lock["review_requests"], list)
        or not isinstance(lock["approved_handoffs"], list)
    ):
        raise RegistrationError(
            "approval_lock_invalid", "registration approval lock boundary is invalid"
        )
    matches = []
    expected_keys = {
        "handoff_id",
        "manifest_sha256",
        "candidate_digest",
        "handoff_digest",
        "contract_release_id",
        "contract_git_tag",
        "contract_git_commit",
        "registration_intake_profile",
        "approval_semantics",
        "registration_only",
        "activation_authorized",
        "task_execution_authorized",
    }
    for entry in [*lock["review_requests"], *lock["approved_handoffs"]]:
        _exact_keys(entry, expected_keys, "approved registration handoff")
        for field in ("manifest_sha256", "candidate_digest", "handoff_digest"):
            _validate_digest(entry[field], field)
        if (
            entry["registration_intake_profile"] != REGISTRATION_INTAKE_PROFILE
            or entry["approval_semantics"] != REGISTRATION_APPROVAL_SEMANTICS
            or not entry["registration_only"]
            or entry["activation_authorized"]
            or entry["task_execution_authorized"]
        ):
            raise RegistrationError(
                "approval_lock_invalid",
                "registration approval entry exceeds registration-only scope",
            )
        if entry in lock["approved_handoffs"] and entry["handoff_id"] == handoff_id:
            matches.append(entry)
    if lock["status"] == "awaiting-human-review" and lock["approved_handoffs"]:
        raise RegistrationError(
            "approval_lock_invalid", "pending approval lock contains approved inputs"
        )
    if len(matches) != 1:
        raise RegistrationError(
            "registration_input_not_approved", "handoff has no unique reviewed approval"
        )
    return matches[0]


def _load_verified_company_schemas(
    company_lock_path: Path,
    bundle_root: Path,
    required_schema_ids: set[str] | frozenset[str] | None = None,
) -> tuple[
    dict[str, Mapping[str, Any]], Mapping[str, str], dict[str, str]
]:
    company_lock = _load_json_bytes(
        _read_local_regular_file(company_lock_path, "Company Contract lock"),
        "Company Contract lock",
    )
    authority = _strict_mapping(company_lock.get("authority"), "Company Contract authority")
    required_authority = {
        "contract_release_id",
        "contract_git_tag",
        "contract_git_commit",
        "contract_release_manifest_sha256",
    }
    if not required_authority.issubset(authority):
        raise RegistrationError(
            "company_contract_lock_invalid", "Company Contract authority lock is incomplete"
        )
    manifest_source = _read_safe_file(bundle_root, PurePosixPath("manifest.json"))
    bundle_lock_source = _read_safe_file(bundle_root, PurePosixPath("bundle-lock.json"))
    manifest = _load_json_bytes(manifest_source, "Contract release manifest")
    bundle_lock = _load_json_bytes(bundle_lock_source, "Contract bundle lock")
    bundle_authority = _strict_mapping(
        bundle_lock.get("authority"), "Contract bundle authority"
    )
    if (
        bundle_lock.get("lock_version") != "orbit.contract-consumer-bundle/1"
        or _digest(manifest_source) != authority["contract_release_manifest_sha256"]
        or bundle_authority.get("release_manifest_sha256")
        != authority["contract_release_manifest_sha256"]
        or manifest.get("release_id") != authority["contract_release_id"]
        or manifest.get("status") != "approved"
        or manifest.get("source_revision", {}).get("tag")
        != authority["contract_git_tag"]
        or bundle_authority.get("contract_release_id")
        != authority["contract_release_id"]
        or bundle_authority.get("contract_git_tag")
        != authority["contract_git_tag"]
        or bundle_authority.get("contract_git_commit")
        != authority["contract_git_commit"]
    ):
        raise RegistrationError(
            "company_contract_identity_mismatch",
            "Contract bundle does not match the locked published release",
        )
    released = _unique_index(
        bundle_lock.get("released_schemas"), "schema_id", "Contract bundle schemas"
    )
    manifest_schemas = _unique_index(
        manifest.get("artifacts", {}).get("schemas"),
        "schema_id",
        "Contract release schemas",
    )
    schema_ids = (
        {_COMMON_SCHEMA_ID, *_REQUIRED_SCHEMA_IDS.values()}
        if required_schema_ids is None
        else set(required_schema_ids)
    )
    schemas: dict[str, Mapping[str, Any]] = {}
    schema_digests: dict[str, str] = {}
    for schema_id in schema_ids:
        if schema_id not in released or schema_id not in manifest_schemas:
            raise RegistrationError(
                "company_schema_missing", "required released Company Schema is missing"
            )
        bundle_entry = released[schema_id]
        manifest_entry = manifest_schemas[schema_id]
        if bundle_entry.get("sha256") != manifest_entry.get("sha256"):
            raise RegistrationError(
                "company_schema_digest_mismatch",
                "Contract bundle Schema digest differs from release manifest",
            )
        schema_path = _safe_relative_path(
            bundle_entry.get("bundle_path"), "Contract bundle Schema"
        )
        schema_source = _read_safe_file(bundle_root, schema_path)
        if _digest(schema_source) != bundle_entry["sha256"]:
            raise RegistrationError(
                "company_schema_digest_mismatch", "Company Schema bytes drifted"
            )
        schema = _load_json_bytes(schema_source, "Company Schema")
        if schema.get("$id") != schema_id:
            raise RegistrationError(
                "company_schema_id_mismatch", "Company Schema identifier differs"
            )
        schemas[schema_id] = schema
        schema_digests[schema_id] = bundle_entry["sha256"]
    return schemas, authority, schema_digests


def _validate_registration_contract_lock(
    lock: Mapping[str, Any],
    authority: Mapping[str, str],
    schema_digests: Mapping[str, str],
    expected_intake_profile: str,
) -> None:
    if (
        lock.get("lock_version")
        != "orbit.company-agent-registration-contract-lock/1.0"
        or lock.get("status") != "registration-handoff-only"
    ):
        raise RegistrationError(
            "registration_contract_lock_invalid", "registration Contract lock is invalid"
        )
    _validate_source_contract_authority(lock.get("authority"), authority)
    expected = {
        _COMMON_SCHEMA_ID,
        _REQUIRED_SCHEMA_IDS["registry"],
        _REQUIRED_SCHEMA_IDS["approval"],
        _REQUIRED_SCHEMA_IDS["audit"],
    }
    _validate_source_schema_entries(lock.get("schemas"), expected, schema_digests)
    target = _strict_mapping(lock.get("target_control_plane"), "target Control Plane")
    _exact_keys(
        target,
        {
            "compatibility_profile",
            "required_operations",
            "registration_only",
            "company_authoritative",
            "formal_company_registry_available",
        },
        "target Control Plane",
    )
    if (
        target.get("compatibility_profile") != expected_intake_profile
        or target.get("compatibility_profile") != REGISTRATION_INTAKE_PROFILE
        or target.get("required_operations") != list(REGISTRATION_INTAKE_OPERATIONS)
        or target.get("registration_only") is not True
        or target.get("company_authoritative") is not False
        or target.get("formal_company_registry_available") is not False
    ):
        raise RegistrationError(
            "source_authority_boundary_invalid",
            "source handoff is incompatible with the registration-only intake profile",
        )


def _validate_handoff_target_authority(value: Any) -> None:
    target = _strict_mapping(value, "handoff target authority")
    _exact_keys(
        target,
        {
            "owner",
            "compatibility_profile",
            "required_operations",
            "registration_only",
            "company_authoritative",
            "formal_registry_write_supported",
        },
        "handoff target authority",
    )
    if (
        target.get("owner") != "Company Control Plane"
        or target.get("compatibility_profile") != REGISTRATION_INTAKE_PROFILE
        or target.get("required_operations") != list(REGISTRATION_INTAKE_OPERATIONS)
        or target.get("registration_only") is not True
        or target.get("company_authoritative") is not False
        or target.get("formal_registry_write_supported") is not False
    ):
        raise RegistrationError(
            "handoff_target_authority_invalid",
            "handoff target exceeds the local registration-only intake profile",
        )


def _validate_candidate_contract_lock(
    lock: Mapping[str, Any],
    authority: Mapping[str, str],
    schema_digests: Mapping[str, str],
) -> None:
    if (
        lock.get("lock_version") != "orbit.company-agent-contract-lock/1.0"
        or lock.get("status") != "published-contract-reference"
    ):
        raise RegistrationError(
            "candidate_contract_lock_invalid", "candidate Contract lock is invalid"
        )
    source_authority = _strict_mapping(lock.get("authority"), "candidate Contract authority")
    if (
        source_authority.get("git_tag") != authority["contract_git_tag"]
        or source_authority.get("git_commit") != authority["contract_git_commit"]
    ):
        raise RegistrationError(
            "company_contract_identity_mismatch", "candidate Contract release differs"
        )
    expected = {
        _COMMON_SCHEMA_ID,
        _REQUIRED_SCHEMA_IDS["definition"],
        _REQUIRED_SCHEMA_IDS["binding"],
        _REQUIRED_SCHEMA_IDS["template"],
    }
    _validate_source_schema_entries(lock.get("schemas"), expected, schema_digests)


def _validate_source_contract_authority(
    value: Any, authority: Mapping[str, str]
) -> None:
    source = _strict_mapping(value, "source Contract authority")
    if (
        source.get("git_tag") != authority["contract_git_tag"]
        or source.get("git_commit") != authority["contract_git_commit"]
    ):
        raise RegistrationError(
            "company_contract_identity_mismatch", "source Contract release differs"
        )


def _validate_source_schema_entries(
    value: Any,
    expected_ids: set[str],
    schema_digests: Mapping[str, str],
) -> None:
    entries = _unique_index(value, "schema_id", "source Contract schemas")
    if set(entries) != expected_ids:
        raise RegistrationError(
            "company_schema_set_mismatch", "source Contract Schema set differs"
        )
    for schema_id, entry in entries.items():
        declared = entry.get("sha256")
        _validate_digest(declared, "source Schema digest")
        if declared != schema_digests[schema_id]:
            raise RegistrationError(
                "company_schema_digest_mismatch", "source Schema digest differs"
            )


class _SchemaValidator:
    """Small fail-closed validator for the keywords used by the locked schemas."""

    def __init__(self, schemas: Mapping[str, Mapping[str, Any]]) -> None:
        self.schemas = schemas

    def validate(self, instance: Any, schema_id: str) -> None:
        try:
            schema = self.schemas[schema_id]
            self._validate(instance, schema, schema, "$", schema_id)
        except RegistrationError:
            raise
        except Exception as error:
            raise RegistrationError(
                "company_schema_validation_failed",
                "registration artifact failed Company Schema validation",
            ) from error

    def _validate(
        self,
        instance: Any,
        schema: Any,
        root_schema: Mapping[str, Any],
        path: str,
        schema_id: str,
    ) -> None:
        if isinstance(schema, bool):
            if not schema:
                self._fail(path)
            return
        if not isinstance(schema, dict):
            self._fail(path)
        if "$ref" in schema:
            target, target_root, target_id = self._resolve_ref(
                schema["$ref"], root_schema, schema_id
            )
            self._validate(instance, target, target_root, path, target_id)
            return
        if "type" in schema and not _matches_json_type(instance, schema["type"]):
            self._fail(path)
        if "const" in schema and instance != schema["const"]:
            self._fail(path)
        if "enum" in schema and instance not in schema["enum"]:
            self._fail(path)
        if "oneOf" in schema:
            matched = 0
            for branch in schema["oneOf"]:
                try:
                    self._validate(instance, branch, root_schema, path, schema_id)
                    matched += 1
                except RegistrationError:
                    pass
            if matched != 1:
                self._fail(path)
        for branch in schema.get("allOf", []):
            self._validate(instance, branch, root_schema, path, schema_id)
        if "if" in schema:
            try:
                self._validate(instance, schema["if"], root_schema, path, schema_id)
                condition = True
            except RegistrationError:
                condition = False
            branch = schema.get("then" if condition else "else")
            if branch is not None:
                self._validate(instance, branch, root_schema, path, schema_id)
        if isinstance(instance, dict):
            required = schema.get("required", [])
            if any(key not in instance for key in required):
                self._fail(path)
            properties = schema.get("properties", {})
            if schema.get("additionalProperties") is False and any(
                key not in properties for key in instance
            ):
                self._fail(path)
            for key, child in properties.items():
                if key in instance:
                    self._validate(
                        instance[key], child, root_schema, f"{path}.{key}", schema_id
                    )
        if isinstance(instance, list):
            if len(instance) < schema.get("minItems", 0):
                self._fail(path)
            if "maxItems" in schema and len(instance) > schema["maxItems"]:
                self._fail(path)
            if schema.get("uniqueItems") and len(
                {_canonical_json(item) for item in instance}
            ) != len(instance):
                self._fail(path)
            if "items" in schema:
                for index, item in enumerate(instance):
                    self._validate(
                        item,
                        schema["items"],
                        root_schema,
                        f"{path}[{index}]",
                        schema_id,
                    )
            if "contains" in schema:
                matched = 0
                for index, item in enumerate(instance):
                    try:
                        self._validate(
                            item,
                            schema["contains"],
                            root_schema,
                            f"{path}[{index}]",
                            schema_id,
                        )
                        matched += 1
                    except RegistrationError:
                        pass
                if matched < schema.get("minContains", 1):
                    self._fail(path)
                if "maxContains" in schema and matched > schema["maxContains"]:
                    self._fail(path)
        if isinstance(instance, str):
            if len(instance) < schema.get("minLength", 0):
                self._fail(path)
            if "maxLength" in schema and len(instance) > schema["maxLength"]:
                self._fail(path)
            if "pattern" in schema and re.search(schema["pattern"], instance) is None:
                self._fail(path)
            if schema.get("format") == "date-time":
                try:
                    parsed = datetime.fromisoformat(instance.replace("Z", "+00:00"))
                except ValueError:
                    self._fail(path)
                if parsed.tzinfo is None:
                    self._fail(path)
        if (
            isinstance(instance, (int, float))
            and not isinstance(instance, bool)
            and "minimum" in schema
            and instance < schema["minimum"]
        ):
            self._fail(path)

    def _resolve_ref(
        self,
        reference: str,
        root_schema: Mapping[str, Any],
        schema_id: str,
    ) -> tuple[Any, Mapping[str, Any], str]:
        if not isinstance(reference, str):
            self._fail("$")
        uri, separator, fragment = reference.partition("#")
        target_id = uri or schema_id
        target_root = root_schema if not uri else self.schemas.get(uri)
        if target_root is None:
            self._fail("$")
        target: Any = target_root
        if separator and fragment:
            if not fragment.startswith("/"):
                self._fail("$")
            for token in fragment[1:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or token not in target:
                    self._fail("$")
                target = target[token]
        return target, target_root, target_id

    @staticmethod
    def _fail(path: str) -> None:
        raise RegistrationError(
            "company_schema_validation_failed",
            f"registration artifact failed Company Schema validation at {path}",
        )


def _matches_json_type(value: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return any(_matches_json_type(value, item) for item in expected)
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def _load_strict_yaml_bytes(source: bytes) -> Mapping[str, Any]:
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RegistrationError("yaml_invalid_utf8", "YAML must be UTF-8") from error
    if "\t" in text:
        raise RegistrationError("yaml_tab_forbidden", "YAML tabs are forbidden")
    raw_lines = text.splitlines()
    lines: list[_YamlLine] = []
    literal_parent_indent: int | None = None
    for number, raw in enumerate(raw_lines, start=1):
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw[indent:]
        if literal_parent_indent is not None and (not stripped or indent > literal_parent_indent):
            if stripped:
                lines.append(_YamlLine(indent, stripped, number))
            continue
        literal_parent_indent = None
        if not stripped:
            continue
        if stripped in {"---", "..."} or stripped.startswith("%"):
            raise RegistrationError(
                "yaml_document_feature_forbidden", "YAML directives and document markers are forbidden"
            )
        if "#" in stripped:
            raise RegistrationError(
                "yaml_comment_forbidden", "YAML comments are forbidden in registration artifacts"
            )
        if re.search(r"(^|[\s\[\]{},:])(?:[&*][A-Za-z0-9_-]+|![^\s]*)", stripped):
            raise RegistrationError(
                "yaml_advanced_feature_forbidden",
                "YAML anchor, alias, or custom tag is forbidden",
            )
        if re.match(r"^<<\s*:", stripped):
            raise RegistrationError(
                "yaml_merge_key_forbidden", "YAML merge keys are forbidden"
            )
        if stripped.endswith(": |-"):
            literal_parent_indent = indent
        elif re.search(r":\s*[|>]", stripped):
            raise RegistrationError(
                "yaml_block_style_forbidden", "only the literal strip block style is supported"
            )
        if indent % 2:
            raise RegistrationError(
                "yaml_indentation_invalid", "YAML indentation must use two-space steps"
            )
        lines.append(_YamlLine(indent, stripped, number))
    if not lines:
        raise RegistrationError("yaml_empty", "YAML document is empty")
    value, index = _parse_yaml_block(lines, 0, lines[0].indent)
    if lines[0].indent != 0 or index != len(lines) or not isinstance(value, dict):
        raise RegistrationError(
            "yaml_structure_invalid", "YAML must contain one top-level mapping"
        )
    return value


def _parse_yaml_block(
    lines: list[_YamlLine], index: int, indent: int
) -> tuple[Any, int]:
    if index >= len(lines) or lines[index].indent != indent:
        raise RegistrationError("yaml_indentation_invalid", "YAML indentation is invalid")
    if lines[index].text.startswith("- "):
        return _parse_yaml_list(lines, index, indent)
    return _parse_yaml_mapping(lines, index, indent)


def _parse_yaml_mapping(
    lines: list[_YamlLine], index: int, indent: int
) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(lines) and lines[index].indent == indent:
        line = lines[index]
        if line.text.startswith("- "):
            break
        key, token = _split_yaml_mapping(line.text)
        if key in result:
            raise RegistrationError("duplicate_yaml_key", "YAML contains a duplicate key")
        index += 1
        if token == "|-":
            content: list[str] = []
            if index >= len(lines) or lines[index].indent <= indent:
                result[key] = ""
                continue
            content_indent = lines[index].indent
            while index < len(lines) and lines[index].indent > indent:
                current = lines[index]
                if current.indent < content_indent:
                    raise RegistrationError(
                        "yaml_indentation_invalid", "YAML literal indentation is invalid"
                    )
                content.append((" " * (current.indent - content_indent)) + current.text)
                index += 1
            result[key] = "\n".join(content)
        elif token == "":
            if index >= len(lines) or lines[index].indent != indent + 2:
                raise RegistrationError(
                    "yaml_indentation_invalid", "YAML nested value is missing or misindented"
                )
            result[key], index = _parse_yaml_block(lines, index, indent + 2)
        else:
            result[key] = _parse_yaml_scalar(token)
        if index < len(lines) and lines[index].indent < indent:
            break
        if index < len(lines) and lines[index].indent > indent:
            raise RegistrationError(
                "yaml_indentation_invalid", "YAML contains an unexpected indentation"
            )
    return result, index


def _parse_yaml_list(
    lines: list[_YamlLine], index: int, indent: int
) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(lines) and lines[index].indent == indent:
        line = lines[index]
        if not line.text.startswith("- "):
            break
        token = line.text[2:].strip()
        if not token:
            raise RegistrationError(
                "yaml_structure_invalid", "empty YAML list items are unsupported"
            )
        index += 1
        if re.match(r"^[A-Za-z_][A-Za-z0-9_-]*\s*:(?:\s|$)", token):
            key, value_token = _split_yaml_mapping(token)
            item: dict[str, Any] = {}
            if value_token == "":
                if index >= len(lines) or lines[index].indent != indent + 4:
                    raise RegistrationError(
                        "yaml_indentation_invalid", "YAML list mapping is misindented"
                    )
                item[key], index = _parse_yaml_block(lines, index, indent + 4)
            elif value_token == "|-":
                raise RegistrationError(
                    "yaml_block_style_forbidden", "literal list mapping values are unsupported"
                )
            else:
                item[key] = _parse_yaml_scalar(value_token)
            if index < len(lines) and lines[index].indent == indent + 2:
                continuation, index = _parse_yaml_mapping(lines, index, indent + 2)
                if set(item).intersection(continuation):
                    raise RegistrationError(
                        "duplicate_yaml_key", "YAML contains a duplicate key"
                    )
                item.update(continuation)
            result.append(item)
        else:
            result.append(_parse_yaml_scalar(token))
        if index < len(lines) and lines[index].indent < indent:
            break
        if index < len(lines) and lines[index].indent > indent:
            raise RegistrationError(
                "yaml_indentation_invalid", "YAML list contains unexpected indentation"
            )
    return result, index


def _split_yaml_mapping(text: str) -> tuple[str, str]:
    if ":" not in text:
        raise RegistrationError(
            "yaml_structure_invalid", "YAML mapping entry lacks a separator"
        )
    key, token = text.split(":", 1)
    key = key.strip()
    if not _YAML_KEY_PATTERN.fullmatch(key):
        raise RegistrationError("yaml_key_invalid", "YAML mapping key is invalid")
    return key, token.strip()


def _parse_yaml_scalar(token: str) -> Any:
    if token in {"[]", "{}"}:
        return [] if token == "[]" else {}
    if token in {"true", "false"}:
        return token == "true"
    if token in {"null", "~"}:
        return None
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", token):
        return int(token)
    if token.startswith('"'):
        try:
            value = json.loads(token)
        except json.JSONDecodeError as error:
            raise RegistrationError("yaml_scalar_invalid", "quoted YAML scalar is invalid") from error
        if not isinstance(value, str):
            raise RegistrationError("yaml_scalar_invalid", "quoted YAML scalar must be a string")
        return value
    if token.startswith("'"):
        if len(token) < 2 or not token.endswith("'"):
            raise RegistrationError("yaml_scalar_invalid", "quoted YAML scalar is invalid")
        return token[1:-1].replace("''", "'")
    if token[0] in "&*!|>{}[],%@`" or token.endswith(":"):
        raise RegistrationError(
            "yaml_scalar_invalid", "unsupported YAML scalar syntax"
        )
    return token


def _record_from_document(
    document: Any, expected_sequence: int, previous_hash: str
) -> _RegistrationRecord:
    record = _strict_mapping(document, "registration ledger record")
    _exact_keys(record, _LEDGER_RECORD_KEYS, "registration ledger record")
    ledger_version = record["ledger_version"]
    if ledger_version not in {
        LEGACY_REGISTRATION_LEDGER_VERSION,
        REGISTRATION_LEDGER_VERSION,
    }:
        raise RegistrationError(
            "unsupported_ledger_version", "registration ledger version is unsupported"
        )
    sequence = _strict_int(record["sequence"], "registration sequence")
    if sequence != expected_sequence:
        raise RegistrationError(
            "sequence_mismatch", "registration ledger sequence is not contiguous"
        )
    if record["record_type"] != "synthetic_registration_evidence":
        raise RegistrationError(
            "unsupported_record_type", "registration record type is unsupported"
        )
    idempotency_key = _strict_string(record["idempotency_key"], "idempotency key")
    if not _IDEMPOTENCY_PATTERN.fullmatch(idempotency_key):
        raise RegistrationError(
            "invalid_idempotency_key", "registration idempotency key is invalid"
        )
    if record["previous_record_hash"] != previous_hash:
        raise RegistrationError(
            "previous_hash_mismatch", "registration ledger hash chain is broken"
        )
    _validate_digest(previous_hash, "previous record hash")
    _validate_digest(record["record_hash"], "record hash")
    payload = _strict_mapping(record["payload"], "registration payload")
    _validate_ledger_payload(
        payload, allow_legacy=ledger_version == LEGACY_REGISTRATION_LEDGER_VERSION
    )
    content = {key: value for key, value in record.items() if key != "record_hash"}
    expected_hash = _digest(_canonical_json(content).encode("utf-8"))
    if record["record_hash"] != expected_hash:
        raise RegistrationError(
            "record_hash_mismatch", "registration ledger record hash differs"
        )
    payload_digest = _digest(_canonical_json(payload).encode("utf-8"))
    expected_id = deterministic_id("registration", idempotency_key, payload_digest)
    if record["record_id"] != expected_id:
        raise RegistrationError(
            "record_id_mismatch", "registration ledger record id differs"
        )
    return _RegistrationRecord(
        sequence,
        expected_id,
        idempotency_key,
        previous_hash,
        payload,
        expected_hash,
    )


def _validate_ledger_payload(
    value: Mapping[str, Any], *, allow_legacy: bool = False
) -> None:
    payload = _strict_mapping(value, "registration ledger payload")
    payload_keys = set(payload)
    is_legacy = allow_legacy and payload_keys == _LEGACY_LEDGER_PAYLOAD_KEYS
    if not is_legacy:
        _exact_keys(payload, _LEDGER_PAYLOAD_KEYS, "registration ledger payload")
    for field in (
        "candidate_digest",
        "handoff_digest",
        "handoff_manifest_sha256",
    ):
        _validate_digest(payload[field], field)
    shared_string_fields = (
        "handoff_id",
        "registry_record_ref",
        "registration_approval_ref",
        "registration_audit_ref",
    )
    current_string_fields = (
        "agent_id",
        "agent_version",
        "definition_ref",
        "definition_digest",
        "binding_ref",
        "binding_digest",
        "template_ref",
        "template_digest",
        "registry_record_digest",
        "owner_role_ref",
        "hierarchy_node_ref",
    )
    for field in shared_string_fields + (() if is_legacy else current_string_fields):
        _strict_string(payload[field], field)
    if not is_legacy:
        for field in (
            "definition_digest",
            "binding_digest",
            "template_digest",
            "registry_record_digest",
        ):
            _validate_digest(payload[field], field)
    if (
        payload["registration_status"] != "draft"
        or payload["evidence_status"] != "synthetic"
        or payload["company_authoritative"] is not False
        or payload["synthetic_registration_evidence_written"] is not True
        or any(
            payload[field] is not False
            for field in (
                "company_registry_write_applied",
                "formal_registry_record_exists",
                "activation_authorized",
                "active",
                "task_execution_authorized",
            )
        )
    ):
        raise RegistrationError(
            "registration_semantic_drift",
            "registration ledger payload exceeds synthetic registration-only scope",
        )
    _scan_for_leaks([payload])


def _artifact_index(value: Any, label: str) -> dict[str, Mapping[str, Any]]:
    return _unique_index(value, "kind", label)


def _unique_index(value: Any, field: str, label: str) -> dict[str, Mapping[str, Any]]:
    if not isinstance(value, list):
        raise RegistrationError("invalid_artifact_list", f"{label} must be a list")
    result: dict[str, Mapping[str, Any]] = {}
    for raw in value:
        item = _strict_mapping(raw, label)
        key = _strict_string(item.get(field), field)
        if key in result:
            raise RegistrationError("duplicate_artifact", f"{label} contains a duplicate")
        result[key] = item
    return result


def _read_hashed_artifacts(
    root: Path, entries: Mapping[str, Mapping[str, Any]]
) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    seen_paths: set[PurePosixPath] = set()
    for kind, entry in entries.items():
        source = _read_and_verify_declared_file(root, entry, kind)
        path = _safe_relative_path(entry.get("path"), kind)
        if path in seen_paths:
            raise RegistrationError(
                "duplicate_artifact_path", "artifact path is reused"
            )
        seen_paths.add(path)
        result[kind] = source
    return result


def _read_and_verify_declared_file(
    root: Path, entry: Mapping[str, Any], label: str
) -> bytes:
    mapping = _strict_mapping(entry, label)
    path = _safe_relative_path(mapping.get("path"), label)
    declared = mapping.get("sha256")
    if not isinstance(declared, str):
        raise RegistrationError("artifact_digest_invalid", "artifact digest is missing")
    declared_hex = declared.removeprefix("sha256:")
    if not _HEX_DIGEST_PATTERN.fullmatch(declared_hex):
        raise RegistrationError("artifact_digest_invalid", "artifact digest is invalid")
    source = _read_safe_file(root, path)
    if _sha256(source) != declared_hex:
        raise RegistrationError(
            "artifact_bytes_mismatch", "artifact raw bytes differ from the manifest"
        )
    return source


def _validate_source_root(value: Path | str) -> Path:
    root = Path(value)
    if not str(root):
        raise RegistrationError("source_root_required", "source root is required")
    if not os.path.lexists(root):
        raise RegistrationError("source_root_not_found", "source root does not exist")
    metadata = os.lstat(root)
    if stat.S_ISLNK(metadata.st_mode):
        raise RegistrationError("source_root_symlink_forbidden", "source root may not be a symlink")
    if not stat.S_ISDIR(metadata.st_mode):
        raise RegistrationError("source_root_not_directory", "source root must be a directory")
    return root.resolve()


def _safe_relative_path(value: Any, label: str) -> PurePosixPath:
    if isinstance(value, Path):
        value = value.as_posix()
    if not isinstance(value, str) or not value or "\\" in value:
        raise RegistrationError("unsafe_source_path", f"{label} path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RegistrationError("unsafe_source_path", f"{label} path must be safe and relative")
    return path


def _read_safe_file(root: Path, relative: PurePosixPath) -> bytes:
    current = root
    for part in relative.parts:
        current = current / part
        if not os.path.lexists(current):
            raise RegistrationError("source_file_not_found", "required source file does not exist")
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise RegistrationError("source_symlink_forbidden", "source path contains a symlink")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(current, flags)
    except OSError as error:
        raise RegistrationError("source_file_unavailable", "source file cannot be opened") from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise RegistrationError("source_not_regular_file", "source artifact must be a regular file")
        if metadata.st_size > MAX_SOURCE_FILE_BYTES:
            raise RegistrationError("source_file_too_large", "source artifact exceeds size limit")
        source = os.read(fd, metadata.st_size + 1)
        if len(source) != metadata.st_size:
            raise RegistrationError("source_read_incomplete", "source artifact read was incomplete")
        return source
    finally:
        os.close(fd)


def _read_local_regular_file(path: Path, label: str) -> bytes:
    if not os.path.lexists(path):
        raise RegistrationError("local_lock_not_found", f"{label} does not exist")
    if stat.S_ISLNK(os.lstat(path).st_mode):
        raise RegistrationError("local_lock_symlink_forbidden", f"{label} may not be a symlink")
    if not path.is_file():
        raise RegistrationError("local_lock_not_regular", f"{label} must be a regular file")
    source = path.read_bytes()
    if len(source) > MAX_SOURCE_FILE_BYTES:
        raise RegistrationError("local_lock_too_large", f"{label} exceeds size limit")
    return source


def _ensure_owner_only_parent(parent: Path) -> None:
    missing: list[Path] = []
    current = parent
    while not os.path.lexists(current):
        missing.append(current)
        if current == current.parent:
            break
        current = current.parent
    if not os.path.lexists(current) or stat.S_ISLNK(os.lstat(current).st_mode) or not current.is_dir():
        raise RegistrationError("ledger_parent_invalid", "registration ledger parent is invalid")
    for directory in reversed(missing):
        try:
            os.mkdir(directory, 0o700)
        except OSError as error:
            raise RegistrationError("ledger_parent_create_failed", "registration ledger parent could not be created") from error
        os.chmod(directory, 0o700)
    if stat.S_ISLNK(os.lstat(parent).st_mode):
        raise RegistrationError("ledger_parent_symlink_forbidden", "registration ledger parent may not be a symlink")
    metadata = os.stat(parent)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise RegistrationError("ledger_parent_owner_mismatch", "registration ledger parent owner differs")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RegistrationError("ledger_parent_permissions_too_broad", "registration ledger parent must be 0700")


def _load_json_bytes(source: bytes, label: str) -> Any:
    try:
        return json.loads(
            source.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except RegistrationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RegistrationError("invalid_json", f"{label} is invalid strict JSON") from error


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RegistrationError("duplicate_json_key", "JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise RegistrationError("invalid_json_constant", f"unsupported JSON constant {value}")


def _canonical_digest_without(value: Mapping[str, Any], path: tuple[str, ...]) -> str:
    canonical = copy.deepcopy(value)
    parent: Any = canonical
    try:
        for key in path[:-1]:
            parent = parent[key]
        del parent[path[-1]]
    except (KeyError, TypeError) as error:
        raise RegistrationError("digest_field_missing", "canonical digest field is missing") from error
    return _sha256(_canonical_json(canonical).encode("utf-8"))


def _validate_digest_descriptor(value: Any, label: str) -> None:
    mapping = _strict_mapping(value, label)
    _exact_keys(mapping, {"algorithm", "canonicalization", "value"}, label)
    if (
        mapping["algorithm"] != "sha256"
        or mapping["canonicalization"] != "orbit.canonical-json/1.0"
        or not isinstance(mapping["value"], str)
        or not _HEX_DIGEST_PATTERN.fullmatch(mapping["value"])
    ):
        raise RegistrationError("digest_descriptor_invalid", f"{label} is invalid")


def _validate_versioned_ref(value: Any, label: str) -> None:
    mapping = _strict_mapping(value, label)
    _exact_keys(mapping, {"id", "version", "digest"}, label)
    _strict_string(mapping["id"], f"{label} id")
    _strict_string(mapping["version"], f"{label} version")
    _validate_digest(mapping["digest"], f"{label} digest")


def _validate_digest(value: Any, label: str) -> None:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise RegistrationError("invalid_digest", f"{label} is invalid")


def _strict_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise RegistrationError("invalid_structure", f"{label} must be an object")
    return value


def _exact_keys(value: Any, expected: set[str], label: str) -> None:
    mapping = _strict_mapping(value, label)
    if set(mapping) != expected:
        raise RegistrationError("unknown_or_missing_field", f"{label} fields differ")


def _strict_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RegistrationError("invalid_string", f"{label} must be a non-empty string")
    return value


def _strict_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RegistrationError("invalid_integer", f"{label} must be an integer")
    return value


def _scan_for_leaks(values: list[Any]) -> None:
    visible = _canonical_json(values)
    if any(pattern.search(visible) for pattern in _LEAK_PATTERNS):
        raise RegistrationError(
            "registration_evidence_leak_detected",
            "registration evidence contains a forbidden path, storage, credential, or Endpoint reference",
        )


def _normalize_json(value: Any) -> Any:
    try:
        return json.loads(_canonical_json(value))
    except (TypeError, ValueError) as error:
        raise RegistrationError("payload_not_json", "registration payload is not strict JSON") from error


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256(source: bytes) -> str:
    return sha256(source).hexdigest()


def _digest(source: bytes) -> str:
    return f"sha256:{_sha256(source)}"

