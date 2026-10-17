"""Human-gated acceptance for the frozen Dataset D0 evidence bundle.

The acceptance ledger is local, synthetic, append-only evidence.  It never
changes Agent or Tool lifecycle state and never creates a Grant, Registry
record, Runtime, deployment, or production authorization.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from .ids import deterministic_id
from .lifecycle_ledger import (
    append_jsonl_document,
    close_ledger,
    open_owner_only_ledger,
    read_jsonl_documents,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REVIEW_REQUEST = (
    _REPO_ROOT / "references" / "dataset-d0-evidence-review-request.json"
)
LEDGER_VERSION = "orbit.synthetic-dataset-d0-evidence-acceptance-ledger/1"
APPROVAL_VERSION = "orbit.synthetic-dataset-d0-evidence-approval/1"
GENESIS_HASH = "sha256:" + ("0" * 64)
MAX_LEDGER_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 128 * 1024
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_PATTERN = re.compile(r"^[a-z][a-z0-9._:-]{2,191}$")
_EXPECTED_EVIDENCE = (
    (
        "acceptance-report",
        "evidence/dataset-tools-d0/2026-08-25/acceptance-report.zh-CN.md",
        "sha256:0b038b53b530c8f12e8eb53a1cee894f6d1015c1507becda400b1dcc59af7f55",
    ),
    (
        "raw-result",
        "evidence/dataset-tools-d0/2026-08-25/result.json",
        "sha256:0dfe9af3244c22ab3727c7a3786ddc2d2c3b862ad701f702db236215efd08e4b",
    ),
    (
        "composition-lock",
        "references/dataset-tool-d0-composition-lock.json",
        "sha256:1d4de535e82d6082ab957e8f03ba4af8c2822fa48875a37792f053f3cd071143",
    ),
    (
        "skill-review-summary",
        "evidence/dataset-tools-d0/2026-08-25/skill-review-summary.json",
        "sha256:72064a19b11937675cafc9bcf80c43a83445da141a73857af283c1328d183ade",
    ),
)


class DatasetEvidenceAcceptanceError(ValueError):
    """Fail-closed Dataset D0 evidence acceptance error."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class VerifiedDatasetEvidenceReview:
    request_id: str
    evidence_bundle_digest: str
    accepted_status_ceiling: str
    approval_semantics: str
    evidence: tuple[Mapping[str, str], ...]


@dataclass(frozen=True)
class DatasetEvidenceApproval:
    decision_id: str
    decision: str
    decided_by_human_ref: str
    approved_at: str
    scope: str
    evidence_bundle_digest: str
    approval_semantics: str
    evidence_status: str
    synthetic_only: bool
    release_authorization: bool


@dataclass(frozen=True)
class DatasetEvidenceAppendResult:
    record_id: str
    record_hash: str
    sequence: int
    appended: bool


@dataclass(frozen=True)
class DatasetEvidenceReplay:
    records_checked: int
    last_record_hash: str
    acceptances: tuple[Mapping[str, Any], ...]


def verify_dataset_evidence_review(
    request_path: Path | str = DEFAULT_REVIEW_REQUEST,
    *,
    repository_root: Path | str = _REPO_ROOT,
) -> VerifiedDatasetEvidenceReview:
    root = Path(repository_root).resolve()
    request = _load_json_file(Path(request_path), "Dataset D0 review request")
    _exact_keys(
        request,
        {
            "request_version",
            "request_id",
            "status",
            "evidence_status",
            "synthetic_only",
            "evidence_bundle_digest",
            "accepted_status_ceiling",
            "evidence",
            "approval_semantics",
            "required_invariants",
        },
        "Dataset D0 review request",
    )
    if (
        request["request_version"]
        != "orbit.synthetic-dataset-d0-evidence-review-request/1"
        or request["status"] != "awaiting-human-review"
        or request["evidence_status"] != "synthetic"
        or request["synthetic_only"] is not True
        or request["accepted_status_ceiling"] != "D0 synthetic active"
    ):
        raise DatasetEvidenceAcceptanceError(
            "review_request_boundary_invalid",
            "Dataset D0 review request exceeds the synthetic boundary",
        )
    _validate_id(request["request_id"], "request id")
    _validate_digest(request["evidence_bundle_digest"], "evidence bundle digest")
    calculated_bundle_digest = _digest_mapping_without(
        request, "evidence_bundle_digest"
    )
    if request["evidence_bundle_digest"] != calculated_bundle_digest:
        raise DatasetEvidenceAcceptanceError(
            "evidence_bundle_digest_mismatch",
            "Dataset D0 review request digest differs",
        )

    evidence = request["evidence"]
    if not isinstance(evidence, list) or len(evidence) != len(_EXPECTED_EVIDENCE):
        raise DatasetEvidenceAcceptanceError(
            "evidence_set_invalid", "Dataset D0 evidence set is incomplete"
        )
    normalized_evidence: list[Mapping[str, str]] = []
    for actual, expected in zip(evidence, _EXPECTED_EVIDENCE):
        entry = _strict_mapping(actual, "Dataset D0 evidence entry")
        _exact_keys(entry, {"kind", "path", "sha256"}, "Dataset D0 evidence entry")
        if (entry["kind"], entry["path"], entry["sha256"]) != expected:
            raise DatasetEvidenceAcceptanceError(
                "evidence_set_drift", "Dataset D0 evidence declaration drifted"
            )
        path = _safe_evidence_file(root, entry["path"])
        if _digest_bytes(path.read_bytes()) != entry["sha256"]:
            raise DatasetEvidenceAcceptanceError(
                "evidence_bytes_mismatch", "Dataset D0 evidence bytes drifted"
            )
        normalized_evidence.append(dict(entry))

    invariants = _strict_mapping(
        request["required_invariants"], "Dataset D0 required invariants"
    )
    if invariants != {
        "lifecycle_assurance_recommendation": "hold",
        "release_authorization": False,
        "agent_lifecycle_mutation": False,
        "tool_lifecycle_mutation": False,
        "company_authoritative": False,
    }:
        raise DatasetEvidenceAcceptanceError(
            "review_invariants_invalid", "Dataset D0 review invariants drifted"
        )
    _verify_evidence_semantics(root)
    return VerifiedDatasetEvidenceReview(
        request_id=request["request_id"],
        evidence_bundle_digest=request["evidence_bundle_digest"],
        accepted_status_ceiling=request["accepted_status_ceiling"],
        approval_semantics=request["approval_semantics"],
        evidence=tuple(normalized_evidence),
    )


def load_dataset_evidence_approval(
    path: Path | str,
    review: VerifiedDatasetEvidenceReview,
) -> DatasetEvidenceApproval:
    value = _load_owner_only_json_file(
        Path(path), "Dataset D0 evidence approval"
    )
    _exact_keys(
        value,
        {
            "approval_version",
            "decision_id",
            "decision",
            "decided_by_human_ref",
            "approved_at",
            "scope",
            "evidence_bundle_digest",
            "approval_semantics",
            "evidence_status",
            "synthetic_only",
            "release_authorization",
        },
        "Dataset D0 evidence approval",
    )
    approval = DatasetEvidenceApproval(
        decision_id=_validate_id(value["decision_id"], "decision id"),
        decision=value["decision"],
        decided_by_human_ref=_validate_id(
            value["decided_by_human_ref"], "human ref"
        ),
        approved_at=_strict_nonempty_string(value["approved_at"], "approved at"),
        scope=value["scope"],
        evidence_bundle_digest=value["evidence_bundle_digest"],
        approval_semantics=value["approval_semantics"],
        evidence_status=value["evidence_status"],
        synthetic_only=value["synthetic_only"],
        release_authorization=value["release_authorization"],
    )
    if (
        value["approval_version"] != APPROVAL_VERSION
        or approval.decision != "approve"
        or approval.scope != "dataset-agent-tools/d0-synthetic-evidence-acceptance"
        or approval.evidence_bundle_digest != review.evidence_bundle_digest
        or approval.approval_semantics != review.approval_semantics
        or approval.evidence_status != "synthetic"
        or approval.synthetic_only is not True
        or approval.release_authorization is not False
    ):
        raise DatasetEvidenceAcceptanceError(
            "approval_scope_invalid",
            "Dataset D0 approval does not match the exact evidence-only scope",
        )
    return approval


class SyntheticDatasetEvidenceAcceptanceLedger:
    """Owner-only local evidence ledger with no lifecycle side effects."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def accept(
        self,
        review: VerifiedDatasetEvidenceReview,
        approval: DatasetEvidenceApproval,
    ) -> DatasetEvidenceAppendResult:
        fd = open_owner_only_ledger(
            self.path,
            create=True,
            exclusive=True,
            error=DatasetEvidenceAcceptanceError,
            label="Dataset D0 evidence acceptance ledger",
        )
        try:
            documents = self._read(fd)
            replay = _replay_documents(documents)
            matches = tuple(
                item
                for item in replay.acceptances
                if item["approval_decision_ref"] == approval.decision_id
            )
            if matches:
                if (
                    len(matches) != 1
                    or matches[0]["evidence_bundle_digest"]
                    != review.evidence_bundle_digest
                ):
                    raise DatasetEvidenceAcceptanceError(
                        "idempotency_conflict",
                        "Dataset D0 approval id was reused for different evidence",
                    )
                record = documents[matches[0]["sequence"]]
                return DatasetEvidenceAppendResult(
                    record_id=record["record_id"],
                    record_hash=record["record_hash"],
                    sequence=record["sequence"],
                    appended=False,
                )
            sequence = len(documents)
            previous_hash = (
                GENESIS_HASH if not documents else documents[-1]["record_hash"]
            )
            acceptance_id = deterministic_id(
                "acceptance",
                review.evidence_bundle_digest,
                approval.decision_id,
            )
            audit_id = deterministic_id("audit", acceptance_id)
            payload = {
                "acceptance_id": acceptance_id,
                "request_id": review.request_id,
                "evidence_bundle_digest": review.evidence_bundle_digest,
                "accepted_status_ceiling": review.accepted_status_ceiling,
                "approval_decision_ref": approval.decision_id,
                "decided_by_human_ref": approval.decided_by_human_ref,
                "accepted_at": approval.approved_at,
                "lifecycle_assurance_recommendation": "hold",
                "release_authorization": False,
                "agent_lifecycle_mutated": False,
                "tool_lifecycle_mutated": False,
                "company_authoritative": False,
                "formal_registry_record_exists": False,
                "preproduction_authorized": False,
                "production_authorized": False,
            }
            audit = {
                "audit_id": audit_id,
                "action": "dataset.d0.evidence.accept",
                "actor_kind": "human",
                "actor_ref": approval.decided_by_human_ref,
                "decision": "allow",
                "outcome": "succeeded",
                "resource_ref": acceptance_id,
                "payload_digest": review.evidence_bundle_digest,
                "occurred_at": approval.approved_at,
                "content_logging": "metadata_only",
            }
            record: dict[str, Any] = {
                "ledger_version": LEDGER_VERSION,
                "sequence": sequence,
                "record_id": deterministic_id(
                    "record", acceptance_id, str(sequence), previous_hash
                ),
                "record_type": "evidence_acceptance_with_audit",
                "idempotency_key": f"dataset-d0-evidence:{approval.decision_id}",
                "previous_record_hash": previous_hash,
                "payload": payload,
                "audit": audit,
            }
            record["record_hash"] = _digest_mapping(record)
            encoded = _canonical_bytes(record) + b"\n"
            append_jsonl_document(
                fd,
                encoded,
                max_ledger_bytes=MAX_LEDGER_BYTES,
                max_record_bytes=MAX_RECORD_BYTES,
                error=DatasetEvidenceAcceptanceError,
                label="Dataset D0 evidence acceptance ledger",
            )
            return DatasetEvidenceAppendResult(
                record_id=record["record_id"],
                record_hash=record["record_hash"],
                sequence=sequence,
                appended=True,
            )
        finally:
            close_ledger(fd)

    def replay(self) -> DatasetEvidenceReplay:
        fd = open_owner_only_ledger(
            self.path,
            create=False,
            exclusive=False,
            error=DatasetEvidenceAcceptanceError,
            label="Dataset D0 evidence acceptance ledger",
        )
        try:
            return _replay_documents(self._read(fd))
        finally:
            close_ledger(fd)

    @staticmethod
    def _read(fd: int) -> tuple[dict[str, Any], ...]:
        return read_jsonl_documents(
            fd,
            max_ledger_bytes=MAX_LEDGER_BYTES,
            max_record_bytes=MAX_RECORD_BYTES,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            error=DatasetEvidenceAcceptanceError,
            label="Dataset D0 evidence acceptance ledger",
        )


def dataset_evidence_review_document(
    review: VerifiedDatasetEvidenceReview,
) -> dict[str, object]:
    return {
        "status": "awaiting-human-review",
        "evidence_status": "synthetic",
        "company_authoritative": False,
        "request_id": review.request_id,
        "evidence_bundle_digest": review.evidence_bundle_digest,
        "accepted_status_ceiling": review.accepted_status_ceiling,
        "approval_semantics": review.approval_semantics,
        "evidence": list(review.evidence),
        "release_authorization": False,
        "agent_lifecycle_mutated": False,
        "tool_lifecycle_mutated": False,
    }


def dataset_evidence_replay_document(
    replay: DatasetEvidenceReplay,
) -> dict[str, object]:
    if replay.records_checked == 0:
        raise DatasetEvidenceAcceptanceError(
            "ledger_empty", "Dataset D0 evidence acceptance ledger is empty"
        )
    return {
        "status": "accepted-d0-synthetic-evidence",
        "evidence_status": "synthetic",
        "company_authoritative": False,
        "records_checked": replay.records_checked,
        "last_record_hash": replay.last_record_hash,
        "acceptances": list(replay.acceptances),
        "release_authorization": False,
        "agent_lifecycle_mutated": False,
        "tool_lifecycle_mutated": False,
        "formal_registry_record_exists": False,
        "preproduction_authorized": False,
        "production_authorized": False,
    }


def _verify_evidence_semantics(root: Path) -> None:
    result = _load_json_file(root / _EXPECTED_EVIDENCE[1][1], "Dataset D0 result")
    summary = _load_json_file(
        root / _EXPECTED_EVIDENCE[3][1], "Dataset D0 skill review summary"
    )
    lock = _load_json_file(
        root / _EXPECTED_EVIDENCE[2][1], "Dataset D0 composition lock"
    )
    checks = result.get("checks")
    docker_review = _strict_mapping(summary.get("docker_d0_review"), "D0 review")
    advisory = _strict_mapping(summary.get("advisory"), "D0 advisory")
    lock_evidence = _strict_mapping(lock.get("evidence"), "D0 lock evidence")
    if (
        result.get("status") != "D0 synthetic active"
        or result.get("failed_checks") != []
        or not isinstance(checks, dict)
        or len(checks) != 27
        or not all(value is True for value in checks.values())
        or docker_review.get("checks_passed") != 27
        or docker_review.get("checks_failed") != 0
        or docker_review.get("lifecycle_assurance_recommendation") != "hold"
        or docker_review.get("release_authorization") is not False
        or advisory.get("recommended_status_ceiling") != "D0 synthetic active"
        or advisory.get("human_terminal_review_required") is not True
        or lock_evidence.get("sha256") != _EXPECTED_EVIDENCE[1][2]
        or lock_evidence.get("acceptance_report_sha256") != _EXPECTED_EVIDENCE[0][2]
        or lock_evidence.get("skill_review_sha256") != _EXPECTED_EVIDENCE[3][2]
    ):
        raise DatasetEvidenceAcceptanceError(
            "evidence_semantics_invalid",
            "Dataset D0 evidence no longer satisfies the accepted status ceiling",
        )


def _replay_documents(
    documents: tuple[dict[str, Any], ...]
) -> DatasetEvidenceReplay:
    previous_hash = GENESIS_HASH
    acceptances: list[Mapping[str, Any]] = []
    decision_ids: set[str] = set()
    for sequence, document in enumerate(documents):
        _exact_keys(
            document,
            {
                "ledger_version",
                "sequence",
                "record_id",
                "record_type",
                "idempotency_key",
                "previous_record_hash",
                "payload",
                "audit",
                "record_hash",
            },
            "Dataset D0 evidence acceptance record",
        )
        if (
            document["ledger_version"] != LEDGER_VERSION
            or document["sequence"] != sequence
            or document["record_type"] != "evidence_acceptance_with_audit"
            or document["previous_record_hash"] != previous_hash
            or document["record_hash"]
            != _digest_mapping_without(document, "record_hash")
        ):
            raise DatasetEvidenceAcceptanceError(
                "ledger_integrity_invalid",
                "Dataset D0 evidence acceptance chain is invalid",
            )
        payload = _strict_mapping(document["payload"], "evidence acceptance payload")
        audit = _strict_mapping(document["audit"], "evidence acceptance audit")
        _exact_keys(
            payload,
            {
                "acceptance_id",
                "request_id",
                "evidence_bundle_digest",
                "accepted_status_ceiling",
                "approval_decision_ref",
                "decided_by_human_ref",
                "accepted_at",
                "lifecycle_assurance_recommendation",
                "release_authorization",
                "agent_lifecycle_mutated",
                "tool_lifecycle_mutated",
                "company_authoritative",
                "formal_registry_record_exists",
                "preproduction_authorized",
                "production_authorized",
            },
            "evidence acceptance payload",
        )
        if (
            payload["accepted_status_ceiling"] != "D0 synthetic active"
            or payload["lifecycle_assurance_recommendation"] != "hold"
            or any(
                payload[field] is not False
                for field in (
                    "release_authorization",
                    "agent_lifecycle_mutated",
                    "tool_lifecycle_mutated",
                    "company_authoritative",
                    "formal_registry_record_exists",
                    "preproduction_authorized",
                    "production_authorized",
                )
            )
        ):
            raise DatasetEvidenceAcceptanceError(
                "acceptance_scope_drift",
                "Dataset D0 acceptance record exceeds evidence-only scope",
            )
        _exact_keys(
            audit,
            {
                "audit_id",
                "action",
                "actor_kind",
                "actor_ref",
                "decision",
                "outcome",
                "resource_ref",
                "payload_digest",
                "occurred_at",
                "content_logging",
            },
            "evidence acceptance audit",
        )
        if (
            audit["action"] != "dataset.d0.evidence.accept"
            or audit["actor_kind"] != "human"
            or audit["decision"] != "allow"
            or audit["outcome"] != "succeeded"
            or audit["resource_ref"] != payload["acceptance_id"]
            or audit["payload_digest"] != payload["evidence_bundle_digest"]
            or audit["actor_ref"] != payload["decided_by_human_ref"]
            or audit["occurred_at"] != payload["accepted_at"]
            or audit["content_logging"] != "metadata_only"
        ):
            raise DatasetEvidenceAcceptanceError(
                "audit_reference_mismatch",
                "Dataset D0 acceptance audit does not close over the acceptance",
            )
        decision_id = payload["approval_decision_ref"]
        if decision_id in decision_ids:
            raise DatasetEvidenceAcceptanceError(
                "duplicate_approval_decision",
                "Dataset D0 approval decision is repeated",
            )
        decision_ids.add(decision_id)
        acceptances.append({"sequence": sequence, **dict(payload), "audit": dict(audit)})
        previous_hash = document["record_hash"]
    return DatasetEvidenceReplay(
        records_checked=len(documents),
        last_record_hash=previous_hash,
        acceptances=tuple(acceptances),
    )


def _safe_evidence_file(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or relative.startswith("/") or ".." in Path(relative).parts:
        raise DatasetEvidenceAcceptanceError(
            "unsafe_evidence_path", "Dataset D0 evidence path is unsafe"
        )
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise DatasetEvidenceAcceptanceError(
            "evidence_file_invalid", "Dataset D0 evidence must be a regular file"
        )
    return path


def _load_json_file(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise DatasetEvidenceAcceptanceError("input_file_invalid", f"{label} is invalid")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except DatasetEvidenceAcceptanceError:
        raise
    except Exception as cause:
        raise DatasetEvidenceAcceptanceError("invalid_json", f"{label} is invalid JSON") from cause
    if not isinstance(value, dict):
        raise DatasetEvidenceAcceptanceError("invalid_json", f"{label} must be an object")
    return value


def _load_owner_only_json_file(path: Path, label: str) -> dict[str, Any]:
    if not os.path.lexists(path):
        raise DatasetEvidenceAcceptanceError("input_file_invalid", f"{label} is invalid")
    if stat.S_ISLNK(os.lstat(path).st_mode):
        raise DatasetEvidenceAcceptanceError("input_symlink_forbidden", f"{label} is unsafe")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as cause:
        raise DatasetEvidenceAcceptanceError(
            "input_file_invalid", f"{label} is unavailable"
        ) from cause
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise DatasetEvidenceAcceptanceError(
                "input_owner_invalid", f"{label} owner or type is invalid"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise DatasetEvidenceAcceptanceError(
                "input_permissions_too_broad", f"{label} must be owner-only"
            )
        if metadata.st_size > 64 * 1024:
            raise DatasetEvidenceAcceptanceError(
                "input_file_too_large", f"{label} exceeds its size limit"
            )
        source = os.read(fd, metadata.st_size + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(
            source.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except DatasetEvidenceAcceptanceError:
        raise
    except Exception as cause:
        raise DatasetEvidenceAcceptanceError(
            "invalid_json", f"{label} is invalid JSON"
        ) from cause
    if not isinstance(value, dict):
        raise DatasetEvidenceAcceptanceError("invalid_json", f"{label} must be an object")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DatasetEvidenceAcceptanceError(
                "duplicate_json_key", "JSON object contains a duplicate key"
            )
        value[key] = item
    return value


def _reject_constant(value: str) -> Any:
    raise DatasetEvidenceAcceptanceError(
        "invalid_json_constant", f"JSON constant is forbidden: {value}"
    )


def _strict_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise DatasetEvidenceAcceptanceError("invalid_structure", f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise DatasetEvidenceAcceptanceError(
            "invalid_structure", f"{label} fields differ"
        )


def _validate_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
        raise DatasetEvidenceAcceptanceError("invalid_id", f"{label} is invalid")
    return value


def _validate_digest(value: Any, label: str) -> None:
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        raise DatasetEvidenceAcceptanceError("invalid_digest", f"{label} is invalid")


def _strict_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DatasetEvidenceAcceptanceError("invalid_string", f"{label} is invalid")
    return value


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest_mapping(value: Mapping[str, Any]) -> str:
    return _digest_bytes(_canonical_bytes(value))


def _digest_mapping_without(value: Mapping[str, Any], field: str) -> str:
    copy_value = dict(value)
    del copy_value[field]
    return _digest_mapping(copy_value)


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{sha256(value).hexdigest()}"

