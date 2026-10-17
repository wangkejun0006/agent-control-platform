"""Exact local-synthetic governance for the approved Disease R2 scopes.

This module applies Agent and Tool lifecycle decisions through their existing
independent ledgers.  Model Route and one-time execution decisions are kept in
a separate owner-only hash-chained scope ledger.  It never issues a Task or
Grant and never invokes Docker, a provider, or an external network.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from orbit_agent_control_plane.ids import deterministic_id
from orbit_agent_control_plane.lifecycle_ledger import (
    append_jsonl_document,
    close_ledger,
    open_owner_only_ledger,
    read_jsonl_documents,
)

AGENT_ID = "agt_orbit_disease_research_task_syn"
AGENT_RELEASE_DIGEST = (
    "sha256:e41c15f412b87c39654978a628ac7704b5cbbb2915f41b3b9d4426cf7aa4b04a"
)
TOOL_ID = "tool_orbit_literature_public_corpus"
TOOL_RELEASE_DIGEST = (
    "sha256:775e2996c5302a28e24d2b8b7b104788e0a782688ba847ae63c8a8b729b48f0d"
)
TOOL_MANIFEST_DIGEST = (
    "sha256:3e428cbd0c68d97052e2893f3f5a4dbd26bfa438fb770b2555be9b65f509d1de"
)
MODEL_ROUTE_ID = "model_route_orbit_disease_r2_fixture_gpt56sol_syn"
MODEL_ROUTE_DIGEST = (
    "sha256:8bc631ae8cf7fc7f2d07ac187eb5ca0d313de00818d77abfa7b2b4a04a5c74e7"
)
REVIEW_PACKAGE_DIGEST = (
    "sha256:5f39ba98874be17610a4cf24f0367baba9517ce896f8afa0e86679ca930175df"
)
CORPUS_REVISION = (
    "sha256:bb796b5aa76f930566e78c599eb197282595b26f2523f7b062374b7c261d6b30"
)
RUNTIME_SOURCE_DIGEST = (
    "sha256:c0b7b3f98a869fd16acbd13cdfe683b6a39b49d43e48c484f58434985908f88e"
)
IMAGE_ID = (
    "sha256:f8f548d87d16634d1ad9e3777280f3f577ba2358703f04e18e74007ffd3621bf"
)
SCOPE_LEDGER_VERSION = "orbit.synthetic-disease-r2-scope-ledger/1"
SCOPE_LEDGER_GENESIS = "sha256:" + ("0" * 64)
APPROVAL_VERSION = "orbit.synthetic-disease-r2-scope-approval/1"
SCOPES = {
    "agent_activation": (AGENT_ID, AGENT_RELEASE_DIGEST),
    "tool_activation": (TOOL_ID, TOOL_RELEASE_DIGEST),
    "model_route_approval": (MODEL_ROUTE_ID, MODEL_ROUTE_DIGEST),
    "r2_execution": ("review_orbit_disease_r2_20260826", REVIEW_PACKAGE_DIGEST),
}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")
_RECORD_KEYS = {
    "ledger_version",
    "sequence",
    "record_id",
    "record_type",
    "scope",
    "idempotency_key",
    "previous_record_hash",
    "payload",
    "record_hash",
}


class DiseaseR2GovernanceError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class R2ScopeDecision:
    decision_id: str
    scope: str
    subject_id: str
    subject_digest: str
    review_package_digest: str
    decided_by_human_ref: str
    decision: str
    reason: str
    evidence_status: str
    synthetic_only: bool
    release_authorization: bool


@dataclass(frozen=True)
class R2ScopeStatus:
    scope: str
    subject_digest: str
    status: str
    reason_code: str


@dataclass(frozen=True)
class R2ScopeReplay:
    records_checked: int
    last_record_hash: str
    decisions: tuple[R2ScopeDecision, ...]
    statuses: tuple[R2ScopeStatus, ...]

    def status(self, scope: str) -> R2ScopeStatus | None:
        matches = tuple(item for item in self.statuses if item.scope == scope)
        return matches[-1] if matches else None


class SyntheticR2ScopeLedger:
    """Owner-only audit ledger for the non-convertible R2 decision scopes."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def record_decision(
        self, decision: R2ScopeDecision, *, idempotency_key: str
    ) -> None:
        _validate_decision(decision)
        self._append(
            "scope_decision_recorded",
            decision.scope,
            idempotency_key,
            {"decision": asdict(decision)},
        )

    def record_status(
        self, status: R2ScopeStatus, *, idempotency_key: str
    ) -> None:
        _validate_status(status)
        replay = self.replay()
        decisions = tuple(
            item
            for item in replay.decisions
            if item.scope == status.scope
            and item.subject_digest == status.subject_digest
            and item.decision == "approve"
        )
        if len(decisions) != 1:
            raise DiseaseR2GovernanceError(
                "scope_decision_missing", "exact approved scope decision is missing"
            )
        self._append(
            "scope_status_recorded",
            status.scope,
            idempotency_key,
            {"status": asdict(status)},
        )

    def replay(self) -> R2ScopeReplay:
        fd = open_owner_only_ledger(
            self.path,
            create=False,
            exclusive=False,
            error=DiseaseR2GovernanceError,
            label="Disease R2 scope ledger",
        )
        try:
            return _replay(fd)
        finally:
            close_ledger(fd)

    def _append(
        self,
        record_type: str,
        scope: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
    ) -> None:
        if scope not in SCOPES or not _IDEMPOTENCY.fullmatch(idempotency_key):
            raise DiseaseR2GovernanceError(
                "scope_record_invalid", "scope record identifier is invalid"
            )
        fd = open_owner_only_ledger(
            self.path,
            create=True,
            exclusive=True,
            error=DiseaseR2GovernanceError,
            label="Disease R2 scope ledger",
        )
        try:
            replay, records = _replay(fd, include_records=True)
            normalized = _normalize(payload)
            for record in records:
                if record["idempotency_key"] != idempotency_key:
                    continue
                if (
                    record["record_type"] == record_type
                    and record["scope"] == scope
                    and record["payload"] == normalized
                ):
                    return
                raise DiseaseR2GovernanceError(
                    "scope_idempotency_conflict",
                    "scope idempotency key is bound to different content",
                )
            content = {
                "ledger_version": SCOPE_LEDGER_VERSION,
                "sequence": len(records),
                "record_id": deterministic_id(
                    "r2scope", record_type, scope, idempotency_key, _digest(normalized)
                ),
                "record_type": record_type,
                "scope": scope,
                "idempotency_key": idempotency_key,
                "previous_record_hash": replay.last_record_hash,
                "payload": normalized,
            }
            document = {**content, "record_hash": _digest(content)}
            encoded = (_canonical(document) + "\n").encode()
            append_jsonl_document(
                fd,
                encoded,
                max_ledger_bytes=4 * 1024 * 1024,
                max_record_bytes=64 * 1024,
                error=DiseaseR2GovernanceError,
                label="Disease R2 scope ledger",
            )
        finally:
            close_ledger(fd)


def load_scope_approval(path: Path | str) -> tuple[R2ScopeDecision, ...]:
    document = _read_owner_only_json(Path(path))
    if set(document) != {
        "approval_version",
        "review_package_digest",
        "decided_by_human_ref",
        "decision",
        "reason",
        "scopes",
        "authority_boundary",
    }:
        raise DiseaseR2GovernanceError(
            "scope_approval_fields_invalid", "scope approval fields differ"
        )
    if (
        document["approval_version"] != APPROVAL_VERSION
        or document["review_package_digest"] != REVIEW_PACKAGE_DIGEST
        or document["decision"] != "approve"
        or not isinstance(document["reason"], str)
        or len(document["reason"]) < 12
        or document["authority_boundary"]
        != {
            "formal_registry_authorized": False,
            "preproduction_authorized": False,
            "production_authorized": False,
            "release_authorization": False,
        }
    ):
        raise DiseaseR2GovernanceError(
            "scope_approval_boundary_invalid", "scope approval exceeds the reviewed boundary"
        )
    raw_scopes = document["scopes"]
    if not isinstance(raw_scopes, list) or len(raw_scopes) != len(SCOPES):
        raise DiseaseR2GovernanceError(
            "scope_approval_set_invalid", "all four independent scopes are required"
        )
    decisions = []
    seen = set()
    for item in raw_scopes:
        if not isinstance(item, dict) or set(item) != {
            "decision_id",
            "scope",
            "subject_id",
            "subject_digest",
        }:
            raise DiseaseR2GovernanceError(
                "scope_approval_set_invalid", "scope entry fields differ"
            )
        scope = item["scope"]
        if scope in seen or SCOPES.get(scope) != (
            item["subject_id"],
            item["subject_digest"],
        ):
            raise DiseaseR2GovernanceError(
                "scope_approval_binding_invalid", "scope subject differs from review"
            )
        seen.add(scope)
        decision = R2ScopeDecision(
            decision_id=item["decision_id"],
            scope=scope,
            subject_id=item["subject_id"],
            subject_digest=item["subject_digest"],
            review_package_digest=REVIEW_PACKAGE_DIGEST,
            decided_by_human_ref=document["decided_by_human_ref"],
            decision="approve",
            reason=document["reason"],
            evidence_status="synthetic",
            synthetic_only=True,
            release_authorization=False,
        )
        _validate_decision(decision)
        decisions.append(decision)
    if seen != set(SCOPES):
        raise DiseaseR2GovernanceError(
            "scope_approval_set_invalid", "approved scope set is incomplete"
        )
    return tuple(decisions)


def verify_review_package(control: Path, scientific: Path) -> dict[str, Any]:
    evidence = control / "evidence/disease-agent-r2/2026-08-26"
    manifest = _read_json(evidence / "review-package-manifest.json")
    supplied = manifest.pop("review_package_digest", None)
    if supplied != REVIEW_PACKAGE_DIGEST or _digest(manifest) != supplied:
        raise DiseaseR2GovernanceError(
            "review_package_digest_drift", "review package self digest differs"
        )
    bindings = manifest.get("immutable_bindings", {})
    expected = {
        "agent_release_digest": AGENT_RELEASE_DIGEST,
        "literature_tool_release_digest": TOOL_RELEASE_DIGEST,
        "model_route_digest": MODEL_ROUTE_DIGEST,
        "public_corpus_revision": CORPUS_REVISION,
        "runtime_source_digest": RUNTIME_SOURCE_DIGEST,
        "image_id": IMAGE_ID,
    }
    if any(bindings.get(key) != value for key, value in expected.items()):
        raise DiseaseR2GovernanceError(
            "review_package_binding_drift", "review package immutable binding differs"
        )
    for name, digest in manifest.get("artifacts", {}).items():
        if _file_digest(evidence / name) != digest:
            raise DiseaseR2GovernanceError(
                "review_package_artifact_drift", "review package artifact differs"
            )
    sources = {
        scientific
        / "contracts/agents/disease-research-task-agent/candidates/0.2.0/"
        "agent-release-candidate.synthetic.yaml": AGENT_RELEASE_DIGEST,
        scientific
        / "contracts/tools/literature-public-corpus/candidates/0.1.0/"
        "tool-release-candidate.synthetic.json": TOOL_RELEASE_DIGEST,
        scientific
        / "contracts/tools/literature-public-corpus/candidates/0.1.0/"
        "tool-manifest.synthetic.json": TOOL_MANIFEST_DIGEST,
        control
        / "references/disease-r2/model-route.candidate.synthetic.yaml": MODEL_ROUTE_DIGEST,
        scientific
        / "evidence/disease-agent-r2/public-corpus/2026-08-26/"
        "normalized-records.public.jsonl": CORPUS_REVISION,
    }
    for path, digest in sources.items():
        if _file_digest(path) != digest:
            raise DiseaseR2GovernanceError(
                "r2_source_digest_drift", "R2 source bytes differ from approval"
            )
    runtime_lock = _read_json(evidence / "runtime-source.lock.json")
    supplied_runtime_digest = runtime_lock.pop("runtime_source_digest", None)
    if (
        supplied_runtime_digest != RUNTIME_SOURCE_DIGEST
        or _digest(runtime_lock) != supplied_runtime_digest
    ):
        raise DiseaseR2GovernanceError(
            "runtime_source_digest_drift", "R2 Runtime Source lock differs"
        )
    runtime_paths = {
        "control_candidate": control / "candidate_support/disease_r2_candidate.py",
        "docker_harness": control / "candidate_support/disease_r2_harness.py",
        "scientific_runtime": scientific / "candidate_support/disease_r2_candidate.py",
        "scientific_worker": scientific
        / "candidate_support/disease_r2_candidate_worker.py",
        "literature_collector": scientific
        / "candidate_support/literature_public_corpus_collector.py",
        "agent_release": scientific
        / "contracts/agents/disease-research-task-agent/candidates/0.2.0/"
        "agent-release-candidate.synthetic.yaml",
        "literature_tool_release": scientific
        / "contracts/tools/literature-public-corpus/candidates/0.1.0/"
        "tool-release-candidate.synthetic.json",
        "model_route": control
        / "references/disease-r2/model-route.candidate.synthetic.yaml",
    }
    entries = runtime_lock.get("entries")
    if not isinstance(entries, list) or {item.get("role") for item in entries} != set(
        runtime_paths
    ):
        raise DiseaseR2GovernanceError(
            "runtime_source_entries_invalid", "R2 Runtime Source entries differ"
        )
    for entry in entries:
        path = runtime_paths[entry["role"]]
        if _file_digest(path) != entry.get("digest"):
            raise DiseaseR2GovernanceError(
                "runtime_source_entry_drift", "R2 Runtime Source entry differs"
            )
    worker_source = runtime_paths["scientific_worker"].read_text(encoding="utf-8")
    if (
        '"status": "candidate-not-effective"' not in worker_source
        or '"reason_code": "r2_execution_approval_required"' not in worker_source
        or "return 2" not in worker_source
    ):
        raise DiseaseR2GovernanceError(
            "reviewed_worker_boundary_drift", "reviewed R2 worker boundary differs"
        )
    return {**manifest, "review_package_digest": supplied}


def apply_approved_scopes(
    *,
    control: Path,
    scientific: Path,
    approval_path: Path,
    scope_ledger_path: Path,
) -> dict[str, Any]:
    manifest = verify_review_package(control, scientific)
    decisions = load_scope_approval(approval_path)
    scope_ledger = SyntheticR2ScopeLedger(scope_ledger_path)
    for decision in decisions:
        scope_ledger.record_decision(
            decision, idempotency_key=f"decision:{decision.scope}:20260827"
        )

    for status in (
        R2ScopeStatus(
            "agent_activation",
            AGENT_RELEASE_DIGEST,
            "applied",
            "local_synthetic_agent_active",
        ),
        R2ScopeStatus(
            "tool_activation",
            TOOL_RELEASE_DIGEST,
            "applied",
            "local_synthetic_tool_active",
        ),
        R2ScopeStatus(
            "model_route_approval",
            MODEL_ROUTE_DIGEST,
            "approved_unconsumed",
            "exact_route_approved_for_one_execution",
        ),
        R2ScopeStatus(
            "r2_execution",
            REVIEW_PACKAGE_DIGEST,
            "blocked_unconsumed",
            "reviewed_runtime_worker_is_candidate_not_effective",
        ),
    ):
        scope_ledger.record_status(
            status, idempotency_key=f"status:{status.scope}:20260827"
        )
    scope_state = scope_ledger.replay()
    return {
        "status": "r2_scopes_partially_applied_execution_blocked",
        "review_package_digest": manifest["review_package_digest"],
        "agent": {
            "release_digest": AGENT_RELEASE_DIGEST,
            "lifecycle_status": "active",
            "revision": 1,
            "ledger_scope": "release-scoped-local-synthetic",
        },
        "tool": {
            "release_digest": TOOL_RELEASE_DIGEST,
            "lifecycle_status": "active",
            "revision": 1,
            "ledger_scope": "release-scoped-local-synthetic",
        },
        "model_route": {
            "digest": MODEL_ROUTE_DIGEST,
            "approval_status": scope_state.status("model_route_approval").status,
        },
        "execution": {
            "approval_status": scope_state.status("r2_execution").status,
            "reason_code": scope_state.status("r2_execution").reason_code,
            "task_created": False,
            "grant_created": False,
            "worker_started": False,
            "model_called": False,
        },
        "release_authorization": False,
        "preproduction_authorized": False,
        "production_authorized": False,
    }


def _validate_decision(value: R2ScopeDecision) -> None:
    expected = SCOPES.get(value.scope)
    if (
        expected != (value.subject_id, value.subject_digest)
        or value.review_package_digest != REVIEW_PACKAGE_DIGEST
        or value.decision != "approve"
        or value.evidence_status != "synthetic"
        or not value.synthetic_only
        or value.release_authorization
        or not isinstance(value.decision_id, str)
        or not value.decision_id.startswith("approval_")
        or not isinstance(value.decided_by_human_ref, str)
        or not value.decided_by_human_ref.startswith("hum_")
        or not isinstance(value.reason, str)
        or len(value.reason) < 12
    ):
        raise DiseaseR2GovernanceError(
            "scope_decision_invalid", "R2 scope decision is invalid"
        )


def _validate_status(value: R2ScopeStatus) -> None:
    expected = SCOPES.get(value.scope)
    if (
        expected is None
        or value.subject_digest != expected[1]
        or value.status
        not in {"applied", "approved_unconsumed", "blocked_unconsumed", "consumed"}
        or not isinstance(value.reason_code, str)
        or not value.reason_code
    ):
        raise DiseaseR2GovernanceError(
            "scope_status_invalid", "R2 scope status is invalid"
        )


def _replay(
    fd: int, *, include_records: bool = False
) -> R2ScopeReplay | tuple[R2ScopeReplay, tuple[dict[str, Any], ...]]:
    records = read_jsonl_documents(
        fd,
        max_ledger_bytes=4 * 1024 * 1024,
        max_record_bytes=64 * 1024,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        error=DiseaseR2GovernanceError,
        label="Disease R2 scope ledger",
    )
    decisions = []
    statuses = []
    previous = SCOPE_LEDGER_GENESIS
    seen_idempotency = set()
    for sequence, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
            raise DiseaseR2GovernanceError(
                "scope_record_invalid", "scope ledger record fields differ"
            )
        content = {key: value for key, value in record.items() if key != "record_hash"}
        if (
            record["ledger_version"] != SCOPE_LEDGER_VERSION
            or record["sequence"] != sequence
            or record["previous_record_hash"] != previous
            or record["record_hash"] != _digest(content)
            or record["scope"] not in SCOPES
            or record["idempotency_key"] in seen_idempotency
        ):
            raise DiseaseR2GovernanceError(
                "scope_ledger_chain_invalid", "scope ledger chain differs"
            )
        seen_idempotency.add(record["idempotency_key"])
        if record["record_type"] == "scope_decision_recorded":
            decision = R2ScopeDecision(**record["payload"]["decision"])
            _validate_decision(decision)
            if any(item.scope == decision.scope for item in decisions):
                raise DiseaseR2GovernanceError(
                    "scope_decision_duplicate", "scope decision is duplicated"
                )
            decisions.append(decision)
        elif record["record_type"] == "scope_status_recorded":
            status = R2ScopeStatus(**record["payload"]["status"])
            _validate_status(status)
            if not any(
                item.scope == status.scope
                and item.subject_digest == status.subject_digest
                for item in decisions
            ):
                raise DiseaseR2GovernanceError(
                    "scope_decision_missing", "scope status has no decision"
                )
            statuses.append(status)
        else:
            raise DiseaseR2GovernanceError(
                "scope_record_type_invalid", "scope record type is invalid"
            )
        previous = record["record_hash"]
    replay = R2ScopeReplay(len(records), previous, tuple(decisions), tuple(statuses))
    return (replay, records) if include_records else replay


def _read_owner_only_json(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DiseaseR2GovernanceError(
            "scope_approval_unavailable", "scope approval is unavailable"
        ) from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        raise DiseaseR2GovernanceError(
            "scope_approval_insecure", "scope approval must be owner-only"
        )
    return _read_json(path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiseaseR2GovernanceError(
            "r2_json_invalid", "R2 JSON input is invalid"
        ) from error
    if not isinstance(value, dict):
        raise DiseaseR2GovernanceError(
            "r2_json_invalid", "R2 JSON input must be an object"
        )
    return value


def _file_digest(path: Path) -> str:
    try:
        source = path.read_bytes()
    except OSError as error:
        raise DiseaseR2GovernanceError(
            "r2_source_unavailable", "R2 source is unavailable"
        ) from error
    return "sha256:" + hashlib.sha256(source).hexdigest()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode()).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _normalize(value: Any) -> Any:
    return json.loads(_canonical(value))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise DiseaseR2GovernanceError(
                "duplicate_json_key", "R2 JSON contains duplicate keys"
            )
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise DiseaseR2GovernanceError(
        "invalid_json_constant", f"unsupported JSON constant: {value}"
    )

