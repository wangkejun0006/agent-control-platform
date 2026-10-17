"""Sanitized Codex CLI installation evidence for the Stage-1 LAN slice.

These records are Receipt/Artifact projections only.  They never create a
RuntimeEvent, qualification, Approval, ExecutionGrant, Lease, or Runtime run.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from ..ids import deterministic_id
from ..qualification.automation import canonical_digest
from .database import Database
from .lan_stage1_models import (
    LanCertificateBindingRow,
    LanCodexInstallationAttemptRow,
    LanCodexInstallationEventRow,
    LanCodexInstallationReceiptRow,
)
from .models import AuditEventRow, ReceiptRow

CODEX_CLI_VERSION = "0.153.0"
CODEX_TARGET_PLATFORM = "x86_64-unknown-linux-musl"
STAGES = ("download", "verify", "install", "version_check", "complete")
EVENT_STATUSES = frozenset({"running", "passed", "failed"})
FAILURE_CODES = frozenset(
    {
        "archive_digest_drift",
        "release_manifest_digest_drift",
        "installation_failed",
        "version_mismatch",
        "device_offline",
    }
)
EVIDENCE_SOURCES = frozenset({"live_stage_events", "recovered_existing_receipt"})
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,159}$")
_SENSITIVE_KEY = re.compile(
    r"(?:secret|token|password|credential|auth(?:entication)?|email|account|"
    r"path|directory|terminal|stdout|stderr|log|certificate|provider|endpoint)",
    re.IGNORECASE,
)


class CodexInstallationError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class CodexInstallationService:
    def __init__(
        self,
        *,
        database: Database,
        approved_release_manifest_digest: str | None = None,
        approved_archive_digest: str | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.database = database
        self.approved_release_manifest_digest = approved_release_manifest_digest
        self.approved_archive_digest = approved_archive_digest
        self.now = now or (lambda: datetime.now(timezone.utc))

    @property
    def configured(self) -> bool:
        return bool(
            self.approved_release_manifest_digest
            and self.approved_archive_digest
            and _DIGEST.fullmatch(self.approved_release_manifest_digest)
            and _DIGEST.fullmatch(self.approved_archive_digest)
        )

    def record_event(
        self,
        *,
        node_id: str,
        document: Mapping[str, Any],
        idempotency_key: str,
        workload_identity: str,
    ) -> dict[str, Any]:
        value = dict(document)
        _reject_sensitive(value, allow_negative_authorization_keys=True)
        _exact_keys(
            value,
            {
                "event_version",
                "attempt_id",
                "predecessor_attempt_id",
                "department_id",
                "codex_cli_version",
                "target_platform",
                "release_manifest_digest",
                "archive_digest",
                "sequence",
                "stage",
                "status",
                "failure_code",
                "observed_at",
                "execution_grant_issued",
                "runtime_started",
                "model_called",
                "production_authorization",
                "release_authorization",
            },
            "codex_installation_event_invalid",
        )
        self._validate_common(value, node_id=node_id)
        if (
            value["event_version"] != "orbit.codex-installation-stage-event/1"
            or not isinstance(value["sequence"], int)
            or isinstance(value["sequence"], bool)
            or value["sequence"] < 1
            or value["stage"] not in STAGES
            or value["status"] not in EVENT_STATUSES
            or not _SAFE_ID.fullmatch(str(value["attempt_id"]))
            or (
                value["predecessor_attempt_id"] is not None
                and not _SAFE_ID.fullmatch(str(value["predecessor_attempt_id"]))
            )
            or (
                value["failure_code"] not in FAILURE_CODES
                if value["status"] == "failed"
                else value["failure_code"] is not None
            )
        ):
            raise CodexInstallationError("codex_installation_event_invalid")
        _parse_time(value["observed_at"], "codex_installation_event_invalid")
        request_digest = canonical_digest(value)
        with self.database.session() as session:
            replay = session.scalar(
                select(LanCodexInstallationEventRow).where(
                    LanCodexInstallationEventRow.idempotency_key == idempotency_key
                )
            )
            if replay is not None:
                if replay.document_digest != request_digest:
                    raise CodexInstallationError("codex_installation_event_replay_conflict")
                return self._event_response(replay, replay=True)
            attempt = session.scalar(
                select(LanCodexInstallationAttemptRow).where(
                    LanCodexInstallationAttemptRow.attempt_id == value["attempt_id"]
                )
            )
            now = self.now()
            if attempt is None:
                self._validate_new_attempt(session, value, node_id=node_id)
                attempt = LanCodexInstallationAttemptRow(
                    attempt_id=value["attempt_id"],
                    predecessor_attempt_id=value["predecessor_attempt_id"],
                    node_id=node_id,
                    department_id=value["department_id"],
                    codex_cli_version=value["codex_cli_version"],
                    target_platform=value["target_platform"],
                    release_manifest_digest=value["release_manifest_digest"],
                    archive_digest=value["archive_digest"],
                    latest_sequence=0,
                    current_stage="download",
                    status="running",
                    failure_code=None,
                    intermediate_events_available=True,
                    resource_revision=0,
                    created_at=now,
                    updated_at=now,
                )
                session.add(attempt)
            self._validate_event_transition(attempt, value, node_id=node_id)
            event_id = deterministic_id(
                "codex-install-event", str(value["attempt_id"]), str(value["sequence"])
            )
            event = LanCodexInstallationEventRow(
                event_id=event_id,
                attempt_id=value["attempt_id"],
                node_id=node_id,
                department_id=value["department_id"],
                sequence=value["sequence"],
                stage=value["stage"],
                status=value["status"],
                failure_code=value["failure_code"],
                document_digest=request_digest,
                idempotency_key=idempotency_key,
                recorded_at=now,
            )
            session.add(event)
            attempt.latest_sequence = value["sequence"]
            attempt.current_stage = value["stage"]
            attempt.status = (
                "failed"
                if value["status"] == "failed"
                else "awaiting_terminal_receipt"
                if value["stage"] == "complete" and value["status"] == "passed"
                else value["status"]
            )
            attempt.failure_code = value["failure_code"]
            attempt.resource_revision += 1
            attempt.updated_at = now
            session.add(
                AuditEventRow(
                    audit_id=deterministic_id("audit", event_id),
                    correlation_id=value["attempt_id"],
                    event_type="codex_installation_stage_recorded",
                    actor_ref=workload_identity,
                    payload={
                        "event_id": event_id,
                        "sequence": value["sequence"],
                        "stage": value["stage"],
                        "status": value["status"],
                        "failure_code": value["failure_code"],
                        "execution_grant_issued": False,
                        "runtime_started": False,
                        "model_called": False,
                    },
                    recorded_at=now,
                )
            )
            session.flush()
            return self._event_response(event, replay=False, revision=attempt.resource_revision)

    def record_receipt(
        self,
        *,
        node_id: str,
        document: Mapping[str, Any],
        idempotency_key: str,
        workload_identity: str,
    ) -> dict[str, Any]:
        value = dict(document)
        _reject_sensitive(value, allow_negative_authorization_keys=True)
        _exact_keys(
            value,
            {
                "schema_version",
                "receipt_id",
                "attempt_id",
                "predecessor_attempt_id",
                "department_id",
                "status",
                "version",
                "target",
                "release_manifest_digest",
                "archive_digest",
                "evidence_source",
                "intermediate_events_available",
                "observed_at",
                "credential_present",
                "account_logged_in",
                "execution_grant_issued",
                "lease_issued",
                "runtime_started",
                "model_called",
                "production_authorization",
                "release_authorization",
            },
            "codex_installation_receipt_invalid",
        )
        common = {
            "department_id": value["department_id"],
            "codex_cli_version": value["version"],
            "target_platform": value["target"],
            "release_manifest_digest": value["release_manifest_digest"],
            "archive_digest": value["archive_digest"],
            "execution_grant_issued": value["execution_grant_issued"],
            "runtime_started": value["runtime_started"],
            "model_called": value["model_called"],
            "production_authorization": value["production_authorization"],
            "release_authorization": value["release_authorization"],
        }
        self._validate_common(common, node_id=node_id)
        if (
            value["schema_version"]
            != "orbit.codex-cli-installation-receipt/0.1-draft"
            or value["status"] != "codex_cli_installed"
            or value["evidence_source"] not in EVIDENCE_SOURCES
            or not _SAFE_ID.fullmatch(str(value["receipt_id"]))
            or not _SAFE_ID.fullmatch(str(value["attempt_id"]))
            or (
                value["predecessor_attempt_id"] is not None
                and not _SAFE_ID.fullmatch(str(value["predecessor_attempt_id"]))
            )
            or value["credential_present"] is not False
            or value["account_logged_in"] is not False
            or value["execution_grant_issued"] is not False
            or value["lease_issued"] is not False
            or value["runtime_started"] is not False
            or value["model_called"] is not False
            or value["production_authorization"] is not False
            or value["release_authorization"] is not False
            or not isinstance(value["intermediate_events_available"], bool)
            or (
                value["evidence_source"] == "recovered_existing_receipt"
                and value["intermediate_events_available"] is not False
            )
        ):
            raise CodexInstallationError("codex_installation_receipt_invalid")
        _parse_time(value["observed_at"], "codex_installation_receipt_invalid")
        receipt_digest = canonical_digest(value)
        with self.database.session() as session:
            replay = session.scalar(
                select(LanCodexInstallationReceiptRow).where(
                    LanCodexInstallationReceiptRow.idempotency_key == idempotency_key
                )
            )
            if replay is not None:
                if replay.receipt_digest != receipt_digest:
                    raise CodexInstallationError("codex_installation_receipt_replay_conflict")
                return self._receipt_response(replay, replay=True)
            attempt = session.scalar(
                select(LanCodexInstallationAttemptRow).where(
                    LanCodexInstallationAttemptRow.attempt_id == value["attempt_id"]
                )
            )
            now = self.now()
            if attempt is None:
                if value["evidence_source"] != "recovered_existing_receipt":
                    raise CodexInstallationError("codex_installation_attempt_not_found")
                self._validate_recovered_predecessor(session, value, node_id=node_id)
                attempt = LanCodexInstallationAttemptRow(
                    attempt_id=value["attempt_id"],
                    predecessor_attempt_id=value["predecessor_attempt_id"],
                    node_id=node_id,
                    department_id=value["department_id"],
                    codex_cli_version=value["version"],
                    target_platform=value["target"],
                    release_manifest_digest=value["release_manifest_digest"],
                    archive_digest=value["archive_digest"],
                    latest_sequence=0,
                    current_stage="complete",
                    status="complete",
                    failure_code=None,
                    intermediate_events_available=False,
                    resource_revision=1,
                    created_at=now,
                    updated_at=now,
                )
                session.add(attempt)
            else:
                if not self._attempt_matches(attempt, value, node_id=node_id):
                    raise CodexInstallationError("codex_installation_attempt_binding_drift")
                if (
                    value["evidence_source"] == "live_stage_events"
                    and attempt.status != "awaiting_terminal_receipt"
                ):
                    raise CodexInstallationError("codex_installation_terminal_event_missing")
                if attempt.status == "failed":
                    raise CodexInstallationError("codex_installation_attempt_failed")
                attempt.status = "complete"
                attempt.current_stage = "complete"
                attempt.failure_code = None
                attempt.intermediate_events_available = value[
                    "intermediate_events_available"
                ]
                attempt.resource_revision += 1
                attempt.updated_at = now
            row = LanCodexInstallationReceiptRow(
                receipt_id=value["receipt_id"],
                attempt_id=value["attempt_id"],
                node_id=node_id,
                department_id=value["department_id"],
                codex_cli_version=value["version"],
                target_platform=value["target"],
                release_manifest_digest=value["release_manifest_digest"],
                archive_digest=value["archive_digest"],
                evidence_source=value["evidence_source"],
                intermediate_events_available=value["intermediate_events_available"],
                receipt_digest=receipt_digest,
                document=value,
                idempotency_key=idempotency_key,
                recorded_at=now,
            )
            session.add(row)
            session.add(
                ReceiptRow(
                    receipt_id=value["receipt_id"],
                    receipt_type="orbit.codex-cli-installation-receipt/0.1-draft",
                    receipt_digest=receipt_digest,
                    subject_ref=f"runtime-node://{node_id}/codex-cli/{value['version']}",
                    document=value,
                    recorded_at=now,
                )
            )
            session.add(
                AuditEventRow(
                    audit_id=deterministic_id("audit", value["receipt_id"]),
                    correlation_id=value["attempt_id"],
                    event_type="codex_installation_receipt_recorded",
                    actor_ref=workload_identity,
                    payload={
                        "receipt_id": value["receipt_id"],
                        "receipt_digest": receipt_digest,
                        "evidence_source": value["evidence_source"],
                        "intermediate_events_available": value[
                            "intermediate_events_available"
                        ],
                        "execution_grant_issued": False,
                        "runtime_started": False,
                        "model_called": False,
                    },
                    recorded_at=now,
                )
            )
            return self._receipt_response(row, replay=False, revision=attempt.resource_revision)

    def projection(self, *, department_id: str) -> dict[str, Any]:
        with self.database.session() as session:
            attempts = tuple(
                session.scalars(
                    select(LanCodexInstallationAttemptRow)
                    .where(LanCodexInstallationAttemptRow.department_id == department_id)
                    .order_by(LanCodexInstallationAttemptRow.id.desc())
                )
            )
            current = attempts[0] if attempts else None
            receipt = (
                None
                if current is None
                else session.scalar(
                    select(LanCodexInstallationReceiptRow).where(
                        LanCodexInstallationReceiptRow.attempt_id == current.attempt_id
                    )
                )
            )
            events = (
                ()
                if current is None
                else tuple(
                    session.scalars(
                        select(LanCodexInstallationEventRow)
                        .where(
                            LanCodexInstallationEventRow.attempt_id == current.attempt_id
                        )
                        .order_by(LanCodexInstallationEventRow.sequence)
                    )
                )
            )
        observed = self.now().isoformat()
        if current is None:
            return {
                "projection_version": "orbit.codex-installation-projection/1",
                "department_id": department_id,
                "applicable": department_id == "technology_center",
                "node_id": None,
                "codex_cli_version": CODEX_CLI_VERSION,
                "target_platform": CODEX_TARGET_PLATFORM,
                "release_manifest_digest": None,
                "archive_digest": None,
                "attempt_id": None,
                "predecessor_attempt_id": None,
                "resource_revision": 0,
                "overall_status": (
                    "waiting_for_device_receipt"
                    if department_id == "technology_center"
                    else "not_applicable"
                ),
                "failure_code": None,
                "updated_at": None,
                "event_freshness": "missing",
                "intermediate_events_available": False,
                "stages": [self._empty_stage(stage) for stage in STAGES],
                "evidence": None,
                "history": [],
                "llm_api_readiness": self._api_readiness("control_plane_readback_required"),
                "observed_at": observed,
                "execution_grant_issued": False,
                "runtime_started": False,
                "model_called": False,
                "production_authorization": False,
                "release_authorization": False,
            }
        event_map = {item.stage: item for item in events}
        history = [
            {
                "attempt_id": item.attempt_id,
                "predecessor_attempt_id": item.predecessor_attempt_id,
                "status": item.status,
                "failure_code": item.failure_code,
                "updated_at": _time(item.updated_at),
            }
            for item in attempts[:10]
        ]
        return {
            "projection_version": "orbit.codex-installation-projection/1",
            "department_id": department_id,
            "applicable": department_id == "technology_center",
            "node_id": current.node_id,
            "codex_cli_version": current.codex_cli_version,
            "target_platform": current.target_platform,
            "release_manifest_digest": current.release_manifest_digest,
            "archive_digest": current.archive_digest,
            "attempt_id": current.attempt_id,
            "predecessor_attempt_id": current.predecessor_attempt_id,
            "resource_revision": current.resource_revision,
            "overall_status": current.status,
            "failure_code": current.failure_code,
            "updated_at": _time(current.updated_at),
            "event_freshness": self._freshness(current.updated_at),
            "intermediate_events_available": current.intermediate_events_available,
            "stages": [self._stage_projection(stage, event_map, receipt) for stage in STAGES],
            "evidence": None if receipt is None else {
                "receipt_id": receipt.receipt_id,
                "receipt_digest": receipt.receipt_digest,
                "evidence_source": receipt.evidence_source,
                "recorded_at": _time(receipt.recorded_at),
                "intermediate_events_available": receipt.intermediate_events_available,
                "credential_present": False,
                "account_logged_in": False,
                "execution_grant_issued": False,
                "lease_issued": False,
                "runtime_started": False,
                "model_called": False,
                "production_authorization": False,
                "release_authorization": False,
            },
            "history": history,
            "llm_api_readiness": self._api_readiness(
                "approved_api_route_required" if receipt is not None else "control_plane_readback_required"
            ),
            "observed_at": observed,
            "execution_grant_issued": False,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }

    def events(self, *, department_id: str, after_sequence: int) -> list[dict[str, Any]]:
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(LanCodexInstallationEventRow)
                    .where(
                        LanCodexInstallationEventRow.department_id == department_id,
                        LanCodexInstallationEventRow.id > after_sequence,
                    )
                    .order_by(LanCodexInstallationEventRow.id)
                    .limit(100)
                )
            )
        return [self._event_response(row, replay=False) for row in rows]

    def _validate_common(self, value: Mapping[str, Any], *, node_id: str) -> None:
        if not self.configured:
            raise CodexInstallationError("codex_installation_release_unconfigured")
        if (
            value.get("department_id") != "technology_center"
            or value.get("codex_cli_version") != CODEX_CLI_VERSION
            or value.get("target_platform") != CODEX_TARGET_PLATFORM
            or value.get("release_manifest_digest")
            != self.approved_release_manifest_digest
            or value.get("archive_digest") != self.approved_archive_digest
            or value.get("execution_grant_issued") is not False
            or value.get("runtime_started") is not False
            or value.get("model_called") is not False
            or value.get("production_authorization") is not False
            or value.get("release_authorization") is not False
            or not _SAFE_ID.fullmatch(str(value.get("department_id", "")))
        ):
            raise CodexInstallationError("codex_installation_release_binding_drift")
        self._validate_node_department(node_id, str(value["department_id"]))

    def _validate_node_department(self, node_id: str, department_id: str) -> None:
        with self.database.session() as session:
            binding = session.scalar(
                select(LanCertificateBindingRow)
                .where(LanCertificateBindingRow.node_id == node_id)
                .order_by(LanCertificateBindingRow.id.desc())
                .limit(1)
            )
        if (
            binding is None
            or binding.status != "active"
            or binding.department_id != department_id
            or _utc(binding.not_after) <= self.now()
        ):
            raise CodexInstallationError("codex_installation_node_scope_invalid")

    @staticmethod
    def _validate_new_attempt(session: Any, value: Mapping[str, Any], *, node_id: str) -> None:
        if value["sequence"] != 1 or value["stage"] != "download":
            raise CodexInstallationError("codex_installation_event_sequence_invalid")
        predecessor_id = value["predecessor_attempt_id"]
        if predecessor_id is None:
            return
        predecessor = session.scalar(
            select(LanCodexInstallationAttemptRow).where(
                LanCodexInstallationAttemptRow.attempt_id == predecessor_id
            )
        )
        if (
            predecessor is None
            or predecessor.node_id != node_id
            or predecessor.department_id != value["department_id"]
            or predecessor.status != "failed"
        ):
            raise CodexInstallationError("codex_installation_predecessor_invalid")

    @staticmethod
    def _validate_recovered_predecessor(
        session: Any, value: Mapping[str, Any], *, node_id: str
    ) -> None:
        predecessor_id = value["predecessor_attempt_id"]
        if predecessor_id is None:
            return
        predecessor = session.scalar(
            select(LanCodexInstallationAttemptRow).where(
                LanCodexInstallationAttemptRow.attempt_id == predecessor_id
            )
        )
        if (
            predecessor is None
            or predecessor.node_id != node_id
            or predecessor.department_id != value["department_id"]
            or predecessor.status != "failed"
        ):
            raise CodexInstallationError("codex_installation_predecessor_invalid")

    @staticmethod
    def _validate_event_transition(
        attempt: LanCodexInstallationAttemptRow,
        value: Mapping[str, Any],
        *,
        node_id: str,
    ) -> None:
        if (
            attempt.node_id != node_id
            or attempt.department_id != value["department_id"]
            or attempt.codex_cli_version != value["codex_cli_version"]
            or attempt.target_platform != value["target_platform"]
            or attempt.release_manifest_digest != value["release_manifest_digest"]
            or attempt.archive_digest != value["archive_digest"]
        ):
            raise CodexInstallationError("codex_installation_attempt_binding_drift")
        if attempt.status in {"failed", "complete", "awaiting_terminal_receipt"}:
            raise CodexInstallationError("codex_installation_attempt_terminal")
        if value["sequence"] != attempt.latest_sequence + 1:
            raise CodexInstallationError("codex_installation_event_sequence_invalid")
        current_index = STAGES.index(attempt.current_stage)
        next_index = STAGES.index(value["stage"])
        if next_index < current_index or next_index > current_index + 1:
            raise CodexInstallationError("codex_installation_stage_transition_invalid")
        # The immediately preceding record must have closed the current stage.
        if (
            attempt.latest_sequence > 0
            and next_index == current_index + 1
            and attempt.status != "passed"
        ):
            raise CodexInstallationError("codex_installation_stage_transition_invalid")

    @staticmethod
    def _attempt_matches(
        attempt: LanCodexInstallationAttemptRow,
        value: Mapping[str, Any],
        *,
        node_id: str,
    ) -> bool:
        return bool(
            attempt.node_id == node_id
            and attempt.department_id == value["department_id"]
            and attempt.codex_cli_version == value["version"]
            and attempt.target_platform == value["target"]
            and attempt.release_manifest_digest == value["release_manifest_digest"]
            and attempt.archive_digest == value["archive_digest"]
        )

    def _freshness(self, value: datetime) -> str:
        seconds = (self.now() - _utc(value)).total_seconds()
        if seconds <= 90:
            return "current"
        if seconds <= 300:
            return "late"
        return "stale"

    @staticmethod
    def _empty_stage(stage: str) -> dict[str, Any]:
        return {
            "stage": stage,
            "status": "waiting",
            "recorded_at": None,
            "sequence": None,
            "failure_code": None,
        }

    @classmethod
    def _stage_projection(
        cls,
        stage: str,
        event_map: Mapping[str, LanCodexInstallationEventRow],
        receipt: LanCodexInstallationReceiptRow | None,
    ) -> dict[str, Any]:
        event = event_map.get(stage)
        if event is None:
            if receipt is not None and stage == "complete":
                return {
                    "stage": stage,
                    "status": "received",
                    "recorded_at": _time(receipt.recorded_at),
                    "sequence": None,
                    "failure_code": None,
                }
            return cls._empty_stage(stage)
        status = {
            "running": "in_progress",
            "passed": "received",
            "failed": "failed",
        }[event.status]
        return {
            "stage": stage,
            "status": status,
            "recorded_at": _time(event.recorded_at),
            "sequence": event.sequence,
            "failure_code": event.failure_code,
        }

    @staticmethod
    def _api_readiness(reason: str) -> dict[str, Any]:
        return {
            "status": "blocked",
            "reason_code": reason,
            "route_options": [],
            "selected_route_id": None,
            "selected_route_revision_digest": None,
            "central_secret_only": True,
            "browser_secret_allowed": False,
            "device_secret_allowed": False,
            "execution_grant_issued": False,
            "runtime_started": False,
            "model_called": False,
        }

    @staticmethod
    def _event_response(
        row: LanCodexInstallationEventRow,
        *,
        replay: bool,
        revision: int | None = None,
    ) -> dict[str, Any]:
        return {
            "event_id": row.event_id,
            "event_cursor": row.id,
            "attempt_id": row.attempt_id,
            "node_id": row.node_id,
            "department_id": row.department_id,
            "sequence": row.sequence,
            "stage": row.stage,
            "status": row.status,
            "failure_code": row.failure_code,
            "recorded_at": _time(row.recorded_at),
            "resource_revision": revision if revision is not None else row.sequence,
            "idempotent_replay": replay,
            "execution_grant_issued": False,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }

    @staticmethod
    def _receipt_response(
        row: LanCodexInstallationReceiptRow,
        *,
        replay: bool,
        revision: int | None = None,
    ) -> dict[str, Any]:
        return {
            "receipt_id": row.receipt_id,
            "receipt_digest": row.receipt_digest,
            "attempt_id": row.attempt_id,
            "node_id": row.node_id,
            "department_id": row.department_id,
            "status": "complete",
            "evidence_source": row.evidence_source,
            "intermediate_events_available": row.intermediate_events_available,
            "recorded_at": _time(row.recorded_at),
            "resource_revision": revision,
            "idempotent_replay": replay,
            "credential_present": False,
            "account_logged_in": False,
            "execution_grant_issued": False,
            "lease_issued": False,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }


def _reject_sensitive(
    value: Mapping[str, Any], *, allow_negative_authorization_keys: bool = False
) -> None:
    allowed = {
        "credential_present",
        "account_logged_in",
        "execution_grant_issued",
        "production_authorization",
        "release_authorization",
    }
    for key, item in value.items():
        if _SENSITIVE_KEY.search(str(key)) and not (
            allow_negative_authorization_keys and key in allowed and item is False
        ):
            raise CodexInstallationError("codex_installation_sensitive_field_rejected")
        if isinstance(item, Mapping):
            _reject_sensitive(
                item,
                allow_negative_authorization_keys=allow_negative_authorization_keys,
            )


def _exact_keys(value: Mapping[str, Any], expected: set[str], reason: str) -> None:
    if set(value) != expected:
        raise CodexInstallationError(reason)


def _parse_time(value: Any, reason: str) -> datetime:
    if not isinstance(value, str):
        raise CodexInstallationError(reason)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CodexInstallationError(reason) from error
    if parsed.tzinfo is None:
        raise CodexInstallationError(reason)
    return parsed.astimezone(timezone.utc)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _time(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")

