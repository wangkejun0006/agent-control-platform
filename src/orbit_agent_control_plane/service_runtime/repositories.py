"""Transactional SQLAlchemy adapters for qualification service state."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from ..ids import deterministic_id
from ..qualification.automation import (
    ReceiptArtifact,
    canonical_digest,
    validate_policy_activation_receipt,
)
from ..qualification.ledger import (
    GENESIS_HASH,
    LEDGER_VERSION,
    QualificationAppendResult,
    QualificationLedgerError,
    QualificationReplay,
    _apply_event,
    _state_from_registration,
    _validate_new_record,
)
from .database import Database
from .models import (
    AuditEventRow,
    GrantRevocationRow,
    OutboxEventRow,
    PolicyActivationRow,
    QualificationEventRow,
    ReceiptRow,
    ReconciliationClaimRow,
    StreamHeadRow,
    WorkerLeaseRow,
)

QUALIFICATION_STREAM = "qualification_events"


class ServiceRepositoryError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class SqlAlchemyQualificationStore:
    """Qualification event store with transactional outbox semantics."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def append(
        self,
        *,
        record_type: str,
        run_id: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
    ) -> QualificationAppendResult:
        return self.append_with_outbox(
            record_type=record_type,
            run_id=run_id,
            payload=payload,
            idempotency_key=idempotency_key,
            outbox_events=(
                {
                    "topic": "qualification.event.recorded",
                    "aggregate_ref": f"qualification-run://{run_id}",
                    "payload": {
                        "run_id": run_id,
                        "record_type": record_type,
                    },
                },
            ),
        )

    def append_with_outbox(
        self,
        *,
        record_type: str,
        run_id: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        outbox_events: Sequence[Mapping[str, Any]],
    ) -> QualificationAppendResult:
        if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 192:
            raise QualificationLedgerError("qualification_idempotency_key_invalid")
        normalized = _normalize_json(payload)
        normalized_outbox = tuple(_normalize_outbox(item) for item in outbox_events)
        with self.database.session() as session:
            existing = session.scalar(
                select(QualificationEventRow).where(
                    QualificationEventRow.idempotency_key == idempotency_key
                )
            )
            if existing is not None:
                if (
                    existing.record_type != record_type
                    or existing.run_id != run_id
                    or existing.payload != normalized
                ):
                    raise QualificationLedgerError("qualification_idempotency_conflict")
                return QualificationAppendResult(
                    existing.sequence,
                    existing.record_id,
                    existing.record_hash,
                    False,
                )
            rows = tuple(
                session.scalars(
                    select(QualificationEventRow).order_by(
                        QualificationEventRow.sequence
                    )
                )
            )
            replay = _service_replay_records(
                tuple(_event_document(row) for row in rows)
            )
            _validate_new_record(replay, record_type, run_id, normalized)
            head = session.get(
                StreamHeadRow, QUALIFICATION_STREAM, with_for_update=True
            )
            if head is None:
                head = StreamHeadRow(
                    stream_name=QUALIFICATION_STREAM,
                    next_sequence=0,
                    last_record_hash=GENESIS_HASH,
                    revision=0,
                )
                session.add(head)
                session.flush()
            if (
                head.next_sequence != replay.records_checked
                or head.last_record_hash != replay.last_record_hash
            ):
                raise QualificationLedgerError("qualification_stream_head_drift")
            sequence = head.next_sequence
            record_id = deterministic_id(
                "qualrec",
                record_type,
                run_id,
                idempotency_key,
                canonical_digest(normalized),
            )
            content = {
                "ledger_version": LEDGER_VERSION,
                "sequence": sequence,
                "record_id": record_id,
                "record_type": record_type,
                "run_id": run_id,
                "idempotency_key": idempotency_key,
                "previous_record_hash": head.last_record_hash,
                "payload": normalized,
            }
            record_hash = canonical_digest(content)
            session.add(
                QualificationEventRow(
                    stream_name=QUALIFICATION_STREAM,
                    sequence=sequence,
                    record_id=record_id,
                    record_type=record_type,
                    run_id=run_id,
                    idempotency_key=idempotency_key,
                    previous_record_hash=head.last_record_hash,
                    payload=normalized,
                    record_hash=record_hash,
                    created_at=_utcnow(),
                )
            )
            for index, event in enumerate(normalized_outbox):
                session.add(
                    OutboxEventRow(
                        event_id=deterministic_id(
                            "outbox", record_id, str(index), event["topic"]
                        ),
                        topic=event["topic"],
                        aggregate_ref=event["aggregate_ref"],
                        payload=event["payload"],
                        status="pending",
                        attempts=0,
                        created_at=_utcnow(),
                        published_at=None,
                    )
                )
            head.next_sequence = sequence + 1
            head.last_record_hash = record_hash
            head.revision += 1
            try:
                session.flush()
            except IntegrityError as error:
                raise QualificationLedgerError(
                    "qualification_concurrent_append"
                ) from error
            return QualificationAppendResult(sequence, record_id, record_hash, True)

    def replay(self) -> QualificationReplay:
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(QualificationEventRow).order_by(
                        QualificationEventRow.sequence
                    )
                )
            )
        return _service_replay_records(tuple(_event_document(row) for row in rows))

    def claim_reconciliation_work(
        self, *, worker_identity: str, limit: int
    ) -> tuple[str, ...]:
        if not worker_identity.startswith("workload_") or not 1 <= limit <= 100:
            raise ServiceRepositoryError("reconciliation_claim_invalid")
        now = _utcnow()
        expires = now + timedelta(seconds=60)
        replay = self.replay()
        candidates = tuple(
            run.run_id
            for run in replay.runs
            if run.status == "running" and run.next_checkpoint_scope is None
        )
        claimed: list[str] = []
        with self.database.session() as session:
            for run_id in candidates:
                if len(claimed) >= limit:
                    break
                row = session.scalar(
                    select(ReconciliationClaimRow)
                    .where(ReconciliationClaimRow.run_id == run_id)
                    .with_for_update()
                )
                if row is not None and _as_utc(row.expires_at) > now:
                    continue
                if row is None:
                    row = ReconciliationClaimRow(
                        run_id=run_id,
                        worker_identity=worker_identity,
                        claimed_at=now,
                        expires_at=expires,
                    )
                    session.add(row)
                else:
                    row.worker_identity = worker_identity
                    row.claimed_at = now
                    row.expires_at = expires
                claimed.append(run_id)
        return tuple(claimed)


class SqlAlchemyPolicyActivationRepository:
    def __init__(self, database: Database) -> None:
        self.database = database

    def record(
        self,
        *,
        policy: Mapping[str, Any],
        policy_digest: str,
        approval_decision: Mapping[str, Any],
        receipt: ReceiptArtifact,
    ) -> bool:
        validate_policy_activation_receipt(
            policy=policy,
            policy_digest=policy_digest,
            approval_decision=approval_decision,
            receipt=receipt,
        )
        metadata = receipt.document["metadata"]
        approval_digest = canonical_digest(approval_decision)
        with self.database.session() as session:
            existing = session.scalar(
                select(PolicyActivationRow).where(
                    PolicyActivationRow.policy_digest == policy_digest
                )
            )
            if existing is not None:
                if (
                    existing.approval_digest != approval_digest
                    or existing.receipt_digest != receipt.digest
                ):
                    raise ServiceRepositoryError("policy_activation_conflict")
                return False
            now = _utcnow()
            session.add(
                PolicyActivationRow(
                    policy_id=metadata["policy_id"],
                    policy_version=metadata["policy_version"],
                    policy_digest=policy_digest,
                    approval_digest=approval_digest,
                    receipt_id=metadata["receipt_id"],
                    receipt_digest=receipt.digest,
                    approval_document=_normalize_json(approval_decision),
                    receipt_document=_normalize_json(receipt.document),
                    activated_at=_parse_time(metadata["activated_at"]),
                    expires_at=_parse_time(metadata["expires_at"]),
                    evidence_status=metadata["evidence_status"],
                    synthetic_only=metadata["synthetic_only"],
                )
            )
            session.add(
                ReceiptRow(
                    receipt_id=metadata["receipt_id"],
                    receipt_type=receipt.schema_id,
                    receipt_digest=receipt.digest,
                    subject_ref=receipt.document["spec"]["automation_policy"]["ref"],
                    document=_normalize_json(receipt.document),
                    recorded_at=now,
                )
            )
            session.add(
                AuditEventRow(
                    audit_id=deterministic_id("audit", metadata["receipt_id"]),
                    correlation_id=metadata["receipt_id"],
                    event_type="automation_policy_activated",
                    actor_ref=approval_decision["spec"]["decided_by_human_ref"],
                    payload={
                        "policy_digest": policy_digest,
                        "approval_digest": approval_digest,
                        "receipt_digest": receipt.digest,
                        "release_authorization": False,
                    },
                    recorded_at=now,
                )
            )
            session.add(
                OutboxEventRow(
                    event_id=deterministic_id("outbox", metadata["receipt_id"]),
                    topic="automation.policy.activated",
                    aggregate_ref=receipt.document["spec"]["automation_policy"]["ref"],
                    payload={
                        "policy_digest": policy_digest,
                        "receipt_digest": receipt.digest,
                        "release_authorization": False,
                    },
                    status="pending",
                    attempts=0,
                    created_at=now,
                    published_at=None,
                )
            )
            return True

    def get_by_policy_digest(self, policy_digest: str) -> dict[str, Any] | None:
        with self.database.session() as session:
            row = session.scalar(
                select(PolicyActivationRow).where(
                    PolicyActivationRow.policy_digest == policy_digest
                )
            )
            if row is None:
                return None
            return {
                "policy_id": row.policy_id,
                "policy_version": row.policy_version,
                "policy_digest": row.policy_digest,
                "approval_digest": row.approval_digest,
                "receipt_id": row.receipt_id,
                "receipt_digest": row.receipt_digest,
                "activated_at": row.activated_at.isoformat(),
                "expires_at": row.expires_at.isoformat(),
                "evidence_status": row.evidence_status,
                "synthetic_only": row.synthetic_only,
                "release_authorization": False,
            }


class SqlGrantRevocationRegistry:
    def __init__(self, database: Database) -> None:
        self.database = database

    def revision(self) -> int:
        with self.database.session() as session:
            return int(
                session.scalar(select(func.max(GrantRevocationRow.revision))) or 0
            )

    def revoke(self, *, grant_id: str, reason_code: str, revoked_by_ref: str) -> int:
        if not grant_id.startswith("grant_") or not revoked_by_ref.startswith(
            ("human_", "workload_")
        ):
            raise ServiceRepositoryError("grant_revocation_invalid")
        with self.database.session() as session:
            existing = session.scalar(
                select(GrantRevocationRow).where(
                    GrantRevocationRow.grant_id == grant_id
                )
            )
            if existing is not None:
                if (
                    existing.reason_code != reason_code
                    or existing.revoked_by_ref != revoked_by_ref
                ):
                    raise ServiceRepositoryError("grant_revocation_conflict")
                return existing.revision
            revision = (
                int(session.scalar(select(func.max(GrantRevocationRow.revision))) or 0)
                + 1
            )
            session.add(
                GrantRevocationRow(
                    grant_id=grant_id,
                    revision=revision,
                    reason_code=reason_code,
                    revoked_by_ref=revoked_by_ref,
                    revoked_at=_utcnow(),
                )
            )
            return revision

    def is_revoked(self, *, grant_id: str, minimum_revision: int) -> bool:
        with self.database.session() as session:
            row = session.scalar(
                select(GrantRevocationRow).where(
                    GrantRevocationRow.grant_id == grant_id
                )
            )
            return row is not None and row.revision >= minimum_revision


class SqlOutboxPublisher:
    """At-least-once outbox publisher with explicit sink-side deduplication key."""

    def __init__(self, database: Database, sink) -> None:
        self.database = database
        self.sink = sink

    def publish_pending(self, *, limit: int) -> int:
        if not 1 <= limit <= 1000:
            raise ServiceRepositoryError("outbox_limit_invalid")
        published = 0
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(OutboxEventRow)
                    .where(OutboxEventRow.status == "pending")
                    .order_by(OutboxEventRow.id)
                    .limit(limit)
                    .with_for_update(skip_locked=True)
                )
            )
            for row in rows:
                row.attempts += 1
                self.sink(
                    {
                        "event_id": row.event_id,
                        "topic": row.topic,
                        "aggregate_ref": row.aggregate_ref,
                        "payload": row.payload,
                    }
                )
                row.status = "published"
                row.published_at = _utcnow()
                published += 1
        return published


class SqlAuditExporter:
    def __init__(self, database: Database) -> None:
        self.database = database

    def record(
        self,
        *,
        correlation_id: str,
        event_type: str,
        actor_ref: str,
        payload: Mapping[str, Any],
    ) -> str:
        normalized = _normalize_json(payload)
        audit_id = deterministic_id(
            "audit",
            correlation_id,
            event_type,
            actor_ref,
            canonical_digest(normalized),
        )
        with self.database.session() as session:
            existing = session.scalar(
                select(AuditEventRow).where(AuditEventRow.audit_id == audit_id)
            )
            if existing is not None:
                return audit_id
            session.add(
                AuditEventRow(
                    audit_id=audit_id,
                    correlation_id=correlation_id,
                    event_type=event_type,
                    actor_ref=actor_ref,
                    payload=normalized,
                    recorded_at=_utcnow(),
                )
            )
        return audit_id


class SqlWorkerLeaseCoordinator:
    def __init__(self, database: Database) -> None:
        self.database = database

    def claim(self, *, run_id: str, worker_identity: str, ttl_seconds: int) -> str:
        if (
            not run_id.startswith("run_")
            or not worker_identity.startswith("workload_")
            or not 5 <= ttl_seconds <= 300
        ):
            raise ServiceRepositoryError("worker_lease_claim_invalid")
        now = _utcnow()
        with self.database.session() as session:
            row = session.scalar(
                select(WorkerLeaseRow)
                .where(WorkerLeaseRow.run_id == run_id)
                .with_for_update()
            )
            if (
                row is not None
                and row.status == "active"
                and _as_utc(row.expires_at) > now
            ):
                if row.worker_identity != worker_identity:
                    raise ServiceRepositoryError("worker_lease_already_claimed")
                return row.lease_id
            lease_id = deterministic_id(
                "lease", run_id, worker_identity, now.isoformat()
            )
            if row is None:
                session.add(
                    WorkerLeaseRow(
                        lease_id=lease_id,
                        run_id=run_id,
                        worker_identity=worker_identity,
                        status="active",
                        claimed_at=now,
                        heartbeat_at=now,
                        expires_at=now + timedelta(seconds=ttl_seconds),
                        closed_at=None,
                        outcome=None,
                        revision=0,
                    )
                )
            else:
                row.lease_id = lease_id
                row.worker_identity = worker_identity
                row.status = "active"
                row.claimed_at = now
                row.heartbeat_at = now
                row.expires_at = now + timedelta(seconds=ttl_seconds)
                row.closed_at = None
                row.outcome = None
                row.revision += 1
            return lease_id

    def heartbeat(self, *, lease_id: str, worker_identity: str) -> None:
        now = _utcnow()
        with self.database.session() as session:
            row = session.scalar(
                select(WorkerLeaseRow)
                .where(WorkerLeaseRow.lease_id == lease_id)
                .with_for_update()
            )
            if (
                row is None
                or row.status != "active"
                or row.worker_identity != worker_identity
                or _as_utc(row.expires_at) <= now
            ):
                raise ServiceRepositoryError("worker_lease_heartbeat_invalid")
            row.heartbeat_at = now
            row.revision += 1

    def close(self, *, lease_id: str, worker_identity: str, outcome: str) -> None:
        if not worker_identity.startswith("workload_"):
            raise ServiceRepositoryError("worker_lease_close_invalid")
        if outcome not in {"completed", "failed", "cancelled"}:
            raise ServiceRepositoryError("worker_lease_outcome_invalid")
        with self.database.session() as session:
            row = session.scalar(
                select(WorkerLeaseRow)
                .where(WorkerLeaseRow.lease_id == lease_id)
                .with_for_update()
            )
            if (
                row is None
                or row.status != "active"
                or row.worker_identity != worker_identity
            ):
                raise ServiceRepositoryError("worker_lease_close_invalid")
            row.status = "closed"
            row.outcome = outcome
            row.closed_at = _utcnow()
            row.revision += 1

    def status(self, lease_id: str) -> dict[str, Any] | None:
        with self.database.session() as session:
            row = session.scalar(
                select(WorkerLeaseRow).where(WorkerLeaseRow.lease_id == lease_id)
            )
            if row is None:
                return None
            return {
                "lease_id": row.lease_id,
                "run_id": row.run_id,
                "worker_identity": row.worker_identity,
                "status": row.status,
                "expires_at": row.expires_at.isoformat(),
                "outcome": row.outcome,
                "revision": row.revision,
            }


def _event_document(row: QualificationEventRow) -> dict[str, Any]:
    return {
        "ledger_version": LEDGER_VERSION,
        "sequence": row.sequence,
        "record_id": row.record_id,
        "record_type": row.record_type,
        "run_id": row.run_id,
        "idempotency_key": row.idempotency_key,
        "previous_record_hash": row.previous_record_hash,
        "payload": row.payload,
        "record_hash": row.record_hash,
    }


def _service_replay_records(
    records: Sequence[Mapping[str, Any]],
) -> QualificationReplay:
    """Replay database rows without changing the digest-bound JSONL handler."""
    states = {}
    previous = GENESIS_HASH
    idempotency_keys: set[str] = set()
    expected_fields = {
        "ledger_version",
        "sequence",
        "record_id",
        "record_type",
        "run_id",
        "idempotency_key",
        "previous_record_hash",
        "payload",
        "record_hash",
    }
    allowed_record_types = {
        "run_registered",
        "stage_receipt_recorded",
        "remediation_receipt_recorded",
        "policy_decision_recorded",
        "evaluation_grant_issued",
        "evaluation_grant_consumed",
        "execution_closure_recorded",
        "human_checkpoint_resolved",
        "run_quarantined",
        "run_cancelled",
    }
    for sequence, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != expected_fields:
            raise QualificationLedgerError("qualification_record_fields_invalid")
        content = {key: value for key, value in record.items() if key != "record_hash"}
        if (
            record["ledger_version"] != LEDGER_VERSION
            or record["sequence"] != sequence
            or record["record_type"] not in allowed_record_types
            or record["previous_record_hash"] != previous
            or record["record_hash"] != canonical_digest(content)
            or record["idempotency_key"] in idempotency_keys
        ):
            raise QualificationLedgerError("qualification_ledger_chain_invalid")
        run_id = record["run_id"]
        if record["record_type"] == "run_registered":
            if run_id in states:
                raise QualificationLedgerError("qualification_run_already_registered")
            states[run_id] = _state_from_registration(run_id, record["payload"])
        else:
            state = states.get(run_id)
            if state is None:
                raise QualificationLedgerError("qualification_run_registration_missing")
            states[run_id] = _apply_event(
                state, record["record_type"], record["payload"]
            )
        previous = record["record_hash"]
        idempotency_keys.add(record["idempotency_key"])
    return QualificationReplay(len(records), previous, tuple(states.values()))


def _normalize_json(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        normalized = json.loads(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
    except (TypeError, ValueError) as error:
        raise ServiceRepositoryError("service_document_invalid") from error
    if not isinstance(normalized, dict):
        raise ServiceRepositoryError("service_document_invalid")
    return normalized


def _normalize_outbox(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalize_json(value)
    if set(normalized) != {"topic", "aggregate_ref", "payload"}:
        raise ServiceRepositoryError("outbox_event_invalid")
    if (
        not isinstance(normalized["topic"], str)
        or not normalized["topic"]
        or not isinstance(normalized["aggregate_ref"], str)
        or not normalized["aggregate_ref"]
        or not isinstance(normalized["payload"], dict)
    ):
        raise ServiceRepositoryError("outbox_event_invalid")
    return normalized


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ServiceRepositoryError("service_time_invalid")
    return parsed.astimezone(timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)

