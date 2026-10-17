"""Signed-Grant control boundary for the external Dataset public worker."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from ..ids import deterministic_id
from .database import Database
from .models import (
    AuditEventRow,
    OutboxEventRow,
    ReceiptRow,
    RuntimeRunRow,
    SignedGrantRow,
    WorkerLeaseRow,
)
from .repositories import (
    SqlAuditExporter,
    SqlGrantRevocationRegistry,
    SqlWorkerLeaseCoordinator,
)
from .runner_queue import (
    SqlRunnerTransport,
    SqlSignedGrantRegistry,
    _append_event,
    _validate_runner_result,
    build_signed_grant_document,
    canonical_bytes,
    canonical_digest,
)
from .runtime_adapter import RuntimeInvocation
from .security import (
    Ed25519EvaluationGrantSigner,
    Ed25519EvaluationGrantVerifier,
)

SIGNING_KEY_ID = "local_pilot_grant_signer"
WORKER_IDENTITY = "workload_dataset_public_acquisition_runner"
OPERATION = "run_dataset_public_metadata"


class DatasetPublicExecutionError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def prepare_dataset_public_execution(
    *,
    database: Database,
    task: Mapping[str, Any],
    task_digest: str,
    grant_candidate: Mapping[str, Any],
    grant_candidate_digest: str,
    composition: Mapping[str, Any],
    composition_digest: str,
    runtime_source_digest: str,
    enablement_receipt: Mapping[str, Any],
    private_key_pem: bytes,
    public_key_pem: bytes,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Create and claim one real, short-lived, signed Dataset ExecutionGrant."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(
        microsecond=0
    )
    receipt_expiry = _time(enablement_receipt.get("expires_at"))
    if (
        enablement_receipt.get("status") != "active"
        or enablement_receipt.get("dataset_execution_scope")
        != "approved_single_use"
        or enablement_receipt.get("production_authorization") is not False
        or enablement_receipt.get("release_authorization") is not False
        or receipt_expiry <= current
    ):
        raise DatasetPublicExecutionError("dataset_execution_enablement_invalid")
    _validate_candidate_graph(
        task=task,
        task_digest=task_digest,
        grant_candidate=grant_candidate,
        grant_candidate_digest=grant_candidate_digest,
        composition=composition,
        composition_digest=composition_digest,
        runtime_source_digest=runtime_source_digest,
    )
    expires = min(current + timedelta(seconds=900), receipt_expiry)
    if (expires - current).total_seconds() < 30:
        raise DatasetPublicExecutionError("dataset_execution_enablement_expiring")
    invocation = RuntimeInvocation.from_mapping(
        {
            "task_id": task["task_id"],
            "task_digest": task_digest,
            "grant_id": grant_candidate["grant_id"],
            "grant_digest": grant_candidate_digest,
            "composition_digest": composition_digest,
            "runtime_source_digest": runtime_source_digest,
            "workload_identity": WORKER_IDENTITY,
            "operation": OPERATION,
            "input_refs": [task["dataset_ref"]],
            "idempotency_key": f"dataset-public:{task['task_id']}:{composition_digest}",
            "expires_at": _time_text(expires),
            "timeout_seconds": min(300, int((expires - current).total_seconds())),
            "data_classification": "public",
            "synthetic_only": False,
            "production_authorization": False,
        }
    )
    signer = Ed25519EvaluationGrantSigner(
        private_key_pem=private_key_pem, key_id=SIGNING_KEY_ID
    )
    if signer.public_key_pem() != public_key_pem:
        raise DatasetPublicExecutionError("dataset_execution_grant_key_mismatch")
    verifier = Ed25519EvaluationGrantVerifier(
        public_key_pem=public_key_pem, key_id=SIGNING_KEY_ID
    )
    grants = SqlSignedGrantRegistry(
        database,
        verifier=verifier,
        revocations=SqlGrantRevocationRegistry(database),
    )
    document = build_signed_grant_document(
        invocation=invocation,
        evidence_status="public",
        issued_at=_time_text(current),
    )
    signature = signer.sign_grant(
        canonical_grant=canonical_bytes(document), key_id=SIGNING_KEY_ID
    )
    grants.register(document=document, key_id=SIGNING_KEY_ID, signature=signature)
    grants.authorize(invocation)
    run_id = SqlRunnerTransport(database, grants=grants).start(invocation=invocation)
    with database.session() as session:
        row = session.scalar(
            select(RuntimeRunRow)
            .where(RuntimeRunRow.run_id == run_id)
            .with_for_update()
        )
        if row is None or row.status not in {"queued", "running"}:
            raise DatasetPublicExecutionError("dataset_execution_runtime_invalid")
        if row.status == "queued":
            row.status = "running"
            row.worker_identity = WORKER_IDENTITY
            row.started_at = current
            row.revision += 1
            _append_event(
                session,
                run_id=run_id,
                event_type="runtime_claimed",
                payload={"worker_identity": WORKER_IDENTITY},
                recorded_at=current,
            )
    lease_id = SqlWorkerLeaseCoordinator(database).claim(
        run_id=run_id,
        worker_identity=WORKER_IDENTITY,
        ttl_seconds=invocation.timeout_seconds,
    )
    SqlAuditExporter(database).record(
        correlation_id=run_id,
        event_type="dataset_public_runtime_started",
        actor_ref=WORKER_IDENTITY,
        payload={
            "grant_digest": invocation.grant_digest,
            "composition_digest": invocation.composition_digest,
            "runtime_source_digest": invocation.runtime_source_digest,
            "release_authorization": False,
        },
    )
    envelope = {
        "envelope_version": "orbit.dataset-public-signed-execution/1",
        "run_id": run_id,
        "lease_id": lease_id,
        "invocation": invocation.to_mapping(),
        "signed_grant": {
            "key_id": SIGNING_KEY_ID,
            "signature": signature,
            "document": document,
        },
        "enablement_receipt_digest": enablement_receipt["receipt_digest"],
        "production_authorization": False,
        "release_authorization": False,
    }
    envelope["envelope_digest"] = canonical_digest(envelope)
    return envelope


def validate_dataset_public_execution_envelope(
    *,
    envelope: Mapping[str, Any],
    public_key_pem: bytes,
    task_digest: str,
    grant_candidate_digest: str,
    composition_digest: str,
    runtime_source_digest: str,
    now: datetime | None = None,
    require_current: bool = True,
) -> RuntimeInvocation:
    """Enforce the signed Grant at the Acquisition Worker adapter boundary."""
    content = {key: value for key, value in envelope.items() if key != "envelope_digest"}
    if (
        envelope.get("envelope_version") != "orbit.dataset-public-signed-execution/1"
        or envelope.get("envelope_digest") != canonical_digest(content)
        or envelope.get("production_authorization") is not False
        or envelope.get("release_authorization") is not False
    ):
        raise DatasetPublicExecutionError("dataset_execution_envelope_invalid")
    signed = envelope.get("signed_grant")
    if not isinstance(signed, Mapping):
        raise DatasetPublicExecutionError("dataset_execution_envelope_invalid")
    verifier = Ed25519EvaluationGrantVerifier(
        public_key_pem=public_key_pem, key_id=SIGNING_KEY_ID
    )
    document = verifier.verify_grant(
        canonical_grant=canonical_bytes(signed.get("document")),
        key_id=str(signed.get("key_id")),
        signature=str(signed.get("signature")),
    )
    invocation = RuntimeInvocation.from_mapping(envelope.get("invocation"))
    spec = document["spec"]
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if (
        (require_current and _time(invocation.expires_at) <= current)
        or invocation.operation != OPERATION
        or invocation.workload_identity != WORKER_IDENTITY
        or invocation.task_digest != task_digest
        or invocation.grant_digest != grant_candidate_digest
        or invocation.composition_digest != composition_digest
        or invocation.runtime_source_digest != runtime_source_digest
        or spec.get("invocation_digest") != canonical_digest(invocation.to_mapping())
        or spec.get("task_digest") != task_digest
        or spec.get("qualification_grant_digest") != grant_candidate_digest
        or spec.get("composition_digest") != composition_digest
        or spec.get("runtime_source_digest") != runtime_source_digest
    ):
        raise DatasetPublicExecutionError("dataset_execution_grant_binding_invalid")
    return invocation


def finalize_dataset_public_execution(
    *,
    database: Database,
    envelope: Mapping[str, Any],
    result: Mapping[str, Any],
    public_key_pem: bytes,
    now: datetime | None = None,
) -> str:
    """Atomically close Runtime, Grant, Lease, Receipt, Audit and Outbox."""
    invocation = validate_dataset_public_execution_envelope(
        envelope=envelope,
        public_key_pem=public_key_pem,
        task_digest=str(envelope["invocation"]["task_digest"]),
        grant_candidate_digest=str(envelope["invocation"]["grant_digest"]),
        composition_digest=str(envelope["invocation"]["composition_digest"]),
        runtime_source_digest=str(envelope["invocation"]["runtime_source_digest"]),
        now=now,
    )
    result_content = dict(result)
    claimed_result_digest = result_content.pop("result_digest", None)
    _validate_runner_result(result_content)
    if (
        claimed_result_digest != canonical_digest(result_content)
        or result.get("status") != "Dataset public-source local pilot pass"
        or result.get("bindings", {}).get("task_digest") != invocation.task_digest
        or result.get("bindings", {}).get("grant_candidate_digest")
        != invocation.grant_digest
        or result.get("bindings", {}).get("composition_digest")
        != invocation.composition_digest
        or result.get("bindings", {}).get("runtime_source_digest")
        != invocation.runtime_source_digest
        or result.get("task", {}).get("task_id") != invocation.task_id
        or result.get("grant", {}).get("grant_id") != invocation.grant_id
    ):
        raise DatasetPublicExecutionError("dataset_execution_result_binding_invalid")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    result_digest = str(claimed_result_digest)
    receipt = {
        "receipt_version": "orbit.dataset-governed-public-pilot-closure/1",
        "run_id": envelope["run_id"],
        "task": result["task"],
        "grant": result["grant"],
        "route": result["route"],
        "worker_lease": result["worker_lease"],
        "result_digest": result_digest,
        "evaluations": result["evaluations"],
        "cleanup": result["cleanup"],
        "lifecycle_assurance": "hold",
        "production_authorization": False,
        "release_authorization": False,
    }
    receipt_digest = canonical_digest(receipt)
    receipt_id = deterministic_id("receipt", envelope["run_id"], "dataset_closure")
    with database.session() as session:
        run = session.scalar(
            select(RuntimeRunRow)
            .where(RuntimeRunRow.run_id == envelope["run_id"])
            .with_for_update()
        )
        grant = session.scalar(
            select(SignedGrantRow)
            .where(SignedGrantRow.grant_id == invocation.grant_id)
            .with_for_update()
        )
        lease = session.scalar(
            select(WorkerLeaseRow)
            .where(WorkerLeaseRow.lease_id == envelope["lease_id"])
            .with_for_update()
        )
        if run is None or grant is None or lease is None:
            raise DatasetPublicExecutionError("dataset_execution_state_missing")
        existing = session.scalar(
            select(ReceiptRow).where(ReceiptRow.receipt_id == receipt_id)
        )
        if existing is not None:
            if existing.receipt_digest != receipt_digest:
                raise DatasetPublicExecutionError("dataset_execution_closure_conflict")
            return receipt_digest
        if (
            run.status != "running"
            or grant.status != "active"
            or lease.status != "active"
            or lease.run_id != run.run_id
            or run.grant_digest != invocation.grant_digest
        ):
            raise DatasetPublicExecutionError("dataset_execution_state_invalid")
        run.status = "completed"
        run.result_document = dict(result)
        run.result_digest = result_digest
        run.closed_at = current
        run.revision += 1
        grant.status = "consumed"
        grant.consumed_at = current
        grant.revision += 1
        lease.status = "closed"
        lease.outcome = "completed"
        lease.closed_at = current
        lease.revision += 1
        _append_event(
            session,
            run_id=run.run_id,
            event_type="runtime_completed",
            payload={"result_digest": result_digest, "reason_code": None},
            recorded_at=current,
        )
        session.add(
            ReceiptRow(
                receipt_id=receipt_id,
                receipt_type=receipt["receipt_version"],
                receipt_digest=receipt_digest,
                subject_ref=f"task://{invocation.task_id}",
                document=receipt,
                recorded_at=current,
            )
        )
        audit_payload = {
            "receipt_digest": receipt_digest,
            "result_digest": result_digest,
            "release_authorization": False,
        }
        session.add(
            AuditEventRow(
                audit_id=deterministic_id("audit", receipt_id),
                correlation_id=run.run_id,
                event_type="dataset_governed_public_pilot_closed",
                actor_ref=WORKER_IDENTITY,
                payload=audit_payload,
                recorded_at=current,
            )
        )
        session.add(
            OutboxEventRow(
                event_id=deterministic_id("outbox", receipt_id),
                topic="dataset.governed_public_pilot.closed",
                aggregate_ref=f"task://{invocation.task_id}",
                payload=audit_payload,
                status="pending",
                attempts=0,
                created_at=current,
                published_at=None,
            )
        )
    return receipt_digest


def fail_dataset_public_execution(
    *,
    database: Database,
    envelope: Mapping[str, Any],
    reason_code: str,
    public_key_pem: bytes,
    now: datetime | None = None,
) -> str:
    """Fail closed and consume the single-use Grant after worker failure."""
    if not reason_code.startswith("dataset_"):
        raise DatasetPublicExecutionError("dataset_execution_failure_reason_invalid")
    invocation = validate_dataset_public_execution_envelope(
        envelope=envelope,
        public_key_pem=public_key_pem,
        task_digest=str(envelope["invocation"]["task_digest"]),
        grant_candidate_digest=str(envelope["invocation"]["grant_digest"]),
        composition_digest=str(envelope["invocation"]["composition_digest"]),
        runtime_source_digest=str(envelope["invocation"]["runtime_source_digest"]),
        now=now,
        require_current=False,
    )
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    receipt = {
        "receipt_version": "orbit.dataset-governed-public-pilot-closure/1",
        "run_id": envelope["run_id"],
        "status": "failed",
        "reason_code": reason_code,
        "task": {"task_id": invocation.task_id, "status": "failed", "revision": 1},
        "grant": {
            "grant_id": invocation.grant_id,
            "status": "consumed",
            "revision": 1,
        },
        "worker_lease": {"status": "closed", "outcome": "failed", "revision": 1},
        "lifecycle_assurance": "hold",
        "production_authorization": False,
        "release_authorization": False,
    }
    receipt_digest = canonical_digest(receipt)
    receipt_id = deterministic_id("receipt", envelope["run_id"], "dataset_closure")
    with database.session() as session:
        run = session.scalar(
            select(RuntimeRunRow)
            .where(RuntimeRunRow.run_id == envelope["run_id"])
            .with_for_update()
        )
        grant = session.scalar(
            select(SignedGrantRow)
            .where(SignedGrantRow.grant_id == invocation.grant_id)
            .with_for_update()
        )
        lease = session.scalar(
            select(WorkerLeaseRow)
            .where(WorkerLeaseRow.lease_id == envelope["lease_id"])
            .with_for_update()
        )
        if run is None or grant is None or lease is None:
            raise DatasetPublicExecutionError("dataset_execution_state_missing")
        existing = session.scalar(
            select(ReceiptRow).where(ReceiptRow.receipt_id == receipt_id)
        )
        if existing is not None:
            if existing.receipt_digest != receipt_digest:
                raise DatasetPublicExecutionError("dataset_execution_closure_conflict")
            return receipt_digest
        if run.status != "running" or grant.status != "active" or lease.status != "active":
            raise DatasetPublicExecutionError("dataset_execution_state_invalid")
        run.status = "failed"
        run.failure_reason_code = reason_code
        run.closed_at = current
        run.revision += 1
        grant.status = "consumed"
        grant.consumed_at = current
        grant.revision += 1
        lease.status = "closed"
        lease.outcome = "failed"
        lease.closed_at = current
        lease.revision += 1
        _append_event(
            session,
            run_id=run.run_id,
            event_type="runtime_failed",
            payload={"result_digest": None, "reason_code": reason_code},
            recorded_at=current,
        )
        session.add(
            ReceiptRow(
                receipt_id=receipt_id,
                receipt_type=receipt["receipt_version"],
                receipt_digest=receipt_digest,
                subject_ref=f"task://{invocation.task_id}",
                document=receipt,
                recorded_at=current,
            )
        )
        payload = {
            "receipt_digest": receipt_digest,
            "reason_code": reason_code,
            "release_authorization": False,
        }
        session.add(
            AuditEventRow(
                audit_id=deterministic_id("audit", receipt_id),
                correlation_id=run.run_id,
                event_type="dataset_governed_public_pilot_failed",
                actor_ref=WORKER_IDENTITY,
                payload=payload,
                recorded_at=current,
            )
        )
        session.add(
            OutboxEventRow(
                event_id=deterministic_id("outbox", receipt_id),
                topic="dataset.governed_public_pilot.failed",
                aggregate_ref=f"task://{invocation.task_id}",
                payload=payload,
                status="pending",
                attempts=0,
                created_at=current,
                published_at=None,
            )
        )
    return receipt_digest


def recover_orphaned_dataset_public_executions(
    *,
    database: Database,
    public_key_pem: bytes,
    enablement_receipt_digest: str,
    reason_code: str = "dataset_control_wrapper_failed_closed",
    now: datetime | None = None,
) -> tuple[dict[str, str], ...]:
    """Close Dataset runs whose signed state exists but host Envelope was lost.

    Recovery reconstructs only the already-signed immutable Envelope from
    authoritative rows.  It creates no Task or Grant and cannot touch another
    operation or workload identity.
    """
    if not _digest(enablement_receipt_digest):
        raise DatasetPublicExecutionError("dataset_execution_enablement_invalid")
    with database.session() as session:
        rows = tuple(
            session.scalars(
                select(RuntimeRunRow).where(RuntimeRunRow.status == "running")
            )
        )
        candidates: list[tuple[RuntimeRunRow, SignedGrantRow, WorkerLeaseRow]] = []
        for run in rows:
            if (
                run.invocation.get("operation") != OPERATION
                or run.invocation.get("workload_identity") != WORKER_IDENTITY
                or not str(run.task_id).startswith("task_orbit_dataset_public_")
            ):
                continue
            grant = session.scalar(
                select(SignedGrantRow).where(
                    SignedGrantRow.grant_id == run.grant_id,
                    SignedGrantRow.status == "active",
                )
            )
            lease = session.scalar(
                select(WorkerLeaseRow).where(
                    WorkerLeaseRow.run_id == run.run_id,
                    WorkerLeaseRow.status == "active",
                )
            )
            if grant is not None and lease is not None:
                candidates.append((run, grant, lease))
    closed: list[dict[str, str]] = []
    for run, grant, lease in candidates:
        envelope = {
            "envelope_version": "orbit.dataset-public-signed-execution/1",
            "run_id": run.run_id,
            "lease_id": lease.lease_id,
            "invocation": dict(run.invocation),
            "signed_grant": {
                "key_id": grant.key_id,
                "signature": grant.signature,
                "document": dict(grant.document),
            },
            "enablement_receipt_digest": enablement_receipt_digest,
            "production_authorization": False,
            "release_authorization": False,
        }
        envelope["envelope_digest"] = canonical_digest(envelope)
        receipt_digest = fail_dataset_public_execution(
            database=database,
            envelope=envelope,
            reason_code=reason_code,
            public_key_pem=public_key_pem,
            now=now,
        )
        closed.append(
            {
                "run_id": run.run_id,
                "grant_id": grant.grant_id,
                "lease_id": lease.lease_id,
                "receipt_digest": receipt_digest,
            }
        )
    return tuple(closed)


def _validate_candidate_graph(
    *,
    task: Mapping[str, Any],
    task_digest: str,
    grant_candidate: Mapping[str, Any],
    grant_candidate_digest: str,
    composition: Mapping[str, Any],
    composition_digest: str,
    runtime_source_digest: str,
) -> None:
    if (
        not task.get("task_id", "").startswith("task_")
        or not grant_candidate.get("grant_id", "").startswith("grant_")
        or grant_candidate.get("task_digest") != task_digest
        or composition.get("task_digest") != task_digest
        or composition.get("grant_candidate_digest") != grant_candidate_digest
        or composition.get("runtime_source_digest") != runtime_source_digest
        or any(
            item.get("production_authorization") is not False
            or item.get("release_authorization") is not False
            for item in (task, grant_candidate, composition)
        )
        or not all(_digest(value) for value in (task_digest, grant_candidate_digest, composition_digest, runtime_source_digest))
    ):
        raise DatasetPublicExecutionError("dataset_execution_candidate_graph_invalid")


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DatasetPublicExecutionError("dataset_execution_time_invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as error:
        raise DatasetPublicExecutionError("dataset_execution_time_invalid") from error


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

