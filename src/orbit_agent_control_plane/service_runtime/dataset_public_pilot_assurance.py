"""Append fail-closed assurance evidence without mutating Dataset receipts."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from ..ids import deterministic_id
from .database import Database
from .models import AuditEventRow, OutboxEventRow, ReceiptRow
from .runner_queue import canonical_digest


class DatasetPublicPilotAssuranceError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def record_dataset_public_pilot_assurance_failure(
    database: Database, *, receipt_digest: str, reason_code: str
) -> str:
    """Append an idempotent Audit/Outbox pair after an assurance failure."""
    if not reason_code.startswith("dataset_"):
        raise DatasetPublicPilotAssuranceError(
            "dataset_public_assurance_reason_invalid"
        )
    payload = {
        "receipt_digest": receipt_digest,
        "reason_code": reason_code,
        "accepted_as_full_chain": False,
        "requires_signed_execution_grant": True,
        "release_authorization": False,
    }
    evidence_digest = canonical_digest(payload)
    audit_id = deterministic_id("audit", "dataset_public_assurance_failed", receipt_digest)
    event_id = deterministic_id("outbox", "dataset_public_assurance_failed", receipt_digest)
    now = datetime.now(timezone.utc)
    with database.session() as session:
        receipt = session.scalar(
            select(ReceiptRow).where(ReceiptRow.receipt_digest == receipt_digest)
        )
        if receipt is None:
            raise DatasetPublicPilotAssuranceError("dataset_public_closure_missing")
        existing = session.scalar(
            select(AuditEventRow).where(AuditEventRow.audit_id == audit_id)
        )
        if existing is not None:
            if existing.payload != payload:
                raise DatasetPublicPilotAssuranceError(
                    "dataset_public_assurance_conflict"
                )
            return evidence_digest
        session.add(
            AuditEventRow(
                audit_id=audit_id,
                correlation_id=receipt.receipt_id,
                event_type="dataset_public_pilot_assurance_failed",
                actor_ref="component_control_plane_lifecycle_assurance",
                payload=payload,
                recorded_at=now,
            )
        )
        session.add(
            OutboxEventRow(
                event_id=event_id,
                topic="dataset.public_pilot.assurance_failed",
                aggregate_ref=receipt.subject_ref,
                payload=payload,
                status="pending",
                attempts=0,
                created_at=now,
                published_at=None,
            )
        )
    return evidence_digest

