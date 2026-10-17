"""Additive workflow associations and immutable delivery evidence.

Native Company Tasks, approvals, runtime rows and leases remain authoritative.
This table holds the new workflow index, document index and delivery evidence.
"""

import json
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, String, select
from sqlalchemy.orm import Mapped, mapped_column

from orbit_agent_control_plane.service_runtime.models import Base
from showcase.live_budget import digest


class DeliveryRecordRow(Base):
    __tablename__ = "orbit_delivery_records"
    record_id: Mapped[str] = mapped_column(String(192), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    workflow_id: Mapped[str | None] = mapped_column(String(160), index=True)
    department_id: Mapped[str | None] = mapped_column(String(96), index=True)
    document: Mapped[dict] = mapped_column(JSON)
    document_digest: Mapped[str] = mapped_column(String(71))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def copy(value):
    return json.loads(json.dumps(value, ensure_ascii=False))


class DeliveryStore:
    def __init__(self, database):
        self.database = database

    def get(self, key):
        with self.database.session() as session:
            row = session.get(DeliveryRecordRow, key)
            if row is None:
                return None
            if digest(row.document) != row.document_digest:
                raise ValueError("delivery_record_digest_mismatch")
            return copy(row.document)

    def list(self, kind, workflow_id=None):
        with self.database.session() as session:
            statement = select(DeliveryRecordRow).where(DeliveryRecordRow.kind == kind)
            if workflow_id is not None:
                statement = statement.where(
                    DeliveryRecordRow.workflow_id == workflow_id
                )
            rows = session.scalars(
                statement.order_by(
                    DeliveryRecordRow.recorded_at, DeliveryRecordRow.record_id
                )
            ).all()
            for row in rows:
                if digest(row.document) != row.document_digest:
                    raise ValueError("delivery_record_digest_mismatch")
            documents = [copy(row.document) for row in rows]
            if kind == "event" and workflow_id is not None:
                documents.sort(key=lambda item: item["sequence"])
                previous = "genesis"
                for index, document in enumerate(documents):
                    if (
                        document["sequence"] != index
                        or document["previous_digest"] != previous
                    ):
                        raise ValueError("delivery_event_chain_invalid")
                    previous = digest(document)
            return documents

    def put(
        self,
        kind,
        key,
        document,
        *,
        workflow_id=None,
        department_id=None,
        mutable=False,
    ):
        with self.database.session() as session:
            row = session.get(DeliveryRecordRow, key)
            if row:
                if row.document_digest == digest(document):
                    return copy(row.document)
                if not mutable:
                    raise ValueError("delivery_immutable_record_conflict")
                row.document, row.document_digest = copy(document), digest(document)
            else:
                session.add(
                    DeliveryRecordRow(
                        record_id=key,
                        kind=kind,
                        workflow_id=workflow_id,
                        department_id=department_id,
                        document=copy(document),
                        document_digest=digest(document),
                        recorded_at=datetime.now(timezone.utc),
                    )
                )
        return copy(document)
