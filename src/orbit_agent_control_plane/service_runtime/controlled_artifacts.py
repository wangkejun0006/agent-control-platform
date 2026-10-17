"""Opaque, department-scoped document intake for the cockpit BFF."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from ..ids import deterministic_id
from .database import Database
from .models import AuditEventRow, ControlledArtifactRow


class ControlledArtifactError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


_MAX_BYTES = 5 * 1024 * 1024
_ALLOWED_MEDIA_TYPES = frozenset(
    {
        "text/plain",
        "text/markdown",
        "text/csv",
        "application/json",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
)
_ALLOWED_CLASSIFICATIONS = frozenset({"public", "internal_standard"})


class ControlledArtifactStore:
    def __init__(self, database: Database) -> None:
        self.database = database

    def upload(
        self,
        *,
        department_id: str,
        filename: str,
        media_type: str,
        content: bytes,
        data_classification: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        _validate_department(department_id)
        clean_filename = _filename(filename)
        normalized_media_type = media_type.split(";", 1)[0].strip().lower()
        if normalized_media_type not in _ALLOWED_MEDIA_TYPES:
            raise ControlledArtifactError("artifact_media_type_not_allowed")
        if data_classification not in _ALLOWED_CLASSIFICATIONS:
            raise ControlledArtifactError("artifact_data_classification_not_allowed")
        if not isinstance(content, bytes) or not content or len(content) > _MAX_BYTES:
            raise ControlledArtifactError("artifact_size_invalid")
        if not isinstance(actor_ref, str) or not actor_ref:
            raise ControlledArtifactError("artifact_actor_invalid")
        content_digest = "sha256:" + hashlib.sha256(content).hexdigest()
        artifact_id = deterministic_id(
            "artifact",
            department_id,
            clean_filename,
            normalized_media_type,
            content_digest,
        )
        artifact_ref = (
            f"artifact://department-cockpit/{department_id}/{artifact_id}"
        )
        recorded_at = datetime.now(timezone.utc)
        with self.database.session() as session:
            existing = session.scalar(
                select(ControlledArtifactRow).where(
                    ControlledArtifactRow.artifact_ref == artifact_ref
                )
            )
            if existing is not None:
                if (
                    existing.department_id != department_id
                    or existing.filename != clean_filename
                    or existing.media_type != normalized_media_type
                    or existing.content_digest != content_digest
                    or existing.content != content
                    or existing.data_classification != data_classification
                ):
                    raise ControlledArtifactError("artifact_idempotency_conflict")
                return {"appended": False, **_metadata(existing)}
            row = ControlledArtifactRow(
                artifact_ref=artifact_ref,
                department_id=department_id,
                filename=clean_filename,
                media_type=normalized_media_type,
                byte_size=len(content),
                content_digest=content_digest,
                data_classification=data_classification,
                scan_status="stored_unscanned",
                content=content,
                uploaded_by_ref=actor_ref,
                recorded_at=recorded_at,
            )
            session.add(row)
            session.add(
                AuditEventRow(
                    audit_id=deterministic_id(
                        "audit", "controlled_artifact_uploaded", artifact_ref
                    ),
                    correlation_id=artifact_id,
                    event_type="controlled_artifact_uploaded",
                    actor_ref=actor_ref,
                    payload={
                        "artifact_ref": artifact_ref,
                        "department_id": department_id,
                        "media_type": normalized_media_type,
                        "byte_size": len(content),
                        "content_digest": content_digest,
                        "data_classification": data_classification,
                        "scan_status": "stored_unscanned",
                        "runtime_projection_authoritative": False,
                        "release_authorization": False,
                    },
                    recorded_at=recorded_at,
                )
            )
            session.flush()
            return {"appended": True, **_metadata(row)}

    def require_department_refs(
        self, *, department_id: str, artifact_refs: tuple[str, ...]
    ) -> tuple[dict[str, Any], ...]:
        _validate_department(department_id)
        if not artifact_refs:
            return ()
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(ControlledArtifactRow).where(
                        ControlledArtifactRow.artifact_ref.in_(artifact_refs)
                    )
                )
            )
        by_ref = {row.artifact_ref: row for row in rows}
        result = []
        for artifact_ref in artifact_refs:
            row = by_ref.get(artifact_ref)
            if row is None:
                raise ControlledArtifactError("controlled_artifact_not_found")
            if row.department_id != department_id:
                raise ControlledArtifactError("controlled_artifact_scope_mismatch")
            result.append(_metadata(row))
        return tuple(result)

    def metadata(self, *, department_id: str, artifact_ref: str) -> dict[str, Any]:
        values = self.require_department_refs(
            department_id=department_id, artifact_refs=(artifact_ref,)
        )
        return values[0]


def _metadata(row: ControlledArtifactRow) -> dict[str, Any]:
    return {
        "artifact_ref": row.artifact_ref,
        "department_id": row.department_id,
        "filename": row.filename,
        "media_type": row.media_type,
        "byte_size": row.byte_size,
        "content_digest": row.content_digest,
        "data_classification": row.data_classification,
        "scan_status": row.scan_status,
        "uploaded_by_ref": row.uploaded_by_ref,
        "recorded_at": row.recorded_at.isoformat(),
        "content_exposed": False,
        "runtime_projection_authoritative": False,
        "release_authorization": False,
    }


def _filename(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 180
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ControlledArtifactError("artifact_filename_invalid")
    return value.strip()


def _validate_department(value: str) -> None:
    if value not in {"product_center", "technology_center", "market_center"}:
        raise ControlledArtifactError("artifact_department_invalid")

