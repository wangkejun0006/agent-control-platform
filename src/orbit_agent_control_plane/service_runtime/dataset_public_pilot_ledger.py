"""Persist the Dataset public pilot terminal receipt in Control Plane state."""

from __future__ import annotations

import argparse
import json
import os
import stat
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from .database import Database
from .models import AuditEventRow, OutboxEventRow, ReceiptRow
from .runner_queue import canonical_digest


class DatasetPublicPilotLedgerError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def record_dataset_public_pilot_closure(
    database: Database, result: Mapping[str, Any]
) -> str:
    document = dict(result)
    claimed = document.pop("result_digest", None)
    if (
        claimed != canonical_digest(document)
        or result.get("status") != "Dataset public-source local pilot pass"
        or result.get("task", {}).get("status") != "completed"
        or result.get("grant", {}).get("status") != "consumed"
        or result.get("route", {}).get("status") != "consumed"
        or result.get("worker_lease", {}).get("status") != "closed"
        or result.get("evaluations", {}).get("domain", {}).get("verdict") != "pass"
        or result.get("evaluations", {}).get("company", {}).get("verdict") != "pass"
        or result.get("lifecycle_assurance") != "hold"
        or result.get("production_authorization") is not False
        or result.get("release_authorization") is not False
    ):
        raise DatasetPublicPilotLedgerError("dataset_public_closure_invalid")
    receipt = {
        "receipt_version": "orbit.dataset-public-source-local-pilot-closure/1",
        "result_digest": claimed,
        "task": result["task"],
        "grant": result["grant"],
        "route": result["route"],
        "worker_lease": result["worker_lease"],
        "evaluations": result["evaluations"],
        "cleanup": result["cleanup"],
        "lifecycle_assurance": "hold",
        "production_authorization": False,
        "release_authorization": False,
    }
    receipt_digest = canonical_digest(receipt)
    receipt_id = "receipt_dataset_public_source_local_pilot_001"
    now = datetime.now(timezone.utc)
    with database.session() as session:
        existing = session.scalar(
            select(ReceiptRow).where(ReceiptRow.receipt_id == receipt_id)
        )
        if existing is not None:
            if existing.receipt_digest != receipt_digest or existing.document != receipt:
                raise DatasetPublicPilotLedgerError("dataset_public_closure_conflict")
            return receipt_digest
        session.add(
            ReceiptRow(
                receipt_id=receipt_id,
                receipt_type=receipt["receipt_version"],
                receipt_digest=receipt_digest,
                subject_ref="task://orbit_dataset_public_sleep_edfx_001",
                document=receipt,
                recorded_at=now,
            )
        )
        session.add(
            AuditEventRow(
                audit_id="audit_dataset_public_source_local_pilot_closed_001",
                correlation_id=receipt_id,
                event_type="dataset_public_pilot_closed",
                actor_ref="workload_dataset_public_pilot_runner",
                payload={
                    "receipt_digest": receipt_digest,
                    "result_digest": claimed,
                    "release_authorization": False,
                },
                recorded_at=now,
            )
        )
        session.add(
            OutboxEventRow(
                event_id="outbox_dataset_public_source_local_pilot_closed_001",
                topic="dataset.public_pilot.closed",
                aggregate_ref="task://orbit_dataset_public_sleep_edfx_001",
                payload={
                    "receipt_digest": receipt_digest,
                    "status": result["status"],
                    "release_authorization": False,
                },
                status="pending",
                attempts=0,
                created_at=now,
                published_at=None,
            )
        )
    return receipt_digest


def _read_owner_only(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise DatasetPublicPilotLedgerError("dataset_public_result_file_invalid")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise DatasetPublicPilotLedgerError("dataset_public_result_file_invalid")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url-file", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    database_url = args.database_url_file.read_text(encoding="utf-8").strip()
    database = Database(database_url)
    try:
        digest = record_dataset_public_pilot_closure(
            database, _read_owner_only(args.result)
        )
    finally:
        database.dispose()
    print(
        json.dumps(
            {
                "status": "recorded",
                "receipt_digest": digest,
                "release_authorization": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

