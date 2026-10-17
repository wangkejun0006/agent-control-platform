from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.dataset_public_pilot_assurance import (
    record_dataset_public_pilot_assurance_failure,
)
from orbit_agent_control_plane.service_runtime.dataset_public_pilot_ledger import (
    record_dataset_public_pilot_closure,
)
from orbit_agent_control_plane.service_runtime.models import (
    AuditEventRow,
    Base,
    ReceiptRow,
)
from orbit_agent_control_plane.service_runtime.runner_queue import canonical_digest


def _result() -> dict:
    value = {
        "status": "Dataset public-source local pilot pass",
        "task": {"status": "completed", "revision": 1},
        "grant": {"status": "consumed", "revision": 1},
        "route": {"status": "consumed", "revision": 1},
        "worker_lease": {"status": "closed", "revision": 1},
        "evaluations": {
            "domain": {"verdict": "pass", "release_authorization": False},
            "company": {"verdict": "pass", "release_authorization": False},
        },
        "cleanup": {"download_payload_files_remaining": 0},
        "lifecycle_assurance": "hold",
        "production_authorization": False,
        "release_authorization": False,
    }
    value["result_digest"] = canonical_digest(value)
    return value


class DatasetPublicPilotAssuranceTests(unittest.TestCase):
    def test_failure_audit_is_idempotent_and_preserves_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Database(
                f"sqlite+pysqlite:///{Path(temporary) / 'state.sqlite3'}"
            )
            Base.metadata.create_all(database.engine)
            receipt_digest = record_dataset_public_pilot_closure(database, _result())
            first = record_dataset_public_pilot_assurance_failure(
                database,
                receipt_digest=receipt_digest,
                reason_code="dataset_signed_execution_grant_missing",
            )
            second = record_dataset_public_pilot_assurance_failure(
                database,
                receipt_digest=receipt_digest,
                reason_code="dataset_signed_execution_grant_missing",
            )
            with database.session() as session:
                receipts = tuple(session.scalars(select(ReceiptRow)))
                audits = tuple(session.scalars(select(AuditEventRow)))
            database.dispose()
        self.assertEqual(first, second)
        self.assertEqual(1, len(receipts))
        self.assertEqual(2, len(audits))
        self.assertEqual("dataset_public_pilot_assurance_failed", audits[-1].event_type)
        self.assertFalse(audits[-1].payload["accepted_as_full_chain"])


if __name__ == "__main__":
    unittest.main()

