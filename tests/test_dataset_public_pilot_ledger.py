from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.dataset_public_pilot_ledger import (
    record_dataset_public_pilot_closure,
)
from orbit_agent_control_plane.service_runtime.models import (
    Base,
    OutboxEventRow,
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
        "cleanup": {
            "download_payload_files_remaining": 0,
            "external_handles_closed": True,
        },
        "lifecycle_assurance": "hold",
        "production_authorization": False,
        "release_authorization": False,
    }
    value["result_digest"] = canonical_digest(value)
    return value


class DatasetPublicPilotLedgerTests(unittest.TestCase):
    def test_closure_receipt_audit_and_outbox_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Database(
                f"sqlite+pysqlite:///{Path(temporary) / 'state.sqlite3'}"
            )
            Base.metadata.create_all(database.engine)
            first = record_dataset_public_pilot_closure(database, _result())
            second = record_dataset_public_pilot_closure(database, _result())
            self.assertEqual(first, second)
            with database.session() as session:
                receipts = tuple(session.scalars(select(ReceiptRow)))
                outbox = tuple(session.scalars(select(OutboxEventRow)))
            database.dispose()
        self.assertEqual(1, len(receipts))
        self.assertEqual(1, len(outbox))
        self.assertEqual("pending", outbox[0].status)
        self.assertFalse(receipts[0].document["release_authorization"])


if __name__ == "__main__":
    unittest.main()

