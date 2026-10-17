from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.dataset_public_execution import (
    fail_dataset_public_execution,
    finalize_dataset_public_execution,
    prepare_dataset_public_execution,
    recover_orphaned_dataset_public_executions,
    validate_dataset_public_execution_envelope,
)
from orbit_agent_control_plane.service_runtime.models import (
    Base,
    ReceiptRow,
    RuntimeRunRow,
    SignedGrantRow,
    WorkerLeaseRow,
)
from orbit_agent_control_plane.service_runtime.runner_queue import canonical_digest


def _digest(character: str) -> str:
    return "sha256:" + character * 64


class DatasetPublicExecutionTests(unittest.TestCase):
    def test_signed_grant_precedes_worker_and_all_terminal_state_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Database(
                f"sqlite+pysqlite:///{Path(temporary) / 'state.sqlite3'}"
            )
            Base.metadata.create_all(database.engine)
            private_key = ed25519.Ed25519PrivateKey.generate()
            private_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            public_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            now = datetime.now(timezone.utc).replace(microsecond=0)
            task_digest = _digest("1")
            grant_digest = _digest("2")
            composition_digest = _digest("3")
            runtime_digest = _digest("4")
            task = {
                "task_id": "task_dataset_public_governed_004",
                "dataset_ref": "dataset://public/physionet/sleep-edfx/1.0.0",
                "production_authorization": False,
                "release_authorization": False,
            }
            grant = {
                "grant_id": "grant_dataset_public_governed_004",
                "task_digest": task_digest,
                "production_authorization": False,
                "release_authorization": False,
            }
            composition = {
                "task_digest": task_digest,
                "grant_candidate_digest": grant_digest,
                "runtime_source_digest": runtime_digest,
                "production_authorization": False,
                "release_authorization": False,
            }
            receipt = {
                "status": "active",
                "dataset_execution_scope": "approved_single_use",
                "expires_at": (now + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
                "receipt_digest": _digest("5"),
                "production_authorization": False,
                "release_authorization": False,
            }
            envelope = prepare_dataset_public_execution(
                database=database,
                task=task,
                task_digest=task_digest,
                grant_candidate=grant,
                grant_candidate_digest=grant_digest,
                composition=composition,
                composition_digest=composition_digest,
                runtime_source_digest=runtime_digest,
                enablement_receipt=receipt,
                private_key_pem=private_pem,
                public_key_pem=public_pem,
                now=now,
            )
            invocation = validate_dataset_public_execution_envelope(
                envelope=envelope,
                public_key_pem=public_pem,
                task_digest=task_digest,
                grant_candidate_digest=grant_digest,
                composition_digest=composition_digest,
                runtime_source_digest=runtime_digest,
                now=now,
            )
            result = {
                "status": "Dataset public-source local pilot pass",
                "bindings": {
                    "task_digest": task_digest,
                    "grant_candidate_digest": grant_digest,
                    "composition_digest": composition_digest,
                    "runtime_source_digest": runtime_digest,
                },
                "task": {
                    "task_id": invocation.task_id,
                    "status": "completed",
                    "revision": 1,
                },
                "grant": {
                    "grant_id": invocation.grant_id,
                    "status": "consumed",
                    "revision": 1,
                },
                "route": {"status": "consumed", "revision": 1},
                "worker_lease": {"status": "closed", "revision": 1},
                "evaluations": {
                    "domain": {"verdict": "pass", "release_authorization": False},
                    "company": {"verdict": "pass", "release_authorization": False},
                },
                "cleanup": {"download_payload_files_remaining": 0},
                "production_authorization": False,
                "release_authorization": False,
            }
            result["result_digest"] = canonical_digest(result)
            first = finalize_dataset_public_execution(
                database=database,
                envelope=envelope,
                result=result,
                public_key_pem=public_pem,
                now=now + timedelta(seconds=1),
            )
            second = finalize_dataset_public_execution(
                database=database,
                envelope=envelope,
                result=result,
                public_key_pem=public_pem,
                now=now + timedelta(seconds=1),
            )
            with database.session() as session:
                grant_row = session.scalar(select(SignedGrantRow))
                lease_row = session.scalar(select(WorkerLeaseRow))
                run_row = session.scalar(select(RuntimeRunRow))
                receipts = tuple(session.scalars(select(ReceiptRow)))
            database.dispose()
        self.assertEqual(first, second)
        self.assertEqual("consumed", grant_row.status)
        self.assertEqual("closed", lease_row.status)
        self.assertEqual("completed", lease_row.outcome)
        self.assertEqual("completed", run_row.status)
        self.assertEqual(1, len(receipts))
        self.assertFalse(receipts[0].document["release_authorization"])

    def test_expired_grant_still_closes_failed_terminal_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Database(
                f"sqlite+pysqlite:///{Path(temporary) / 'state.sqlite3'}"
            )
            Base.metadata.create_all(database.engine)
            private_key = ed25519.Ed25519PrivateKey.generate()
            private_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            public_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            now = datetime.now(timezone.utc).replace(microsecond=0)
            task_digest = _digest("6")
            grant_digest = _digest("7")
            composition_digest = _digest("8")
            runtime_digest = _digest("9")
            envelope = prepare_dataset_public_execution(
                database=database,
                task={
                    "task_id": "task_dataset_public_governed_timeout",
                    "dataset_ref": "dataset://public/physionet/sleep-edfx/1.0.0",
                    "production_authorization": False,
                    "release_authorization": False,
                },
                task_digest=task_digest,
                grant_candidate={
                    "grant_id": "grant_dataset_public_governed_timeout",
                    "task_digest": task_digest,
                    "production_authorization": False,
                    "release_authorization": False,
                },
                grant_candidate_digest=grant_digest,
                composition={
                    "task_digest": task_digest,
                    "grant_candidate_digest": grant_digest,
                    "runtime_source_digest": runtime_digest,
                    "production_authorization": False,
                    "release_authorization": False,
                },
                composition_digest=composition_digest,
                runtime_source_digest=runtime_digest,
                enablement_receipt={
                    "status": "active",
                    "dataset_execution_scope": "approved_single_use",
                    "expires_at": (now + timedelta(minutes=2))
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "receipt_digest": _digest("a"),
                    "production_authorization": False,
                    "release_authorization": False,
                },
                private_key_pem=private_pem,
                public_key_pem=public_pem,
                now=now,
            )
            receipt_digest = fail_dataset_public_execution(
                database=database,
                envelope=envelope,
                reason_code="dataset_execution_timeout",
                public_key_pem=public_pem,
                now=now + timedelta(minutes=3),
            )
            with database.session() as session:
                grant_row = session.scalar(select(SignedGrantRow))
                lease_row = session.scalar(select(WorkerLeaseRow))
                run_row = session.scalar(select(RuntimeRunRow))
                receipt_row = session.scalar(select(ReceiptRow))
            database.dispose()
        self.assertEqual(receipt_digest, receipt_row.receipt_digest)
        self.assertEqual("consumed", grant_row.status)
        self.assertEqual("closed", lease_row.status)
        self.assertEqual("failed", lease_row.outcome)
        self.assertEqual("failed", run_row.status)

    def test_orphan_recovery_reconstructs_signed_envelope_and_closes(self) -> None:
        database = Database("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(database.engine)
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        now = datetime.now(timezone.utc).replace(microsecond=0)
        task_digest = _digest("b")
        grant_digest = _digest("c")
        composition_digest = _digest("d")
        runtime_digest = _digest("e")
        receipt_digest = _digest("f")
        envelope = prepare_dataset_public_execution(
            database=database,
            task={
                "task_id": "task_orbit_dataset_public_orphan_006",
                "dataset_ref": "dataset://public/physionet/sleep-edfx/1.0.0",
                "production_authorization": False,
                "release_authorization": False,
            },
            task_digest=task_digest,
            grant_candidate={
                "grant_id": "grant_orbit_dataset_public_orphan_006",
                "task_digest": task_digest,
                "production_authorization": False,
                "release_authorization": False,
            },
            grant_candidate_digest=grant_digest,
            composition={
                "task_digest": task_digest,
                "grant_candidate_digest": grant_digest,
                "runtime_source_digest": runtime_digest,
                "production_authorization": False,
                "release_authorization": False,
            },
            composition_digest=composition_digest,
            runtime_source_digest=runtime_digest,
            enablement_receipt={
                "status": "active",
                "dataset_execution_scope": "approved_single_use",
                "expires_at": (now + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
                "receipt_digest": receipt_digest,
                "production_authorization": False,
                "release_authorization": False,
            },
            private_key_pem=private_pem,
            public_key_pem=public_pem,
            now=now,
        )
        self.assertEqual(receipt_digest, envelope["enablement_receipt_digest"])
        closed = recover_orphaned_dataset_public_executions(
            database=database,
            public_key_pem=public_pem,
            enablement_receipt_digest=receipt_digest,
            now=now + timedelta(seconds=1),
        )
        duplicate = recover_orphaned_dataset_public_executions(
            database=database,
            public_key_pem=public_pem,
            enablement_receipt_digest=receipt_digest,
            now=now + timedelta(seconds=2),
        )
        with database.session() as session:
            grant_row = session.scalar(select(SignedGrantRow))
            lease_row = session.scalar(select(WorkerLeaseRow))
            run_row = session.scalar(select(RuntimeRunRow))
        database.dispose()
        self.assertEqual(1, len(closed))
        self.assertEqual((), duplicate)
        self.assertEqual("consumed", grant_row.status)
        self.assertEqual("closed", lease_row.status)
        self.assertEqual("failed", run_row.status)


if __name__ == "__main__":
    unittest.main()

