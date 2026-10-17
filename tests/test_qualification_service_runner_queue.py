from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from orbit_agent_control_plane.qualification.automation import (
    canonical_digest,
    validate_execution_closure,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.models import Base
from orbit_agent_control_plane.service_runtime.repositories import (
    SqlAuditExporter,
    SqlGrantRevocationRegistry,
    SqlWorkerLeaseCoordinator,
)
from orbit_agent_control_plane.service_runtime.runner_queue import (
    DurableRunnerWorker,
    RunnerQueueError,
    SqlRunnerTransport,
    SqlSignedGrantRegistry,
    build_signed_grant_document,
    canonical_bytes,
)
from orbit_agent_control_plane.service_runtime.runtime_adapter import (
    FrameworkNeutralRuntimeAdapter,
    RuntimeAdapterDescriptor,
    RuntimeAdapterError,
    RuntimeInvocation,
)
from orbit_agent_control_plane.service_runtime.runtime_stage import (
    SignedRuntimeStageHandler,
)
from orbit_agent_control_plane.service_runtime.security import (
    Ed25519EvaluationGrantSigner,
    Ed25519EvaluationGrantVerifier,
)

ROOT = Path(__file__).resolve().parents[1]

DIGESTS = {
    name: "sha256:" + character * 64
    for name, character in {
        "task": "a",
        "grant": "b",
        "composition": "c",
        "runtime": "d",
        "adapter": "e",
    }.items()
}


def slow_handler(_):
    time.sleep(3)
    return {
        "artifact_ref": "artifact://disease-r2/results/slow",
        "release_authorization": False,
        "production_authorization": False,
    }


class AccountedFailure(ValueError):
    reason_code = "r2_gateway_returned_model_drift"
    failure_result: ClassVar[dict] = {
        "status": "R2 provider-backed public-corpus failed",
        "failure_reason_code": reason_code,
        "usage": {
            "model_calls": 1,
            "request_attempts": 1,
            "input_tokens": 510,
            "output_tokens": 182,
            "cost_usd": "0.008010",
            "cost_cny": "0.060075",
        },
        "provider_response_set_digest": "sha256:" + "9" * 64,
        "release_authorization": False,
        "production_authorization": False,
    }


def accounted_failure_handler(_):
    raise AccountedFailure("provider response rejected after usage")


class DurableRunnerQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        database_path = Path(self.temporary.name) / "control-plane.sqlite3"
        self.database = Database(f"sqlite+pysqlite:///{database_path}")
        Base.metadata.create_all(self.database.engine)
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.signer = Ed25519EvaluationGrantSigner(
            private_key_pem=private_pem,
            key_id="local_pilot_grant_signer",
        )
        self.revocations = SqlGrantRevocationRegistry(self.database)
        self.grants = SqlSignedGrantRegistry(
            self.database,
            verifier=Ed25519EvaluationGrantVerifier(
                public_key_pem=self.signer.public_key_pem(),
                key_id="local_pilot_grant_signer",
            ),
            revocations=self.revocations,
        )
        self.transport = SqlRunnerTransport(self.database, grants=self.grants)
        self.adapter = FrameworkNeutralRuntimeAdapter(
            descriptor=RuntimeAdapterDescriptor.from_mapping(
                {
                    "adapter_id": "runtime_adapter_public_pilot",
                    "version": "0.1.0",
                    "digest": DIGESTS["adapter"],
                    "runtime_family": "disease_r2_public_pilot",
                    "conformance_profiles": ["core_dispatch", "isolated_workload"],
                    "supported_operations": ["run_public_r2_attempt"],
                    "supports_checkpoint_restore": False,
                    "evidence_status": "public",
                    "synthetic_only": False,
                }
            ),
            transport=self.transport,
        )

    def tearDown(self) -> None:
        self.database.dispose()
        self.temporary.cleanup()

    def _invocation(
        self,
        *,
        suffix: str,
        classification: str = "public",
        synthetic_only: bool = False,
    ) -> RuntimeInvocation:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        grant_digest = "sha256:" + hashlib.sha256(suffix.encode()).hexdigest()
        return RuntimeInvocation.from_mapping(
            {
                "task_id": f"task_public_pilot_{suffix}",
                "task_digest": DIGESTS["task"],
                "grant_id": f"grant_public_pilot_{suffix}",
                "grant_digest": grant_digest,
                "composition_digest": DIGESTS["composition"],
                "runtime_source_digest": DIGESTS["runtime"],
                "workload_identity": "workload_r2_evaluation_runner",
                "operation": "run_public_r2_attempt",
                "input_refs": ["artifact://disease-r2/public-pilot/attempt-001"],
                "idempotency_key": f"public-pilot:{suffix}:attempt-001",
                "expires_at": expires_at.replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z"),
                "timeout_seconds": 300,
                "data_classification": classification,
                "synthetic_only": synthetic_only,
                "production_authorization": False,
            }
        )

    def _register_grant(self, invocation: RuntimeInvocation) -> None:
        issued_at = datetime.now(timezone.utc).replace(microsecond=0)
        document = build_signed_grant_document(
            invocation=invocation,
            evidence_status=("synthetic" if invocation.synthetic_only else "public"),
            issued_at=issued_at.isoformat().replace("+00:00", "Z"),
        )
        signature = self.signer.sign_grant(
            canonical_grant=canonical_bytes(document),
            key_id="local_pilot_grant_signer",
        )
        self.assertTrue(
            self.grants.register(
                document=document,
                key_id="local_pilot_grant_signer",
                signature=signature,
            )
        )

    def _worker(self, handler=None) -> DurableRunnerWorker:
        if handler is None:
            handler = lambda _: {
                "artifact_ref": "artifact://disease-r2/results/attempt-001",
                "model_requests": 0,
                "release_authorization": False,
                "production_authorization": False,
            }
        return DurableRunnerWorker(
            self.database,
            grants=self.grants,
            leases=SqlWorkerLeaseCoordinator(self.database),
            audit=SqlAuditExporter(self.database),
            handlers={"run_public_r2_attempt": handler},
        )

    def test_public_run_closes_grant_lease_events_result_and_audit(self) -> None:
        invocation = self._invocation(suffix="success")
        self._register_grant(invocation)
        run_id = self.adapter.start(invocation.to_mapping())
        self.assertEqual(run_id, self.adapter.start(invocation.to_mapping()))
        self.assertEqual(run_id, self._worker().run_once())
        result = self.adapter.collect_result(run_id=run_id)
        self.assertEqual("completed", result["status"])
        self.assertFalse(result["result"]["release_authorization"])
        self.assertEqual("consumed", self.grants.status(invocation.grant_id)["status"])
        event_types = [
            event["event_type"]
            for event in self.adapter.stream_events(run_id=run_id, after_sequence=-1)
        ]
        self.assertEqual(
            ["runtime_queued", "runtime_claimed", "runtime_completed"],
            event_types,
        )
        self.assertEqual("ready", self.transport.health()["status"])

    def test_signed_stage_bridge_closes_alpha2_execution_receipt(self) -> None:
        candidate = json.loads(
            (
                ROOT
                / "evidence/disease-agent-r2/2026-08-27-automation-policy-alpha2/qualification-candidate.attempt-004.synthetic.json"
            ).read_text(encoding="utf-8")
        )
        issued = datetime.now(timezone.utc).replace(microsecond=0)
        expires = issued + timedelta(minutes=5)
        evaluation_grant = {
            "grant_id": "grant_public_stage_bridge_test",
            "grant_digest": "sha256:" + "6" * 64,
            "issued_at": issued.isoformat().replace("+00:00", "Z"),
            "expires_at": expires.isoformat().replace("+00:00", "Z"),
            "policy_decision_receipt_digest": "sha256:" + "7" * 64,
        }
        handler = lambda _: {
            "artifact_ref": "artifact://disease-r2/results/provider-fixture",
            "usage": {
                "model_calls": 2,
                "request_attempts": 2,
                "input_tokens": 600,
                "output_tokens": 90,
                "cost_usd": "0.02",
                "cost_cny": "0.14",
            },
            "release_authorization": False,
            "production_authorization": False,
        }
        bridge = SignedRuntimeStageHandler(
            adapter=self.adapter,
            grants=self.grants,
            signer=self.signer,
            signing_key_id="local_pilot_grant_signer",
            operation="run_public_r2_attempt",
            drive_runner_once=self._worker(handler).run_once,
        )
        result = bridge(
            {
                "run_id": "run_public_stage_bridge_test",
                "stage": "model_literature_r2",
                "candidate": candidate,
                "evaluation_grant": evaluation_grant,
                "policy": {
                    "metadata": {
                        "evidence_status": "public",
                        "synthetic_only": False,
                    }
                },
            }
        )
        self.assertEqual("pass", result.observation.outcome)
        self.assertEqual(2, result.observation.side_effects.provider_calls)
        validate_execution_closure(result.execution_closure)
        self.assertFalse(
            result.execution_closure["spec"]["authority_boundary"][
                "release_authorization"
            ]
        )
        self.assertEqual(
            canonical_digest(handler({})),
            result.execution_closure["spec"]["result"]["digest"],
        )

    def test_queued_run_survives_transport_and_worker_restart(self) -> None:
        invocation = self._invocation(suffix="restart")
        self._register_grant(invocation)
        run_id = self.transport.start(invocation=invocation)
        restarted_transport = SqlRunnerTransport(self.database, grants=self.grants)
        restarted_worker = self._worker()
        self.assertEqual(run_id, restarted_worker.run_once())
        self.assertEqual("completed", restarted_transport.result(run_id=run_id)["status"])

    def test_cancelled_run_closes_without_calling_handler(self) -> None:
        invocation = self._invocation(suffix="cancel")
        self._register_grant(invocation)
        run_id = self.transport.start(invocation=invocation)
        self.transport.cancel(run_id=run_id, reason_code="human_cancelled")
        calls = []
        self._worker(lambda value: calls.append(value)).run_once()
        self.assertEqual([], calls)
        self.assertEqual("cancelled", self.transport.result(run_id=run_id)["status"])

    def test_revocation_and_idempotency_drift_fail_closed(self) -> None:
        invocation = self._invocation(suffix="revoked")
        self._register_grant(invocation)
        self.revocations.revoke(
            grant_id=invocation.grant_id,
            reason_code="pilot_cancelled",
            revoked_by_ref="human_local_trusted_operator",
        )
        with self.assertRaisesRegex(RunnerQueueError, "runner_signed_grant_revoked"):
            self.transport.start(invocation=invocation)

        first = self._invocation(suffix="drift")
        self._register_grant(first)
        self.transport.start(invocation=first)
        second = self._invocation(suffix="drift_second")
        changed = dict(second.to_mapping())
        changed["idempotency_key"] = first.idempotency_key
        second = RuntimeInvocation.from_mapping(changed)
        self._register_grant(second)
        with self.assertRaisesRegex(
            RuntimeAdapterError, "runtime_idempotency_conflict"
        ):
            self.transport.start(invocation=second)

    def test_secret_or_physical_path_in_result_fails_closed(self) -> None:
        invocation = self._invocation(suffix="unsafe")
        self._register_grant(invocation)
        run_id = self.transport.start(invocation=invocation)
        self._worker(
            lambda _: {
                "secret": "do-not-log",
                "release_authorization": False,
                "production_authorization": False,
            }
        ).run_once()
        result = self.transport.result(run_id=run_id)
        self.assertEqual("failed", result["status"])
        self.assertEqual("runtime_secret_or_path_forbidden", result["failure_reason_code"])

    def test_synthetic_only_adapter_rejects_public_invocation(self) -> None:
        descriptor = dict(self.adapter.describe_capabilities())
        descriptor["adapter_id"] = "runtime_adapter_synthetic_only"
        descriptor["evidence_status"] = "synthetic"
        descriptor["synthetic_only"] = True
        adapter = FrameworkNeutralRuntimeAdapter(
            descriptor=RuntimeAdapterDescriptor.from_mapping(descriptor),
            transport=self.transport,
        )
        with self.assertRaisesRegex(
            RuntimeAdapterError, "runtime_adapter_authority_invalid"
        ):
            adapter.validate(self._invocation(suffix="boundary").to_mapping())

    def test_running_cancel_terminates_child_process_and_closes(self) -> None:
        invocation = self._invocation(suffix="running_cancel")
        self._register_grant(invocation)
        run_id = self.transport.start(invocation=invocation)
        worker = self._worker(slow_handler)
        thread = threading.Thread(target=worker.run_once)
        thread.start()
        deadline = time.monotonic() + 2
        while self.transport.status(run_id)["status"] != "running":
            if time.monotonic() >= deadline:
                self.fail("worker did not claim run")
            time.sleep(0.01)
        self.transport.cancel(run_id=run_id, reason_code="human_cancelled")
        thread.join(3)
        self.assertFalse(thread.is_alive())
        result = self.transport.result(run_id=run_id)
        self.assertEqual("cancelled", result["status"])
        self.assertEqual("runtime_cancelled", result["failure_reason_code"])

    def test_cancel_between_claim_and_process_start_keeps_reason(self) -> None:
        invocation = self._invocation(suffix="cancel_claim_window")
        self._register_grant(invocation)
        run_id = self.transport.start(invocation=invocation)
        calls = []
        worker = self._worker(lambda value: calls.append(value))

        def cancel_on_first_status(claimed_run_id):
            self.assertEqual(run_id, claimed_run_id)
            self.transport.cancel(run_id=run_id, reason_code="human_cancelled")
            return "cancel_requested"

        with patch.object(worker, "_status", side_effect=cancel_on_first_status):
            self.assertEqual(run_id, worker.run_once())
        self.assertEqual([], calls)
        result = self.transport.result(run_id=run_id)
        self.assertEqual("cancelled", result["status"])
        self.assertEqual("runtime_cancelled", result["failure_reason_code"])

    def test_runtime_timeout_terminates_child_process_and_fails_closed(self) -> None:
        value = self._invocation(suffix="timeout").to_mapping()
        value["timeout_seconds"] = 1
        invocation = RuntimeInvocation.from_mapping(value)
        self._register_grant(invocation)
        run_id = self.transport.start(invocation=invocation)
        started = time.monotonic()
        self._worker(slow_handler).run_once()
        self.assertLess(time.monotonic() - started, 2.5)
        result = self.transport.result(run_id=run_id)
        self.assertEqual("failed", result["status"])
        self.assertEqual("runtime_handler_timeout", result["failure_reason_code"])

    def test_failed_handler_preserves_only_sanitized_usage_envelope(self) -> None:
        invocation = self._invocation(suffix="accounted_failure")
        self._register_grant(invocation)
        run_id = self.transport.start(invocation=invocation)
        self._worker(accounted_failure_handler).run_once()
        result = self.transport.result(run_id=run_id)
        self.assertEqual("failed", result["status"])
        self.assertEqual(
            "r2_gateway_returned_model_drift", result["failure_reason_code"]
        )
        self.assertEqual(510, result["result"]["usage"]["input_tokens"])
        self.assertEqual(182, result["result"]["usage"]["output_tokens"])
        self.assertRegex(result["result_digest"], r"^sha256:[0-9a-f]{64}$")
        visible = json.dumps(result, sort_keys=True)
        self.assertNotIn("provider response rejected", visible)


if __name__ == "__main__":
    unittest.main()

