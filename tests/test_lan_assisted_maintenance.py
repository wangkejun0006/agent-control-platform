from __future__ import annotations

import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.lan_stage1 import (
    LanNodeService,
    LanStage1Error,
)
from orbit_agent_control_plane.service_runtime.lan_stage1_api import (
    create_workload_app,
)
from orbit_agent_control_plane.service_runtime.lan_stage1_models import (
    LanAssistedMaintenanceSessionRow,
)
from orbit_agent_control_plane.service_runtime.models import Base


NOW = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)
HANDLER = "orbit-maintenance-handler/wsl-logind-keepalive-v6"
ASSET = "Install-OrbitWslKeepaliveFromLan-v6.ps1"
ASSET_DIGEST = "sha256:" + hashlib.sha256(b"synthetic reviewed asset").hexdigest()


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        return self.value


def principal(
    node_id: str = "node_technology_001",
    department_id: str = "technology_center",
    fingerprint: str = "sha256:" + "a" * 64,
) -> dict[str, object]:
    return {
        "node_id": node_id,
        "department_id": department_id,
        "workload_identity": f"workload_{node_id}",
        "certificate_fingerprint": fingerprint,
        "production_authorization": False,
        "release_authorization": False,
    }


class AssistedMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = Database("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(self.database.engine)
        self.clock = Clock()
        self.nodes = LanNodeService(self.database, now=self.clock)

    def tearDown(self) -> None:
        self.database.dispose()

    def open_session(self) -> dict[str, object]:
        return self.nodes.open_assisted_maintenance_session(
            principal=principal(), node_id="node_technology_001",
            requested_handler_ids=[HANDLER], duration_seconds=1800,
            local_user_initiated=True,
            idempotency_key="maintenance-session-tech-001",
        )

    def enqueue(self) -> dict[str, object]:
        return self.nodes.enqueue_maintenance_job(
            node_id="node_technology_001", handler_id=HANDLER,
            asset_name=ASSET, asset_digest=ASSET_DIGEST,
            idempotency_key="maintenance-job-tech-001",
            actor_ref="operator_local_platform_owner",
        )

    def test_full_outbound_allowlisted_receipt_loop(self) -> None:
        session = self.open_session()
        self.assertEqual(1800, session["duration_seconds"])
        self.assertEqual(1800, session["remaining_seconds"])
        self.assertFalse(session["runtime_started"])
        job = self.enqueue()
        self.assertNotIn("command", job)
        self.assertNotIn("args", job)
        claimed = self.nodes.claim_maintenance_job_long_poll(
            principal=principal(), node_id="node_technology_001",
            session_id=str(session["session_id"]),
            idempotency_key="maintenance-claim-tech-001", wait_seconds=0,
        )
        self.assertEqual(job["job_id"], claimed["job_id"])
        claimed_replay = self.nodes.claim_maintenance_job_long_poll(
            principal=principal(), node_id="node_technology_001",
            session_id=str(session["session_id"]),
            idempotency_key="maintenance-claim-tech-001", wait_seconds=0,
        )
        self.assertTrue(claimed_replay["replayed"])
        self.assertEqual(job["job_id"], claimed_replay["job_id"])
        self.assertIsNone(self.nodes.claim_maintenance_job_long_poll(
            principal=principal(), node_id="node_technology_001",
            session_id=str(session["session_id"]),
            idempotency_key="maintenance-claim-tech-002", wait_seconds=0,
        ))
        document = {
            "session_id": session["session_id"],
            "job_digest": job["job_digest"],
            "handler_id": HANDLER,
            "asset_digest": ASSET_DIGEST,
            "started_at": "2026-09-02T12:01:00Z",
            "completed_at": "2026-09-02T12:02:00Z",
            "outcome": "succeeded",
            "reason_code": "maintenance_handler_succeeded",
            "sanitized_summary": "固定处理器已完成；未启动Runtime，未调用模型。",
            "output_digest": "sha256:" + "b" * 64,
            "output_truncated": False,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }
        receipt = self.nodes.record_maintenance_receipt(
            principal=principal(), node_id="node_technology_001",
            job_id=str(job["job_id"]), document=document,
            idempotency_key="maintenance-receipt-tech-001",
        )
        self.assertEqual("succeeded", receipt["outcome"])
        replay = self.nodes.record_maintenance_receipt(
            principal=principal(), node_id="node_technology_001",
            job_id=str(job["job_id"]), document=document,
            idempotency_key="maintenance-receipt-tech-001",
        )
        self.assertTrue(replay["replayed"])
        status = self.nodes.maintenance_status(node_id="node_technology_001")
        self.assertEqual("completed", status["jobs"][0]["status"])
        self.assertEqual(receipt["receipt_id"], status["receipts"][0]["receipt_id"])

    def test_unknown_handler_scope_and_expiry_fail_closed(self) -> None:
        with self.assertRaisesRegex(LanStage1Error, "lan_maintenance_handler_not_allowed"):
            self.nodes.open_assisted_maintenance_session(
                principal=principal(), node_id="node_technology_001",
                requested_handler_ids=["orbit-maintenance-handler/arbitrary-shell"],
                duration_seconds=1800, local_user_initiated=True,
                idempotency_key="maintenance-session-unknown-handler",
            )
        session = self.open_session()
        self.clock.value += timedelta(minutes=10)
        resumed = self.nodes.open_assisted_maintenance_session(
            principal=principal(), node_id="node_technology_001",
            requested_handler_ids=[HANDLER], duration_seconds=1800,
            local_user_initiated=True,
            idempotency_key="maintenance-session-tech-resume-001",
        )
        self.assertTrue(resumed["resumed"])
        self.assertEqual(1200, resumed["remaining_seconds"])
        with self.assertRaisesRegex(LanStage1Error, "lan_node_scope_not_allowed"):
            self.nodes.claim_maintenance_job_long_poll(
                principal=principal(node_id="node_market_001", department_id="market_center"),
                node_id="node_technology_001", session_id=str(session["session_id"]),
                idempotency_key="maintenance-wrong-node-001", wait_seconds=0,
            )
        self.clock.value += timedelta(minutes=21)
        with self.assertRaisesRegex(LanStage1Error, "lan_maintenance_session_not_active"):
            self.nodes.enqueue_maintenance_job(
                node_id="node_technology_001", handler_id=HANDLER,
                asset_name=ASSET, asset_digest=ASSET_DIGEST,
                idempotency_key="maintenance-job-expired-001",
                actor_ref="operator_local_platform_owner",
            )

    def test_same_node_can_supersede_an_active_older_handler_window(self) -> None:
        previous = self.open_session()
        with self.database.session() as session:
            row = session.scalar(select(LanAssistedMaintenanceSessionRow))
            self.assertIsNotNone(row)
            row.allowed_handler_ids = {
                "items": ["orbit-maintenance-handler/wsl-logind-keepalive-v4"]
            }
        successor = self.nodes.open_assisted_maintenance_session(
            principal=principal(), node_id="node_technology_001",
            requested_handler_ids=[HANDLER], duration_seconds=1800,
            local_user_initiated=True,
            idempotency_key="maintenance-session-tech-v6-successor",
        )
        self.assertNotEqual(previous["session_id"], successor["session_id"])
        self.assertFalse(successor["resumed"])
        status = self.nodes.maintenance_status(node_id="node_technology_001")
        previous_projection = next(
            item for item in status["sessions"]
            if item["session_id"] == previous["session_id"]
        )
        self.assertFalse(previous_projection["active"])

    def test_sensitive_or_unbound_receipt_is_rejected(self) -> None:
        session = self.open_session()
        job = self.enqueue()
        self.nodes.claim_maintenance_job_long_poll(
            principal=principal(), node_id="node_technology_001",
            session_id=str(session["session_id"]),
            idempotency_key="maintenance-claim-sensitive-001", wait_seconds=0,
        )
        document = {
            "session_id": session["session_id"], "job_digest": job["job_digest"],
            "handler_id": HANDLER, "asset_digest": ASSET_DIGEST,
            "started_at": "2026-09-02T12:01:00Z",
            "completed_at": "2026-09-02T12:02:00Z", "outcome": "failed",
            "reason_code": "maintenance_handler_failed",
            "sanitized_summary": "C:\\Users\\someone\\secret.txt",
            "output_digest": "sha256:" + "b" * 64,
            "output_truncated": True, "runtime_started": False,
            "model_called": False, "production_authorization": False,
            "release_authorization": False,
        }
        with self.assertRaisesRegex(LanStage1Error, "lan_maintenance_receipt_invalid"):
            self.nodes.record_maintenance_receipt(
                principal=principal(), node_id="node_technology_001",
                job_id=str(job["job_id"]), document=document,
                idempotency_key="maintenance-receipt-sensitive-001",
            )

    def test_receipt_time_order_and_job_window_are_bound(self) -> None:
        session = self.open_session()
        job = self.enqueue()
        self.nodes.claim_maintenance_job_long_poll(
            principal=principal(), node_id="node_technology_001",
            session_id=str(session["session_id"]),
            idempotency_key="maintenance-claim-time-001", wait_seconds=0,
        )
        document = {
            "session_id": session["session_id"], "job_digest": job["job_digest"],
            "handler_id": HANDLER, "asset_digest": ASSET_DIGEST,
            "started_at": "2026-09-02T12:03:00Z",
            "completed_at": "2026-09-02T12:02:00Z", "outcome": "failed",
            "reason_code": "maintenance_handler_failed",
            "sanitized_summary": "处理器时间顺序异常。",
            "output_digest": "sha256:" + "b" * 64,
            "output_truncated": False, "runtime_started": False,
            "model_called": False, "production_authorization": False,
            "release_authorization": False,
        }
        with self.assertRaisesRegex(LanStage1Error, "lan_maintenance_receipt_time_invalid"):
            self.nodes.record_maintenance_receipt(
                principal=principal(), node_id="node_technology_001",
                job_id=str(job["job_id"]), document=document,
                idempotency_key="maintenance-receipt-time-order-001",
            )
        document["started_at"] = "2026-09-02T12:25:01Z"
        document["completed_at"] = "2026-09-02T12:25:02Z"
        with self.assertRaisesRegex(LanStage1Error, "lan_maintenance_receipt_time_invalid"):
            self.nodes.record_maintenance_receipt(
                principal=principal(), node_id="node_technology_001",
                job_id=str(job["job_id"]), document=document,
                idempotency_key="maintenance-receipt-outside-window-001",
            )

    def test_workload_api_opens_claims_and_records_without_command_surface(self) -> None:
        class Workloads:
            @staticmethod
            def verify_caddy_forwarded_peer(**_kwargs: object) -> dict[str, object]:
                return principal()

        client = TestClient(create_workload_app(workloads=Workloads(), nodes=self.nodes))
        headers = {
            "X-Orbit-Client-Cert-Der": "synthetic-forwarded-by-test-caddy",
            "X-Orbit-Client-Cert-Fingerprint": "sha256:" + "a" * 64,
            "Idempotency-Key": "maintenance-api-session-001",
        }
        opened = client.post(
            "/v1/runtime-nodes/node_technology_001/assisted-maintenance-sessions",
            headers=headers,
            json={
                "requested_handler_ids": [HANDLER],
                "duration_seconds": 1800,
                "local_user_initiated": True,
            },
        )
        self.assertEqual(201, opened.status_code, opened.text)
        session = opened.json()
        job = self.enqueue()
        claimed = client.post(
            f"/v1/runtime-nodes/node_technology_001/assisted-maintenance-sessions/"
            f"{session['session_id']}/job-claims?wait_seconds=0",
            headers={**headers, "Idempotency-Key": "maintenance-api-claim-001"},
            json={},
        )
        self.assertEqual(200, claimed.status_code, claimed.text)
        self.assertNotIn("command", claimed.json())
        document = {
            "session_id": session["session_id"], "job_digest": job["job_digest"],
            "handler_id": HANDLER, "asset_digest": ASSET_DIGEST,
            "started_at": "2026-09-02T12:01:00Z",
            "completed_at": "2026-09-02T12:02:00Z",
            "outcome": "succeeded", "reason_code": "maintenance_handler_succeeded",
            "sanitized_summary": "处理器完成；无Runtime或模型调用。",
            "output_digest": "sha256:" + "b" * 64,
            "output_truncated": False, "runtime_started": False,
            "model_called": False, "production_authorization": False,
            "release_authorization": False,
        }
        recorded = client.post(
            f"/v1/runtime-nodes/node_technology_001/maintenance-jobs/{job['job_id']}/receipts",
            headers={**headers, "Idempotency-Key": "maintenance-api-receipt-001"},
            json={"document": document},
        )
        self.assertEqual(201, recorded.status_code, recorded.text)
        self.assertFalse(recorded.json()["runtime_started"])


if __name__ == "__main__":
    unittest.main()

