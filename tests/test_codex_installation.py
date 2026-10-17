from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from orbit_agent_control_plane.service_runtime.codex_installation import (
    CodexInstallationError,
    CodexInstallationService,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.lan_stage1_models import (
    LanCertificateBindingRow,
)
from orbit_agent_control_plane.service_runtime.models import Base

DIGEST_MANIFEST = "sha256:" + "1" * 64
DIGEST_ARCHIVE = "sha256:" + "2" * 64
NODE_ID = "node_technology_001"
DEPARTMENT_ID = "technology_center"


def make_service() -> CodexInstallationService:
    database = Database("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(database.engine)
    now = datetime(2026, 9, 3, 8, 0, tzinfo=timezone.utc)
    with database.session() as session:
        session.add(
            LanCertificateBindingRow(
                binding_id="binding_technology_001",
                node_id=NODE_ID,
                department_id=DEPARTMENT_ID,
                uri_san=f"spiffe://orbit.local/workload/{NODE_ID}",
                fingerprint="sha256:" + "3" * 64,
                serial_number="12345",
                certificate_der=b"synthetic-certificate",
                public_key_digest="sha256:" + "4" * 64,
                status="active",
                issued_at=now,
                not_before=now - timedelta(minutes=1),
                not_after=now + timedelta(days=30),
                renewal_after=now + timedelta(days=23),
            )
        )
    return CodexInstallationService(
        database=database,
        approved_release_manifest_digest=DIGEST_MANIFEST,
        approved_archive_digest=DIGEST_ARCHIVE,
        now=lambda: now,
    )


def event(
    *,
    sequence: int,
    stage: str,
    status: str,
    failure_code: str | None = None,
    attempt_id: str = "codex_attempt_001",
    predecessor_attempt_id: str | None = None,
) -> dict[str, object]:
    return {
        "event_version": "orbit.codex-installation-stage-event/1",
        "attempt_id": attempt_id,
        "predecessor_attempt_id": predecessor_attempt_id,
        "department_id": DEPARTMENT_ID,
        "codex_cli_version": "0.153.0",
        "target_platform": "x86_64-unknown-linux-musl",
        "release_manifest_digest": DIGEST_MANIFEST,
        "archive_digest": DIGEST_ARCHIVE,
        "sequence": sequence,
        "stage": stage,
        "status": status,
        "failure_code": failure_code,
        "observed_at": "2026-09-03T08:00:00Z",
        "execution_grant_issued": False,
        "runtime_started": False,
        "model_called": False,
        "production_authorization": False,
        "release_authorization": False,
    }


def receipt(
    *,
    attempt_id: str = "codex_attempt_001",
    source: str = "live_stage_events",
    intermediate: bool = True,
    predecessor_attempt_id: str | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "orbit.codex-cli-installation-receipt/0.1-draft",
        "receipt_id": f"receipt_{attempt_id}",
        "attempt_id": attempt_id,
        "predecessor_attempt_id": predecessor_attempt_id,
        "department_id": DEPARTMENT_ID,
        "status": "codex_cli_installed",
        "version": "0.153.0",
        "target": "x86_64-unknown-linux-musl",
        "release_manifest_digest": DIGEST_MANIFEST,
        "archive_digest": DIGEST_ARCHIVE,
        "evidence_source": source,
        "intermediate_events_available": intermediate,
        "observed_at": "2026-09-03T08:00:00Z",
        "credential_present": False,
        "account_logged_in": False,
        "execution_grant_issued": False,
        "lease_issued": False,
        "runtime_started": False,
        "model_called": False,
        "production_authorization": False,
        "release_authorization": False,
    }


def record(
    service: CodexInstallationService,
    value: dict[str, object],
    key: str,
) -> dict[str, object]:
    return service.record_event(
        node_id=NODE_ID,
        document=value,
        idempotency_key=key,
        workload_identity=f"spiffe://orbit.local/workload/{NODE_ID}",
    )


def check_records_ordered_events_and_terminal_receipt(service: CodexInstallationService) -> None:
    sequence = 0
    for stage in ("download", "verify", "install", "version_check", "complete"):
        sequence += 1
        record(service, event(sequence=sequence, stage=stage, status="running"), f"event-{sequence:04d}")
        sequence += 1
        result = record(
            service,
            event(sequence=sequence, stage=stage, status="passed"),
            f"event-{sequence:04d}",
        )
        assert result["execution_grant_issued"] is False
    completed = service.record_receipt(
        node_id=NODE_ID,
        document=receipt(),
        idempotency_key="receipt-live-0001",
        workload_identity=f"spiffe://orbit.local/workload/{NODE_ID}",
    )
    assert completed["status"] == "complete"
    projection = service.projection(department_id=DEPARTMENT_ID)
    assert projection["overall_status"] == "complete"
    assert projection["evidence"]["account_logged_in"] is False
    assert projection["llm_api_readiness"]["central_secret_only"] is True
    assert projection["llm_api_readiness"]["browser_secret_allowed"] is False
    assert projection["llm_api_readiness"]["device_secret_allowed"] is False
    assert {stage["status"] for stage in projection["stages"]} == {"received"}
    serialized = str(projection).lower()
    for forbidden in ("auth.json", "provider_url", "physical_path", "terminal_output"):
        assert forbidden not in serialized


def check_idempotent_replay_and_conflict_are_distinct(service: CodexInstallationService) -> None:
    value = event(sequence=1, stage="download", status="running")
    record(service, value, "event-replay-0001")
    replay = record(service, value, "event-replay-0001")
    assert replay["idempotent_replay"] is True
    changed = dict(value)
    changed["status"] = "passed"
    with unittest.TestCase().assertRaisesRegex(CodexInstallationError, "replay_conflict"):
        record(service, changed, "event-replay-0001")


def check_rejects_unordered_drifted_or_sensitive_events(
    service: CodexInstallationService,
    mutation: dict[str, object],
    reason: str,
) -> None:
    value = event(sequence=1, stage="download", status="running")
    value.update(mutation)
    with unittest.TestCase().assertRaisesRegex(CodexInstallationError, reason):
        record(service, value, f"event-invalid-{reason}")


def check_failure_requires_successor_attempt(service: CodexInstallationService) -> None:
    failed = record(
        service,
        event(
            sequence=1,
            stage="download",
            status="failed",
            failure_code="device_offline",
        ),
        "event-failed-0001",
    )
    with unittest.TestCase().assertRaisesRegex(CodexInstallationError, "attempt_terminal"):
        record(
            service,
            event(sequence=2, stage="download", status="running"),
            "event-failed-0002",
        )
    successor = event(
        sequence=1,
        stage="download",
        status="running",
        attempt_id="codex_attempt_002",
        predecessor_attempt_id="codex_attempt_001",
    )
    recorded = record(service, successor, "event-successor-0001")
    assert recorded["attempt_id"] == "codex_attempt_002"
    resumed = service.events(
        department_id=DEPARTMENT_ID,
        after_sequence=int(failed["event_cursor"]),
    )
    assert [item["attempt_id"] for item in resumed] == ["codex_attempt_002"]
    assert resumed[0]["event_cursor"] > failed["event_cursor"]


def check_adopts_existing_owner_local_terminal_receipt_without_fake_events(
    service: CodexInstallationService,
) -> None:
    value = receipt(
        attempt_id="codex_attempt_recovered_001",
        source="recovered_existing_receipt",
        intermediate=False,
    )
    service.record_receipt(
        node_id=NODE_ID,
        document=value,
        idempotency_key="receipt-recovered-0001",
        workload_identity=f"spiffe://orbit.local/workload/{NODE_ID}",
    )
    projection = service.projection(department_id=DEPARTMENT_ID)
    assert projection["intermediate_events_available"] is False
    assert projection["evidence"]["evidence_source"] == "recovered_existing_receipt"
    assert projection["stages"][-1]["status"] == "received"
    assert all(stage["status"] == "waiting" for stage in projection["stages"][:-1])


def check_revoked_certificate_and_wrong_department_fail_closed(
    service: CodexInstallationService,
) -> None:
    wrong_department = event(sequence=1, stage="download", status="running")
    wrong_department["department_id"] = "product_center"
    with unittest.TestCase().assertRaisesRegex(CodexInstallationError, "binding_drift"):
        record(service, wrong_department, "event-wrong-department-0001")

    with service.database.session() as session:
        binding = session.query(LanCertificateBindingRow).one()
        binding.status = "revoked"
    with unittest.TestCase().assertRaisesRegex(CodexInstallationError, "node_scope_invalid"):
        record(
            service,
            event(sequence=1, stage="download", status="running"),
            "event-revoked-certificate-0001",
        )


def check_terminal_receipt_must_be_complete_and_keep_all_authority_negative(
    service: CodexInstallationService,
) -> None:
    incomplete = receipt(
        attempt_id="codex_attempt_recovered_incomplete",
        source="recovered_existing_receipt",
        intermediate=False,
    )
    del incomplete["archive_digest"]
    with unittest.TestCase().assertRaisesRegex(CodexInstallationError, "receipt_invalid"):
        service.record_receipt(
            node_id=NODE_ID,
            document=incomplete,
            idempotency_key="receipt-incomplete-0001",
            workload_identity=f"spiffe://orbit.local/workload/{NODE_ID}",
        )

    unauthorized = receipt(
        attempt_id="codex_attempt_recovered_unauthorized",
        source="recovered_existing_receipt",
        intermediate=False,
    )
    unauthorized["execution_grant_issued"] = True
    with unittest.TestCase().assertRaisesRegex(CodexInstallationError, "binding_drift"):
        service.record_receipt(
            node_id=NODE_ID,
            document=unauthorized,
            idempotency_key="receipt-authority-positive-0001",
            workload_identity=f"spiffe://orbit.local/workload/{NODE_ID}",
        )


class CodexInstallationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = make_service()

    def test_records_ordered_events_and_terminal_receipt(self) -> None:
        check_records_ordered_events_and_terminal_receipt(self.service)

    def test_idempotent_replay_and_conflict_are_distinct(self) -> None:
        check_idempotent_replay_and_conflict_are_distinct(self.service)

    def test_rejects_unordered_drifted_or_sensitive_events(self) -> None:
        cases = [
            ({"sequence": 2}, "sequence_invalid"),
            ({"stage": "extract"}, "event_invalid"),
            ({"attempt_id": "../escape"}, "event_invalid"),
            ({"release_manifest_digest": "sha256:" + "9" * 64}, "binding_drift"),
            ({"terminal_log": "sensitive"}, "sensitive_field_rejected"),
            ({"failure_code": "raw_exception"}, "event_invalid"),
        ]
        for mutation, reason in cases:
            with self.subTest(reason=reason, mutation=mutation):
                check_rejects_unordered_drifted_or_sensitive_events(
                    make_service(), mutation, reason
                )

    def test_other_departments_are_explicitly_not_applicable(self) -> None:
        projection = self.service.projection(department_id="product_center")
        self.assertFalse(projection["applicable"])
        self.assertEqual("not_applicable", projection["overall_status"])

    def test_failure_requires_successor_attempt(self) -> None:
        check_failure_requires_successor_attempt(self.service)

    def test_adopts_existing_receipt_without_fake_events(self) -> None:
        check_adopts_existing_owner_local_terminal_receipt_without_fake_events(
            self.service
        )

    def test_revoked_certificate_and_wrong_department_fail_closed(self) -> None:
        check_revoked_certificate_and_wrong_department_fail_closed(self.service)

    def test_terminal_receipt_keeps_authority_negative(self) -> None:
        check_terminal_receipt_must_be_complete_and_keep_all_authority_negative(
            self.service
        )


if __name__ == "__main__":
    unittest.main()

