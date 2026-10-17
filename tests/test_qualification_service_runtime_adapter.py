from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from orbit_agent_control_plane.service_runtime.runtime_adapter import (
    DisabledRunnerTransport,
    FrameworkNeutralRuntimeAdapter,
    RuntimeAdapterDescriptor,
    RuntimeAdapterError,
    RuntimeAdapterRegistry,
)

DIGEST = "sha256:" + ("a" * 64)


def invocation() -> dict:
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    return {
        "task_id": "task_runtime_adapter_test_syn",
        "task_digest": "sha256:" + ("b" * 64),
        "grant_id": "grant_runtime_adapter_test_syn",
        "grant_digest": "sha256:" + ("c" * 64),
        "composition_digest": "sha256:" + ("d" * 64),
        "runtime_source_digest": "sha256:" + ("e" * 64),
        "workload_identity": "workload_runtime_adapter_test",
        "operation": "run_qualification_attempt",
        "input_refs": ["artifact://disease-r2/attempt-005"],
        "idempotency_key": "runtime-adapter:test:001",
        "expires_at": expires.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "timeout_seconds": 300,
        "synthetic_only": True,
    }


class RuntimeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.descriptor = RuntimeAdapterDescriptor.from_mapping(
            {
                "adapter_id": "runtime_adapter_framework_neutral_syn",
                "version": "0.1.0",
                "digest": DIGEST,
                "runtime_family": "disease_r2_v4",
                "conformance_profiles": [
                    "core_dispatch",
                    "tool_data_enforced",
                    "isolated_workload",
                ],
                "supported_operations": ["run_qualification_attempt"],
                "supports_checkpoint_restore": False,
                "evidence_status": "architecture_reference",
                "synthetic_only": True,
            }
        )
        self.adapter = FrameworkNeutralRuntimeAdapter(
            descriptor=self.descriptor,
            transport=DisabledRunnerTransport(),
        )

    def test_registry_requires_exact_id_version_and_digest(self) -> None:
        registry = RuntimeAdapterRegistry()
        registry.register(self.adapter)
        self.assertIs(
            self.adapter,
            registry.resolve(
                adapter_id=self.descriptor.adapter_id,
                version=self.descriptor.version,
                digest=self.descriptor.digest,
            ),
        )
        with self.assertRaisesRegex(
            RuntimeAdapterError, "runtime_adapter_not_registered"
        ):
            registry.resolve(
                adapter_id=self.descriptor.adapter_id,
                version=self.descriptor.version,
                digest="sha256:" + ("f" * 64),
            )

    def test_fail_closed_transport_and_no_physical_input_refs(self) -> None:
        value = invocation()
        validated = self.adapter.validate(value)
        self.assertEqual("run_qualification_attempt", validated.operation)
        with self.assertRaisesRegex(
            RuntimeAdapterError, "runner_transport_not_configured"
        ):
            self.adapter.start(value)
        value["input_refs"] = ["file:///Users/example/secret"]
        with self.assertRaisesRegex(RuntimeAdapterError, "runtime_input_ref_invalid"):
            self.adapter.validate(value)

    def test_operation_expiry_and_synthetic_boundaries(self) -> None:
        value = invocation()
        value["operation"] = "shell"
        with self.assertRaisesRegex(
            RuntimeAdapterError, "runtime_operation_not_supported"
        ):
            self.adapter.validate(value)
        value = invocation()
        value["synthetic_only"] = False
        with self.assertRaisesRegex(RuntimeAdapterError, "runtime_invocation_invalid"):
            self.adapter.validate(value)
        value = invocation()
        value["expires_at"] = "2026-01-01T00:00:00Z"
        with self.assertRaisesRegex(RuntimeAdapterError, "runtime_invocation_expired"):
            self.adapter.validate(value)
        value = invocation()
        value["expires_at"] = (
            (datetime.now(timezone.utc) + timedelta(hours=1))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        with self.assertRaisesRegex(RuntimeAdapterError, "runtime_invocation_expired"):
            self.adapter.validate(value)


if __name__ == "__main__":
    unittest.main()

