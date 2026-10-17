from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.container_engine import (
    ContainerEngineError,
    RootlessDockerEngineAdapter,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.models import (
    AuditEventRow,
    Base,
    ReceiptRow,
    RuntimeRunRow,
)
from orbit_agent_control_plane.service_runtime.repositories import (
    SqlGrantRevocationRegistry,
)
from orbit_agent_control_plane.service_runtime.runtime_adapter import (
    RuntimeAdapterError,
    RuntimeInvocation,
)
from orbit_agent_control_plane.service_runtime.runtime_artifact_api import (
    install_runtime_artifact_routes,
)
from orbit_agent_control_plane.service_runtime.runtime_artifact_models import (
    RuntimeNodeLeaseClaimRow,
)
from orbit_agent_control_plane.service_runtime.runtime_artifacts import (
    RuntimeArtifactError,
    RuntimeArtifactService,
)

NOW = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
DIGESTS = {
    name: "sha256:" + char * 64
    for name, char in {
        "source": "1", "image": "2", "isolation": "3", "adapter": "4",
        "dockerfile": "5", "lock": "6", "base": "7", "sbom": "8",
        "provenance": "9", "vulnerability": "a", "license": "b",
        "bundle": "c", "signature": "d", "task": "e", "grant": "f",
        "composition": "0", "seccomp": "a", "route": "b",
        "realization": "6", "binding": "d",
    }.items()
}


def manifest() -> dict:
    value = {
        "api_version": "company-ai-os/v1alpha3-draft",
        "kind": "RuntimeArtifactManifest",
        "metadata": {
            "artifact_id": "runtime_artifact_market_hermes_syn",
            "version": "0.1.0-d0",
            "revision": 1,
            "evidence_status": "synthetic_d0",
            "synthetic_only": True,
            "created_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        "spec": {
            "runtime_family": "hermes",
            "upstream_revision": "synthetic-hermes-revision-001",
            "runtime_source_lock_ref": {"id": "runtime_source_lock_hermes_syn", "version": "0.1.0-d0", "digest": DIGESTS["lock"]},
            "runtime_source_digest": DIGESTS["source"],
            "runtime_realization_ref": {
                "id": "runtime_realization_market_hermes_syn",
                "version": "0.1.0-d0",
                "digest": DIGESTS["realization"],
            },
            "runtime_realization_digest": DIGESTS["realization"],
            "oci_image": {
                "layout_media_type": "application/vnd.oci.layout.header.v1+json",
                "manifest_digest": DIGESTS["image"],
                "config_digest": DIGESTS["base"],
                "target_platform": "linux/amd64",
                "archive_digest": DIGESTS["bundle"],
                "floating_tag_allowed": False,
            },
            "runtime_adapter": {
                "adapter_id": "runtime_adapter_hermes_syn", "version": "0.1.0-d0",
                "source_digest": DIGESTS["adapter"],
                "capability_report_ref": {"id": "adapter_capability_hermes_syn", "version": "0.1.0-d0", "digest": DIGESTS["provenance"]},
                "capability_report_digest": DIGESTS["provenance"],
            },
            "build_inputs": {
                "dockerfile_digest": DIGESTS["dockerfile"],
                "dependency_lock_digest": DIGESTS["lock"],
                "base_image_digest": DIGESTS["base"],
                "build_arguments_contain_secrets": False,
            },
            "evidence": {
                "sbom_ref": "evidence://synthetic/hermes/sbom", "sbom_digest": DIGESTS["sbom"],
                "build_provenance_ref": "evidence://synthetic/hermes/provenance", "build_provenance_digest": DIGESTS["provenance"],
                "vulnerability_report_ref": "evidence://synthetic/hermes/vulnerability", "vulnerability_report_digest": DIGESTS["vulnerability"],
                "license_report_ref": "evidence://synthetic/hermes/license", "license_report_digest": DIGESTS["license"],
            },
            "container_isolation_profile_ref": {"id": "container_isolation_d0_syn", "version": "0.1.0-d0", "digest": DIGESTS["isolation"]},
            "container_isolation_profile_digest": DIGESTS["isolation"],
            "supported_scope": {
                "agent_release_refs": [{"id": "agent_release_market_planner_syn", "version": "0.1.0-d0", "digest": DIGESTS["task"]}],
                "model_protocols": ["openai_chat_completions"],
                "tool_operations": [],
                "data_classifications": ["synthetic", "public"],
            },
            "minimum_runner_capabilities": {
                "os_family": "linux", "wsl_distribution": "Ubuntu-22.04", "container_engine": "rootless-docker",
                "rootless_required": True, "systemd_required": True, "seccomp_required": True, "cgroup_resource_limits_required": True,
            },
            "artifact_bundle": {
                "bundle_ref": "bundle://synthetic/hermes/runtime-artifact",
                "artifact_set_manifest_digest": DIGESTS["bundle"],
                "signature_bundle_digest": DIGESTS["signature"],
                "verification_key_ref": "key://synthetic/runtime-artifact-verifier",
            },
            "lifecycle": {"status": "qualified_d0", "revoked_at": None, "superseding_artifact_ref": None},
            "manifest_digest": "",
        },
        "authority_boundary": {
            "agent_identity_created": False, "execution_grant_issued": False,
            "deployment_activated": False, "production_authorized": False, "release_authorization": False,
        },
    }
    value["spec"]["manifest_digest"] = embedded_digest(value, "manifest_digest")
    return value


def embedded_digest(value: dict, field: str) -> str:
    normalized = copy.deepcopy(value)
    del normalized["spec"][field]
    source = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(source).hexdigest()


def capability(
    revision_digest: str | None = None,
    *,
    import_receipt_digests: tuple[str, ...] = (),
) -> dict:
    return {
        "report_version": "orbit.runtime-node-capability-report/0.1-draft",
        "node_id": "node_market_syn_001",
        "deployment_instance_ref": "artifact://deployment-instances/market-001",
        "workload_identity": "workload_market_runner_syn",
        "observed_at": NOW.isoformat().replace("+00:00", "Z"),
        "platform": {"os": "linux", "distribution": "ubuntu", "version": "22.04", "wsl_version": 2},
        "oci_platform": "linux/amd64",
        "systemd": True,
        "engine": {"engine_id": "rootless-docker", "version": "27.0.0", "rootless": True, "user_namespace": True},
        "controls": {"cgroup_v2": True, "seccomp": True, "resource_limits": True, "task_relay_network": True},
        "verified_runtime_artifact_digests": (
            [] if revision_digest is None else [revision_digest]
        ),
        "verified_image_digests": (
            [] if revision_digest is None else [DIGESTS["image"]]
        ),
        "verified_import_receipt_digests": list(import_receipt_digests),
        "workload_scope": {
            "department_ids": ["market_center"],
            "agent_bindings": [
                {
                    "id": "agent_binding_market_professional_syn",
                    "digest": DIGESTS["binding"],
                }
            ],
        },
        "synthetic_only": True,
        "production_authorization": False,
    }


def import_receipt(candidate: dict, report_digest: str) -> dict:
    artifact = manifest()
    value = {
        "api_version": "company-ai-os/v1alpha3-draft",
        "kind": "RuntimeArtifactImportReceipt",
        "metadata": {
            "receipt_id": "runtime_import_market_syn_001",
            "revision": 1,
            "status": "imported",
            "evidence_status": "synthetic_d0",
            "synthetic_only": True,
            "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
        },
        "spec": {
            "runtime_node_ref": {
                "id": "node_market_syn_001",
                "version": "0.1.0-d0",
                "digest": report_digest,
            },
            "deployment_instance_ref": {
                "id": "deployment_market_syn_001",
                "version": "0.1.0-d0",
                "digest": report_digest,
            },
            "runtime_artifact_manifest_ref": {
                "id": candidate["artifact_id"],
                "version": artifact["metadata"]["version"],
                "digest": candidate["revision_digest"],
            },
            "runtime_artifact_manifest_digest": candidate["revision_digest"],
            "runtime_source_digest": candidate["runtime_source_digest"],
            "runtime_image_manifest_digest": candidate["runtime_image_digest"],
            "container_isolation_profile_digest": candidate[
                "isolation_profile_digest"
            ],
            "artifact_set_manifest_digest": artifact["spec"]["artifact_bundle"][
                "artifact_set_manifest_digest"
            ],
            "signature_bundle_digest": artifact["spec"]["artifact_bundle"][
                "signature_bundle_digest"
            ],
            "engine_observation": {
                "engine": "rootless-docker",
                "rootless": True,
                "platform": artifact["spec"]["oci_image"]["target_platform"],
                "wsl_distribution": "Ubuntu-22.04",
                "systemd": True,
                "seccomp": True,
                "cgroup_resource_limits": True,
            },
            "verification": {
                "signature_valid": True,
                "artifact_set_valid": True,
                "manifest_digest_valid": True,
                "source_digest_valid": True,
                "image_digest_valid": True,
                "platform_compatible": True,
                "isolation_compatible": True,
                "artifact_not_revoked": True,
                "probe_passed": True,
            },
            "capability_report_ref": {
                "id": "capability_market_syn_001",
                "version": "0.1.0-d0",
                "digest": report_digest,
            },
            "capability_report_digest": report_digest,
            "failure_reasons": [],
            "audit_refs": ["audit://runtime/import/market-001"],
            "receipt_digest": "",
        },
        "authority_boundary": {
            "execution_grant_issued": False,
            "runtime_started": False,
            "agent_activated": False,
            "deployment_activated": False,
            "production_authorized": False,
            "release_authorization": False,
        },
    }
    value["spec"]["receipt_digest"] = embedded_digest(value, "receipt_digest")
    return value


def container_invocation() -> RuntimeInvocation:
    return RuntimeInvocation.from_mapping(
        {
            "task_id": "task_market_container_syn",
            "task_digest": DIGESTS["task"],
            "grant_id": "grant_market_container_syn",
            "grant_digest": DIGESTS["grant"],
            "composition_digest": DIGESTS["composition"],
            "runtime_source_digest": DIGESTS["source"],
            "runtime_artifact_digest": DIGESTS["bundle"],
            "runtime_image_digest": DIGESTS["image"],
            "isolation_profile_digest": isolation_profile()["spec"]["profile_digest"],
            "input_snapshot_refs": ["artifact://inputs/market-001"],
            "department_id": "market_center",
            "agent_binding_ref": "agent_binding_market_professional_syn",
            "agent_binding_digest": DIGESTS["binding"],
            "workload_identity": "workload_market_runner_syn",
            "operation": "run_professional_task",
            "input_refs": ["artifact://inputs/market-001"],
            "idempotency_key": "runtime:market:container:0001",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "timeout_seconds": 900,
            "data_classification": "synthetic",
            "synthetic_only": True,
            "production_authorization": False,
        }
    )


def isolation_profile() -> dict:
    value = {
        "api_version": "company-ai-os/v1alpha3-draft",
        "kind": "ContainerIsolationProfile",
        "metadata": {"profile_id": "container_isolation_d0_syn", "version": "0.1.0-d0", "evidence_status": "synthetic_d0", "synthetic_only": True, "created_at": NOW.isoformat().replace("+00:00", "Z")},
        "spec": {
            "engine": {"family": "rootless-docker", "rootless": True, "socket_mounted_into_task": False, "privileged": False},
            "identity": {"run_as_non_root": True, "uid": 10001, "gid": 10001, "supplemental_groups_allowed": False},
            "filesystem": {"root_read_only": True, "host_paths_mounted": False, "windows_drives_mounted": False, "docker_socket_mounted": False, "secret_volumes_mounted": False, "mounts": [
                {"class": "input_snapshot", "access": "read_only", "source_kind": "logical_artifact", "cross_task_shared": False},
                {"class": "task_workspace", "access": "read_write", "source_kind": "task_volume", "cross_task_shared": False},
                {"class": "task_tmpfs", "access": "read_write", "source_kind": "tmpfs", "cross_task_shared": False},
            ]},
            "linux_security": {"no_new_privileges": True, "drop_all_capabilities": True, "added_capabilities": [], "seccomp_profile_ref": "policy://synthetic/seccomp/default-deny", "seccomp_profile_digest": DIGESTS["seccomp"]},
            "network": {"mode": "task_gateway_relay_only", "host_network": False, "published_ports": [], "direct_internet": False, "allowed_logical_destinations": ["gateway://task-relay"]},
            "resources": {"cpu_millis": 1000, "memory_mib": 1024, "pids": 128, "workspace_mib": 1024, "tmpfs_mib": 128, "runtime_seconds": 900},
            "lifecycle": {"task_exclusive": True, "cross_task_memory": False, "needs_input_retention_seconds": 600, "checkpoint_classes": ["checkpoint", "result_draft", "diff", "artifact"], "terminal_cleanup_required": True},
            "profile_digest": "",
        },
        "authority_boundary": {"execution_grant_issued": False, "task_state_changed": False, "deployment_activated": False, "production_authorized": False, "release_authorization": False},
    }
    value["spec"]["profile_digest"] = embedded_digest(value, "profile_digest")
    return value


class RuntimeArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="orbit-runtime-artifact-")
        self.database = Database(f"sqlite+pysqlite:///{Path(self.temporary.name) / 'state.sqlite3'}")
        Base.metadata.create_all(self.database.engine)
        self.service = RuntimeArtifactService(
            database=self.database,
            grant_revocations=SqlGrantRevocationRegistry(self.database),
            authorized_node_scopes={
                "node_market_syn_001": {
                    "workload_identity": "workload_market_runner_syn",
                    "deployment_instance_ref": (
                        "artifact://deployment-instances/market-001"
                    ),
                    "workload_scope": {
                        "department_ids": ["market_center"],
                        "agent_bindings": [
                            {
                                "id": "agent_binding_market_professional_syn",
                                "digest": DIGESTS["binding"],
                            }
                        ],
                    },
                }
            },
            now=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.database.dispose()
        self.temporary.cleanup()

    def _candidate(self) -> dict:
        return self.service.record_candidate(
            document=manifest(),
            expected_latest_revision_digest="none",
            reason="登记市场中心 Hermes 的精确 D0 Runtime Artifact 候选",
            idempotency_key="artifact:market:hermes:0001",
            actor_ref="human_control_plane_admin_syn",
        )

    def _qualify(self, candidate: dict, *, suffix: str = "0001") -> dict:
        return self.service.qualify_d0(
            artifact_id=candidate["artifact_id"],
            revision_digest=candidate["revision_digest"],
            expected_bindings=candidate["qualification_bindings"],
            reason="公司管理员记录精确摘要绑定的合成 D0 资格通过回执",
            idempotency_key=f"artifact:market:qualification:{suffix}",
            actor_ref="human_control_plane_admin_syn",
        )

    def test_candidate_revision_bundle_and_revocation_are_independent_evidence(self) -> None:
        candidate = self._candidate()
        self.assertEqual("candidate", candidate["status"])
        self.assertFalse(
            self.service.list_artifacts()["items"][0]["schedulable"]
        )
        qualified = self._qualify(candidate)
        replay = self._qualify(candidate)
        self.assertTrue(qualified["qualification_recorded"])
        self.assertTrue(
            self.service.list_artifacts()["items"][0]["schedulable"]
        )
        self.assertTrue(replay["idempotent_replay"])
        wrong_bindings = copy.deepcopy(candidate["qualification_bindings"])
        wrong_bindings["runtime_image_digest"] = DIGESTS["base"]
        with self.assertRaisesRegex(
            RuntimeArtifactError, "runtime_artifact_qualification_binding_drift"
        ):
            self.service.qualify_d0(
                artifact_id=candidate["artifact_id"],
                revision_digest=candidate["revision_digest"],
                expected_bindings=wrong_bindings,
                reason="错误摘要不得产生 Runtime Artifact 资格通过回执",
                idempotency_key="artifact:market:qualification:wrong:0001",
                actor_ref="human_control_plane_admin_syn",
            )
        self.assertNotEqual(candidate["runtime_source_digest"], candidate["runtime_image_digest"])
        detail = self.service.revision(artifact_id=candidate["artifact_id"], revision_digest=candidate["revision_digest"])
        self.assertFalse(detail["revoked"])
        bundle = self.service.bundle_metadata(artifact_id=candidate["artifact_id"], revision_digest=candidate["revision_digest"])
        self.assertTrue(bundle["logical_metadata_only"])
        self.assertFalse(bundle["bundle_bytes_included"])
        revoked = self.service.revoke(
            artifact_id=candidate["artifact_id"],
            expected_revision_digest=candidate["revision_digest"],
            reason="撤销该精确 D0 制品并阻止新的节点 Lease",
            idempotency_key="artifact:market:revoke:0001",
            actor_ref="human_control_plane_admin_syn",
        )
        self.assertFalse(revoked["schedulable"])
        self.assertFalse(revoked["release_authorization"])
        with self.assertRaisesRegex(
            RuntimeArtifactError, "runtime_artifact_qualification_revoked"
        ):
            self.service.qualify_d0(
                artifact_id=candidate["artifact_id"],
                revision_digest=candidate["revision_digest"],
                expected_bindings=candidate["qualification_bindings"],
                reason="撤销后的 Artifact 不得获得新的资格通过回执",
                idempotency_key="artifact:market:qualification:revoked:0001",
                actor_ref="human_control_plane_admin_syn",
            )

    def test_manifest_secret_path_and_expected_revision_drift_fail_closed(self) -> None:
        unsafe = manifest()
        unsafe["spec"]["artifact_bundle"]["bundle_ref"] = "file:///Users/example/runtime.oci.tar"
        with self.assertRaisesRegex(RuntimeArtifactError, "runtime_artifact_manifest_invalid"):
            self.service.record_candidate(
                document=unsafe, expected_latest_revision_digest="none",
                reason="拒绝包含物理路径的 Runtime Artifact 候选",
                idempotency_key="artifact:unsafe:path:0001",
                actor_ref="human_control_plane_admin_syn",
            )
        for suffix, mutate in (
            (
                "media",
                lambda value: value["spec"]["oci_image"].update(
                    {"layout_media_type": "application/vnd.docker.image.rootfs.diff.tar"}
                ),
            ),
            (
                "floating",
                lambda value: value["spec"]["oci_image"].update(
                    {"floating_tag_allowed": True}
                ),
            ),
            (
                "source-image",
                lambda value: value["spec"].update(
                    {
                        "runtime_source_digest": value["spec"]["oci_image"][
                            "manifest_digest"
                        ]
                    }
                ),
            ),
        ):
            invalid = manifest()
            mutate(invalid)
            invalid["spec"]["manifest_digest"] = embedded_digest(
                invalid, "manifest_digest"
            )
            with self.assertRaisesRegex(
                RuntimeArtifactError, "runtime_artifact_manifest_invalid"
            ):
                self.service.record_candidate(
                    document=invalid,
                    expected_latest_revision_digest="none",
                    reason="错误 OCI 媒体类型、浮动标签或摘要替换必须拒绝",
                    idempotency_key=f"artifact:unsafe:{suffix}:0001",
                    actor_ref="human_control_plane_admin_syn",
                )
        candidate = self._candidate()
        changed = manifest()
        changed["spec"]["runtime_source_digest"] = "sha256:" + "e" * 64
        changed["spec"]["manifest_digest"] = embedded_digest(changed, "manifest_digest")
        with self.assertRaisesRegex(RuntimeArtifactError, "expected_revision_drift"):
            self.service.record_candidate(
                document=changed, expected_latest_revision_digest="none",
                reason="陈旧预期摘要必须失败关闭且不覆盖现有 Revision",
                idempotency_key="artifact:drift:0002",
                actor_ref="human_control_plane_admin_syn",
            )
        self.assertEqual(candidate["revision_digest"], self.service.list_artifacts()["items"][0]["revision_digest"])

    def test_node_capability_and_import_require_rootless_verified_exact_digest(self) -> None:
        candidate = self._candidate()
        self._qualify(candidate)
        preflight = self.service.record_capability_report(
            node_id="node_market_syn_001", document=capability(),
            idempotency_key="node:market:capability:0001", workload_identity="workload_market_runner_syn",
        )
        self.assertEqual("eligible_d0", preflight["status"])
        receipt = self.service.record_import_receipt(
            node_id="node_market_syn_001",
            document=import_receipt(candidate, preflight["report_digest"]),
            idempotency_key="node:market:import:0001", workload_identity="workload_market_runner_syn",
        )
        self.assertEqual("imported", receipt["outcome"])
        self.assertEqual(
            "urn:company-ai-os:draft:schema:runtime-artifact-import-receipt:0.3",
            receipt["contract_consumer"]["schema_id"],
        )
        post_import = self.service.record_capability_report(
            node_id="node_market_syn_001",
            document=capability(
                candidate["revision_digest"],
                import_receipt_digests=(receipt["receipt_digest"],),
            ),
            idempotency_key="node:market:capability:post-import:0001",
            workload_identity="workload_market_runner_syn",
        )
        self.assertEqual("eligible_d0", post_import["status"])
        with self.database.session() as session:
            receipt_types = set(session.scalars(select(ReceiptRow.receipt_type)))
            audit_types = set(session.scalars(select(AuditEventRow.event_type)))
        self.assertTrue(
            {
                "runtime_artifact_qualification_d0",
                "runtime_node_capability_report",
                "runtime_artifact_import",
            }.issubset(receipt_types)
        )
        self.assertTrue(
            {
                "runtime_artifact_qualified_d0",
                "runtime_node_capability_recorded",
                "runtime_artifact_import_recorded",
            }.issubset(audit_types)
        )

        rootful = capability(candidate["revision_digest"])
        rootful["node_id"] = "node_market_syn_002"
        rootful["engine"]["rootless"] = False
        denied = self.service.record_capability_report(
            node_id="node_market_syn_002", document=rootful,
            idempotency_key="node:market:capability:0002", workload_identity="workload_market_runner_syn",
        )
        self.assertEqual("ineligible", denied["status"])
        self.assertIn("runtime_node_rootless_engine_invalid", denied["reason_codes"])

        widened = capability(candidate["revision_digest"])
        widened["workload_scope"]["department_ids"].append("technology_center")
        widened_denied = self.service.record_capability_report(
            node_id="node_market_syn_001",
            document=widened,
            idempotency_key="node:market:capability:widened:0001",
            workload_identity="workload_market_runner_syn",
        )
        self.assertEqual("ineligible", widened_denied["status"])
        self.assertIn(
            "runtime_node_authorized_scope_drift",
            widened_denied["reason_codes"],
        )

    def test_lease_rejects_wrong_department_binding_and_unqualified_artifact(
        self,
    ) -> None:
        qualified = self._candidate()
        self._qualify(qualified)
        candidate_document = manifest()
        candidate_document["metadata"]["artifact_id"] = (
            "runtime_artifact_market_candidate_syn"
        )
        candidate_document["spec"]["lifecycle"]["status"] = "qualified_d0"
        candidate_document["spec"]["manifest_digest"] = embedded_digest(
            candidate_document, "manifest_digest"
        )
        unqualified = self.service.record_candidate(
            document=candidate_document,
            expected_latest_revision_digest="none",
            reason="登记作者自报 qualified 但没有公司资格回执的 Artifact",
            idempotency_key="artifact:market:unqualified:0001",
            actor_ref="human_control_plane_admin_syn",
        )
        preflight = self.service.record_capability_report(
            node_id="node_market_syn_001",
            document=capability(),
            idempotency_key="node:market:scope-capability:preflight:0001",
            workload_identity="workload_market_runner_syn",
        )
        import_receipts = []
        for suffix, artifact in (("qualified", qualified), ("candidate", unqualified)):
            receipt_document = import_receipt(artifact, preflight["report_digest"])
            receipt_document["metadata"]["receipt_id"] = (
                f"runtime_import_market_{suffix}_syn"
            )
            receipt_document["spec"]["receipt_digest"] = embedded_digest(
                receipt_document, "receipt_digest"
            )
            import_receipts.append(self.service.record_import_receipt(
                node_id="node_market_syn_001",
                document=receipt_document,
                idempotency_key=f"node:market:scope-import:{suffix}:0001",
                workload_identity="workload_market_runner_syn",
            ))
        report_document = capability(
            qualified["revision_digest"],
            import_receipt_digests=tuple(
                item["receipt_digest"] for item in import_receipts
            ),
        )
        report_document["verified_runtime_artifact_digests"].append(
            unqualified["revision_digest"]
        )
        report = self.service.record_capability_report(
            node_id="node_market_syn_001",
            document=report_document,
            idempotency_key="node:market:scope-capability:post-import:0001",
            workload_identity="workload_market_runner_syn",
        )

        def queue_run(
            *,
            run_id: str,
            artifact: dict,
            department_id: str,
            binding_ref: str,
            binding_digest: str,
        ) -> None:
            invocation = container_invocation().to_mapping()
            invocation.update(
                {
                    "department_id": department_id,
                    "agent_binding_ref": binding_ref,
                    "agent_binding_digest": binding_digest,
                    "runtime_artifact_digest": artifact["revision_digest"],
                    "runtime_image_digest": artifact["runtime_image_digest"],
                    "runtime_source_digest": artifact["runtime_source_digest"],
                    "isolation_profile_digest": artifact[
                        "isolation_profile_digest"
                    ],
                }
            )
            with self.database.session() as session:
                session.add(
                    RuntimeRunRow(
                        run_id=run_id,
                        task_id=f"task_{run_id}",
                        grant_id=f"grant_{run_id}",
                        grant_digest=DIGESTS["grant"],
                        composition_digest=DIGESTS["composition"],
                        runtime_source_digest=artifact["runtime_source_digest"],
                        runtime_artifact_digest=artifact["revision_digest"],
                        runtime_image_digest=artifact["runtime_image_digest"],
                        isolation_profile_digest=artifact[
                            "isolation_profile_digest"
                        ],
                        input_snapshot_refs=["artifact://inputs/market-001"],
                        invocation_digest=DIGESTS["task"],
                        idempotency_key=f"runtime:{run_id}:enqueue:0001",
                        invocation=invocation,
                        status="queued",
                        worker_identity=None,
                        cancel_reason_code=None,
                        failure_reason_code=None,
                        result_document=None,
                        result_digest=None,
                        created_at=NOW,
                        expires_at=NOW + timedelta(minutes=5),
                        started_at=None,
                        closed_at=None,
                        revision=0,
                    )
                )

        cases = (
            (
                "run_wrong_department_syn",
                qualified,
                "technology_center",
                "agent_binding_market_professional_syn",
                DIGESTS["binding"],
            ),
            (
                "run_wrong_binding_syn",
                qualified,
                "market_center",
                "agent_binding_other_professional_syn",
                DIGESTS["binding"],
            ),
            (
                "run_unqualified_artifact_syn",
                unqualified,
                "market_center",
                "agent_binding_market_professional_syn",
                DIGESTS["binding"],
            ),
        )
        for sequence, case in enumerate(cases, start=1):
            queue_run(
                run_id=case[0],
                artifact=case[1],
                department_id=case[2],
                binding_ref=case[3],
                binding_digest=case[4],
            )
            denied = self.service.claim_lease(
                node_id="node_market_syn_001",
                expected_capability_report_digest=report["report_digest"],
                idempotency_key=f"node:market:scope-lease:{sequence}:0001",
                workload_identity="workload_market_runner_syn",
            )
            self.assertFalse(denied["claimed"])
            with self.database.session() as session:
                row = session.query(RuntimeRunRow).filter_by(run_id=case[0]).one()
                row.status = "cancelled"

        queue_run(
            run_id="run_exact_scope_syn",
            artifact=qualified,
            department_id="market_center",
            binding_ref="agent_binding_market_professional_syn",
            binding_digest=DIGESTS["binding"],
        )
        claimed = self.service.claim_lease(
            node_id="node_market_syn_001",
            expected_capability_report_digest=report["report_digest"],
            idempotency_key="node:market:scope-lease:exact:0001",
            workload_identity="workload_market_runner_syn",
        )
        self.assertTrue(claimed["claimed"])
        self.assertRegex(claimed["receipt_id"], r"^receipt_runtime_lease_")
        with self.database.session() as session:
            self.assertIsNotNone(
                session.scalar(
                    select(ReceiptRow).where(
                        ReceiptRow.receipt_id == claimed["receipt_id"]
                    )
                )
            )
            self.assertIsNotNone(
                session.scalar(
                    select(AuditEventRow).where(
                        AuditEventRow.event_type == "runtime_node_lease_claimed"
                    )
                )
            )

    def test_rootless_engine_builds_non_executing_relay_only_request(self) -> None:
        request = RootlessDockerEngineAdapter().build_task_request(
            invocation=container_invocation(),
            isolation_profile=isolation_profile(),
            container_name="orbit-market-task-001",
        )
        self.assertFalse(request["shell"])
        self.assertFalse(request["execute"])
        self.assertEqual(["ALL"], request["security"]["cap_drop"])
        self.assertTrue(request["root_filesystem_read_only"])
        self.assertFalse(request["network"]["host_network"])
        self.assertEqual([], request["network"]["published_ports"])
        self.assertTrue(all("docker.sock" not in str(item) for item in request["mounts"]))

        unsafe = isolation_profile()
        unsafe["spec"]["engine"]["privileged"] = True
        unsafe["spec"]["profile_digest"] = embedded_digest(unsafe, "profile_digest")
        with self.assertRaisesRegex(ContainerEngineError, "container_isolation_profile_invalid"):
            RootlessDockerEngineAdapter().build_task_request(
                invocation=container_invocation(), isolation_profile=unsafe,
                container_name="orbit-market-task-001",
            )

        for mutate in (
            lambda value: value["spec"]["filesystem"].update(
                {"docker_socket_mounted": True}
            ),
            lambda value: value["spec"]["filesystem"].update(
                {"host_paths_mounted": True}
            ),
            lambda value: value["spec"]["filesystem"].update(
                {"windows_drives_mounted": True}
            ),
            lambda value: value["spec"]["linux_security"].update(
                {"added_capabilities": ["NET_ADMIN"]}
            ),
            lambda value: value["spec"]["network"].update(
                {"host_network": True}
            ),
        ):
            rejected = isolation_profile()
            mutate(rejected)
            rejected["spec"]["profile_digest"] = embedded_digest(
                rejected, "profile_digest"
            )
            with self.assertRaisesRegex(
                ContainerEngineError, "container_isolation_profile_invalid"
            ):
                RootlessDockerEngineAdapter().build_task_request(
                    invocation=container_invocation(),
                    isolation_profile=rejected,
                    container_name="orbit-market-task-001",
                )

        for source_ref in (
            "file:///Users/example/input.txt",
            "artifact://inputs/docker.sock",
            "artifact://nas/team-share",
            "artifact://inputs/mnt/windows",
        ):
            invocation_value = container_invocation().to_mapping()
            invocation_value["input_snapshot_refs"] = [source_ref]
            with self.assertRaisesRegex(
                (ContainerEngineError, RuntimeAdapterError),
                "(?:container_mount_source_invalid|runtime_input_ref_invalid)",
            ):
                RootlessDockerEngineAdapter().build_task_request(
                    invocation=RuntimeInvocation.from_mapping(invocation_value),
                    isolation_profile=isolation_profile(),
                    container_name="orbit-market-task-001",
                )

    def test_runtime_invocation_container_binding_is_all_or_nothing(self) -> None:
        value = container_invocation().to_mapping()
        self.assertTrue(RuntimeInvocation.from_mapping(value).container_bound)
        del value["runtime_image_digest"]
        with self.assertRaisesRegex(RuntimeAdapterError, "runtime_invocation_invalid"):
            RuntimeInvocation.from_mapping(value)

    def test_model_gateway_exchange_is_audited_and_always_denied_in_d0(self) -> None:
        response = self.service.exchange_model_token(
            node_id="node_market_syn_001",
            document={
                "task_id": "task_missing_syn", "grant_id": "grant_missing_syn",
                "run_id": "run_missing_syn", "route_revision_digest": DIGESTS["route"],
                "data_classification": "synthetic", "production_authorization": False,
            },
            idempotency_key="gateway:exchange:deny:0001",
            workload_identity="workload_market_runner_syn",
        )
        self.assertEqual("denied", response["outcome"])
        self.assertFalse(response["token_issued"])
        self.assertFalse(response["provider_called"])
        self.assertFalse(response["secret_bytes_accessed"])

    def test_container_evidence_is_append_only_lease_bound_and_image_bound(self) -> None:
        run_id = "run_market_container_evidence_syn"
        with self.database.session() as session:
            session.add(
                RuntimeRunRow(
                    run_id=run_id,
                    task_id="task_market_container_syn",
                    grant_id="grant_market_container_syn",
                    grant_digest=DIGESTS["grant"],
                    composition_digest=DIGESTS["composition"],
                    runtime_source_digest=DIGESTS["source"],
                    runtime_artifact_digest=DIGESTS["bundle"],
                    runtime_image_digest=DIGESTS["image"],
                    isolation_profile_digest=DIGESTS["isolation"],
                    input_snapshot_refs=["artifact://inputs/market-001"],
                    invocation_digest=DIGESTS["task"],
                    idempotency_key="runtime:evidence:enqueue:0001",
                    invocation={
                        "data_classification": "synthetic",
                        "production_authorization": False,
                    },
                    status="leased",
                    worker_identity="workload_market_runner_syn",
                    cancel_reason_code=None,
                    failure_reason_code=None,
                    result_document=None,
                    result_digest=None,
                    created_at=NOW,
                    expires_at=NOW + timedelta(minutes=5),
                    started_at=NOW,
                    closed_at=None,
                    revision=1,
                )
            )
            session.add(
                RuntimeNodeLeaseClaimRow(
                    lease_id="lease_market_container_syn",
                    idempotency_key="node:market:lease:0001",
                    node_id="node_market_syn_001",
                    run_id=run_id,
                    invocation_digest=DIGESTS["task"],
                    capability_report_digest=DIGESTS["provenance"],
                    status="active",
                    claimed_at=NOW,
                    expires_at=NOW + timedelta(minutes=5),
                    closed_at=None,
                )
            )
        with self.assertRaisesRegex(
            RuntimeArtifactError, "runtime_container_event_order_invalid"
        ):
            self.service.append_run_evidence(
                node_id="node_market_syn_001",
                run_id=run_id,
                evidence_type="container_event",
                document={
                    "event_type": "started",
                    "container_ref": "task://market/container-001",
                    "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
                    "retain_until": None,
                    "production_authorization": False,
                    "release_authorization": False,
                },
                idempotency_key="runtime:evidence:out-of-order:0001",
                workload_identity="workload_market_runner_syn",
            )
        for event, key in (("created", "created"), ("started", "started")):
            self.service.append_run_evidence(
                node_id="node_market_syn_001",
                run_id=run_id,
                evidence_type="container_event",
                document={
                    "event_type": event,
                    "container_ref": "task://market/container-001",
                    "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
                    "retain_until": None,
                    "production_authorization": False,
                    "release_authorization": False,
                },
                idempotency_key=f"runtime:evidence:{key}:0001",
                workload_identity="workload_market_runner_syn",
            )
        paused = self.service.append_run_evidence(
            node_id="node_market_syn_001",
            run_id=run_id,
            evidence_type="container_event",
            document={
                "event_type": "needs_input",
                "container_ref": "task://market/container-001",
                "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
                "retain_until": (NOW + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
                "production_authorization": False,
                "release_authorization": False,
            },
            idempotency_key="runtime:evidence:pause:0001",
            workload_identity="workload_market_runner_syn",
        )
        replay = self.service.append_run_evidence(
            node_id="node_market_syn_001",
            run_id=run_id,
            evidence_type="container_event",
            document={
                "event_type": "needs_input",
                "container_ref": "task://market/container-001",
                "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
                "retain_until": (NOW + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
                "production_authorization": False,
                "release_authorization": False,
            },
            idempotency_key="runtime:evidence:pause:0001",
            workload_identity="workload_market_runner_syn",
        )
        self.assertEqual(2, paused["sequence"])
        self.assertTrue(replay["idempotent_replay"])
        with self.database.session() as session:
            lease = session.query(RuntimeNodeLeaseClaimRow).filter_by(
                run_id=run_id
            ).one()
            run = session.query(RuntimeRunRow).filter_by(run_id=run_id).one()
            self.assertEqual("closed", lease.status)
            self.assertEqual("paused", run.status)

        with self.assertRaisesRegex(
            RuntimeArtifactError, "runtime_checkpoint_source_image_binding_drift"
        ):
            self.service.append_run_evidence(
                node_id="node_market_syn_001",
                run_id=run_id,
                evidence_type="checkpoint_receipt",
                document={
                    "checkpoint_refs": ["artifact://checkpoints/market-001"],
                    "source_image_digest": DIGESTS["base"],
                    "created_at": NOW.isoformat().replace("+00:00", "Z"),
                    "production_authorization": False,
                    "release_authorization": False,
                },
                idempotency_key="runtime:evidence:checkpoint:0001",
                workload_identity="workload_market_runner_syn",
            )

        checkpoint = self.service.append_run_evidence(
            node_id="node_market_syn_001",
            run_id=run_id,
            evidence_type="checkpoint_receipt",
            document={
                "checkpoint_refs": ["artifact://checkpoints/market-001"],
                "source_image_digest": DIGESTS["image"],
                "created_at": NOW.isoformat().replace("+00:00", "Z"),
                "production_authorization": False,
                "release_authorization": False,
            },
            idempotency_key="runtime:evidence:checkpoint:valid:0001",
            workload_identity="workload_market_runner_syn",
        )
        self.assertEqual(3, checkpoint["sequence"])

        cleanup_document = {
            "outcome": "completed",
            "container_removed": True,
            "network_removed": True,
            "workspace_removed": True,
            "removed_at": NOW.isoformat().replace("+00:00", "Z"),
            "production_authorization": False,
            "release_authorization": False,
        }
        cleanup = self.service.append_run_evidence(
            node_id="node_market_syn_001",
            run_id=run_id,
            evidence_type="cleanup_receipt",
            document=cleanup_document,
            idempotency_key="runtime:evidence:cleanup:0001",
            workload_identity="workload_market_runner_syn",
        )
        cleanup_replay = self.service.append_run_evidence(
            node_id="node_market_syn_001",
            run_id=run_id,
            evidence_type="cleanup_receipt",
            document=cleanup_document,
            idempotency_key="runtime:evidence:cleanup:0001",
            workload_identity="workload_market_runner_syn",
        )
        self.assertEqual(4, cleanup["sequence"])
        self.assertTrue(cleanup_replay["idempotent_replay"])
        with self.assertRaisesRegex(
            RuntimeArtifactError, "runtime_container_resume_requires_new_grant"
        ):
            self.service.append_run_evidence(
                node_id="node_market_syn_001",
                run_id=run_id,
                evidence_type="container_event",
                document={
                    "event_type": "resumed",
                    "container_ref": "task://market/container-001",
                    "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
                    "retain_until": None,
                    "production_authorization": False,
                    "release_authorization": False,
                },
                idempotency_key="runtime:evidence:after-cleanup:0001",
                workload_identity="workload_market_runner_syn",
            )

        terminal_run_id = "run_market_terminal_evidence_syn"
        with self.database.session() as session:
            session.add(
                RuntimeRunRow(
                    run_id=terminal_run_id,
                    task_id="task_market_terminal_syn",
                    grant_id="grant_market_terminal_syn",
                    grant_digest=DIGESTS["grant"],
                    composition_digest=DIGESTS["composition"],
                    runtime_source_digest=DIGESTS["source"],
                    runtime_artifact_digest=DIGESTS["bundle"],
                    runtime_image_digest=DIGESTS["image"],
                    isolation_profile_digest=DIGESTS["isolation"],
                    input_snapshot_refs=["artifact://inputs/market-terminal"],
                    invocation_digest=DIGESTS["composition"],
                    idempotency_key="runtime:evidence:terminal-enqueue:0001",
                    invocation={
                        "data_classification": "synthetic",
                        "production_authorization": False,
                    },
                    status="leased",
                    worker_identity="workload_market_runner_syn",
                    cancel_reason_code=None,
                    failure_reason_code=None,
                    result_document=None,
                    result_digest=None,
                    created_at=NOW,
                    expires_at=NOW + timedelta(minutes=5),
                    started_at=None,
                    closed_at=None,
                    revision=1,
                )
            )
            session.add(
                RuntimeNodeLeaseClaimRow(
                    lease_id="lease_market_terminal_syn",
                    idempotency_key="node:market:terminal-lease:0001",
                    node_id="node_market_syn_001",
                    run_id=terminal_run_id,
                    invocation_digest=DIGESTS["composition"],
                    capability_report_digest=DIGESTS["provenance"],
                    status="active",
                    claimed_at=NOW,
                    expires_at=NOW + timedelta(minutes=5),
                    closed_at=None,
                )
            )
        for sequence, event in enumerate(("created", "started", "cancelled")):
            terminal = self.service.append_run_evidence(
                node_id="node_market_syn_001",
                run_id=terminal_run_id,
                evidence_type="container_event",
                document={
                    "event_type": event,
                    "container_ref": "task://market/container-terminal",
                    "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
                    "retain_until": None,
                    "production_authorization": False,
                    "release_authorization": False,
                },
                idempotency_key=f"runtime:evidence:terminal:{event}:0001",
                workload_identity="workload_market_runner_syn",
            )
            self.assertEqual(sequence, terminal["sequence"])
        with self.database.session() as session:
            terminal_lease = session.query(RuntimeNodeLeaseClaimRow).filter_by(
                run_id=terminal_run_id
            ).one()
            terminal_run = session.query(RuntimeRunRow).filter_by(
                run_id=terminal_run_id
            ).one()
            self.assertEqual("closed", terminal_lease.status)
            self.assertEqual("cancelled", terminal_run.status)
        with self.database.session() as session:
            receipt_types = set(session.scalars(select(ReceiptRow.receipt_type)))
            audit_types = set(session.scalars(select(AuditEventRow.event_type)))
        self.assertTrue(
            {
                "runtime_container_event",
                "runtime_checkpoint_receipt",
                "runtime_cleanup_receipt",
            }.issubset(receipt_types)
        )
        self.assertTrue(
            {
                "runtime_container_event_recorded",
                "runtime_checkpoint_receipt_recorded",
                "runtime_cleanup_receipt_recorded",
            }.issubset(audit_types)
        )

    def test_cleanup_can_close_a_lease_before_any_runtime_starts(self) -> None:
        run_id = "run_market_prestart_cleanup_syn"
        now = NOW
        with self.database.session() as session:
            session.add(
                RuntimeRunRow(
                    run_id=run_id,
                    task_id="task_market_prestart_cleanup_syn",
                    grant_id="grant_market_prestart_cleanup_syn",
                    grant_digest=DIGESTS["grant"],
                    composition_digest=DIGESTS["composition"],
                    runtime_source_digest=DIGESTS["source"],
                    runtime_artifact_digest=DIGESTS["bundle"],
                    runtime_image_digest=DIGESTS["image"],
                    isolation_profile_digest=DIGESTS["isolation"],
                    input_snapshot_refs=["artifact://inputs/market-prestart"],
                    invocation_digest=DIGESTS["task"],
                    idempotency_key="runtime:prestart-cleanup:enqueue:0001",
                    invocation={
                        "data_classification": "synthetic",
                        "production_authorization": False,
                    },
                    status="leased",
                    worker_identity="workload_market_runner_syn",
                    cancel_reason_code=None,
                    failure_reason_code=None,
                    result_document=None,
                    result_digest=None,
                    created_at=now,
                    expires_at=now + timedelta(minutes=5),
                    started_at=None,
                    closed_at=None,
                    revision=1,
                )
            )
            session.add(
                RuntimeNodeLeaseClaimRow(
                    lease_id="lease_market_prestart_cleanup_syn",
                    idempotency_key="node:market:prestart-lease:0001",
                    node_id="node_market_syn_001",
                    run_id=run_id,
                    invocation_digest=DIGESTS["task"],
                    capability_report_digest=DIGESTS["provenance"],
                    status="active",
                    claimed_at=now,
                    expires_at=now + timedelta(minutes=5),
                    closed_at=None,
                )
            )
        receipt = self.service.append_run_evidence(
            node_id="node_market_syn_001",
            run_id=run_id,
            evidence_type="cleanup_receipt",
            document={
                "outcome": "cancelled",
                "container_removed": True,
                "network_removed": True,
                "workspace_removed": True,
                "removed_at": now.isoformat().replace("+00:00", "Z"),
                "production_authorization": False,
                "release_authorization": False,
            },
            idempotency_key="runtime:prestart-cleanup:receipt:0001",
            workload_identity="workload_market_runner_syn",
        )
        self.assertEqual("cleanup_receipt", receipt["evidence_type"])
        self.assertRegex(receipt["receipt_id"], r"^receipt_runtime_evidence_")
        with self.database.session() as session:
            lease = session.query(RuntimeNodeLeaseClaimRow).filter_by(
                run_id=run_id
            ).one()
            run = session.query(RuntimeRunRow).filter_by(run_id=run_id).one()
            self.assertEqual("closed", lease.status)
            self.assertEqual("cancelled", run.status)
            self.assertEqual("runtime_cleanup_before_start", run.cancel_reason_code)
            self.assertIsNone(run.started_at)

    def test_result_package_is_grant_run_bound_and_idempotent_before_cleanup(self) -> None:
        run_id = "run_market_result_syn"
        task_id = "tsk_market_result_syn_001"
        grant_id = "grant_market_result_syn_001"
        with self.database.session() as session:
            session.add(
                RuntimeRunRow(
                    run_id=run_id,
                    task_id=task_id,
                    grant_id=grant_id,
                    grant_digest=DIGESTS["grant"],
                    composition_digest=DIGESTS["composition"],
                    runtime_source_digest=DIGESTS["source"],
                    runtime_artifact_digest=DIGESTS["bundle"],
                    runtime_image_digest=DIGESTS["image"],
                    isolation_profile_digest=DIGESTS["isolation"],
                    input_snapshot_refs=["artifact://inputs/market-result"],
                    invocation_digest=DIGESTS["task"],
                    idempotency_key="runtime:result:enqueue:0001",
                    invocation={
                        "data_classification": "synthetic",
                        "production_authorization": False,
                    },
                    status="leased",
                    worker_identity="workload_market_runner_syn",
                    cancel_reason_code=None,
                    failure_reason_code=None,
                    result_document=None,
                    result_digest=None,
                    created_at=NOW,
                    expires_at=NOW + timedelta(minutes=5),
                    started_at=None,
                    closed_at=None,
                    revision=1,
                )
            )
            session.add(
                RuntimeNodeLeaseClaimRow(
                    lease_id="lease_market_result_syn",
                    idempotency_key="node:market:result-lease:0001",
                    node_id="node_market_syn_001",
                    run_id=run_id,
                    invocation_digest=DIGESTS["task"],
                    capability_report_digest=DIGESTS["provenance"],
                    status="active",
                    claimed_at=NOW,
                    expires_at=NOW + timedelta(minutes=5),
                    closed_at=None,
                )
            )
        for event in ("created", "started", "completed"):
            self.service.append_run_evidence(
                node_id="node_market_syn_001",
                run_id=run_id,
                evidence_type="container_event",
                document={
                    "event_type": event,
                    "container_ref": "task://market/container-result",
                    "recorded_at": NOW.isoformat().replace("+00:00", "Z"),
                    "retain_until": None,
                    "production_authorization": False,
                    "release_authorization": False,
                },
                idempotency_key=f"runtime:result:event:{event}:0001",
                workload_identity="workload_market_runner_syn",
            )
        document = {
            "schema_version": "0.3",
            "result_id": "res_market_result_syn_001",
            "task_id": task_id,
            "agent_id": "agt_market_result_syn",
            "agent_version": "0.1.0-d0.1",
            "agent_definition_ref": {
                "id": "agt_market_result_syn", "version": "0.1.0-d0.1",
                "digest": DIGESTS["task"],
            },
            "agent_binding_ref": {
                "id": "bind_market_result_syn", "version": "0.1.0-d0.1",
                "digest": DIGESTS["binding"],
            },
            "execution_grant_ref": {
                "id": grant_id, "version": "0.1.0-d0.1",
                "digest": DIGESTS["grant"],
            },
            "invocation_ref": "invocation_market_result_syn_001",
            "hierarchy_snapshot_ref": "hsnap_market_result_syn_001",
            "runtime_run_ref": f"runtime-run://{run_id}",
            "status": "succeeded",
            "summary": "合成任务已完成确定性检查。",
            "artifacts": [],
            "evidence": [],
            "limitations": ["仅为合成 D0 证据。"],
            "risk_flags": [],
            "tool_usage": [],
            "data_usage_receipt_refs": [],
            "model_usage_refs": [],
            "used_dependency_refs": [],
            "business_outcome": {
                "source_system_ref": "runtime://orbit/deterministic-d0",
                "source_status": "passed",
                "normalized_outcome": "completed",
                "reason_codes": ["synthetic_check_passed"],
            },
            "evaluation": {"state": "not_run", "evaluation_refs": []},
            "human_disposition": {"state": "pending"},
            "audit_event_refs": ["audit_market_result_syn_001"],
            "produced_at": NOW.isoformat().replace("+00:00", "Z"),
        }
        recorded = self.service.append_run_evidence(
            node_id="node_market_syn_001",
            run_id=run_id,
            evidence_type="result_package",
            document=document,
            idempotency_key="runtime:result:package:0001",
            workload_identity="workload_market_runner_syn",
        )
        replay = self.service.append_run_evidence(
            node_id="node_market_syn_001",
            run_id=run_id,
            evidence_type="result_package",
            document=document,
            idempotency_key="runtime:result:package:0002",
            workload_identity="workload_market_runner_syn",
        )
        self.assertEqual("result_package", recorded["evidence_type"])
        self.assertTrue(replay["idempotent_replay"])
        with self.database.session() as session:
            run = session.query(RuntimeRunRow).filter_by(run_id=run_id).one()
            self.assertEqual(document, run.result_document)
            self.assertEqual("completed", run.status)
            self.assertIsNotNone(run.result_digest)
        changed = copy.deepcopy(document)
        changed["summary"] = "不同的结果。"
        with self.assertRaisesRegex(RuntimeArtifactError, "runtime_result_conflict"):
            self.service.append_run_evidence(
                node_id="node_market_syn_001",
                run_id=run_id,
                evidence_type="result_package",
                document=changed,
                idempotency_key="runtime:result:package:0003",
                workload_identity="workload_market_runner_syn",
            )

    def test_admin_api_exposes_only_logical_bundle_metadata(self) -> None:
        app = FastAPI()
        install_runtime_artifact_routes(
            app, service=self.service,
            authenticate_human=lambda request, required_roles: {"human_ref": "human_control_plane_admin_syn", "role_refs": list(required_roles)},
            require_mutating_human=lambda request, required_roles: {"human_ref": "human_control_plane_admin_syn", "role_refs": list(required_roles)},
            require_workload=lambda request: {"workload_identity": "workload_market_runner_syn"},
        )
        with TestClient(app) as client:
            created = client.post(
                "/v1/runtime-artifact-candidates",
                json={"document": manifest(), "expected_latest_revision_digest": "none", "reason": "通过公司 API 登记精确 D0 Runtime Artifact", "idempotency_key": "artifact:api:create:0001"},
            )
            self.assertEqual(201, created.status_code, created.text)
            item = created.json()
            self.assertEqual("candidate", item["status"])
            qualified = client.post(
                "/v1/runtime-artifacts/"
                f"{item['artifact_id']}/revisions/{item['revision_digest']}"
                "/qualifications",
                json={
                    **item["qualification_bindings"],
                    "reason": "通过公司 API 记录精确摘要的合成 D0 资格回执",
                    "idempotency_key": "artifact:api:qualification:0001",
                },
            )
            self.assertEqual(201, qualified.status_code, qualified.text)
            self.assertEqual("qualified_d0", qualified.json()["status"])
            bundle = client.get(f"/v1/runtime-artifacts/{item['artifact_id']}/revisions/{item['revision_digest']}/bundle")
            self.assertEqual(200, bundle.status_code)
            self.assertFalse(bundle.json()["bundle_bytes_included"])
            self.assertEqual(
                "explicit_revision_digest_only",
                bundle.json()["selection_semantics"],
            )
            self.assertNotIn("content", bundle.json())
            missing_revision = client.get(
                f"/v1/runtime-artifacts/{item['artifact_id']}/bundle"
            )
            explicit_revision = client.get(
                f"/v1/runtime-artifacts/{item['artifact_id']}/bundle",
                params={"revision_digest": item["revision_digest"]},
            )
            self.assertEqual(422, missing_revision.status_code)
            self.assertEqual(200, explicit_revision.status_code)
            self.assertEqual(
                item["revision_digest"], explicit_revision.json()["revision_digest"]
            )


if __name__ == "__main__":
    unittest.main()

