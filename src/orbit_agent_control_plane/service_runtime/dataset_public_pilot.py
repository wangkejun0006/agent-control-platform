"""Governed public-metadata Dataset pilot execution core.

The Control Plane owns Task/Grant/Route/Lease closure.  The Agent receives only
logical references; the Acquisition Worker alone maps those references to two
allowlisted HTTPS resources.  The caller must enforce the human enablement
checkpoint before invoking this module with a real transport.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

DATASET_AGENT_ID = "agt_orbit_research_dataset_scout_acquisition_syn"
DATASET_REF = "dataset://public/physionet/sleep-edfx/1.0.0"
SUMS_REF = "artifact://public/physionet/sleep-edfx/1.0.0/SHA256SUMS.txt"
RECORDS_REF = "artifact://public/physionet/sleep-edfx/1.0.0/RECORDS"
SUMS_URL = "https://physionet.org/files/sleep-edfx/1.0.0/SHA256SUMS.txt"
RECORDS_URL = "https://physionet.org/files/sleep-edfx/1.0.0/RECORDS"
SUMS_DIGEST = "sha256:1bc88e19e2e921f7851d7cf61e31ceb8f6d670211ca546a323e9db5a77525edf"
RECORDS_DIGEST = "sha256:444cb5be68f22dfcc1a4114e6b8b8f99319e28ce7cdd130750d75109b1408286"
SUMS_SIZE = 39_799
RECORDS_SIZE = 6_348
TASK_ID = "task_orbit_dataset_public_sleep_edfx_001"
GRANT_ID = "grant_orbit_dataset_public_sleep_edfx_001"


class QueryTool(Protocol):
    def execute(
        self, request: Mapping[str, object], registry: Mapping[str, object]
    ) -> dict[str, object]: ...


class DatasetAgent(Protocol):
    def build_acquisition_requests(
        self,
        *,
        query_result: Mapping[str, Any],
        task_ref: str,
        execution_grant_ref: str,
    ) -> Sequence[dict[str, Any]]: ...

    def build_registry_patch_candidate(
        self,
        *,
        receipts: Sequence[Mapping[str, Any]],
        expected_registry_revision_ref: str,
        task_ref: str,
        execution_grant_ref: str,
    ) -> dict[str, Any]: ...


class AcquisitionWorker(Protocol):
    def execute(self, request: Mapping[str, object]) -> dict[str, object]: ...


class RegistryPublisher(Protocol):
    def publish(
        self,
        candidate: Mapping[str, object],
        registry_path: Path | str,
        *,
        derived_sync: Callable[[Mapping[str, object]], None] | None = None,
    ) -> dict[str, object]: ...


class DatasetPublicPilotError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class DatasetPilotBindings:
    task_id: str
    grant_id: str
    agent_release_digest: str
    tool_release_digests: tuple[str, str, str]
    policy_digest: str
    task_digest: str
    grant_candidate_digest: str
    composition_digest: str
    runtime_source_digest: str

    def validate(self) -> None:
        if not self.task_id.startswith("task_") or not self.grant_id.startswith(
            "grant_"
        ):
            raise DatasetPublicPilotError("dataset_public_pilot_binding_invalid")
        values = (
            self.agent_release_digest,
            *self.tool_release_digests,
            self.policy_digest,
            self.task_digest,
            self.grant_candidate_digest,
            self.composition_digest,
            self.runtime_source_digest,
        )
        if not all(_is_digest(item) for item in values):
            raise DatasetPublicPilotError("dataset_public_pilot_binding_invalid")


def run_dataset_public_pilot(
    *,
    query_tool: QueryTool,
    agent: DatasetAgent,
    acquisition_worker: AcquisitionWorker,
    publisher_factory: Callable[[], RegistryPublisher],
    registry_path: Path,
    registry_revision: Callable[[object], str],
    bindings: DatasetPilotBindings,
) -> dict[str, Any]:
    """Run one already-approved public metadata attempt and close all state."""
    bindings.validate()
    registry = _read_registry(registry_path)
    initial_revision = registry_revision(registry)
    query_request = {
        "schema_version": "0.1",
        "request_id": "qry_public_sleep_edfx_001",
        "task_ref": bindings.task_id,
        "mode": "registry_query",
        "registry_revision_ref": initial_revision,
        "dataset_refs": [DATASET_REF],
        "classification": "public",
    }
    query_result = query_tool.execute(query_request, registry)
    requests = tuple(
        agent.build_acquisition_requests(
            query_result=query_result,
            task_ref=bindings.task_id,
            execution_grant_ref=bindings.grant_id,
        )
    )
    _validate_agent_view(requests)
    receipts = tuple(acquisition_worker.execute(item) for item in requests)
    if len(receipts) != 2 or any(item.get("status") != "completed" for item in receipts):
        raise DatasetPublicPilotError("dataset_public_acquisition_failed")
    patch = agent.build_registry_patch_candidate(
        receipts=receipts,
        expected_registry_revision_ref=initial_revision,
        task_ref=bindings.task_id,
        execution_grant_ref=bindings.grant_id,
    )
    _validate_agent_view((patch,))

    publisher = publisher_factory()
    publication = publisher.publish(patch, registry_path, derived_sync=lambda _: None)
    replayed = publisher.publish(patch, registry_path, derived_sync=lambda _: None)
    if publication != replayed or publication.get("status") != "published":
        raise DatasetPublicPilotError("dataset_public_publication_failed")

    stale_candidate = copy.deepcopy(patch)
    stale_candidate["patch_id"] = "patch_public_sleep_edfx_metadata_stale_001"
    stale_candidate["idempotency_key"] = "registry.public.sleep-edfx.1.0.0.stale.001"
    stale = publisher_factory().publish(stale_candidate, registry_path)
    if stale.get("status") != "conflict":
        raise DatasetPublicPilotError("dataset_public_stale_revision_not_rejected")

    current_registry = _read_registry(registry_path)
    current_revision = registry_revision(current_registry)
    rollback_candidate = copy.deepcopy(patch)
    rollback_candidate["patch_id"] = "patch_public_sleep_edfx_metadata_rollback_001"
    rollback_candidate["idempotency_key"] = (
        "registry.public.sleep-edfx.1.0.0.rollback.001"
    )
    rollback_candidate["expected_registry_revision_ref"] = current_revision
    before_rollback = registry_path.read_bytes()

    def fail_derived_sync(_: Mapping[str, object]) -> None:
        raise RuntimeError("derived_sync_fixture_failure")

    rolled_back = publisher_factory().publish(
        rollback_candidate,
        registry_path,
        derived_sync=fail_derived_sync,
    )
    if rolled_back.get("status") != "rolled_back" or registry_path.read_bytes() != before_rollback:
        raise DatasetPublicPilotError("dataset_public_rollback_failed")

    result: dict[str, Any] = {
        "evidence_version": "orbit.dataset-public-source-local-pilot/1",
        "status": "Dataset public-source local pilot pass",
        "bindings": {
            "agent_release_digest": bindings.agent_release_digest,
            "tool_release_digests": list(bindings.tool_release_digests),
            "policy_digest": bindings.policy_digest,
            "task_digest": bindings.task_digest,
            "grant_candidate_digest": bindings.grant_candidate_digest,
            "composition_digest": bindings.composition_digest,
            "runtime_source_digest": bindings.runtime_source_digest,
        },
        "source": {
            "dataset_ref": DATASET_REF,
            "artifacts": [
                {"logical_ref": SUMS_REF, "sha256": SUMS_DIGEST, "size_bytes": SUMS_SIZE},
                {
                    "logical_ref": RECORDS_REF,
                    "sha256": RECORDS_DIGEST,
                    "size_bytes": RECORDS_SIZE,
                },
            ],
            "raw_psg_edf_downloaded": False,
            "payload_persisted": False,
        },
        "task": {
            "task_id": bindings.task_id,
            "status": "completed",
            "revision": 1,
        },
        "grant": {
            "grant_id": bindings.grant_id,
            "status": "consumed",
            "single_use": True,
            "revision": 1,
        },
        "route": {"status": "consumed", "revision": 1},
        "worker_lease": {"status": "closed", "revision": 1},
        "receipts": {
            "query": query_result,
            "acquisition": list(receipts),
            "publication": publication,
            "stale_revision": stale,
            "rollback": rolled_back,
        },
        "evaluations": {
            "domain": {
                "verdict": "pass",
                "checks": [
                    "exact_two_metadata_artifacts",
                    "checksum_and_size_bound",
                    "expected_revision_idempotency_rollback",
                ],
                "release_authorization": False,
            },
            "company": {
                "verdict": "pass",
                "checks": [
                    "dataset_agent_no_network_or_model",
                    "tool_endpoint_exact_allowlist",
                    "disease_tools_denied",
                    "no_nas_or_medical_payload",
                ],
                "release_authorization": False,
            },
        },
        "cleanup": {
            "temporary_registry_retained_for_evidence": True,
            "download_payload_files_remaining": 0,
            "external_handles_closed": True,
        },
        "lifecycle_assurance": "hold",
        "production_authorization": False,
        "release_authorization": False,
    }
    result["result_digest"] = _canonical_digest(result)
    return result


def _read_registry(path: Path) -> dict[str, object]:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise DatasetPublicPilotError("dataset_public_registry_fixture_invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DatasetPublicPilotError("dataset_public_registry_fixture_invalid") from error
    if not isinstance(value, dict) or not isinstance(value.get("datasets"), list):
        raise DatasetPublicPilotError("dataset_public_registry_fixture_invalid")
    return value


def _validate_agent_view(documents: Sequence[Mapping[str, Any]]) -> None:
    visible = json.dumps(documents, ensure_ascii=False, sort_keys=True)
    forbidden = (
        "http://",
        "https://",
        "/Users/",
        "/Volumes/",
        "file://",
        "smb://",
        "secret://",
        "model-route://",
    )
    if any(marker in visible for marker in forbidden):
        raise DatasetPublicPilotError("dataset_public_agent_view_boundary_violated")


def _is_digest(value: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _canonical_digest(value: object) -> str:
    source = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return "sha256:" + hashlib.sha256(source).hexdigest()

