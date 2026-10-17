from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.service_runtime.dataset_public_pilot import (
    RECORDS_DIGEST,
    RECORDS_SIZE,
    SUMS_DIGEST,
    SUMS_SIZE,
    DatasetPilotBindings,
    run_dataset_public_pilot,
)

ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC = ROOT.parent / "orbit-health-system/scientific-research-platform"
sys.path.insert(0, str(SCIENTIFIC / "src"))

from orbit_scientific_research_platform.dataset_agent.public_pilot import (
    DATASET_REF,
    PublicPilotDatasetAgent,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _registry_revision(value: object) -> str:
    source = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "registry://revision/sha256/" + hashlib.sha256(source).hexdigest()


class _QueryFixture:
    def execute(self, request: dict[str, object], registry: dict[str, object]) -> dict:
        if request["registry_revision_ref"] != _registry_revision(registry):
            raise ValueError("registry_revision_conflict")
        return {
            "classification": "public",
            "dataset_refs": [DATASET_REF],
            "registry_revision_ref": request["registry_revision_ref"],
        }


class _PublisherFixture:
    def __init__(self, sandbox: Path) -> None:
        self.sandbox = sandbox
        self.results: dict[str, tuple[str, dict]] = {}

    def publish(self, candidate, registry_path, *, derived_sync=None):
        target = Path(registry_path)
        target.resolve().relative_to(self.sandbox)
        source = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(source.encode()).hexdigest()
        key = str(candidate["idempotency_key"])
        if key in self.results:
            previous_digest, result = self.results[key]
            if previous_digest != digest:
                raise ValueError("idempotency_conflict")
            return copy.deepcopy(result)
        original = target.read_bytes()
        registry = json.loads(original)
        previous_revision = _registry_revision(registry)
        if candidate["expected_registry_revision_ref"] != previous_revision:
            result = {"status": "conflict", "rollback_performed": False}
        else:
            updated = copy.deepcopy(registry)
            row = updated["datasets"][0]
            artifacts = row.setdefault("acquired_artifacts", [])
            for operation in candidate["operations"]:
                artifact = {
                    name: operation[name]
                    for name in (
                        "acquisition_receipt_ref",
                        "artifact_ref",
                        "content_sha256",
                        "size_bytes",
                    )
                }
                if artifact not in artifacts:
                    artifacts.append(artifact)
            target.write_text(json.dumps(updated, sort_keys=True) + "\n")
            try:
                if derived_sync is not None:
                    derived_sync(updated)
            except RuntimeError:
                target.write_bytes(original)
                result = {"status": "rolled_back", "rollback_performed": True}
            else:
                result = {"status": "published", "rollback_performed": False}
        self.results[key] = (digest, copy.deepcopy(result))
        return result


class _MetadataReceiptWorker:
    """Non-network fixture; byte/checksum behavior is tested in the Tool repo."""

    def execute(self, request: dict[str, object]) -> dict[str, object]:
        digest = str(request["expected_content_sha256"])
        size = int(request["expected_size_bytes"])
        if (digest, size) not in {
            (SUMS_DIGEST, SUMS_SIZE),
            (RECORDS_DIGEST, RECORDS_SIZE),
        }:
            raise ValueError("fixture_artifact_drift")
        return {
            "schema_version": "0.1",
            "receipt_id": "acqrcpt_" + digest[7:27],
            "request_ref": "receipt://acquisition-request/" + str(request["request_id"]),
            "dataset_ref": request["dataset_ref"],
            "artifact_ref": "artifact://public/sha256/" + digest[7:],
            "content_sha256": digest,
            "size_bytes": size,
            "bytes_transferred": size,
            "status": "completed",
            "classification": "public",
            "synthetic": False,
        }


class DatasetPublicFullChainTests(unittest.TestCase):
    def test_fixture_closes_task_grant_route_lease_evaluations_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary).resolve()
            registry_path = sandbox / "registry.public.json"
            registry_path.write_text(
                json.dumps(
                    {
                        "schema_version": "0.1",
                        "datasets": [{"dataset_ref": DATASET_REF, "release": "1.0.0"}],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = run_dataset_public_pilot(
                query_tool=_QueryFixture(),
                agent=PublicPilotDatasetAgent(),
                acquisition_worker=_MetadataReceiptWorker(),
                publisher_factory=lambda: _PublisherFixture(sandbox),
                registry_path=registry_path,
                registry_revision=_registry_revision,
                bindings=DatasetPilotBindings(
                    task_id="task_dataset_public_test_001",
                    grant_id="grant_dataset_public_test_001",
                    agent_release_digest=_digest("a"),
                    tool_release_digests=(_digest("b"), _digest("c"), _digest("d")),
                    policy_digest=_digest("e"),
                    task_digest=_digest("f"),
                    grant_candidate_digest=_digest("1"),
                    composition_digest=_digest("2"),
                    runtime_source_digest=_digest("3"),
                ),
            )
        self.assertEqual("Dataset public-source local pilot pass", result["status"])
        self.assertEqual("completed", result["task"]["status"])
        self.assertEqual("consumed", result["grant"]["status"])
        self.assertEqual("closed", result["worker_lease"]["status"])
        self.assertEqual("pass", result["evaluations"]["domain"]["verdict"])
        self.assertEqual("pass", result["evaluations"]["company"]["verdict"])
        self.assertEqual("conflict", result["receipts"]["stale_revision"]["status"])
        self.assertEqual("rolled_back", result["receipts"]["rollback"]["status"])
        self.assertEqual(0, result["cleanup"]["download_payload_files_remaining"])
        self.assertEqual("hold", result["lifecycle_assurance"])
        self.assertFalse(result["release_authorization"])

    def test_cross_chain_permissions_and_agent_view_fail_closed(self) -> None:
        allowed = {
            "dataset": {
                "query_registry_watchlist",
                "acquire_public_metadata_artifact",
                "publish_registry_patch_sandbox",
            },
            "disease": {
                "model.invoke",
                "search_public_corpus",
                "fetch_public_record",
            },
        }
        self.assertTrue(allowed["dataset"].isdisjoint(allowed["disease"]))
        candidate = copy.deepcopy(allowed)
        candidate["dataset"].add("model.invoke")
        self.assertFalse(candidate["dataset"].isdisjoint(candidate["disease"]))


if __name__ == "__main__":
    unittest.main()

