from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.registration import (
    HISTORICAL_ALPHA1_COMPANY_LOCK,
    HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
)
from orbit_agent_control_plane.tool_registry import (
    DEFAULT_DATASET_TOOL_INTAKE_PROFILE,
    ToolRegistryError,
    load_tool_candidate_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
DATASET_REGISTRY_ROOT = (
    ROOT / "showcase/vendor-fixtures/dataset-registry"
)
RELEASE_MANIFEST = Path("contracts/tools/0.1.0/release-manifest.json")
HISTORICAL_ALPHA1_ARGS = {
    "company_lock_path": HISTORICAL_ALPHA1_COMPANY_LOCK,
    "contract_bundle_root": HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
}


class ToolRegistryTest(unittest.TestCase):
    def assert_reason(self, reason: str, callback) -> None:
        with self.assertRaises(ToolRegistryError) as raised:
            callback()
        self.assertEqual(reason, raised.exception.reason_code)

    def test_exact_release_registers_three_independent_draft_candidates(self) -> None:
        bundle = load_tool_candidate_bundle(
            DATASET_REGISTRY_ROOT, RELEASE_MANIFEST, **HISTORICAL_ALPHA1_ARGS
        )

        self.assertEqual("dataset-tools-v0.1.0-synthetic", bundle.source_release_id)
        self.assertEqual("contract-v0.1.0-alpha.1", bundle.company_contract_release_id)
        self.assertEqual(3, len(bundle.candidates))
        self.assertEqual(
            {
                "tool_orbit_dataset_query_watchlist",
                "tool_orbit_dataset_acquisition_worker",
                "tool_orbit_dataset_registry_publisher",
            },
            {candidate.tool_id for candidate in bundle.candidates},
        )
        for candidate in bundle.candidates:
            with self.subTest(tool_id=candidate.tool_id):
                self.assertEqual(candidate.manifest_digest, candidate.release_digest)
                self.assertEqual("evaluation", candidate.source_manifest_status)
                self.assertEqual("draft", candidate.registry_status)
                self.assertTrue(candidate.synthetic_only)
                self.assertFalse(candidate.company_authoritative)
                self.assertTrue(candidate.capabilities)
                self.assertTrue(candidate.d0_allowed_operation_ids)
                self.assertIn("public", candidate.allowed_data_classifications)

        acquisition = bundle.candidate(
            "tool_orbit_dataset_acquisition_worker"
        )
        self.assertEqual(
            ("acquire_synthetic_artifact",),
            acquisition.d0_allowed_operation_ids,
        )
        self.assertIn("acquire_authorized_artifact", acquisition.operation_ids)
        self.assertNotIn(
            "acquire_authorized_artifact", acquisition.d0_allowed_operation_ids
        )

    def test_manifest_and_domain_schema_raw_byte_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "registry"
            shutil.copytree(DATASET_REGISTRY_ROOT / "contracts", fixture / "contracts")
            shutil.copytree(DATASET_REGISTRY_ROOT / "schemas", fixture / "schemas")
            manifest = (
                fixture
                / "contracts"
                / "tools"
                / "0.1.0"
                / "query-watchlist.tool-manifest.json"
            )
            manifest.write_bytes(manifest.read_bytes() + b"\n")
            self.assert_reason(
                "tool_manifest_digest_mismatch",
                lambda: load_tool_candidate_bundle(
                    fixture, RELEASE_MANIFEST, **HISTORICAL_ALPHA1_ARGS
                ),
            )

            shutil.rmtree(fixture)
            shutil.copytree(DATASET_REGISTRY_ROOT / "contracts", fixture / "contracts")
            shutil.copytree(DATASET_REGISTRY_ROOT / "schemas", fixture / "schemas")
            schema = fixture / "schemas" / "dataset_acquisition_request.schema.json"
            schema.write_bytes(schema.read_bytes() + b"\n")
            self.assert_reason(
                "domain_schema_digest_mismatch",
                lambda: load_tool_candidate_bundle(
                    fixture, RELEASE_MANIFEST, **HISTORICAL_ALPHA1_ARGS
                ),
            )

    def test_unreviewed_release_or_widened_profile_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile_path = Path(temporary) / "profile.json"
            profile = json.loads(
                DEFAULT_DATASET_TOOL_INTAKE_PROFILE.read_text(encoding="utf-8")
            )
            profile["boundary"]["activation_authorized"] = True
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            self.assert_reason(
                "tool_intake_profile_invalid",
                lambda: load_tool_candidate_bundle(
                    DATASET_REGISTRY_ROOT,
                    RELEASE_MANIFEST,
                    intake_profile_path=profile_path,
                    **HISTORICAL_ALPHA1_ARGS,
                ),
            )

            profile = json.loads(
                DEFAULT_DATASET_TOOL_INTAKE_PROFILE.read_text(encoding="utf-8")
            )
            acquisition = next(
                item
                for item in profile["tools"]
                if item["tool_id"] == "tool_orbit_dataset_acquisition_worker"
            )
            acquisition["d0_allowed_operation_ids"] = [
                "acquire_authorized_artifact"
            ]
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            self.assert_reason(
                "tool_d0_operation_boundary_invalid",
                lambda: load_tool_candidate_bundle(
                    DATASET_REGISTRY_ROOT,
                    RELEASE_MANIFEST,
                    intake_profile_path=profile_path,
                    **HISTORICAL_ALPHA1_ARGS,
                ),
            )

    def test_duplicate_json_keys_and_symlinked_source_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / "registry"
            shutil.copytree(DATASET_REGISTRY_ROOT / "contracts", fixture / "contracts")
            shutil.copytree(DATASET_REGISTRY_ROOT / "schemas", fixture / "schemas")
            release = fixture / RELEASE_MANIFEST
            release.write_text(
                release.read_text(encoding="utf-8").replace(
                    '"release_id":',
                    '"release_id": "duplicate",\n  "release_id":',
                    1,
                ),
                encoding="utf-8",
            )
            self.assert_reason(
                "duplicate_json_key",
                lambda: load_tool_candidate_bundle(
                    fixture, RELEASE_MANIFEST, **HISTORICAL_ALPHA1_ARGS
                ),
            )

            release.unlink()
            release.symlink_to(DATASET_REGISTRY_ROOT / RELEASE_MANIFEST)
            self.assert_reason(
                "source_symlink_forbidden",
                lambda: load_tool_candidate_bundle(
                    fixture, RELEASE_MANIFEST, **HISTORICAL_ALPHA1_ARGS
                ),
            )


if __name__ == "__main__":
    unittest.main()

