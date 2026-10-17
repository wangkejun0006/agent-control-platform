import hashlib
import json
import re
import unittest
from pathlib import Path


class CompanyContractLockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[1]
        self.lock = json.loads(
            (self.repo_root / "references" / "company-contract-lock.json").read_text(
                encoding="utf-8"
            )
        )

    def test_lock_records_approved_architecture_and_contract_release(self) -> None:
        lock = self.lock
        self.assertEqual("0.2.0", lock["lock_version"])
        self.assertEqual("current_development_baseline", lock["status"])
        self.assertEqual("orbit-agent-architecture", lock["authority"]["repository_id"])
        self.assertEqual(
            "80391eafa430ac7ee84d6057ef028ab92209bbd1",
            lock["authority"]["architecture_commit"],
        )
        self.assertEqual(
            "contract-v0.1.0-alpha.2",
            lock["authority"]["contract_release_id"],
        )
        self.assertEqual(
            "bc7f21e67dbadd6aa618954fea4656b3387382f9",
            lock["authority"]["contract_git_commit"],
        )
        self.assertEqual(
            "sha256:ffc9b78cda101e263dcbc0a60060cc48c5c11dec0eb1aba5aca50a74b489521a",
            lock["authority"]["contract_release_manifest_sha256"],
        )
        self.assertEqual(
            ["synthetic", "public"],
            lock["pilot_boundary"]["data_classifications"],
        )
        self.assertEqual(
            "forbidden_in_initial_loop",
            lock["pilot_boundary"]["model_usage"],
        )
        self.assertEqual("forbidden", lock["pilot_boundary"]["network_access"])
        self.assertFalse(lock["pilot_boundary"]["production_authorization"])

    def test_contract_release_matches_embedded_consumer_bundle(self) -> None:
        authority = self.lock["authority"]
        bundle_root = (
            self.repo_root
            / "packages"
            / "agent-authoring-toolkit"
            / "contract-bundles"
            / authority["contract_release_id"]
        )
        bundle = json.loads((bundle_root / "bundle-lock.json").read_text())
        manifest = json.loads((bundle_root / "manifest.json").read_text())
        manifest_digest = "sha256:" + hashlib.sha256(
            (bundle_root / "manifest.json").read_bytes()
        ).hexdigest()
        self.assertEqual(authority["contract_release_id"], manifest["release_id"])
        self.assertEqual(authority["contract_git_tag"], manifest["source_revision"]["tag"])
        self.assertEqual(
            authority["contract_git_commit"],
            bundle["authority"]["contract_git_commit"],
        )
        self.assertEqual(
            authority["contract_release_manifest_sha256"], manifest_digest
        )
        self.assertEqual(
            authority["contract_release_manifest_sha256"],
            bundle["authority"]["release_manifest_sha256"],
        )
        released_by_id = {
            entry["schema_id"]: entry for entry in bundle["released_schemas"]
        }
        manifest_by_id = {
            entry["schema_id"]: entry
            for entry in manifest["artifacts"]["schemas"]
        }
        self.assertEqual(30, len(released_by_id))
        self.assertEqual(set(manifest_by_id), set(released_by_id))
        for schema_id, entry in released_by_id.items():
            with self.subTest(schema_id=schema_id):
                source = bundle_root / entry["bundle_path"]
                self.assertEqual(entry["sha256"], manifest_by_id[schema_id]["sha256"])
                self.assertEqual(
                    entry["sha256"],
                    "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
                )

    def test_alpha1_is_explicit_historical_replay_only(self) -> None:
        history = json.loads(
            (
                self.repo_root
                / "references"
                / "company-contract-lock.alpha.1.history.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            "contract-v0.1.0-alpha.1",
            history["authority"]["contract_release_id"],
        )
        semantic_lock = json.loads(
            (
                self.repo_root / "references" / "semantic-authority-lock.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            {
                "release_id": "contract-v0.1.0-alpha.1",
                "consumer_lock_path": (
                    "references/company-contract-lock.alpha.1.history.json"
                ),
            },
            semantic_lock["historical_replay"][0],
        )
        self.assertNotEqual(
            history["authority"]["contract_release_id"],
            self.lock["authority"]["contract_release_id"],
        )

    def test_runtime_composition_schemas_are_published_not_locally_invented(self) -> None:
        authority = self.lock["authority"]
        bundle_root = (
            self.repo_root
            / "packages"
            / "agent-authoring-toolkit"
            / "contract-bundles"
            / authority["contract_release_id"]
        )
        bundle = json.loads((bundle_root / "bundle-lock.json").read_text())
        schema_ids = {entry["schema_id"] for entry in bundle["released_schemas"]}
        self.assertTrue(
            {
                "urn:company-ai-os:schema:tool-manifest:0.3",
                "urn:company-ai-os:schema:task:0.3",
                "urn:company-ai-os:schema:execution-grant:0.1",
                "urn:company-ai-os:schema:runtime-event:0.1",
                "urn:company-ai-os:schema:model-route:0.1",
                "urn:company-ai-os:schema:system-composition:0.1",
            }.issubset(schema_ids)
        )

    def test_synthetic_agent_contract_references_are_immutable(self) -> None:
        digest_pattern = re.compile(r"^sha256:[a-f0-9]{64}$")
        seen_paths = set()
        for contract in self.lock["synthetic_agent_contracts"]:
            for artifact in ("definition", "binding"):
                with self.subTest(role=contract["role"], artifact=artifact):
                    path = contract[f"{artifact}_path"]
                    self.assertTrue(path.startswith("contracts/examples/agents/"))
                    self.assertNotIn(path, seen_paths)
                    seen_paths.add(path)
                    self.assertRegex(contract[f"{artifact}_sha256"], digest_pattern)


if __name__ == "__main__":
    unittest.main()

