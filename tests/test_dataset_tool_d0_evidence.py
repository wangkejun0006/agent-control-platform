from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "references" / "dataset-tool-d0-composition-lock.json"


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"expected JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


class DatasetToolD0EvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = _load(LOCK_PATH)
        evidence = self.lock["evidence"]
        self.assertIsInstance(evidence, dict)
        self.evidence = evidence
        self.result_path = ROOT / str(evidence["path"])
        self.result = _load(self.result_path)

    def test_evidence_digests_close_and_all_checks_pass(self) -> None:
        self.assertEqual(self.evidence["sha256"], _sha256(self.result_path))
        report_path = ROOT / str(self.evidence["acceptance_report_path"])
        review_path = ROOT / str(self.evidence["skill_review_path"])
        self.assertEqual(self.evidence["acceptance_report_sha256"], _sha256(report_path))
        self.assertEqual(self.evidence["skill_review_sha256"], _sha256(review_path))
        self.assertEqual("D0 synthetic active", self.result["status"])
        self.assertEqual([], self.result["failed_checks"])
        self.assertEqual(27, len(self.result["checks"]))
        self.assertTrue(all(self.result["checks"].values()))

    def test_container_and_nonproduction_boundaries_are_explicit(self) -> None:
        guards = self.result["container_guards"]
        self.assertEqual(65532, guards["effective_uid"])
        self.assertTrue(guards["non_root"])
        self.assertTrue(guards["root_filesystem_write_blocked"])
        self.assertTrue(guards["external_network_probe_blocked"])
        self.assertTrue(guards["no_new_privileges"])
        self.assertEqual("0000000000000000", guards["effective_capabilities_hex"])
        self.assertEqual([], guards["sensitive_environment_names"])
        self.assertFalse(self.result["runtime_composition"]["production_authorized"])
        self.assertTrue(all(value is False for value in self.lock["denies"].values()))
        source = self.result_path.read_text(encoding="utf-8")
        self.assertNotIn("/Users/", source)
        self.assertNotIn("/Volumes/", source)

    def test_release_composition_and_review_are_digest_bound(self) -> None:
        composition = self.result["runtime_composition"]
        self.assertEqual(
            self.lock["agent_release"]["release_digest"],
            composition["agent_release_digest"],
        )
        expected_tools = {
            item["tool_id"]: item["release_digest"]
            for item in self.lock["tool_release"]["tools"]
        }
        actual_tools = {
            item["tool_id"]: item["release_digest"]
            for item in composition["tool_releases"]
        }
        self.assertEqual(expected_tools, actual_tools)
        implementation = self.lock["control_plane_implementation"]
        self.assertEqual(
            implementation["harness_sha256"],
            _sha256(ROOT / "scripts" / "run_dataset_tool_d0.py"),
        )
        self.assertEqual(
            implementation["docker_runner_sha256"],
            _sha256(ROOT / "scripts" / "run_dataset_tool_d0_docker.py"),
        )
        review = _load(ROOT / str(self.evidence["skill_review_path"]))
        advisory = review["advisory"]
        self.assertFalse(advisory["grant_issued_by_skill"])
        self.assertFalse(advisory["agent_or_tool_activated_by_skill"])
        self.assertFalse(advisory["authoritative_registry_written_by_skill"])
        self.assertFalse(advisory["runtime_started_by_skill"])
        self.assertFalse(advisory["production_authorized"])


if __name__ == "__main__":
    unittest.main()

