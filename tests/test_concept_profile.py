from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.concept_profile import (
    CONCEPT_BINDINGS_VERSION,
    ConceptProfileError,
    build_review_concept_bindings,
    concept_profile_status,
    load_company_concept_profile,
    validate_review_concept_bindings,
)


class CompanyConceptProfileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_company_concept_profile()

    def _bindings(self, concept_ids: list[str] | None = None) -> dict[str, object]:
        return {
            "binding_version": CONCEPT_BINDINGS_VERSION,
            "profile_version": self.profile.profile_version,
            "profile_sha256": self.profile.profile_sha256,
            "architecture_commit": self.profile.source["commit"],
            "catalog_sha256": self.profile.source["catalog_sha256"],
            "concept_ids": sorted(concept_ids or list(self.profile.concept_ids)),
        }

    def test_profile_closes_published_catalog_and_unique_authority(self) -> None:
        status = concept_profile_status()
        self.assertEqual("verified_read_only_consumer_lock", status["status"])
        self.assertEqual(41, status["concept_count"])
        self.assertEqual(
            ["orbit.concept/execution-grant"],
            status["effective_task_authority"],
        )
        self.assertEqual("none", status["authority_claim"])

    def test_runtime_review_requires_execution_dependency_concepts(self) -> None:
        concepts = validate_review_concept_bindings(
            self._bindings(),
            manifest_type="runtime_execution_review",
            scope_kinds={"agent_activation", "r2_execution"},
            profile=self.profile,
        )
        self.assertIn("orbit.concept/execution-grant", concepts)
        self.assertIn("orbit.concept/agent-release", concepts)

    def test_builder_emits_minimal_sorted_scope_dependencies(self) -> None:
        binding = build_review_concept_bindings(
            manifest_type="runtime_execution_review",
            scope_kinds={"model_route_approval", "r2_execution"},
            additional_concept_ids={"orbit.concept/tool-manifest"},
            profile=self.profile,
        )
        concepts = binding["concept_ids"]
        self.assertEqual(sorted(concepts), concepts)
        self.assertIn("orbit.concept/model-route", concepts)
        self.assertIn("orbit.concept/gateway", concepts)
        self.assertIn("orbit.concept/tool-manifest", concepts)
        self.assertIn("orbit.concept/execution-grant", concepts)

    def test_alias_cannot_replace_stable_concept_id(self) -> None:
        bindings = self._bindings()
        bindings["concept_ids"].append("orbit.concept/grant")  # type: ignore[union-attr]
        bindings["concept_ids"].sort()  # type: ignore[union-attr]
        with self.assertRaisesRegex(ConceptProfileError, "unknown_id"):
            validate_review_concept_bindings(
                bindings,
                manifest_type="runtime_execution_review",
                scope_kinds={"r2_execution"},
                profile=self.profile,
            )

    def test_profile_duplicate_key_fails_closed(self) -> None:
        source = (
            '{"profile_version":"orbit.control-plane-concept-profile/1",'
            '"profile_version":"drift"}'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text(source, encoding="utf-8")
            with self.assertRaisesRegex(ConceptProfileError, "duplicate_key"):
                load_company_concept_profile(path)

    def test_profile_digest_changes_when_consumer_lock_changes(self) -> None:
        path = Path(__file__).resolve().parents[1] / "references/company-concept-profile.json"
        original = json.loads(path.read_text(encoding="utf-8"))
        changed = copy.deepcopy(original)
        changed["source"]["commit"] = "0" * 40
        encoded = (json.dumps(changed, sort_keys=True) + "\n").encode("utf-8")
        self.assertNotEqual(
            self.profile.profile_sha256,
            "sha256:" + hashlib.sha256(encoded).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()

