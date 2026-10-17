from __future__ import annotations

import json
import unittest
from pathlib import Path

from orbit_agent_control_plane.qualification.service import (
    REQUIRED_ADAPTER_ROLES,
    REQUIRED_CAPABILITIES,
    QualificationServiceError,
    assess_production_readiness,
    validate_service_profile,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "references" / "qualification-service-profile.candidate.json"


def binding(role: str, *, component_suffix: str | None = None) -> dict:
    return {
        "role": role,
        "component_id": f"component_{component_suffix or role}",
        "version": "0.1.0",
        "digest": "sha256:" + (format(REQUIRED_ADAPTER_ROLES.index(role) + 1, "x") * 64)[:64],
        "evidence_status": "verified_runtime",
        "capabilities": sorted(REQUIRED_CAPABILITIES[role]),
        "synthetic_only": False,
        "runtime_verified": True,
    }


class QualificationServiceReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = json.loads(PROFILE.read_text(encoding="utf-8"))

    def test_candidate_profile_is_valid_but_not_service_deployment(self) -> None:
        validate_service_profile(self.profile)
        result = assess_production_readiness(profile=self.profile, adapters=[])
        self.assertFalse(result.ready)
        self.assertEqual("not_ready", result.status)
        self.assertEqual(len(REQUIRED_ADAPTER_ROLES), len(result.blocker_codes))
        self.assertFalse(result.release_authorization)

    def test_complete_runtime_verified_adapter_set_reaches_review_only(self) -> None:
        adapters = [binding(role) for role in REQUIRED_ADAPTER_ROLES]
        result = assess_production_readiness(profile=self.profile, adapters=adapters)
        self.assertTrue(result.ready)
        self.assertEqual("ready_for_preproduction_review", result.status)
        self.assertEqual((), result.blocker_codes)
        self.assertFalse(result.release_authorization)

    def test_synthetic_or_missing_capability_adapter_fails_closed(self) -> None:
        adapters = [binding(role) for role in REQUIRED_ADAPTER_ROLES]
        adapters[0]["synthetic_only"] = True
        adapters[0]["evidence_status"] = "synthetic"
        adapters[1]["capabilities"].pop()
        result = assess_production_readiness(profile=self.profile, adapters=adapters)
        self.assertIn(
            "adapter_runtime_evidence_missing_authoritative_store",
            result.blocker_codes,
        )
        self.assertIn(
            "adapter_capabilities_incomplete_schema_migrations",
            result.blocker_codes,
        )

    def test_human_and_workload_identity_must_be_separate_components(self) -> None:
        adapters = [binding(role) for role in REQUIRED_ADAPTER_ROLES]
        adapters[REQUIRED_ADAPTER_ROLES.index("human_identity")]["component_id"] = (
            "component_shared_identity"
        )
        adapters[REQUIRED_ADAPTER_ROLES.index("workload_identity")]["component_id"] = (
            "component_shared_identity"
        )
        result = assess_production_readiness(profile=self.profile, adapters=adapters)
        self.assertIn("human_workload_identity_not_separated", result.blocker_codes)

    def test_jsonl_cannot_be_declared_authoritative(self) -> None:
        self.profile["authoritative_state"] = "jsonl"
        with self.assertRaisesRegex(QualificationServiceError, "service_profile_invalid"):
            validate_service_profile(self.profile)


if __name__ == "__main__":
    unittest.main()

