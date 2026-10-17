from __future__ import annotations

import unittest

from orbit_agent_control_plane.service_runtime.pipeline import GovernedReleasePipeline

SNAPSHOT = "sha256:" + "a" * 64


class _RoutePreflight:
    def __init__(self, *, status: str = "ready", digest: str = SNAPSHOT) -> None:
        self.status = status
        self.digest = digest

    def deploy_preflight(self, route_id: str) -> dict:
        return {
            "route_id": route_id,
            "snapshot_digest": self.digest,
            "status": self.status,
            "reason_codes": ([] if self.status == "ready" else ["observation_stale"]),
            "provider_execution_started": False,
            "release_authorization": False,
        }


class GovernedPipelineModelRouteTests(unittest.TestCase):
    def test_exact_ready_snapshot_passes_before_effective_state(self) -> None:
        pipeline = GovernedReleasePipeline(
            database=object(),
            qualification_store=object(),
            model_route_reconciler=_RoutePreflight(),
        )
        result = pipeline.deploy_preflight(
            route_id="route_disease_r2_fixture_gpt_5_6_sol_public",
            expected_snapshot_digest=SNAPSHOT,
        )
        self.assertEqual("ready", result["status"])
        self.assertFalse(result["provider_execution_started"])

    def test_blocked_or_digest_drift_fails_closed(self) -> None:
        for route_preflight in (
            _RoutePreflight(status="blocked"),
            _RoutePreflight(digest="sha256:" + "b" * 64),
        ):
            with self.subTest(route_preflight=route_preflight):
                pipeline = GovernedReleasePipeline(
                    database=object(),
                    qualification_store=object(),
                    model_route_reconciler=route_preflight,
                )
                with self.assertRaisesRegex(
                    ValueError, "governed_pipeline_model_route_preflight_blocked"
                ):
                    pipeline.deploy_preflight(
                        route_id="route_disease_r2_fixture_gpt_5_6_sol_public",
                        expected_snapshot_digest=SNAPSHOT,
                    )


if __name__ == "__main__":
    unittest.main()

