from __future__ import annotations

import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from orbit_agent_control_plane.service_runtime.api import (
    create_app,
    load_service_runtime,
)
from orbit_agent_control_plane.service_runtime.config import ServiceSettings
from orbit_agent_control_plane.service_runtime.governance_catalogs import (
    GovernanceCatalogError,
)
from orbit_agent_control_plane.service_runtime.models import (
    Base,
    SystemRegistryRow,
    ToolSemanticScopeRow,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_ROOT = ROOT / "evidence/disease-agent-r2/2026-08-27-automation-policy-alpha2"


class FakeHumanVerifier:
    def verify_oidc_assertion(self, *, token: str, expected_audience: str) -> dict:
        del expected_audience
        if token == "department-token":
            return {
                "human_ref": "human_department_owner_syn",
                "role_refs": ["role_department_owner"],
                "department_refs": ["technology_center"],
            }
        if token == "admin-token":
            return {
                "human_ref": "human_control_plane_admin_syn",
                "role_refs": ["role_control_plane_admin"],
                "department_refs": [],
            }
        raise AssertionError("unexpected test token")


def _settings(*, mutations_enabled: bool = False) -> ServiceSettings:
    return ServiceSettings(
        mode="local_synthetic",
        database_url="sqlite+pysqlite:///:memory:",
        policy_path=POLICY_ROOT / "automation-policy.disease-r2.synthetic.json",
        review_package_path=POLICY_ROOT / "automation-policy-review-package.json",
        profile_path=ROOT / "references/qualification-service-profile.candidate.json",
        adapter_evidence_path=None,
        oidc_issuer=None,
        oidc_audience=None,
        oidc_required_key_id=None,
        oidc_allowed_roles=(),
        oidc_admin_subject_digests=(),
        oidc_public_key_ref=None,
        workload_ca_ref=None,
        workload_allowed_identities=(),
        grant_signing_key_ref=None,
        grant_signing_key_id=None,
        secret_bindings_path=None,
        workload_trust_domain=None,
        mutations_enabled=mutations_enabled,
        host="127.0.0.1",
        port=8431,
    )


class GovernanceCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = load_service_runtime(
            settings=_settings(),
            repository_root=ROOT,
            human_verifier=FakeHumanVerifier(),
        )
        Base.metadata.create_all(self.runtime.database.engine)

    def tearDown(self) -> None:
        self.runtime.database.dispose()

    def test_bootstrap_imports_exact_release_terms_tools_and_systems(self) -> None:
        first = self.runtime.governance_catalogs.bootstrap()
        second = self.runtime.governance_catalogs.bootstrap()
        self.assertEqual(first, second)
        self.assertEqual("semantic-authority-v0.1.0-alpha.7", first["semantic_release_id"])
        self.assertEqual(43, first["term_count"])
        self.assertEqual(4, first["tool_scope_count"])
        self.assertEqual(2, first["system_count"])
        self.assertEqual("projection_only", first["authority_claim"])
        self.assertFalse(first["release_authorization"])

        term = self.runtime.governance_catalogs.term(
            "orbit.term/tool-semantic-scope"
        )["term"]
        self.assertEqual("none", term["authority_claim"])
        self.assertFalse(term["creates_human_checkpoint"])

        lan_terms = {
            item["term_id"]: item
            for item in self.runtime.governance_catalogs.terms()["terms"]
            if item["term_id"]
            in {
                "orbit.term/stage1-lan-service-profile",
                "orbit.term/runtime-node-enrollment-receipt",
                "orbit.term/deployment-release-lock",
                "orbit.term/runtime-node-assisted-maintenance-session",
                "orbit.term/runtime-node-maintenance-job",
                "orbit.term/runtime-node-maintenance-receipt",
            }
        }
        self.assertEqual(
            {
                "orbit.term/stage1-lan-service-profile",
                "orbit.term/runtime-node-enrollment-receipt",
                "orbit.term/deployment-release-lock",
                "orbit.term/runtime-node-assisted-maintenance-session",
                "orbit.term/runtime-node-maintenance-job",
                "orbit.term/runtime-node-maintenance-receipt",
            },
            set(lan_terms),
        )
        self.assertTrue(
            all(item["publication_status"] == "draft" for item in lan_terms.values())
        )
        self.assertTrue(
            all(item["authority_claim"] == "none" for item in lan_terms.values())
        )
        self.assertTrue(
            all(not item["creates_human_checkpoint"] for item in lan_terms.values())
        )

        tools = self.runtime.governance_catalogs.tools()["tools"]
        self.assertEqual(3, len(tools))
        self.assertEqual(4, sum(len(tool["operations"]) for tool in tools))
        self.assertTrue(all(tool["registration_only"] for tool in tools))
        self.assertTrue(
            all(not tool["activation_authorization"] for tool in tools)
        )

        systems = {
            item["system_id"]: item
            for item in self.runtime.governance_catalogs.systems()["systems"]
        }
        self.assertEqual(
            "technology_center", systems["sys_orbit_health"]["department_ref"]
        )
        self.assertEqual(
            "market_center",
            systems["sys_smart_jewelry_ai_growth"]["department_ref"],
        )
        for system in systems.values():
            self.assertEqual("physical_move_deferred", system["migration_status"])
            self.assertFalse(system["runtime_effective"])
            self.assertFalse(system["production_authorized"])

    def test_scope_collision_requires_explicit_alias_or_supersession(self) -> None:
        self.runtime.governance_catalogs.bootstrap()
        base = {
            "scope_id": "toolscope_dataset_watchlist_alias_syn",
            "tool_id": "tool_dataset_watchlist_alias_syn",
            "tool_version": "0.1.0-synthetic",
            "manifest_digest": "sha256:" + "1" * 64,
            "operation_id": "read_watchlist_alias",
            "capability": "dataset_registry.query_watchlist",
            "semantic_scope": {
                "domain": "dataset",
                "resource_kind": "registry_watchlist",
                "action": "read",
                "side_effect_class": "none",
            },
            "canonical_scope_key": "dataset:registry_watchlist:read:none",
            "relationship": {"mode": "canonical", "target_scope_id": None},
            "status": "registered",
            "evidence_status": "synthetic",
            "owner_ref": "role_orbit_platform_owner",
            "source_release_id": "semantic-authority-v0.1.0-alpha.7",
            "registration_only": True,
            "activation_authorization": False,
            "production_authorized": False,
        }
        with self.assertRaisesRegex(
            GovernanceCatalogError, "tool_semantic_scope_collision"
        ):
            self.runtime.governance_catalogs.register_tool_scope(
                candidate=base,
                actor_ref="human_control_plane_admin_syn",
            )
        alias = {
            **base,
            "relationship": {
                "mode": "alias",
                "target_scope_id": "toolscope_dataset_query_watchlist_0_1_0_syn_query",
            },
        }
        result = self.runtime.governance_catalogs.register_tool_scope(
            candidate=alias,
            actor_ref="human_control_plane_admin_syn",
        )
        self.assertTrue(result["appended"])
        self.assertEqual("alias", result["scope"]["relationship"]["mode"])
        self.assertFalse(result["release_authorization"])

    def test_alpha6_bootstrap_preserves_predecessor_seed_provenance(self) -> None:
        self.runtime.governance_catalogs.bootstrap()
        predecessor = "semantic-authority-v0.1.0-alpha.5"
        with self.runtime.database.session() as session:
            for row in session.query(ToolSemanticScopeRow).all():
                row.source_release_id = predecessor
            for row in session.query(SystemRegistryRow).all():
                row.source_release_id = predecessor

        result = self.runtime.governance_catalogs.bootstrap()
        self.assertEqual("semantic-authority-v0.1.0-alpha.7", result["semantic_release_id"])
        with self.runtime.database.session() as session:
            self.assertEqual(
                {predecessor},
                {
                    row.source_release_id
                    for row in session.query(ToolSemanticScopeRow).all()
                },
            )
            self.assertEqual(
                {predecessor},
                {
                    row.source_release_id
                    for row in session.query(SystemRegistryRow).all()
                },
            )

    def test_authenticated_read_api_and_fail_closed_registration(self) -> None:
        app = create_app(self.runtime)
        client = TestClient(app)
        headers = {"Authorization": "Bearer department-token"}
        self.assertEqual(401, client.get("/v1/systems").status_code)
        systems = client.get(
            "/v1/systems",
            headers=headers,
            params={"department_id": "technology_center"},
        )
        self.assertEqual(200, systems.status_code)
        self.assertEqual(1, len(systems.json()["systems"]))
        cross_department = client.get(
            "/v1/systems",
            headers=headers,
            params={"department_id": "market_center"},
        )
        self.assertEqual(403, cross_department.status_code)
        term = client.get(
            "/v1/semantic-terms/orbit.term/tool-semantic-scope", headers=headers
        )
        self.assertEqual(200, term.status_code)
        tools = client.get("/v1/tools", headers=headers)
        self.assertEqual(200, tools.status_code)

        candidate = {
            "scope_id": "toolscope_candidate_syn",
            "tool_id": "tool_candidate_syn",
            "tool_version": "0.1.0-synthetic",
            "manifest_digest": "sha256:" + "2" * 64,
            "operation_id": "run_candidate",
            "capability": "candidate.run",
            "semantic_scope": {
                "domain": "candidate",
                "resource_kind": "artifact",
                "action": "read",
                "side_effect_class": "none",
            },
            "canonical_scope_key": "candidate:artifact:read:none",
            "relationship": {"mode": "canonical", "target_scope_id": None},
            "status": "registered",
            "evidence_status": "synthetic",
            "owner_ref": "role_orbit_platform_owner",
            "source_release_id": "semantic-authority-v0.1.0-alpha.7",
            "registration_only": True,
            "activation_authorization": False,
            "production_authorized": False,
        }
        response = client.post(
            "/v1/tool-registrations",
            headers={"Authorization": "Bearer admin-token"},
            json=candidate,
        )
        self.assertEqual(503, response.status_code)
        self.assertEqual("mutations_disabled", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()

