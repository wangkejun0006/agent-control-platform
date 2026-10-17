from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.model_catalog import (
    ModelCatalogError,
    ModelCatalogService,
)
from orbit_agent_control_plane.service_runtime.model_catalog_models import (
    DepartmentAgentProposalRow,
    ModelCatalogEntryRow,
)
from orbit_agent_control_plane.service_runtime.model_route import (
    ModelRouteReconciler,
    ModelRouteStore,
)
from orbit_agent_control_plane.service_runtime.models import (
    Base,
    ModelRouteRevisionRow,
)

NOW = datetime(2026, 9, 3, 8, 0, tzinfo=timezone.utc)


class ModelCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="orbit-model-catalog-")
        self.database = Database(
            f"sqlite+pysqlite:///{Path(self.temporary.name) / 'state.sqlite3'}"
        )
        Base.metadata.create_all(self.database.engine)
        self.service = ModelCatalogService(
            database=self.database,
            model_routes=ModelRouteReconciler(store=ModelRouteStore(self.database)),
            now=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.database.dispose()
        self.temporary.cleanup()

    def _available_entry(self, preset_id="provider_preset_minimax_cn") -> dict:
        preset = next(
            item
            for item in self.service.list_provider_presets()["items"]
            if item["provider_preset_id"] == preset_id
        )
        discovery = self.service.discover_provider_models(
            provider_preset_id=preset["provider_preset_id"],
            provider_preset_revision_digest=preset["revision_digest"],
            region_id=preset["regions"][0]["region_id"],
            connection_alias=preset["regions"][0]["connection_aliases"][0],
            idempotency_key="catalog:discovery:0001",
            actor_ref="human_admin_syn",
        )
        self.assertFalse(discovery["automatically_published"])
        candidate = self.service.create_catalog_entry(
            discovery_digest=discovery["discovery_digest"],
            provider_model_key=discovery["models"][0]["provider_model_key"],
            idempotency_key="catalog:candidate:0001",
            actor_ref="human_admin_syn",
        )
        self.assertEqual("candidate", candidate["lifecycle_state"])
        self.service.bind_catalog_credential(
            entry_id=candidate["entry_id"],
            expected_entry_revision_digest=candidate["entry_revision_digest"],
            authentication_mode="api_key_ref",
            credential_binding_ref="secret://company/minimax/current",
            qualification_evidence_refs=["sha256:" + "1" * 64],
            evidence_expires_at=NOW + timedelta(hours=2),
            idempotency_key="catalog:credential:0001",
            actor_ref="human_admin_syn",
        )
        receipt = self.service.publish_catalog_entry(
            entry_id=candidate["entry_id"],
            expected_entry_revision_digest=candidate["entry_revision_digest"],
            reason="公司管理员核对目录能力、凭据与证据时效后上架",
            idempotency_key="catalog:availability:0001",
            actor_ref="human_admin_syn",
        )
        self.assertFalse(receipt["model_route_created"])
        return next(
            item
            for item in self.service.list_catalog_entries()["items"]
            if item["entry_id"] == candidate["entry_id"]
        )

    def test_catalog_publication_does_not_create_model_route(self) -> None:
        entry = self._available_entry()
        self.assertEqual("available_for_proposal", entry["lifecycle_state"])
        self.assertTrue(entry["can_be_used_for_new_proposals"])
        self.assertFalse(entry["raw_endpoint_visible"])
        self.assertEqual("synthetic_d0", entry["evidence_status"])
        self.assertFalse(entry["live_provider_health_checked"])
        self.assertFalse(entry["production_authorization"])
        with self.database.session() as session:
            self.assertEqual(0, len(tuple(session.scalars(select(ModelRouteRevisionRow)))))

    def test_department_proposal_deterministically_creates_route_candidate(self) -> None:
        entry = self._available_entry("provider_preset_openai_codex")
        proposal = self.service.submit_agent_proposal(
            department_id="technology_center",
            agent_name="技术变更评审 Agent",
            identity="核对合成代码变更的范围、测试与交付风险",
            task_scope="只读评审经过批准的合成源码快照",
            typical_inputs=["合成源码快照", "变更目标"],
            expected_outputs=["结构化评审报告", "建议差异"],
            prohibited_actions=["修改源码", "提交 Git", "访问宿主目录"],
            model_requirements={
                "capabilities": ["text", "structured_output", "reasoning"],
                "data_classifications": ["synthetic"],
            },
            selected_catalog_entry_id=entry["entry_id"],
            selected_catalog_entry_revision_digest=entry["entry_revision_digest"],
            agent_kind="professional",
            runtime_kind="codex",
            supersedes_package_digest=None,
            idempotency_key="agent:proposal:technology:0001",
            actor_ref="human_technology_owner_syn",
        )
        replay = self.service.submit_agent_proposal(
            department_id="technology_center",
            agent_name="技术变更评审 Agent",
            identity="核对合成代码变更的范围、测试与交付风险",
            task_scope="只读评审经过批准的合成源码快照",
            typical_inputs=["合成源码快照", "变更目标"],
            expected_outputs=["结构化评审报告", "建议差异"],
            prohibited_actions=["修改源码", "提交 Git", "访问宿主目录"],
            model_requirements={
                "capabilities": ["text", "structured_output", "reasoning"],
                "data_classifications": ["synthetic"],
            },
            selected_catalog_entry_id=entry["entry_id"],
            selected_catalog_entry_revision_digest=entry["entry_revision_digest"],
            agent_kind="professional",
            runtime_kind="codex",
            supersedes_package_digest=None,
            idempotency_key="agent:proposal:technology:0001",
            actor_ref="human_technology_owner_syn",
        )
        self.assertEqual(proposal["package_digest"], replay["package_digest"])
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual("not_reviewed", proposal["model_route_approval_status"])
        self.assertEqual("not_reviewed", proposal["agent_activation_status"])
        self.assertFalse(proposal["execution_grant_issued"])
        self.assertFalse(proposal["model_route"]["raw_endpoint_included"])
        activation = self.service.decide_agent_activation(
            proposal_id=proposal["proposal_id"],
            expected_package_digest=proposal["package_digest"],
            expected_agent_definition_digest=proposal["agent_binding"][
                "agent_definition_digest"
            ],
            decision="approved",
            reason="Agent定义边界已核对，独立批准该精确候选",
            idempotency_key="agent:activation:technology:0001",
            actor_ref="human_admin_syn",
        )
        self.assertTrue(activation["model_route_approval_unchanged"])
        self.assertFalse(activation["execution_grant_issued"])
        review = self.service.list_agent_route_reviews()["items"][0]
        self.assertEqual("approved", review["agent_activation_status"])
        self.assertEqual("not_reviewed", review["model_route_approval_status"])
        self.assertFalse(review["agent_and_route_eligible"])
        with self.database.session() as session:
            self.assertEqual(1, len(tuple(session.scalars(select(ModelRouteRevisionRow)))))
            self.assertEqual(1, len(tuple(session.scalars(select(DepartmentAgentProposalRow)))))

    def test_retirement_blocks_new_proposals_without_deleting_history(self) -> None:
        entry = self._available_entry()
        retired = self.service.retire_catalog_entry(
            entry_id=entry["entry_id"],
            expected_entry_revision_digest=entry["entry_revision_digest"],
            reason="停止新增部门申报但保留既有路线证据",
            idempotency_key="catalog:retirement:0001",
            actor_ref="human_admin_syn",
        )
        self.assertEqual("retired", retired["to_state"])
        replay = self.service.retire_catalog_entry(
            entry_id=entry["entry_id"], expected_entry_revision_digest=entry["entry_revision_digest"],
            reason="停止新增部门申报但保留既有路线证据",
            idempotency_key="catalog:retirement:0001", actor_ref="human_admin_syn",
        )
        self.assertEqual(retired["receipt_digest"], replay["receipt_digest"])
        self.assertTrue(replay["idempotent_replay"])
        projection = self.service.proposal_catalog(
            department_id="market_center",
            model_requirements={
                "capabilities": ["text"],
                "data_classifications": ["synthetic"],
            },
        )
        item = next(item for item in projection["items"] if item["entry_id"] == entry["entry_id"])
        self.assertFalse(item["selectable"])
        with self.database.session() as session:
            self.assertEqual(3, len(tuple(session.scalars(select(ModelCatalogEntryRow)))))

    def test_unknown_provider_requires_onboarding_proposal(self) -> None:
        with self.assertRaises(ModelCatalogError) as context:
            self.service.discover_provider_models(
                provider_preset_id="provider_preset_unknown_vendor",
                provider_preset_revision_digest="sha256:" + "0" * 64,
                region_id="custom",
                connection_alias="自定义连接",
                idempotency_key="catalog:unknown:0001",
                actor_ref="human_admin_syn",
            )
        self.assertEqual("model_provider_preset_not_found", context.exception.reason_code)

    def test_expired_discovery_is_not_selectable_even_with_current_credential(self) -> None:
        entry = self._available_entry()
        self.service.bind_catalog_credential(
            entry_id=entry["entry_id"], expected_entry_revision_digest=entry["entry_revision_digest"],
            authentication_mode="api_key_ref", credential_binding_ref="secret://company/minimax/current",
            qualification_evidence_refs=["sha256:" + "1" * 64],
            evidence_expires_at=NOW + timedelta(days=2), idempotency_key="catalog:credential:0002", actor_ref="human_admin_syn",
        )
        self.service.now = lambda: NOW + timedelta(hours=25)
        item = self.service.proposal_catalog(department_id="technology_center")["items"][0]
        self.assertEqual("healthy", item["credential_health"])
        self.assertFalse(item["selectable"])
        self.assertEqual("expired", item["provider_health_status"])

    def test_provider_onboarding_is_non_effective_and_rejects_unknown_protocols(self) -> None:
        request = {
            "display_name": "合成供应商候选", "requested_regions": ["cn_mainland"],
            "required_protocols": ["openai_responses"],
            "reason": "需要评估新的供应商协议和数据边界",
            "idempotency_key": "provider:onboarding:0001", "actor_ref": "human_admin_syn",
        }
        result = self.service.submit_provider_onboarding(**request)
        self.assertEqual("candidate", result["status"])
        self.assertFalse(result["provider_preset_created"])
        self.assertTrue(self.service.submit_provider_onboarding(**request)["idempotent_replay"])
        for change in (
            {"required_protocols": ["arbitrary_protocol"]},
            {"requested_regions": ["https://arbitrary.invalid"]},
            {"requested_regions": ["cn_mainland", "cn_mainland"]},
            {"required_protocols": ["openai_responses", "openai_responses"]},
        ):
            with self.subTest(change=change), self.assertRaises(ModelCatalogError):
                self.service.submit_provider_onboarding(**{**request, **change, "idempotency_key": "provider:onboarding:0002"})


if __name__ == "__main__":
    unittest.main()

