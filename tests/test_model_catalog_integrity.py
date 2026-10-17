from __future__ import annotations

import copy
import json
import os
import subprocess
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.model_catalog import (
    _PRESETS,
    ModelCatalogError,
    _preset_document,
)
from orbit_agent_control_plane.service_runtime.models import ModelRouteRevisionRow
from tests import test_model_catalog as catalog_fixture

NOW = catalog_fixture.NOW


class ModelCatalogIntegrityTests(unittest.TestCase):
    setUp = catalog_fixture.ModelCatalogTests.setUp
    tearDown = catalog_fixture.ModelCatalogTests.tearDown
    _available_entry = catalog_fixture.ModelCatalogTests._available_entry

    def test_server_minimum_capabilities_cannot_be_lowered_by_request(self):
        presets = copy.deepcopy(_PRESETS)
        presets[1]["models"][0]["capabilities"] = ["text", "structured_output"]
        with patch(
            "orbit_agent_control_plane.service_runtime.model_catalog._PRESETS", presets
        ):
            entry = self._available_entry("provider_preset_openai_codex")
            request = self.proposal_request(entry)
            request["model_requirements"]["capabilities"] = ["text"]
            with self.assertRaises(ModelCatalogError):
                self.service.submit_agent_proposal(**request)

    def test_missing_model_capacity_blocks_candidate(self):
        presets = copy.deepcopy(_PRESETS)
        presets[1]["models"][0]["model_limits"]["max_input_tokens"] = 100
        with patch(
            "orbit_agent_control_plane.service_runtime.model_catalog._PRESETS", presets
        ):
            entry = self._available_entry("provider_preset_openai_codex")
            with self.assertRaises(ModelCatalogError):
                self.service.submit_agent_proposal(**self.proposal_request(entry))

    def test_hidden_preset_facts_are_revision_bound(self):
        original = _PRESETS[0]
        for target, field, value in [
            ("regions", "endpoint", "https://synthetic.invalid/v1"),
            ("models", "provider_model_id", "synthetic-other"),
            ("models", "capabilities", ["text"]),
        ]:
            changed = copy.deepcopy(original)
            changed[target][0][field] = value
            self.assertNotEqual(
                _preset_document(original)["revision_digest"],
                _preset_document(changed)["revision_digest"],
            )
            self.assertNotIn("endpoint", str(_preset_document(changed)))

    def proposal_request(self, entry, **changes):
        return dict(
            department_id="technology_center",
            agent_name="合成代码评审",
            identity="合成源码只读评审职责",
            task_scope="只读检查合成源码的边界",
            typical_inputs=["合成源码快照"],
            expected_outputs=["结构化评审意见"],
            prohibited_actions=["不得修改源码或访问宿主"],
            model_requirements={
                "capabilities": ["text", "structured_output", "tool_calling"],
                "data_classifications": ["synthetic"],
            },
            selected_catalog_entry_id=entry["entry_id"],
            selected_catalog_entry_revision_digest=entry["entry_revision_digest"],
            agent_kind="professional",
            runtime_kind="codex",
            supersedes_package_digest=None,
            idempotency_key="integrity:proposal:0001",
            actor_ref="human_technology_owner_syn",
            **changes,
        )

    def test_incompatible_protocol_is_rejected_even_with_lowered_requirements(self):
        entry = self._available_entry()
        request = self.proposal_request(entry)
        request["model_requirements"]["capabilities"] = ["text"]
        with self.assertRaises(ModelCatalogError):
            self.service.submit_agent_proposal(**request)
        with self.database.session() as session:
            self.assertEqual([], list(session.scalars(select(ModelRouteRevisionRow))))

    def test_renewal_requires_new_exact_credential(self):
        entry = self._available_entry()
        self.service.now = lambda: NOW + timedelta(hours=25)
        preset = self.service.list_provider_presets()["items"][0]
        discovery = self.service.discover_provider_models(
            provider_preset_id=preset["provider_preset_id"],
            provider_preset_revision_digest=preset["revision_digest"],
            region_id="cn_mainland",
            connection_alias="MiniMax 中国连接",
            idempotency_key="integrity:discovery:renew",
            actor_ref="human_admin_syn",
        )
        successor = self.service.create_catalog_entry(
            discovery_digest=discovery["discovery_digest"],
            provider_model_key="minimax_text_d0",
            expected_entry_revision_digest=entry["entry_revision_digest"],
            idempotency_key="integrity:entry:renew",
            actor_ref="human_admin_syn",
        )
        self.assertGreater(successor["revision"], entry["revision"])
        self.assertEqual("candidate", successor["lifecycle_state"])
        self.assertEqual("not_bound", successor["credential_health"])
        self.assertFalse(successor["can_be_used_for_new_proposals"])
        with self.assertRaises(ModelCatalogError):
            self.service.publish_catalog_entry(
                entry_id=successor["entry_id"],
                expected_entry_revision_digest=successor["entry_revision_digest"],
                reason="缺少新修订资格必须拒绝",
                idempotency_key="integrity:publish:denied",
                actor_ref="human_admin_syn",
            )

    def test_failed_package_write_rolls_back_route(self):
        entry = self._available_entry("provider_preset_openai_codex")
        original = self.service._audit

        def fail(event, *args, **kwargs):
            if event == "department_agent_proposal_submitted":
                raise RuntimeError("synthetic_failure_after_route")
            return original(event, *args, **kwargs)

        with (
            patch.object(self.service, "_audit", side_effect=fail),
            self.assertRaises(RuntimeError),
        ):
            self.service.submit_agent_proposal(**self.proposal_request(entry))
        with self.database.session() as session:
            self.assertEqual([], list(session.scalars(select(ModelRouteRevisionRow))))

    def test_accepted_replay_survives_expiry_without_new_route(self):
        entry = self._available_entry("provider_preset_openai_codex")
        request = self.proposal_request(entry)
        first = self.service.submit_agent_proposal(**request)
        self.service.now = lambda: NOW + timedelta(hours=25)
        replay = self.service.submit_agent_proposal(**request)
        self.assertEqual(first["package_digest"], replay["package_digest"])
        self.assertTrue(replay["historical_receipt_only"])
        with self.assertRaises(ModelCatalogError):
            self.service.submit_agent_proposal(
                **{**request, "idempotency_key": "integrity:new:expired"}
            )
        with self.assertRaises(ModelCatalogError):
            self.service.submit_agent_proposal(
                **{**request, "actor_ref": "human_other_syn"}
            )
        with self.database.session() as session:
            self.assertEqual(
                1, len(list(session.scalars(select(ModelRouteRevisionRow))))
            )

    def test_revision_requires_latest_returned_package(self):
        entry = self._available_entry("provider_preset_openai_codex")
        first = self.service.submit_agent_proposal(**self.proposal_request(entry))
        request = {
            **self.proposal_request(entry),
            "supersedes_package_digest": first["package_digest"],
            "idempotency_key": "integrity:revision:0002",
        }
        with self.assertRaises(ModelCatalogError):
            self.service.submit_agent_proposal(**request)
        self.service.decide_agent_activation(
            proposal_id=first["proposal_id"],
            expected_package_digest=first["package_digest"],
            expected_agent_definition_digest=first["agent_binding"][
                "agent_definition_digest"
            ],
            decision="revision_required",
            reason="请收窄任务范围后重新申报",
            idempotency_key="integrity:return:0001",
            actor_ref="human_admin_syn",
        )
        second = self.service.submit_agent_proposal(**request)
        self.assertEqual(2, second["revision"])
        with self.assertRaises(ModelCatalogError):
            self.service.submit_agent_proposal(
                **{**request, "idempotency_key": "integrity:stale:0003"}
            )
        history = self.service.list_agent_route_reviews(
            department_id="technology_center"
        )["items"]
        self.assertEqual(2, len(history))
        self.assertFalse(
            next(item for item in history if item["revision"] == 1)["can_revise"]
        )
        self.assertEqual(
            [],
            self.service.list_agent_route_reviews(department_id="market_center")[
                "items"
            ],
        )

    def test_onboarding_cannot_link_unmatched_preset(self):
        proposal = self.service.submit_provider_onboarding(
            display_name="合成供应商待核验",
            requested_regions=["cn_mainland"],
            required_protocols=["anthropic_messages"],
            reason="需要核对协议和区域来源",
            idempotency_key="onboarding:integrity:submit",
            actor_ref="human_admin_syn",
        )
        preset = self.service.list_provider_presets()["items"][0]
        with self.assertRaises(ModelCatalogError):
            self.service.review_provider_onboarding(
                proposal_id=proposal["proposal_id"],
                expected_proposal_digest=proposal["proposal_digest"],
                expected_review_digest=None,
                status="linked_to_preset",
                reason="协议不匹配必须拒绝关联",
                provider_preset_id=preset["provider_preset_id"],
                provider_preset_revision_digest=preset["revision_digest"],
                idempotency_key="onboarding:integrity:review",
                actor_ref="human_admin_syn",
            )

    def test_export_requires_account_mapping_and_department(self):
        entry = self._available_entry("provider_preset_openai_codex")
        proposal = self.service.submit_agent_proposal(**self.proposal_request(entry))
        for department in ["technology_center", "market_center"]:
            with self.assertRaises(ModelCatalogError):
                self.service.export_agent_proposal(
                    department_id=department, package_digest=proposal["package_digest"]
                )

    def test_credential_receipt_replay_is_stable_and_rotation_blocks_new_use(self):
        entry = self._available_entry("provider_preset_openai_codex")
        health = {
            "healthy": True,
            "binding_version": "synthetic-v1",
            "secret_fingerprint": "sha256:" + "f" * 64,
        }
        with patch.object(
            self.service.model_routes.secret_provider, "health", return_value=health
        ):
            request = {
                "entry_id": entry["entry_id"],
                "expected_entry_revision_digest": entry["entry_revision_digest"],
                "expected_binding_version": "synthetic-v1",
                "idempotency_key": "credential:exact:version",
                "actor_ref": "human_admin_syn",
            }
            first = self.service.qualify_catalog_api_key(**request)
            self.service.now = lambda: NOW + timedelta(minutes=1)
            replay = self.service.qualify_catalog_api_key(**request)
            self.assertEqual(first["expires_at"], replay["expires_at"])
            health["binding_version"] = "synthetic-v2"
            item = self.service.list_catalog_entries()["items"][0]
            self.assertFalse(item["can_be_used_for_new_proposals"])

    def test_exchange_matches_locked_draft_and_detects_tampering(self):
        entry = self._available_entry("provider_preset_openai_codex")
        request = {
            **self.proposal_request(entry),
            "proposer_account_ref": "account://synthetic/technology/owner",
            "department_owner_ref": "account://synthetic/technology/owner",
        }
        proposal = self.service.submit_agent_proposal(**request)
        result = self.service.export_agent_proposal(
            department_id="technology_center", package_digest=proposal["package_digest"]
        )
        self.assertNotEqual(
            result["source_package_digest"],
            result["document"]["spec"]["package_digest"],
        )
        path = Path(self.temporary.name) / "export.json"
        path.write_text(json.dumps(result["document"], ensure_ascii=False))
        root = Path(__file__).resolve().parents[1]
        checked = subprocess.run(
            [
                "node",
                str(root / "scripts/verify_model_catalog_exchange.mjs"),
                os.environ.get("ORBIT_TEST_ARCHITECTURE_ROOT", str(root.parent / "orbit-agent-architecture")),
                str(path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, checked.returncode, checked.stderr)
        self.assertNotIn("endpoint", path.read_text())
        valid_json = path.read_text()
        for invalid_json, reason in [
            (
                '{"api_version":"duplicate",' + valid_json[1:],
                "exchange_duplicate_json_key",
            ),
            ('{"unexpected_field":false,' + valid_json[1:], "exchange_schema_invalid"),
        ]:
            path.write_text(invalid_json)
            rejected = subprocess.run(
                checked.args, check=False, capture_output=True, text=True
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn(reason, rejected.stderr)
        from orbit_agent_control_plane.service_runtime.model_catalog_models import (
            DepartmentAgentProposalRow,
        )

        with self.database.session() as session:
            row = session.scalar(select(DepartmentAgentProposalRow))
            changed = copy.deepcopy(row.document)
            changed["exchange_context"]["department_owner_ref"] = (
                "account://synthetic/other/owner"
            )
            row.document = changed
        with self.assertRaises(ModelCatalogError):
            self.service.export_agent_proposal(
                department_id="technology_center",
                package_digest=proposal["package_digest"],
            )

