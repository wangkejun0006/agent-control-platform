from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.models import (
    AgentReleaseSelection,
    RuntimeCompositionRequest,
    ToolCapabilityRequirement,
)
from orbit_agent_control_plane.registration import (
    HISTORICAL_ALPHA1_COMPANY_LOCK,
    HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
)
from orbit_agent_control_plane.router import (
    RuntimeComposer,
    RuntimeCompositionError,
)
from orbit_agent_control_plane.tool_lifecycle import (
    SyntheticToolApprovalDecision,
    SyntheticToolLifecycleLedger,
    ToolLifecycleEvaluation,
)
from orbit_agent_control_plane.tool_registry import load_tool_candidate_bundle

ROOT = Path(__file__).resolve().parents[1]
DATASET_REGISTRY_ROOT = (
    ROOT / "showcase/vendor-fixtures/dataset-registry"
)
RELEASE_MANIFEST = Path("contracts/tools/0.1.0/release-manifest.json")
AGENT_RELEASE_DIGEST = "sha256:" + ("a" * 64)
MODEL_ROUTE_DIGEST = "sha256:" + ("b" * 64)
POLICY_DIGEST = "sha256:" + ("c" * 64)
GRANT_DIGEST = "sha256:" + ("d" * 64)


class RuntimeCompositionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        parent = Path(self.temporary.name) / "ledger"
        parent.mkdir(mode=0o700)
        self.ledger = SyntheticToolLifecycleLedger(
            parent / "tool-lifecycle.synthetic.jsonl"
        )
        self.bundle = load_tool_candidate_bundle(
            DATASET_REGISTRY_ROOT,
            RELEASE_MANIFEST,
            company_lock_path=HISTORICAL_ALPHA1_COMPANY_LOCK,
            contract_bundle_root=HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
        )
        for index, candidate in enumerate(self.bundle.candidates):
            evaluation = ToolLifecycleEvaluation(
                report_id=f"eval_dataset_tool_{index}_syn",
                subject_tool_id=candidate.tool_id,
                subject_release_digest=candidate.release_digest,
                evaluator_ref="agt_orbit_company_evaluator_syn",
                verdict="pass",
                release_recommendation="recommend",
                allowed_operation_ids=candidate.d0_allowed_operation_ids,
                evidence_refs=(f"evidence_dataset_tool_{index}_syn",),
                risk_flags=(),
            )
            approval = SyntheticToolApprovalDecision(
                decision_id=f"approval_dataset_tool_{index}_syn",
                action="activate",
                subject_tool_id=candidate.tool_id,
                subject_release_digest=candidate.release_digest,
                decided_by_human_ref="hum_orbit_platform_owner_syn",
                decision="approve",
                reason="D0 synthetic runtime composition",
            )
            self.ledger.register_candidate(
                candidate, idempotency_key=f"tool:register:{index}"
            )
            self.ledger.record_evaluation(
                evaluation, idempotency_key=f"tool:evaluate:{index}"
            )
            self.ledger.record_approval(
                approval, idempotency_key=f"tool:approve:{index}"
            )
            self.ledger.activate(
                candidate.tool_id,
                candidate.release_digest,
                approval_decision_ref=approval.decision_id,
                idempotency_key=f"tool:activate:{index}",
            )
        self.composer = RuntimeComposer()

    def request(self, **overrides: object) -> RuntimeCompositionRequest:
        agent = AgentReleaseSelection(
            agent_id="agt_orbit_research_dataset_scout_acquisition_syn",
            release_digest=AGENT_RELEASE_DIGEST,
            capabilities=frozenset(
                {
                    "dataset_acquisition.request_create",
                    "dataset_registry.patch_candidate_create",
                }
            ),
            requested_tool_capabilities=frozenset(
                {
                    "dataset_registry.query_watchlist",
                    "dataset_acquisition.authorized_execute",
                    "dataset_registry.publish_candidate",
                }
            ),
            allowed_data_classifications=frozenset({"public"}),
            active=True,
        )
        values: dict[str, object] = {
            "task_id": "task_dataset_full_chain_d0_syn",
            "data_classification": "public",
            "agent": agent,
            "tool_requirements": (
                ToolCapabilityRequirement(
                    "query_watchlist",
                    "dataset_registry.query_watchlist",
                    "query_registry_watchlist",
                ),
                ToolCapabilityRequirement(
                    "acquisition_worker",
                    "dataset_acquisition.authorized_execute",
                    "acquire_synthetic_artifact",
                ),
                ToolCapabilityRequirement(
                    "registry_publisher",
                    "dataset_registry.publish_candidate",
                    "publish_registry_patch",
                ),
            ),
            "model_route_ref": "model_route_dataset_agent_structured_syn",
            "model_route_digest": MODEL_ROUTE_DIGEST,
            "policy_ref": "policy_dataset_tools_d0_syn",
            "policy_digest": POLICY_DIGEST,
            "execution_grant_ref": "grant_dataset_full_chain_d0_syn",
            "execution_grant_digest": GRANT_DIGEST,
            "input_registry_revision": "registry_revision_synthetic_0001",
            "budget_units": 10,
        }
        values.update(overrides)
        return RuntimeCompositionRequest(**values)

    def assert_reason(self, reason: str, callback) -> None:
        with self.assertRaises(RuntimeCompositionError) as raised:
            callback()
        self.assertEqual(reason, raised.exception.reason_code)

    def test_composition_pins_agent_tools_model_policy_grant_revision_and_budget(self) -> None:
        composition = self.composer.compose(
            self.request(), self.ledger.replay().tools
        )

        self.assertEqual(
            "agt_orbit_research_dataset_scout_acquisition_syn",
            composition.agent_id,
        )
        self.assertEqual(AGENT_RELEASE_DIGEST, composition.agent_release_digest)
        self.assertEqual(3, len(composition.tool_releases))
        self.assertEqual(
            {candidate.release_digest for candidate in self.bundle.candidates},
            {release.release_digest for release in composition.tool_releases},
        )
        self.assertEqual(MODEL_ROUTE_DIGEST, composition.model_route_digest)
        self.assertEqual(POLICY_DIGEST, composition.policy_digest)
        self.assertEqual(GRANT_DIGEST, composition.execution_grant_digest)
        self.assertEqual(
            "registry_revision_synthetic_0001",
            composition.input_registry_revision,
        )
        self.assertEqual(10, composition.budget_units)
        self.assertEqual("synthetic", composition.evidence_status)
        self.assertFalse(composition.production_authorized)

    def test_inactive_ambiguous_or_unapproved_tool_release_fails_closed(self) -> None:
        tools = list(self.ledger.replay().tools)
        acquisition_index = next(
            index
            for index, state in enumerate(tools)
            if state.candidate.tool_id == "tool_orbit_dataset_acquisition_worker"
        )
        acquisition = tools[acquisition_index]
        tools[acquisition_index] = type(acquisition)(
            candidate=acquisition.candidate,
            status="suspended",
            revision=acquisition.revision,
            evaluation=acquisition.evaluation,
            approvals=acquisition.approvals,
            transitions=acquisition.transitions,
        )
        self.assert_reason(
            "active_tool_release_not_found",
            lambda: self.composer.compose(self.request(), tools),
        )

        tools = list(self.ledger.replay().tools)
        tools.append(acquisition)
        self.assert_reason(
            "active_tool_release_ambiguous",
            lambda: self.composer.compose(self.request(), tools),
        )

        widened = self.request(
            tool_requirements=(
                ToolCapabilityRequirement(
                    "acquisition_worker",
                    "dataset_acquisition.authorized_execute",
                    "acquire_authorized_artifact",
                ),
            )
        )
        self.assert_reason(
            "active_tool_release_not_found",
            lambda: self.composer.compose(widened, self.ledger.replay().tools),
        )

    def test_agent_permission_grant_digest_and_logical_ref_gates_fail_closed(self) -> None:
        agent = self.request().agent
        self.assert_reason(
            "agent_release_inactive",
            lambda: self.composer.compose(
                self.request(
                    agent=AgentReleaseSelection(
                        agent_id=agent.agent_id,
                        release_digest=agent.release_digest,
                        capabilities=agent.capabilities,
                        requested_tool_capabilities=agent.requested_tool_capabilities,
                        allowed_data_classifications=agent.allowed_data_classifications,
                        active=False,
                    )
                ),
                self.ledger.replay().tools,
            ),
        )
        self.assert_reason(
            "composition_digest_invalid",
            lambda: self.composer.compose(
                self.request(execution_grant_digest="sha256:bad"),
                self.ledger.replay().tools,
            ),
        )
        self.assert_reason(
            "composition_logical_ref_invalid",
            lambda: self.composer.compose(
                self.request(input_registry_revision="/Volumes/registry.json"),
                self.ledger.replay().tools,
            ),
        )
        reduced_agent = AgentReleaseSelection(
            agent_id=agent.agent_id,
            release_digest=agent.release_digest,
            capabilities=agent.capabilities,
            requested_tool_capabilities=frozenset(
                {"dataset_registry.query_watchlist"}
            ),
            allowed_data_classifications=agent.allowed_data_classifications,
            active=True,
        )
        self.assert_reason(
            "tool_capability_not_requested_by_agent",
            lambda: self.composer.compose(
                self.request(agent=reduced_agent), self.ledger.replay().tools
            ),
        )

    def test_no_tool_agent_composes_without_implicit_tool_authority(self) -> None:
        request = self.request(
            agent=AgentReleaseSelection(
                agent_id="agt_orbit_disease_research_task_syn",
                release_digest=AGENT_RELEASE_DIGEST,
                capabilities=frozenset({"disease_research_task.execute_synthetic"}),
                requested_tool_capabilities=frozenset(),
                allowed_data_classifications=frozenset({"synthetic"}),
                active=True,
            ),
            data_classification="synthetic",
            tool_requirements=(),
            model_route_ref="model_route_none_disease_r1_syn",
        )
        composition = self.composer.compose(request, ())
        self.assertEqual((), composition.tool_releases)
        self.assertEqual(
            "agt_orbit_disease_research_task_syn", composition.agent_id
        )


if __name__ == "__main__":
    unittest.main()

