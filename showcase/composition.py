"""Exercise inherited Tool intake/lifecycle/composition with local contracts.

This checks immutable selection, not actual publication or remote Tool execution.
"""

from dataclasses import asdict, replace
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
from orbit_agent_control_plane.router import RuntimeComposer, RuntimeCompositionError
from orbit_agent_control_plane.tool_lifecycle import (
    SyntheticToolApprovalDecision,
    SyntheticToolLifecycleLedger,
    ToolLifecycleEvaluation,
)
from orbit_agent_control_plane.tool_registry import load_tool_candidate_bundle


def run(root: Path, source_digest: str) -> dict:
    project = Path(__file__).resolve().parents[1]
    bundle = load_tool_candidate_bundle(
        project / "showcase/vendor-fixtures/dataset-registry",
        Path("contracts/tools/0.1.0/release-manifest.json"),
        company_lock_path=HISTORICAL_ALPHA1_COMPANY_LOCK,
        contract_bundle_root=HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
    )
    ledger = SyntheticToolLifecycleLedger(root / "tools.jsonl")
    for index, candidate in enumerate(bundle.candidates):
        approval = SyntheticToolApprovalDecision(
            f"approval_demo_tool_{index}_syn",
            "activate",
            candidate.tool_id,
            candidate.release_digest,
            "hum_demo_reviewer_syn",
            "approve",
            "Scripted fictional tool approval fixture",
        )
        evaluation = ToolLifecycleEvaluation(
            f"eval_demo_tool_{index}_syn",
            candidate.tool_id,
            candidate.release_digest,
            "agt_demo_independent_evaluator_syn",
            "pass",
            "recommend",
            candidate.d0_allowed_operation_ids,
            (f"evidence_demo_tool_{index}_syn",),
            (),
        )
        ledger.register_candidate(candidate, idempotency_key=f"register:{index}")
        ledger.record_evaluation(evaluation, idempotency_key=f"evaluate:{index}")
        ledger.record_approval(approval, idempotency_key=f"approve:{index}")
        ledger.activate(
            candidate.tool_id,
            candidate.release_digest,
            approval_decision_ref=approval.decision_id,
            idempotency_key=f"activate:{index}",
        )
    capabilities = frozenset(
        cap for item in bundle.candidates for cap in item.capabilities
    )
    request = RuntimeCompositionRequest(
        task_id="task_orbit_composition_syn",
        data_classification="public",
        agent=AgentReleaseSelection(
            "agt_orbit_dataset_demo_syn",
            source_digest,
            frozenset({"dataset_acquisition.request_create"}),
            capabilities,
            frozenset({"public"}),
            True,
        ),
        tool_requirements=tuple(
            ToolCapabilityRequirement(
                f"tool_{index}",
                candidate.capabilities[0],
                candidate.d0_allowed_operation_ids[0],
            )
            for index, candidate in enumerate(bundle.candidates)
        ),
        model_route_ref="model_route_offline_fixture_syn",
        model_route_digest=source_digest,
        policy_ref="policy_demo_no_network_syn",
        policy_digest=source_digest,
        execution_grant_ref="grant_demo_composition_syn",
        execution_grant_digest=source_digest,
        input_registry_revision="catalog-demo-v3",
        budget_units=1,
    )
    composer = RuntimeComposer()
    composition = composer.compose(request, ledger.replay().tools)
    refusal = None
    widened = replace(
        request,
        tool_requirements=(
            ToolCapabilityRequirement(
                "acquisition",
                "dataset_acquisition.authorized_execute",
                "acquire_authorized_artifact",
            ),
        ),
    )
    try:
        composer.compose(widened, ledger.replay().tools)
    except RuntimeCompositionError as error:
        refusal = error.reason_code
    return {
        "composition": asdict(composition),
        "tool_lifecycle": asdict(ledger.replay()),
        "widened_operation_refusal": refusal,
        "scripted_approval_fixture": True,
        "tools_executed": False,
        "registry_published": False,
    }
