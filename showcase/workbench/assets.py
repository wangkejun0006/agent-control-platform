"""Native lifecycle ledgers and strict Tool intake, with explicit local approvals."""

from dataclasses import asdict
from pathlib import Path

from orbit_agent_control_plane.lifecycle import (
    AgentCandidate,
    LifecycleEvaluation,
    SyntheticAgentLifecycleLedger,
    SyntheticApprovalDecision,
)
from orbit_agent_control_plane.registration import (
    HISTORICAL_ALPHA1_COMPANY_LOCK,
    HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
)
from orbit_agent_control_plane.tool_lifecycle import (
    SyntheticToolApprovalDecision,
    SyntheticToolLifecycleLedger,
    ToolLifecycleEvaluation,
)
from orbit_agent_control_plane.tool_registry import load_tool_candidate_bundle
from showcase.live_budget import digest, require

from .documents import parse_document
from .tools import execute_tool

DEPARTMENTS = ("product_center", "technology_center", "market_center")
DEPT_NAMES = {
    "product_center": "产品部门",
    "technology_center": "技术部门",
    "market_center": "市场部门",
}
HERE = Path(__file__).parent


class DeliveryAssets:
    def __init__(self, root):
        self.agents = SyntheticAgentLifecycleLedger(root / "agent-lifecycle.jsonl")
        self.tools = SyntheticToolLifecycleLedger(root / "tool-lifecycle.jsonl")
        self.bundle = load_tool_candidate_bundle(
            HERE / "contracts",
            Path("release-manifest.json"),
            intake_profile_path=HERE / "contracts/intake-profile.json",
            company_lock_path=HISTORICAL_ALPHA1_COMPANY_LOCK,
            contract_bundle_root=HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
        )
        for dept in DEPARTMENTS:
            candidate = AgentCandidate(
                "agt_delivery_" + dept,
                digest({"department": dept, "version": 1}),
                "definition_delivery_" + dept,
                "binding_delivery_" + dept,
                "role_department_owner_syn",
                "system_delivery_syn",
                ("new_stable_agent", "purpose"),
                True,
            )
            self.agents.register_candidate(
                candidate, idempotency_key="register:" + dept
            )
        for candidate in self.bundle.candidates:
            self.tools.register_candidate(
                candidate, idempotency_key="register:" + candidate.tool_id
            )

    def status(self):
        return {
            "agents": [
                {
                    "id": s.candidate.agent_id,
                    "name": DEPT_NAMES[
                        s.candidate.agent_id.removeprefix("agt_delivery_")
                    ]
                    + "专业Agent",
                    "department_id": s.candidate.agent_id.removeprefix("agt_delivery_"),
                    "status": s.status,
                    "release_digest": s.candidate.release_digest,
                    "evaluation": asdict(s.evaluation) if s.evaluation else None,
                    "capabilities": [
                        "delivery." + s.candidate.agent_id.removeprefix("agt_delivery_")
                    ],
                    "version": "1.0.0",
                }
                for s in self.agents.replay().agents
            ],
            "tools": [
                {
                    "id": s.candidate.tool_id,
                    "name": s.candidate.operation_ids[0],
                    "status": s.status,
                    "release_digest": s.candidate.release_digest,
                    "version": s.candidate.version,
                    "operations": list(s.candidate.d0_allowed_operation_ids),
                    "evaluation": asdict(s.evaluation) if s.evaluation else None,
                    "network_egress": "deny_all",
                    "approval_is_execution_grant": False,
                }
                for s in self.tools.replay().tools
            ],
        }

    def action(self, kind, identity, action, actor, key):
        if action == "evaluate":
            # A bounded, reproducible local check: verified release bytes,
            # real parsing/retrieval and requirement checks, never model PASS.
            import json

            manifest = json.loads((HERE / "fixtures/manifest.json").read_text())
            documents = []
            for item in manifest["documents"]:
                content = (HERE / "fixtures" / item["filename"]).read_bytes()
                require(
                    __import__("hashlib").sha256(content).hexdigest() == item["sha256"],
                    "fixture_source_drift",
                )
                documents.append(
                    {
                        **item,
                        **parse_document(item["filename"], content),
                        "artifact_ref": "artifact://synthetic/qualification/"
                        + item["filename"],
                        "shared_with": list(DEPARTMENTS),
                    }
                )
            snapshot = {
                "documents": documents,
                "scenario": "normal",
                "department_id": "product_center",
            }
            require(
                execute_tool("validate_requirements", {}, snapshot)["passed"],
                "asset_requirement_self_check_failed",
            )
            require(
                execute_tool("run_acceptance", {}, snapshot)["passed"],
                "asset_acceptance_self_check_failed",
            )
            require(
                bool(
                    execute_tool("retrieve_evidence", {"query": "权限 引用"}, snapshot)[
                        "citations"
                    ]
                ),
                "asset_retrieval_self_check_failed",
            )
        if kind == "agents":
            state = self.agents.replay().agent(identity)
            release = state.candidate.release_digest
            if action == "evaluate":
                self.agents.record_evaluation(
                    LifecycleEvaluation(
                        "eval_" + identity,
                        identity,
                        release,
                        "agt_delivery_independent_evaluator_syn",
                        "pass",
                        "recommend",
                        ("evidence_delivery_fixed_suite_syn",),
                        (),
                    ),
                    idempotency_key=key,
                )
            elif action == "activate":
                decision = SyntheticApprovalDecision(
                    "approval_" + digest(key)[7:35],
                    "activate",
                    identity,
                    release,
                    actor,
                    "approve",
                    "本机账号明确批准演示Agent激活，不构成生产授权",
                )
                self.agents.record_approval(decision, idempotency_key=key + ":approval")
                self.agents.activate_stable(
                    identity,
                    approval_decision_ref=decision.decision_id,
                    idempotency_key=key,
                )
            elif action == "suspend":
                self.agents.suspend(
                    identity,
                    actor_kind="system",
                    actor_ref=actor,
                    reason_code="local_operator_suspended",
                    idempotency_key=key,
                )
            else:
                require(False, "asset_action_not_allowed")
        else:
            require(kind == "tools", "asset_kind_invalid")
            state = self.tools.replay().tool(identity)
            release = state.candidate.release_digest
            if action == "evaluate":
                self.tools.record_evaluation(
                    ToolLifecycleEvaluation(
                        "eval_" + identity,
                        identity,
                        release,
                        "agt_delivery_independent_evaluator_syn",
                        "pass",
                        "recommend",
                        state.candidate.d0_allowed_operation_ids,
                        ("evidence_delivery_fixed_suite_syn",),
                        (),
                    ),
                    idempotency_key=key,
                )
            elif action == "activate":
                decision = SyntheticToolApprovalDecision(
                    "approval_" + digest(key)[7:35],
                    "activate",
                    identity,
                    release,
                    actor,
                    "approve",
                    "本机账号明确批准演示Tool激活，不构成生产授权",
                )
                self.tools.record_approval(decision, idempotency_key=key + ":approval")
                self.tools.activate(
                    identity,
                    release,
                    approval_decision_ref=decision.decision_id,
                    idempotency_key=key,
                )
            elif action == "suspend":
                self.tools.suspend(
                    identity,
                    release,
                    actor_ref=actor,
                    reason_code="local_operator_suspended",
                    idempotency_key=key,
                )
            else:
                require(False, "asset_action_not_allowed")
        return self.status()
