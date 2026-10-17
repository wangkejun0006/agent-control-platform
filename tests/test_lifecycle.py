from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from orbit_agent_control_plane.lifecycle import (
    AgentCandidate,
    ApprovedAgentTemplate,
    LifecycleError,
    LifecycleEvaluation,
    ParentTaskScope,
    SyntheticAgentLifecycleLedger,
    SyntheticApprovalDecision,
    TaskAgentRequest,
    classify_structural_change,
    instantiate_task_agent,
)


DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)


class SyntheticAgentLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "agent-lifecycle.synthetic.jsonl"
        self.candidate = AgentCandidate(
            agent_id="agt_lifecycle_assurance_syn",
            release_digest=DIGEST_A,
            definition_ref="definition_lifecycle_assurance_syn",
            binding_ref="binding_lifecycle_assurance_syn",
            owner_role_ref="role_platform_owner_syn",
            agent_system_ref="agent_system_company_control_syn",
            change_fields=("new_stable_agent", "purpose"),
            structural_change=True,
        )
        self.evaluation = LifecycleEvaluation(
            report_id="evaluation_lifecycle_assurance_syn",
            subject_agent_id=self.candidate.agent_id,
            subject_release_digest=self.candidate.release_digest,
            evaluator_agent_id="agt_evaluator_syn",
            verdict="pass",
            release_recommendation="recommend",
            evidence_refs=("evidence_contract_suite_syn", "evidence_safety_suite_syn"),
            risk_flags=(),
        )

    def approval(self, action: str, *, digest: str = DIGEST_A) -> SyntheticApprovalDecision:
        return SyntheticApprovalDecision(
            decision_id=f"decision_lifecycle_{action}_syn",
            action=action,
            subject_agent_id=self.candidate.agent_id,
            subject_release_digest=digest,
            decided_by_human_ref="human_platform_owner_syn",
            decision="approve",
            reason=f"approve D0 synthetic lifecycle {action}",
        )

    def assert_reason(self, reason: str, callback) -> None:
        with self.assertRaises(LifecycleError) as raised:
            callback()
        self.assertEqual(reason, raised.exception.reason_code)

    def test_stable_agent_requires_independent_evaluation_and_exact_human_approval(self) -> None:
        ledger = SyntheticAgentLifecycleLedger(self.path)
        first = ledger.register_candidate(self.candidate, idempotency_key="candidate:assurance")
        retry = ledger.register_candidate(self.candidate, idempotency_key="candidate:assurance")
        self.assertTrue(first.appended)
        self.assertFalse(retry.appended)

        self.assert_reason(
            "approval_decision_missing",
            lambda: ledger.activate_stable(
                self.candidate.agent_id,
                approval_decision_ref="decision_missing_syn",
                idempotency_key="transition:activate:missing",
            ),
        )
        self.assert_reason(
            "self_evaluation_forbidden",
            lambda: ledger.record_evaluation(
                replace(
                    self.evaluation,
                    evaluator_agent_id=self.candidate.agent_id,
                ),
                idempotency_key="evaluation:self",
            ),
        )

        ledger.record_evaluation(self.evaluation, idempotency_key="evaluation:pass")
        self.assert_reason(
            "approval_subject_mismatch",
            lambda: ledger.record_approval(
                self.approval("activate", digest=DIGEST_B),
                idempotency_key="approval:wrong-digest",
            ),
        )
        activate = self.approval("activate")
        ledger.record_approval(activate, idempotency_key="approval:activate")
        ledger.activate_stable(
            self.candidate.agent_id,
            approval_decision_ref=activate.decision_id,
            idempotency_key="transition:activate",
        )

        ledger.suspend(
            self.candidate.agent_id,
            actor_kind="system",
            actor_ref="system_security_monitor_syn",
            reason_code="synthetic_risk_signal",
            idempotency_key="transition:suspend",
        )
        self.assert_reason(
            "approval_decision_missing",
            lambda: ledger.retire_stable(
                self.candidate.agent_id,
                approval_decision_ref="decision_missing_syn",
                idempotency_key="transition:retire:missing",
            ),
        )
        retire = self.approval("retire")
        ledger.record_approval(retire, idempotency_key="approval:retire")
        ledger.retire_stable(
            self.candidate.agent_id,
            approval_decision_ref=retire.decision_id,
            idempotency_key="transition:retire",
        )

        replay = SyntheticAgentLifecycleLedger(self.path).replay()
        state = replay.agent(self.candidate.agent_id)
        self.assertEqual(7, replay.records_checked)
        self.assertEqual("retired", state.status)
        self.assertEqual(4, state.revision)
        self.assertEqual(2, len(state.approvals))
        self.assertFalse(state.evaluation.release_authorization)
        self.assertFalse(state.transitions[1].automatic)
        self.assertTrue(state.transitions[2].automatic)

    def template(self) -> ApprovedAgentTemplate:
        return ApprovedAgentTemplate(
            template_id="template_research_task_agent_syn",
            version="0.1.0",
            template_digest=DIGEST_B,
            child_definition_ref="definition_research_task_agent_syn",
            agent_system_ref="agent_system_research_syn",
            capabilities=("dataset_metadata_review", "evidence_summary"),
            tool_operations=("registry_metadata_read",),
            data_operations=("discover", "read"),
            data_classifications=("synthetic", "public"),
            budget_units=10,
            max_lifetime_seconds=600,
            max_delegation_depth=0,
            approved_by_human_ref="human_platform_owner_syn",
        )

    def parent(self) -> ParentTaskScope:
        return ParentTaskScope(
            task_id="task_parent_research_syn",
            agent_system_ref="agent_system_research_syn",
            capabilities=("dataset_metadata_review", "evidence_summary"),
            tool_operations=("registry_metadata_read",),
            data_operations=("discover", "read"),
            data_classifications=("synthetic", "public"),
            budget_units=8,
            remaining_lifetime_seconds=500,
            max_delegation_depth=0,
        )

    def request(self) -> TaskAgentRequest:
        template = self.template()
        return TaskAgentRequest(
            agent_id="agt_task_dataset_review_syn",
            parent_task_id=self.parent().task_id,
            template_id=template.template_id,
            template_version=template.version,
            template_digest=template.template_digest,
            child_definition_ref=template.child_definition_ref,
            agent_system_ref=template.agent_system_ref,
            capabilities=("dataset_metadata_review",),
            tool_operations=("registry_metadata_read",),
            data_operations=("read",),
            data_classifications=("synthetic",),
            budget_units=5,
            lifetime_seconds=300,
            delegation_depth=0,
            approval_obligations_preserved=True,
        )

    def test_approved_template_task_agent_auto_activates_and_auto_retires(self) -> None:
        template = self.template()
        parent = self.parent()
        request = self.request()
        instantiation = instantiate_task_agent(template, parent, request)
        self.assertEqual("allow", instantiation.policy_decision)

        ledger = SyntheticAgentLifecycleLedger(self.path)
        ledger.spawn_task_agent(
            template,
            parent,
            request,
            idempotency_key="spawn:dataset-review",
        )
        active = ledger.replay().agent(request.agent_id)
        self.assertEqual("active", active.status)
        self.assertTrue(active.transitions[0].automatic)
        self.assertEqual((), active.approvals)

        ledger.retire_task_agent(
            request.agent_id,
            idempotency_key="retire:dataset-review",
        )
        retired = SyntheticAgentLifecycleLedger(self.path).replay().agent(
            request.agent_id
        )
        self.assertEqual("retired", retired.status)
        self.assertTrue(retired.cleanup.runtime_destroyed)
        self.assertTrue(retired.cleanup.grants_revoked)
        self.assertTrue(retired.cleanup.identity_soft_retired)
        self.assertTrue(retired.cleanup.working_memory_deleted)
        self.assertTrue(retired.cleanup.audit_retained)

    def test_template_escape_and_non_d0_request_fail_closed(self) -> None:
        template = self.template()
        parent = self.parent()
        request = self.request()
        scenarios = (
            (replace(request, budget_units=9), "budget_not_parent_subset"),
            (
                replace(request, capabilities=("dataset_metadata_review", "shell")),
                "capability_not_parent_subset",
            ),
            (
                replace(request, data_classifications=("internal",)),
                "classification_not_parent_subset",
            ),
            (
                replace(request, approval_obligations_preserved=False),
                "approval_obligations_weakened",
            ),
        )
        for invalid, reason in scenarios:
            with self.subTest(reason=reason):
                self.assert_reason(
                    reason,
                    lambda invalid=invalid: instantiate_task_agent(
                        template, parent, invalid
                    ),
                )

    def test_structural_classification_tamper_and_file_tamper_fail_closed(self) -> None:
        self.assertTrue(classify_structural_change(("purpose",)))
        self.assertFalse(classify_structural_change(("implementation_refactor",)))
        self.assert_reason(
            "structural_classification_mismatch",
            lambda: SyntheticAgentLifecycleLedger(self.path).register_candidate(
                replace(self.candidate, structural_change=False),
                idempotency_key="candidate:bad-classification",
            ),
        )

        ledger = SyntheticAgentLifecycleLedger(self.path)
        ledger.register_candidate(self.candidate, idempotency_key="candidate:tamper")
        source = self.path.read_text(encoding="utf-8")
        self.path.write_text(
            source.replace("new_stable_agent", "implementation_refactor"),
            encoding="utf-8",
        )
        os.chmod(self.path, 0o600)
        self.assert_reason(
            "record_hash_mismatch",
            lambda: SyntheticAgentLifecycleLedger(self.path).replay(),
        )

    def test_duplicate_key_symlink_and_broad_permissions_are_rejected(self) -> None:
        ledger = SyntheticAgentLifecycleLedger(self.path)
        ledger.register_candidate(self.candidate, idempotency_key="candidate:file")
        source = self.path.read_text(encoding="utf-8")
        self.path.write_text(
            source.replace('"sequence":0', '"sequence":0,"sequence":0', 1),
            encoding="utf-8",
        )
        os.chmod(self.path, 0o600)
        self.assert_reason(
            "duplicate_json_key",
            lambda: SyntheticAgentLifecycleLedger(self.path).replay(),
        )

        target = Path(self.temporary.name) / "target.jsonl"
        target.write_text("", encoding="utf-8")
        os.chmod(target, 0o600)
        link = Path(self.temporary.name) / "link.jsonl"
        link.symlink_to(target)
        self.assert_reason(
            "ledger_symlink_forbidden",
            lambda: SyntheticAgentLifecycleLedger(link).replay(),
        )

        other = Path(self.temporary.name) / "broad.jsonl"
        broad = SyntheticAgentLifecycleLedger(other)
        broad.register_candidate(self.candidate, idempotency_key="candidate:broad")
        os.chmod(other, 0o644)
        self.assert_reason(
            "ledger_permissions_too_broad",
            lambda: SyntheticAgentLifecycleLedger(other).replay(),
        )


if __name__ == "__main__":
    unittest.main()

