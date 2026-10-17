from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from orbit_agent_control_plane.qualification.automation import (
    BOUNDARY_NAMES,
    CheckpointDecision,
    CheckpointPolicy,
    PolicyEngine,
    QualificationAutomationError,
    QualificationCandidate,
    RemediationPlan,
    StageCheck,
    StageHandlerResult,
    StageObservation,
    StageSideEffects,
    build_policy_activation_receipt,
    build_remediation_receipt,
    build_stage_receipt,
    canonical_digest,
    issue_evaluation_grant,
    validate_automation_policy,
)
from orbit_agent_control_plane.qualification.ledger import (
    JsonlQualificationEventStore,
    QualificationController,
    QualificationLedgerError,
    QualificationReconciler,
    qualification_run_snapshot,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64
POLICY_CREATED = "2026-08-27T00:00:00+00:00"
POLICY_EXPIRES = "2026-08-28T00:00:00+00:00"
NOW = datetime(2026, 8, 27, 1, 0, tzinfo=timezone.utc)


def automation_policy(
    stage_plan: tuple[str, ...] = (
        "runtime_realization",
        "model_literature_r2",
        "release_review",
    ),
) -> dict:
    return {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "AutomationPolicy",
        "metadata": {
            "policy_id": "pol_disease_qualification_syn",
            "version": "0.1.0",
            "status": "candidate",
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "created_at": POLICY_CREATED,
            "expires_at": POLICY_EXPIRES,
        },
        "spec": {
            "purpose": "agent_release_qualification",
            "subject_constraints": {
                "agent_ids": ["agt_disease_research_syn"],
                "release_states": ["candidate", "evaluation"],
                "runtime_families": ["thin_python_worker"],
                "data_classifications": ["synthetic", "public"],
            },
            "stage_plan": list(stage_plan),
            "execution_envelope": {
                "model_route_refs": [
                    {
                        "role": "model_route",
                        "ref": "model-route://disease_r2/0.1.0",
                        "digest": DIGEST_B,
                    }
                ],
                "tool_scopes": [
                    {
                        "tool_release": {
                            "role": "literature_tool_release",
                            "ref": "tool-release://literature_public/0.1.0",
                            "digest": DIGEST_C,
                        },
                        "operations": [
                            "fetch_public_record",
                            "search_public_corpus",
                        ],
                    }
                ],
                "input_artifact_allowlist": [
                    {
                        "role": "agent_release",
                        "ref": "agent-release://disease_r2/0.2.0",
                        "digest": canonical_digest("agent_release"),
                    },
                    {
                        "role": "public_corpus_revision",
                        "ref": "corpus://disease_r2/revision_001",
                        "digest": DIGEST_D,
                    }
                ],
                "endpoint_origin_allowlist": [
                    "https://api.synthetic.example/v1/chat/completions"
                ],
                "isolation_profile_digests": [DIGEST_E],
                "trusted_stage_handlers": [
                    {
                        "id": "worker_qualification_syn",
                        "version": "0.1.0",
                        "digest": DIGEST_A,
                    }
                ],
                "evaluation_suite_refs": [
                    {
                        "role": "domain_evaluation_suite",
                        "ref": "artifact://disease_r2/domain_suite",
                        "digest": canonical_digest("domain_suite"),
                    },
                    {
                        "role": "company_evaluation_suite",
                        "ref": "artifact://disease_r2/company_suite",
                        "digest": canonical_digest("company_suite"),
                    },
                ],
                "max_concurrency": 1,
                "max_attempts_per_stage": 3,
                "max_total_attempts": 12,
                "max_runtime_seconds": 900,
                "max_model_requests": 8,
                "max_input_tokens": 24000,
                "max_output_tokens": 2048,
                "max_cost_usd": "0.20",
                "max_cost_cny": "1.50",
                "agent_direct_network": False,
                "agent_credentials": False,
                "nas_access": False,
                "real_medical_data": False,
            },
            "remediation_envelope": {
                "allowed_failure_classes": [
                    "engineering_compatibility",
                    "deterministic_test_failure",
                    "transient_runtime",
                    "quality_candidate_revision",
                ],
                "source_change_policy": "implementation_only_same_runtime_family",
                "immutable_attempt_history": True,
                "independent_verification": True,
                "unchanged_boundaries": list(BOUNDARY_NAMES),
            },
            "human_checkpoint_triggers": [
                "purpose_or_owner_change",
                "capability_or_tool_scope_expansion",
                "data_classification_expansion",
                "provider_model_or_endpoint_change",
                "budget_ceiling_expansion",
                "isolation_or_identity_weakening",
                "real_data_or_nas_access",
                "risk_waiver_or_evaluation_override",
                "formal_registration",
                "preproduction_promotion",
                "production_promotion",
                "policy_budget_exhausted",
            ],
            "authority_boundary": {
                "may_issue_evaluation_grant": True,
                "may_activate_agent": False,
                "may_activate_tool": False,
                "may_approve_model_route": False,
                "may_register_formally": False,
                "may_promote_preproduction": False,
                "may_promote_production": False,
                "release_authorization": False,
            },
        },
    }


def candidate(attempt_number: int = 1) -> QualificationCandidate:
    suffix = str(attempt_number)
    return QualificationCandidate.from_mapping(
        {
            "attempt_id": f"attempt_disease_r2_{suffix}_syn",
            "attempt_number": attempt_number,
            "agent_id": "agt_disease_research_syn",
            "release_state": "candidate",
            "agent_release_ref": "agent-release://disease_r2/0.2.0",
            "agent_release_digest": canonical_digest("agent_release"),
            "runtime_family": "thin_python_worker",
            "runtime_source_digest": canonical_digest(f"runtime_source:{suffix}"),
            "composition_ref": f"composition://disease_r2/attempt_{suffix}",
            "composition_digest": canonical_digest(f"composition:{suffix}"),
            "task_ref": f"task://disease_r2/attempt_{suffix}",
            "task_digest": canonical_digest(f"task:{suffix}"),
            "grant_candidate_ref": f"grant-candidate://disease_r2/attempt_{suffix}",
            "grant_candidate_digest": canonical_digest(f"grant:{suffix}"),
            "data_classification": "public",
            "model_route_digest": DIGEST_B,
            "tool_operations": (
                f"{DIGEST_C}#fetch_public_record",
                f"{DIGEST_C}#search_public_corpus",
            ),
            "endpoint_origins": ("https://api.synthetic.example/v1/chat/completions",),
            "input_artifact_digests": (
                canonical_digest("agent_release"),
                DIGEST_D,
            ),
            "isolation_profile_digest": DIGEST_E,
            "stage_handler_digests": (DIGEST_A,),
            "evaluation_suite_digests": (
                canonical_digest("domain_suite"),
                canonical_digest("company_suite"),
            ),
            "max_model_requests": 4,
            "max_input_tokens": 12000,
            "max_output_tokens": 1024,
            "max_cost_usd": "0.10",
            "max_cost_cny": "0.75",
            "max_runtime_seconds": 600,
            "agent_direct_network": False,
            "agent_credentials": False,
            "nas_access": False,
            "real_medical_data": False,
            "boundary_digests": {
                name: canonical_digest(f"boundary:{name}") for name in BOUNDARY_NAMES
            },
        }
    )


def activation_chain(policy: dict):
    policy_digest = canonical_digest(policy)
    approval = {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "ApprovalDecision",
        "metadata": {
            "decision_id": "decision_disease_automation_policy_syn",
            "approval_id": "approval_disease_automation_policy_syn",
            "task_id": "task_disease_policy_review_syn",
            "status": "immutable",
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "decided_at": "2026-08-27T00:30:00+00:00",
        },
        "spec": {
            "decision": "approve",
            "decided_by_human_ref": "human_platform_owner_syn",
            "decided_by_role_ref": "role_platform_owner",
            "scope_ref": "policy://pol_disease_qualification_syn/0.1.0",
            "scope_digest": policy_digest,
            "reason": "approve exact synthetic qualification policy envelope",
            "expires_at": POLICY_EXPIRES,
            "separation_of_duties_check_ref": "audit://sod_policy_syn",
            "audit_event_refs": ["audit_policy_activation_syn"],
        },
    }
    activation = build_policy_activation_receipt(
        policy=policy,
        policy_digest=policy_digest,
        approval_decision=approval,
        activated_at="2026-08-27T00:31:00+00:00",
    )
    return approval, activation


def observation(
    stage: str,
    *,
    outcome: str = "pass",
    failure_class: str = "none",
    reason: str = "stage_passed",
) -> StageObservation:
    return StageObservation(
        stage=stage,
        outcome=outcome,
        failure_class=failure_class,
        reason_codes=(reason,),
        checks=(
            StageCheck(
                "deterministic_check",
                "pass" if outcome == "pass" else "blocked",
                None if outcome == "pass" else reason,
            ),
        ),
        inputs=(
            {
                "role": "runtime_composition",
                "ref": "composition://disease_r2/input",
                "digest": canonical_digest("input"),
            },
        ),
        executor={
            "component": {
                "id": "component_qualification_worker",
                "version": "0.1.0",
                "digest": DIGEST_A,
            },
            "deterministic": True,
            "environment_profile_digest": DIGEST_E,
        },
        side_effects=StageSideEffects(
            effective_task_created=stage == "model_literature_r2",
            effective_grant_created=stage == "model_literature_r2",
            provider_calls=1 if stage == "model_literature_r2" else 0,
        ),
        started_at="2026-08-27T01:00:00+00:00",
        completed_at="2026-08-27T01:00:01+00:00",
    )


def execution_closure(context: dict, stage: str) -> dict:
    grant = context["evaluation_grant"]
    candidate_mapping = context["candidate"]
    return {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "ExecutionClosureReceipt",
        "metadata": {
            "receipt_id": f"receipt_{stage}_closure_syn",
            "run_id": context["run_id"],
            "attempt_id": candidate_mapping["attempt_id"],
            "stage": stage,
            "status": "completed",
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "closed_at": "2026-08-27T01:00:02+00:00",
        },
        "spec": {
            "composition": {
                "role": "runtime_composition",
                "ref": candidate_mapping["composition_ref"],
                "digest": candidate_mapping["composition_digest"],
            },
            "task": {
                "ref": candidate_mapping["task_ref"],
                "digest": candidate_mapping["task_digest"],
                "status": "completed",
                "revision": 1,
            },
            "grant": {
                "ref": f"grant://{grant['grant_id']}",
                "digest": grant["grant_digest"],
                "status": "consumed",
                "revision": 1,
            },
            "route": {
                "ref": "ledger://route_disease_r2_syn",
                "digest": canonical_digest("route"),
                "status": "consumed",
                "revision": 1,
            },
            "worker_lease": {
                "ref": "ledger://lease_disease_r2_syn",
                "digest": canonical_digest("lease"),
                "status": "closed",
                "revision": 1,
            },
            "policy_decision": {
                "ref": f"receipt://{grant['policy_decision_receipt_digest'][7:23]}",
                "digest": grant["policy_decision_receipt_digest"],
                "status": "consumed",
                "revision": 1,
            },
            "model_route": {
                "ref": "model-route://disease_r2/0.1.0",
                "digest": candidate_mapping["model_route_digest"],
                "status": "consumed",
                "revision": 1,
            },
            "result": {
                "role": "result_package",
                "ref": f"artifact://disease_r2/{stage}/result",
                "digest": canonical_digest(f"result:{stage}"),
            },
            "evaluations": [
                {
                    "evaluator_class": "domain",
                    "report": {
                        "role": "domain_evaluation",
                        "ref": f"artifact://disease_r2/{stage}/domain",
                        "digest": canonical_digest(f"domain:{stage}"),
                    },
                    "verdict": "pass",
                    "release_authorization": False,
                },
                {
                    "evaluator_class": "company",
                    "report": {
                        "role": "company_evaluation",
                        "ref": f"artifact://disease_r2/{stage}/company",
                        "digest": canonical_digest(f"company:{stage}"),
                    },
                    "verdict": "pass",
                    "release_authorization": False,
                },
            ],
            "usage": {
                "model_calls": 1,
                "request_attempts": 1,
                "input_tokens": 100,
                "output_tokens": 20,
                "cost_usd": "0.01",
                "cost_cny": "0.07",
                "runtime_seconds": 1,
            },
            "cleanup": {
                "process_group_terminated": True,
                "temporary_workspace_removed": True,
                "credentials_absent": True,
                "external_handles_closed": True,
                "cleanup_errors": [],
            },
            "audit_refs": [f"ledger://audit_{stage}_syn"],
            "terminal_consistency": {
                "task_terminal": True,
                "grant_terminal": True,
                "route_terminal": True,
                "lease_terminal": True,
                "policy_decision_bound": True,
                "result_and_evaluations_bound": True,
                "replay_passed": True,
            },
            "authority_boundary": {
                "formal_registry_written": False,
                "agent_activated": False,
                "preproduction_promoted": False,
                "production_promoted": False,
                "release_authorization": False,
            },
        },
    }


class QualificationAutomationTests(unittest.TestCase):
    def test_policy_activation_requires_exact_human_approval(self) -> None:
        policy = automation_policy(("runtime_realization",))
        approval, activation = activation_chain(policy)
        self.assertEqual(activation.document["metadata"]["status"], "active")
        forged = json.loads(json.dumps(approval))
        forged["spec"]["decided_by_human_ref"] = "component_policy_engine"
        with self.assertRaisesRegex(
            QualificationAutomationError, "automation_policy_approval_invalid"
        ):
            build_policy_activation_receipt(
                policy=policy,
                policy_digest=canonical_digest(policy),
                approval_decision=forged,
                activated_at="2026-08-27T00:31:00+00:00",
            )

    def test_policy_validation_fail_closes_on_contract_shape_and_insecure_endpoint(
        self,
    ) -> None:
        policy = automation_policy()
        missing_trigger = json.loads(json.dumps(policy))
        missing_trigger["spec"]["human_checkpoint_triggers"] = ["production_promotion"]
        with self.assertRaisesRegex(
            QualificationAutomationError, "automation_policy_triggers_invalid"
        ):
            validate_automation_policy(missing_trigger)

        insecure_endpoint = json.loads(json.dumps(policy))
        insecure_endpoint["spec"]["execution_envelope"]["endpoint_origin_allowlist"] = [
            "http://api.synthetic.example/v1/chat/completions"
        ]
        with self.assertRaisesRegex(
            QualificationAutomationError, "endpoint_allowlist_invalid"
        ):
            validate_automation_policy(insecure_endpoint)

        expected_scopes = {
            "formal_registration": "formal_registration",
            "release_review": "agent_activation",
            "preproduction_promotion": "preproduction_promotion",
            "production_promotion": "production_promotion",
        }
        human_policy = automation_policy(tuple(expected_scopes))
        for stage, expected_scope in expected_scopes.items():
            with self.subTest(stage=stage):
                decision = CheckpointPolicy.classify(
                    policy=human_policy,
                    observation=observation(stage),
                    stage_attempt=0,
                    total_attempt=0,
                )
                self.assertEqual("human_checkpoint", decision.next_action)
                self.assertEqual(expected_scope, decision.human_checkpoint_scope)

    def test_policy_engine_issues_stage_scoped_single_use_grant(self) -> None:
        policy = automation_policy(("model_literature_r2", "release_review"))
        subject = candidate()
        policy_digest = canonical_digest(policy)
        _, activation = activation_chain(policy)
        decision = PolicyEngine.evaluate(
            policy=policy,
            policy_digest=policy_digest,
            policy_activation=activation,
            run_id="run_disease_r2_syn",
            stage="model_literature_r2",
            candidate=subject,
            decided_at="2026-08-27T01:00:00+00:00",
        )
        self.assertEqual(decision.document["spec"]["decision"], "allow")
        self.assertFalse(
            decision.document["spec"]["authority_boundary"]["human_approval"]
        )
        grant = issue_evaluation_grant(
            run_id="run_disease_r2_syn",
            stage="model_literature_r2",
            candidate=subject,
            policy_decision=decision,
            issued_at="2026-08-27T01:00:00+00:00",
            expires_at="2026-08-27T01:10:00+00:00",
        )
        self.assertEqual(grant.stage, "model_literature_r2")
        self.assertTrue(grant.single_use)
        self.assertFalse(grant.production_authorization)

    def test_public_pilot_policy_preserves_public_receipt_and_grant_evidence(self) -> None:
        policy = automation_policy(("model_literature_r2", "release_review"))
        policy["metadata"].update(
            {
                "policy_id": "pol_disease_public_pilot",
                "evidence_status": "public",
                "synthetic_only": False,
            }
        )
        validate_automation_policy(policy)
        policy_digest = canonical_digest(policy)
        approval = {
            "api_version": "company-ai-os/v1alpha1",
            "kind": "ApprovalDecision",
            "metadata": {
                "decision_id": "decision_disease_public_pilot",
                "approval_id": "approval_disease_public_pilot",
                "task_id": "task_disease_public_pilot_review",
                "status": "immutable",
                "evidence_status": "public",
                "synthetic_only": False,
                "decided_at": "2026-08-27T00:30:00+00:00",
            },
            "spec": {
                "decision": "approve",
                "decided_by_human_ref": "human_platform_owner_syn",
                "decided_by_role_ref": "role_platform_owner",
                "scope_ref": "policy://pol_disease_public_pilot/0.1.0",
                "scope_digest": policy_digest,
                "reason": "approve exact public corpus pilot envelope",
                "expires_at": POLICY_EXPIRES,
                "separation_of_duties_check_ref": "audit://public_pilot/sod",
                "audit_event_refs": ["audit_public_pilot_approval"],
            },
        }
        activation = build_policy_activation_receipt(
            policy=policy,
            policy_digest=policy_digest,
            approval_decision=approval,
            activated_at="2026-08-27T00:31:00+00:00",
        )
        self.assertEqual("public", activation.document["metadata"]["evidence_status"])
        self.assertFalse(activation.document["metadata"]["synthetic_only"])
        subject = candidate()
        decision = PolicyEngine.evaluate(
            policy=policy,
            policy_digest=policy_digest,
            policy_activation=activation,
            run_id="run_disease_public_pilot",
            stage="model_literature_r2",
            candidate=subject,
            decided_at="2026-08-27T01:00:00+00:00",
        )
        self.assertFalse(decision.document["metadata"]["synthetic_only"])
        grant = issue_evaluation_grant(
            run_id="run_disease_public_pilot",
            stage="model_literature_r2",
            candidate=subject,
            policy_decision=decision,
            issued_at="2026-08-27T01:00:00+00:00",
            expires_at="2026-08-27T01:10:00+00:00",
        )
        self.assertFalse(grant.synthetic_only)
        stage = build_stage_receipt(
            run_id="run_disease_public_pilot",
            candidate=subject,
            sequence=0,
            observation=observation("model_literature_r2"),
            decision=CheckpointDecision("advance", None, ("stage_passed",)),
        )
        self.assertEqual("public", stage.document["metadata"]["evidence_status"])
        self.assertFalse(stage.document["metadata"]["synthetic_only"])

    def test_policy_expansion_requires_human_and_cannot_issue_grant(self) -> None:
        policy = automation_policy(("model_literature_r2",))
        _, activation = activation_chain(policy)
        expanded = replace(candidate(), agent_direct_network=True)
        decision = PolicyEngine.evaluate(
            policy=policy,
            policy_digest=canonical_digest(policy),
            policy_activation=activation,
            run_id="run_disease_r2_syn",
            stage="model_literature_r2",
            candidate=expanded,
            decided_at="2026-08-27T01:00:00+00:00",
        )
        self.assertEqual(decision.document["spec"]["decision"], "require_human")
        with self.assertRaisesRegex(
            QualificationAutomationError, "evaluation_grant_policy_denied"
        ):
            issue_evaluation_grant(
                run_id="run_disease_r2_syn",
                stage="model_literature_r2",
                candidate=expanded,
                policy_decision=decision,
                issued_at="2026-08-27T01:00:00+00:00",
                expires_at="2026-08-27T01:01:00+00:00",
            )

    def test_policy_rejects_unlisted_agent_release_digest(self) -> None:
        policy = automation_policy(("model_literature_r2",))
        _, activation = activation_chain(policy)
        drifted = replace(candidate(), agent_release_digest=canonical_digest("drifted"))
        decision = PolicyEngine.evaluate(
            policy=policy,
            policy_digest=canonical_digest(policy),
            policy_activation=activation,
            run_id="run_disease_r2_syn",
            stage="model_literature_r2",
            candidate=drifted,
            decided_at="2026-08-27T01:00:00+00:00",
        )
        self.assertEqual("require_human", decision.document["spec"]["decision"])
        self.assertIn(
            "policy_release_state_outside_envelope",
            decision.document["spec"]["reason_codes"],
        )

    def test_runtime_engineering_failure_is_machine_remediable(self) -> None:
        policy = automation_policy(("runtime_realization", "release_review"))
        blocked = observation(
            "runtime_realization",
            outcome="blocked",
            failure_class="engineering_compatibility",
            reason="runtime_entrypoint_incompatible",
        )
        checkpoint = CheckpointPolicy.classify(
            policy=policy,
            observation=blocked,
            stage_attempt=0,
            total_attempt=0,
        )
        self.assertEqual(checkpoint.next_action, "auto_remediate")
        self.assertIsNone(checkpoint.human_checkpoint_scope)

    def test_stage_retry_ceiling_pauses_for_machine_repair_not_human_approval(
        self,
    ) -> None:
        policy = automation_policy(("runtime_realization",))
        blocked = observation(
            "runtime_realization",
            outcome="blocked",
            failure_class="engineering_compatibility",
            reason="runtime_entrypoint_incompatible",
        )
        checkpoint = CheckpointPolicy.classify(
            policy=policy,
            observation=blocked,
            stage_attempt=policy["spec"]["execution_envelope"][
                "max_attempts_per_stage"
            ],
            total_attempt=1,
        )
        self.assertEqual("automation_pause", checkpoint.next_action)
        self.assertIsNone(checkpoint.human_checkpoint_scope)
        self.assertIn(
            "verified_same_family_remediation_required",
            checkpoint.reason_codes,
        )

    def test_remediation_rejects_permission_boundary_change(self) -> None:
        policy = automation_policy(("runtime_realization",))
        predecessor = candidate()
        blocked = observation(
            "runtime_realization",
            outcome="blocked",
            failure_class="engineering_compatibility",
            reason="runtime_entrypoint_incompatible",
        )
        checkpoint = CheckpointPolicy.classify(
            policy=policy,
            observation=blocked,
            stage_attempt=0,
            total_attempt=0,
        )
        stage_receipt = build_stage_receipt(
            run_id="run_disease_r2_syn",
            candidate=predecessor,
            sequence=0,
            observation=blocked,
            decision=checkpoint,
        )
        changed_boundaries = dict(predecessor.boundary_digests)
        changed_boundaries["capabilities"] = canonical_digest("expanded")
        successor = replace(candidate(2), boundary_digests=changed_boundaries)
        plan = RemediationPlan(
            successor=successor,
            changes=(
                {
                    "component_ref": "component://runtime_adapter/0.1.0",
                    "change_class": "adapter_fix",
                    "before_digest": predecessor.runtime_source_digest,
                    "after_digest": successor.runtime_source_digest,
                    "reason": "repair synthetic runtime entrypoint compatibility",
                },
            ),
            verification_receipt_refs=(
                {
                    "role": "verification_receipt",
                    "ref": "receipt://runtime_adapter_check_syn",
                    "digest": canonical_digest("verification"),
                },
            ),
        )
        with self.assertRaisesRegex(
            QualificationAutomationError, "remediation_boundary_changed"
        ):
            build_remediation_receipt(
                run_id="run_disease_r2_syn",
                policy=policy,
                policy_digest=canonical_digest(policy),
                predecessor=predecessor,
                failed_stage_receipt=stage_receipt,
                plan=plan,
                created_at="2026-08-27T01:00:02+00:00",
            )


class QualificationLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "qualification.jsonl"
        self.store = JsonlQualificationEventStore(self.path)
        self.controller = QualificationController(self.store)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def register(
        self,
        stage_plan: tuple[str, ...],
        policy: dict | None = None,
    ) -> None:
        policy = policy or automation_policy(stage_plan)
        approval, activation = activation_chain(policy)
        self.controller.register_run(
            run_id="run_disease_r2_syn",
            policy=policy,
            policy_digest=canonical_digest(policy),
            policy_activation=activation,
            policy_approval_decision=approval,
            candidate=candidate(),
            stage_plan=stage_plan,
            stage_handlers={
                stage: {
                    "id": "component_qualification_worker",
                    "version": "0.1.0",
                    "digest": DIGEST_A,
                }
                for stage in stage_plan
            },
            registered_at="2026-08-27T01:00:00+00:00",
            idempotency_key="register:disease-r2",
        )

    def test_reconciler_pauses_for_machine_repair_without_human_checkpoint(
        self,
    ) -> None:
        stage_plan = ("runtime_realization",)
        policy = automation_policy(stage_plan)
        policy["spec"]["execution_envelope"]["max_attempts_per_stage"] = 1
        self.register(stage_plan, policy)
        remediation_calls = []

        def failing_handler(_: dict) -> StageHandlerResult:
            return StageHandlerResult(
                observation(
                    "runtime_realization",
                    outcome="blocked",
                    failure_class="engineering_compatibility",
                    reason="runtime_entrypoint_incompatible",
                )
            )

        def retry_handler(context: dict, _: StageObservation) -> RemediationPlan:
            remediation_calls.append(context["candidate"]["attempt_id"])
            predecessor = QualificationCandidate.from_mapping(context["candidate"])
            successor = candidate(predecessor.attempt_number + 1)
            return RemediationPlan(
                successor=successor,
                changes=(
                    {
                        "component_ref": "component://runtime_adapter/0.1.0",
                        "change_class": "workflow_candidate_revision",
                        "before_digest": predecessor.runtime_source_digest,
                        "after_digest": successor.runtime_source_digest,
                        "reason": "retry once before requesting verified repair",
                    },
                ),
                verification_receipt_refs=(
                    {
                        "role": "verification_receipt",
                        "ref": "receipt://bounded_retry_syn",
                        "digest": canonical_digest("bounded_retry"),
                    },
                ),
            )

        state = QualificationReconciler(
            self.controller,
            stage_handlers={"runtime_realization": failing_handler},
            remediation_handlers={"runtime_realization": retry_handler},
            handler_digests={"runtime_realization": DIGEST_A},
            now=lambda: NOW,
        ).run_until_checkpoint("run_disease_r2_syn")
        self.assertEqual("remediating", state.status)
        self.assertIsNone(state.next_checkpoint_scope)
        self.assertEqual(1, len(remediation_calls))
        self.assertEqual(
            "automation_pause",
            state.last_stage_receipt.document["spec"]["decision"]["next_action"],
        )

    def test_reconciler_repairs_runtime_and_stops_at_release_review(self) -> None:
        stage_plan = (
            "runtime_realization",
            "model_literature_r2",
            "release_review",
        )
        self.register(stage_plan)

        def runtime_handler(context: dict) -> StageHandlerResult:
            if context["candidate"]["attempt_number"] == 1:
                return StageHandlerResult(
                    observation(
                        "runtime_realization",
                        outcome="blocked",
                        failure_class="engineering_compatibility",
                        reason="runtime_entrypoint_incompatible",
                    )
                )
            return StageHandlerResult(observation("runtime_realization"))

        def remediation_handler(
            context: dict, failed: StageObservation
        ) -> RemediationPlan:
            predecessor = QualificationCandidate.from_mapping(context["candidate"])
            successor = candidate(predecessor.attempt_number + 1)
            return RemediationPlan(
                successor=successor,
                changes=(
                    {
                        "component_ref": "component://runtime_adapter/0.1.0",
                        "change_class": "adapter_fix",
                        "before_digest": predecessor.runtime_source_digest,
                        "after_digest": successor.runtime_source_digest,
                        "reason": "repair synthetic runtime entrypoint compatibility",
                    },
                ),
                verification_receipt_refs=(
                    {
                        "role": "verification_receipt",
                        "ref": "receipt://runtime_adapter_check_syn",
                        "digest": canonical_digest("verification"),
                    },
                ),
            )

        def r2_handler(context: dict) -> StageHandlerResult:
            return StageHandlerResult(
                observation("model_literature_r2"),
                execution_closure(context, "model_literature_r2"),
            )

        reconciler = QualificationReconciler(
            self.controller,
            stage_handlers={
                "runtime_realization": runtime_handler,
                "model_literature_r2": r2_handler,
                "release_review": lambda _: StageHandlerResult(
                    observation("release_review")
                ),
            },
            remediation_handlers={"runtime_realization": remediation_handler},
            handler_digests={stage: DIGEST_A for stage in stage_plan},
            now=lambda: NOW,
        )
        state = reconciler.run_until_checkpoint("run_disease_r2_syn")
        self.assertEqual(state.status, "waiting_human")
        self.assertEqual(state.current_stage, "release_review")
        self.assertEqual(state.next_checkpoint_scope, "agent_activation")
        self.assertEqual(state.candidate.attempt_number, 2)
        self.assertEqual(len(state.remediation_receipts), 1)
        self.assertEqual(len(state.policy_decisions), 1)
        self.assertEqual(len(state.evaluation_grants), 1)
        self.assertEqual(state.evaluation_grants[0].consumption_status, "consumed")
        self.assertEqual(len(state.execution_closures), 1)
        self.assertEqual(
            state.execution_closures[0].document["metadata"]["stage"],
            "model_literature_r2",
        )
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        snapshot = qualification_run_snapshot(
            state, updated_at="2026-08-27T01:05:00+00:00"
        )
        self.assertEqual(snapshot.document["kind"], "QualificationRun")
        self.assertEqual(snapshot.document["metadata"]["status"], "waiting_human")
        self.assertEqual(
            snapshot.document["spec"]["next_checkpoint"]["scope"],
            "agent_activation",
        )
        self.assertEqual(len(snapshot.document["spec"]["execution_closure_refs"]), 1)

        state = reconciler.run_until_checkpoint("run_disease_r2_syn")
        self.assertEqual(state.status, "waiting_human")
        self.assertEqual(len(state.stage_receipts), 4)

        self.controller.resolve_human_checkpoint(
            run_id="run_disease_r2_syn",
            approval_decision={
                "api_version": "company-ai-os/v1alpha1",
                "kind": "ApprovalDecision",
                "metadata": {
                    "decision_id": "decision_release_review_syn",
                    "approval_id": "approval_release_review_syn",
                    "task_id": "task_release_review_syn",
                    "status": "immutable",
                    "evidence_status": "synthetic",
                    "synthetic_only": True,
                    "decided_at": "2026-08-27T01:10:00+00:00",
                },
                "spec": {
                    "decision": "approve",
                    "decided_by_human_ref": "human_platform_owner_syn",
                    "decided_by_role_ref": "role_platform_owner",
                    "scope_ref": ("checkpoint://agent_activation/run_disease_r2_syn"),
                    "scope_digest": canonical_digest(
                        {
                            "scope": "agent_activation",
                            "run_id": "run_disease_r2_syn",
                            "composition_ref": state.candidate.composition_ref,
                            "composition_digest": state.candidate.composition_digest,
                            "reason_codes": ["human_release_decision_required"],
                        }
                    ),
                    "reason": "approve exact synthetic release review checkpoint",
                    "expires_at": "2026-08-27T01:20:00+00:00",
                    "separation_of_duties_check_ref": "audit://sod_release_syn",
                    "audit_event_refs": ["audit_release_review_syn"],
                },
            },
            idempotency_key="approve:release-review",
        )
        self.assertEqual(
            self.controller.replay().run("run_disease_r2_syn").status,
            "completed",
        )

    def test_formal_registration_activation_and_promotions_are_separate_gates(
        self,
    ) -> None:
        stage_plan = (
            "formal_registration",
            "release_review",
            "preproduction_promotion",
            "production_promotion",
        )
        self.register(stage_plan)
        reconciler = QualificationReconciler(
            self.controller,
            stage_handlers={
                stage: (
                    lambda _, selected=stage: StageHandlerResult(observation(selected))
                )
                for stage in stage_plan
            },
            remediation_handlers={},
            handler_digests={stage: DIGEST_A for stage in stage_plan},
            now=lambda: NOW,
        )
        expected_scopes = (
            "formal_registration",
            "agent_activation",
            "preproduction_promotion",
            "production_promotion",
        )
        decision_digests: set[str] = set()
        for index, expected_scope in enumerate(expected_scopes, start=1):
            state = reconciler.run_until_checkpoint("run_disease_r2_syn")
            self.assertEqual("waiting_human", state.status)
            self.assertEqual(expected_scope, state.next_checkpoint_scope)
            scope_content = {
                "scope": expected_scope,
                "run_id": state.run_id,
                "composition_ref": state.candidate.composition_ref,
                "composition_digest": state.candidate.composition_digest,
                "reason_codes": ["human_release_decision_required"],
            }
            approval = {
                "api_version": "company-ai-os/v1alpha1",
                "kind": "ApprovalDecision",
                "metadata": {
                    "decision_id": f"decision_release_gate_{index}_syn",
                    "approval_id": f"approval_release_gate_{index}_syn",
                    "task_id": f"task_release_gate_{index}_syn",
                    "status": "immutable",
                    "evidence_status": "synthetic",
                    "synthetic_only": True,
                    "decided_at": "2026-08-27T01:10:00+00:00",
                },
                "spec": {
                    "decision": "approve",
                    "decided_by_human_ref": "human_platform_owner_syn",
                    "decided_by_role_ref": "role_platform_owner",
                    "scope_ref": f"checkpoint://{expected_scope}/{state.run_id}",
                    "scope_digest": canonical_digest(scope_content),
                    "reason": "approve exact synthetic release gate",
                    "expires_at": "2026-08-27T01:20:00+00:00",
                    "separation_of_duties_check_ref": (
                        f"audit://sod_release_gate_{index}_syn"
                    ),
                    "audit_event_refs": [f"audit_release_gate_{index}_syn"],
                },
            }
            decision_digests.add(canonical_digest(approval))
            self.controller.resolve_human_checkpoint(
                run_id=state.run_id,
                approval_decision=approval,
                idempotency_key=f"approve:release-gate:{index}",
            )
        final = self.controller.replay().run("run_disease_r2_syn")
        self.assertEqual("completed", final.status)
        self.assertEqual(4, len(final.human_checkpoint_decisions))
        self.assertEqual(4, len(decision_digests))

    def test_two_execution_stages_receive_distinct_single_use_grants(self) -> None:
        stage_plan = ("isolation_e4", "model_literature_r2", "release_review")
        self.register(stage_plan)

        def executing_handler(context: dict) -> StageHandlerResult:
            stage = context["stage"]
            return StageHandlerResult(
                observation(stage), execution_closure(context, stage)
            )

        reconciler = QualificationReconciler(
            self.controller,
            stage_handlers={
                "isolation_e4": executing_handler,
                "model_literature_r2": executing_handler,
                "release_review": lambda _: StageHandlerResult(
                    observation("release_review")
                ),
            },
            remediation_handlers={},
            handler_digests={stage: DIGEST_A for stage in stage_plan},
            now=lambda: NOW,
        )
        state = reconciler.run_until_checkpoint("run_disease_r2_syn")
        self.assertEqual(state.status, "waiting_human")
        self.assertEqual(
            [item.grant.stage for item in state.evaluation_grants],
            ["isolation_e4", "model_literature_r2"],
        )
        self.assertEqual(
            len({item.grant.grant_digest for item in state.evaluation_grants}), 2
        )
        self.assertTrue(
            all(
                item.consumption_status == "consumed"
                for item in state.evaluation_grants
            )
        )

    def test_invalid_execution_closure_consumes_grant_and_quarantines(self) -> None:
        stage_plan = ("model_literature_r2", "release_review")
        self.register(stage_plan)

        def handler(context: dict) -> StageHandlerResult:
            closure = execution_closure(context, "model_literature_r2")
            closure["spec"]["usage"]["cost_usd"] = "0.11"
            return StageHandlerResult(observation("model_literature_r2"), closure)

        state = QualificationReconciler(
            self.controller,
            stage_handlers={
                "model_literature_r2": handler,
                "release_review": lambda _: StageHandlerResult(
                    observation("release_review")
                ),
            },
            remediation_handlers={},
            handler_digests={stage: DIGEST_A for stage in stage_plan},
            now=lambda: NOW,
        ).run_until_checkpoint("run_disease_r2_syn")
        self.assertEqual(state.status, "quarantined")
        self.assertEqual(
            state.next_checkpoint_reason_codes,
            ("execution_closure_binding_invalid",),
        )
        self.assertEqual(state.evaluation_grants[0].consumption_status, "consumed")
        self.assertEqual(state.evaluation_grants[0].outcome, "fail")
        self.assertEqual(state.execution_closures, ())

    def test_replay_rejects_tampering(self) -> None:
        self.register(("runtime_realization",))
        record = json.loads(self.path.read_text(encoding="utf-8").splitlines()[0])
        record["payload"]["candidate"]["nas_access"] = True
        self.path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            QualificationLedgerError, "qualification_ledger_chain_invalid"
        ):
            self.store.replay()

    def test_handler_digest_drift_quarantines_without_calling_handler(self) -> None:
        self.register(("runtime_realization",))
        calls = []

        def handler(_: dict) -> StageHandlerResult:
            calls.append("called")
            return StageHandlerResult(observation("runtime_realization"))

        state = QualificationReconciler(
            self.controller,
            stage_handlers={"runtime_realization": handler},
            remediation_handlers={},
            handler_digests={"runtime_realization": canonical_digest("drifted")},
            now=lambda: NOW,
        ).run_until_checkpoint("run_disease_r2_syn")
        self.assertEqual(state.status, "quarantined")
        self.assertEqual(calls, [])
        self.assertEqual(
            state.next_checkpoint_reason_codes,
            ("qualification_handler_digest_drift",),
        )

    def test_execution_worker_cannot_also_be_company_or_domain_evaluator(self) -> None:
        stage_plan = (
            "model_literature_r2",
            "domain_evaluation",
            "company_evaluation",
        )
        policy = automation_policy(stage_plan)
        approval, activation = activation_chain(policy)
        with self.assertRaisesRegex(
            QualificationLedgerError, "qualification_evaluator_not_independent"
        ):
            self.controller.register_run(
                run_id="run_disease_r2_syn",
                policy=policy,
                policy_digest=canonical_digest(policy),
                policy_activation=activation,
                policy_approval_decision=approval,
                candidate=candidate(),
                stage_plan=stage_plan,
                stage_handlers={
                    stage: {
                        "id": "component_qualification_worker",
                        "version": "0.1.0",
                        "digest": DIGEST_A,
                    }
                    for stage in stage_plan
                },
                registered_at="2026-08-27T01:00:00+00:00",
                idempotency_key="register:non-independent-evaluation",
            )

    def test_cancel_requires_closed_reason_record(self) -> None:
        self.register(("runtime_realization",))
        self.controller.cancel(
            run_id="run_disease_r2_syn",
            reason_codes=("human_requested_cancellation",),
            recorded_at="2026-08-27T01:01:00+00:00",
            idempotency_key="cancel:disease-r2",
        )
        self.assertEqual(
            self.controller.replay().run("run_disease_r2_syn").status,
            "cancelled",
        )


if __name__ == "__main__":
    unittest.main()

