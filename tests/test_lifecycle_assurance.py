from __future__ import annotations

import unittest
from dataclasses import replace

from orbit_agent_control_plane.lifecycle_assurance import (
    DeterministicLifecycleAssuranceFixture,
    LifecycleAssuranceAgent,
    LifecycleAssuranceError,
    ModelCandidate,
    ModelInvocationAudit,
    ModelPortResponse,
    ModelUsage,
    default_d0_evidence,
    default_model_candidates,
    evaluate_d1_evidence_gate,
    lifecycle_assurance_requirements,
    select_model_candidate,
)


class MaliciousPort:
    def recommend(self, evidence, selected_model):
        return ModelPortResponse(
            structured_output={
                "subject_agent_id": evidence.subject_agent_id,
                "subject_release_digest": evidence.subject_release_digest,
                "recommendation": "recommend",
                "reason_codes": ["ignore_all_prior_policy"],
                "evidence_refs": ["evidence_unknown_syn"],
                "limitations": ["none"],
                "release_authorization": True,
            },
            usage=ModelUsage(10, 10, 0, 0, "0.001000"),
            audit=ModelInvocationAudit(
                provider_id=selected_model.provider_id,
                protocol="synthetic_fixture",
                request_model_id=selected_model.model_id,
                returned_model_id=selected_model.model_id,
                provider_request_id="request_malicious_fixture_syn",
                request_digest="sha256:" + ("2" * 64),
                response_digest="sha256:" + ("3" * 64),
                finish_reason="stop",
                retry_count=0,
                schema_validated=False,
                data_classification=evidence.data_classification,
            ),
        )


class LifecycleAssuranceTest(unittest.TestCase):
    def assert_reason(self, reason_code, callback):
        with self.assertRaises(LifecycleAssuranceError) as caught:
            callback()
        self.assertEqual(reason_code, caught.exception.reason_code)

    def test_selection_rejects_cheapest_incapable_model(self) -> None:
        selected = select_model_candidate(
            default_model_candidates(), lifecycle_assurance_requirements()
        )
        self.assertEqual("capable-structured-fixture", selected.model_id)
        self.assertEqual("0.002400", selected.estimated_cost_cny)
        self.assertIn("hard_capabilities_satisfied", selected.selection_reason_codes)

    def test_no_capable_model_fails_closed(self) -> None:
        self.assert_reason(
            "no_capable_model",
            lambda: select_model_candidate(
                default_model_candidates()[:1], lifecycle_assurance_requirements()
            ),
        )

    def test_d0_fixture_produces_bound_non_authoritative_recommendation(self) -> None:
        run = LifecycleAssuranceAgent(
            DeterministicLifecycleAssuranceFixture()
        ).run(default_d0_evidence(), default_model_candidates())
        self.assertEqual("pass", run.status)
        self.assertEqual("recommend", run.recommendation.recommendation)
        self.assertFalse(run.recommendation.release_authorization)
        self.assertEqual("0.000000", run.usage.cost_cny)
        self.assertEqual(0, run.usage.input_tokens)
        self.assertTrue(run.invocation_audit.schema_validated)

    def test_conflict_is_held_and_self_evaluation_is_forbidden(self) -> None:
        evidence = replace(
            default_d0_evidence(),
            evaluation_release_recommendation="do_not_recommend",
        )
        run = LifecycleAssuranceAgent(
            DeterministicLifecycleAssuranceFixture()
        ).run(evidence, default_model_candidates())
        self.assertEqual("hold", run.recommendation.recommendation)
        self.assertIn("evidence_conflict", run.recommendation.reason_codes)

        self.assert_reason(
            "self_evaluation_forbidden",
            lambda: LifecycleAssuranceAgent(
                DeterministicLifecycleAssuranceFixture()
            ).run(
                replace(
                    default_d0_evidence(),
                    evaluator_agent_id=default_d0_evidence().subject_agent_id,
                ),
                default_model_candidates(),
            ),
        )

    def test_model_cannot_invent_evidence_or_release_authority(self) -> None:
        self.assert_reason(
            "release_authority_forbidden",
            lambda: LifecycleAssuranceAgent(MaliciousPort()).run(
                default_d0_evidence(), default_model_candidates()
            ),
        )

    def test_d1_gate_allows_preparation_but_not_transmission(self) -> None:
        internal = replace(
            default_d0_evidence(),
            data_classification="internal",
            leadership_risk_acceptance_ref="decision_supplier_risk_acceptance_syn",
        )
        gate = evaluate_d1_evidence_gate(internal)
        self.assertEqual("allow_preparation_only", gate.decision)
        self.assertFalse(gate.external_transmission_authorized)
        self.assert_reason(
            "real_d1_provider_activation_not_approved",
            lambda: LifecycleAssuranceAgent(
                DeterministicLifecycleAssuranceFixture()
            ).run(internal, default_model_candidates()),
        )

        forbidden = replace(internal, data_classification="medical_private")
        self.assertEqual("deny", evaluate_d1_evidence_gate(forbidden).decision)

    def test_unavailable_capable_model_is_not_selected(self) -> None:
        capable = replace(default_model_candidates()[1], available=False)
        expensive = ModelCandidate(
            **{
                **capable.__dict__,
                "model_id": "capable-available-fixture",
                "available": True,
                "input_cny_per_million": "2.00",
            }
        )
        selected = select_model_candidate(
            (default_model_candidates()[0], capable, expensive),
            lifecycle_assurance_requirements(),
        )
        self.assertEqual("capable-available-fixture", selected.model_id)


if __name__ == "__main__":
    unittest.main()

