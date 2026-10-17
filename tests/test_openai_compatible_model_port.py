from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from orbit_agent_control_plane.lifecycle_assurance import (
    LifecycleAssuranceAgent,
    LifecycleAssuranceError,
    assurance_document,
    default_d0_evidence,
)
from orbit_agent_control_plane.openai_compatible_model_port import (
    HttpResponse,
    OpenAICompatibleLifecycleAssurancePort,
    OpenAICompatibleRuntimeConfig,
    load_model_capability_observation,
)


OBSERVATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "references"
    / "fixture-fixture-structured-v1-lifecycle-assurance-d0.json"
)


class RecordingSecretResolver:
    def __init__(self, secret: str = "secret-value-for-test") -> None:
        self.secret = secret
        self.calls = 0

    def resolve(self, secret_ref: str) -> str:
        self.calls += 1
        self.last_ref = secret_ref
        return self.secret


class FakeTransport:
    def __init__(self, responses: list[HttpResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def send(self, url, headers, body, timeout_seconds):
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_seconds": timeout_seconds,
            }
        )
        return self.responses.pop(0)


def provider_response(
    *,
    recommendation: str = "recommend",
    model: str = "fixture-structured-v1",
) -> HttpResponse:
    output = {
        "subject_agent_id": "agt_candidate_lifecycle_probe_syn",
        "subject_release_digest": "sha256:" + ("a" * 64),
        "recommendation": recommendation,
        "reason_codes": ["EVIDENCE_COMPLETE"],
        "evidence_refs": [
            "evidence_contract_suite_syn",
            "evidence_safety_suite_syn",
        ],
        "limitations": ["human_approval_still_required"],
        "release_authorization": False,
    }
    body = {
        "id": "chatcmpl-provider-port-syn",
        "model": model,
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": json.dumps(output, separators=(",", ":")),
                },
            }
        ],
        "usage": {
            "prompt_tokens": 317,
            "completion_tokens": 140,
            "prompt_tokens_details": {
                "cached_tokens": 0,
                "cache_write_tokens": 0,
            },
        },
    }
    return HttpResponse(
        200,
        {"content-type": "application/json"},
        json.dumps(body, separators=(",", ":")).encode("utf-8"),
    )


class OpenAICompatibleLifecycleAssurancePortTest(unittest.TestCase):
    def setUp(self) -> None:
        self.observation = load_model_capability_observation(OBSERVATION_PATH)
        self.environment = {
            "ORBIT_MODEL_PROVIDER_ID": "fixture",
            "ORBIT_MODEL_BASE_URL": "https://api.example.test",
            "ORBIT_MODEL_ID": "fixture-structured-v1",
            "ORBIT_MODEL_ALLOWED_RETURNED_IDS": (
                "fixture-structured-v1,fixture-structured-v1-2026-07-09"
            ),
            "ORBIT_MODEL_SECRET_REF": "env:WEMETA_API_KEY",
            "ORBIT_MODEL_CNY_PER_USD": "10",
        }

    def config(self, budget: str = "0.50") -> OpenAICompatibleRuntimeConfig:
        return OpenAICompatibleRuntimeConfig.from_environment(
            self.environment,
            self.observation,
            max_cost_cny=budget,
        )

    def run_port(
        self,
        transport,
        secret_resolver=None,
        budget="0.50",
        evidence=None,
    ):
        config = self.config(budget)
        resolver = secret_resolver or RecordingSecretResolver()
        port = OpenAICompatibleLifecycleAssurancePort(
            config,
            self.observation,
            resolver,
            transport,
            sleeper=lambda _: None,
        )
        run = LifecycleAssuranceAgent(port).run(
            evidence or default_d0_evidence(),
            (self.observation.as_candidate(config.cny_per_usd),),
        )
        return run, resolver

    def test_success_is_schema_bound_budgeted_and_secret_safe(self) -> None:
        transport = FakeTransport([provider_response()])
        run, resolver = self.run_port(transport)

        self.assertEqual("recommend", run.recommendation.recommendation)
        self.assertFalse(run.recommendation.release_authorization)
        self.assertEqual("0.057850", run.usage.cost_cny)
        self.assertEqual(1, resolver.calls)
        self.assertEqual(1, len(transport.calls))
        request = json.loads(transport.calls[0]["body"])
        schema = request["response_format"]["json_schema"]["schema"]
        self.assertNotIn("uniqueItems", json.dumps(schema))
        self.assertEqual("fixture-structured-v1", request["model"])
        self.assertEqual(256, request["max_tokens"])
        self.assertEqual("openai_chat_completions", run.invocation_audit.protocol)
        self.assertTrue(run.invocation_audit.schema_validated)
        document_text = json.dumps(assurance_document(run), sort_keys=True)
        self.assertNotIn("secret-value-for-test", document_text)
        self.assertNotIn("api.example.test", document_text)

    def test_budget_preflight_blocks_before_secret_or_network(self) -> None:
        transport = FakeTransport([provider_response()])
        resolver = RecordingSecretResolver()
        with self.assertRaises(LifecycleAssuranceError) as caught:
            self.run_port(transport, resolver, budget="0.000001")
        self.assertEqual("provider_budget_preflight_exceeded", caught.exception.reason_code)
        self.assertEqual(0, resolver.calls)
        self.assertEqual([], transport.calls)

    def test_retries_429_once_but_never_retries_400(self) -> None:
        rate_limited = HttpResponse(429, {"retry-after": "0"}, b"{}")
        transport = FakeTransport([rate_limited, provider_response()])
        run, _ = self.run_port(transport)
        self.assertEqual(1, run.invocation_audit.retry_count)
        self.assertEqual(2, len(transport.calls))

        rejected = FakeTransport([HttpResponse(400, {}, b"{}"), provider_response()])
        with self.assertRaises(LifecycleAssuranceError) as caught:
            self.run_port(rejected)
        self.assertEqual("provider_request_rejected", caught.exception.reason_code)
        self.assertEqual(1, len(rejected.calls))

    def test_returned_model_mismatch_fails_closed(self) -> None:
        transport = FakeTransport([provider_response(model="unapproved-model")])
        with self.assertRaises(LifecycleAssuranceError) as caught:
            self.run_port(transport)
        self.assertEqual("provider_response_binding_invalid", caught.exception.reason_code)

    def test_observed_provider_versioned_model_id_is_explicitly_allowed(self) -> None:
        transport = FakeTransport(
            [provider_response(model="fixture-structured-v1-2026-07-09")]
        )
        run, _ = self.run_port(transport)

        self.assertEqual(
            "fixture-structured-v1-2026-07-09",
            run.invocation_audit.returned_model_id,
        )

    def test_failed_evaluation_cannot_be_recommended_by_provider(self) -> None:
        failed = replace(
            default_d0_evidence(),
            evaluation_verdict="fail",
            risk_codes=("risk_evidence_conflict",),
        )
        transport = FakeTransport([provider_response(recommendation="recommend")])
        with self.assertRaises(LifecycleAssuranceError) as caught:
            self.run_port(transport, evidence=failed)
        self.assertEqual("failed_evaluation_ignored", caught.exception.reason_code)

    def test_d1_is_blocked_before_secret_or_network(self) -> None:
        config = self.config()
        transport = FakeTransport([provider_response()])
        resolver = RecordingSecretResolver()
        port = OpenAICompatibleLifecycleAssurancePort(
            config,
            self.observation,
            resolver,
            transport,
        )
        internal = replace(
            default_d0_evidence(),
            data_classification="internal",
            leadership_risk_acceptance_ref="decision_supplier_risk_acceptance_syn",
        )
        with self.assertRaises(LifecycleAssuranceError) as caught:
            LifecycleAssuranceAgent(port).run(
                internal,
                (self.observation.as_candidate(config.cny_per_usd),),
            )
        self.assertEqual(
            "real_d1_provider_activation_not_approved", caught.exception.reason_code
        )
        self.assertEqual(0, resolver.calls)
        self.assertEqual([], transport.calls)

    def test_runtime_configuration_rejects_unreviewed_endpoint_and_model(self) -> None:
        insecure = {**self.environment, "ORBIT_MODEL_BASE_URL": "http://api.example.test"}
        with self.assertRaises(LifecycleAssuranceError) as caught:
            OpenAICompatibleRuntimeConfig.from_environment(
                insecure,
                self.observation,
                max_cost_cny="0.50",
            )
        self.assertEqual("provider_base_url_invalid", caught.exception.reason_code)

        wrong_model = {**self.environment, "ORBIT_MODEL_ID": "gpt-5.6-terra"}
        with self.assertRaises(LifecycleAssuranceError) as caught:
            OpenAICompatibleRuntimeConfig.from_environment(
                wrong_model,
                self.observation,
                max_cost_cny="0.50",
            )
        self.assertEqual("provider_observation_mismatch", caught.exception.reason_code)


if __name__ == "__main__":
    unittest.main()

