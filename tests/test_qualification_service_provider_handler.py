from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from candidate_support.disease_r2_execution_worker import digest as worker_digest
from candidate_support.disease_r2_model_gateway import GatewayHttpResponse
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.disease_r2_provider_handler import (
    EXACT_RETURNED_MODEL_ID,
    PROPOSED_RETURNED_MODEL_IDS,
    ExactReturnedModelTransport,
    OwnerOnlyEvidenceStore,
    ProviderAttemptFailure,
    ProviderBackedDiseaseR2Handler,
    ProviderHandlerError,
    RecordingGatewayTransport,
)
from orbit_agent_control_plane.service_runtime.models import Base, RuntimeRunRow
from orbit_agent_control_plane.service_runtime.provider_evaluation import (
    ProviderCompanyEvaluationHandler,
    ProviderDomainEvaluationHandler,
)
from orbit_agent_control_plane.service_runtime.runner_main import _returned_model_ids
from orbit_agent_control_plane.service_runtime.runner_queue import canonical_digest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = (
    ROOT.parent
    / "orbit-health-system/scientific-research-platform/evidence/"
    "disease-agent-r2/public-corpus/2026-08-26/normalized-records.public.jsonl"
)


class FakeTransport:
    def __init__(self, values):
        self.values = list(values)

    def send(self, url, headers, body, timeout_seconds):
        del url, headers, body, timeout_seconds
        value, input_tokens, output_tokens = self.values.pop(0)
        return GatewayHttpResponse(
            200,
            json.dumps(
                {
                    "model": EXACT_RETURNED_MODEL_ID,
                    "choices": [{"message": {"content": json.dumps(value)}}],
                    "usage": {
                        "prompt_tokens": input_tokens,
                        "completion_tokens": output_tokens,
                    },
                }
            ).encode(),
        )


class ProviderBackedHandlerTests(unittest.TestCase):
    def test_provider_handler_uses_frozen_corpus_and_owner_only_evidence(self) -> None:
        offline = json.loads(
            (
                ROOT
                / "evidence/disease-agent-r2/2026-08-26/offline-result.synthetic.json"
            ).read_text(encoding="utf-8")
        )
        values = [
            (
                {
                    "population": "adults with fictional stationery",
                    "intervention_or_exposure": "behavioral interventions",
                    "outcomes": ["sleep", "function", "uncertainty"],
                    "clinical_action_requested": False,
                },
                900,
                80,
            ),
            (
                {
                    "queries": [
                        {
                            "query_id": "query_fictional_stationery_behavioral_syn",
                            "query_text": "fictional stationery adults cognitive behavioral therapy systematic review",
                        },
                        {
                            "query_id": "query_fictional_stationery_outcomes_syn",
                            "query_text": "fictional stationery adults long term outcomes sleep intervention",
                        },
                    ]
                },
                1000,
                140,
            ),
            ({"claims": offline["claims"]}, 3000, 300),
            (offline["synthesis"], 2000, 200),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            evidence_root = Path(temporary) / "provider-evidence"
            handler = ProviderBackedDiseaseR2Handler(
                provider_secret="provider-secret-for-offline-test",
                corpus_path=CORPUS,
                evidence_store=OwnerOnlyEvidenceStore(evidence_root),
                gateway_transport=FakeTransport(values),
            )
            outcome = handler(
                {
                    "task_id": "task_public_pilot_attempt_001",
                    "grant_digest": "sha256:" + "a" * 64,
                    "composition_digest": "sha256:" + "b" * 64,
                    "runtime_source_digest": "sha256:" + "c" * 64,
                    "operation": "run_public_r2_provider_attempt",
                    "data_classification": "public",
                    "synthetic_only": False,
                    "production_authorization": False,
                }
            )
            self.assertEqual(
                "R2 provider-backed public-corpus pass", outcome["status"]
            )
            self.assertEqual(4, outcome["usage"]["model_calls"])
            self.assertEqual("0.056100", outcome["usage"]["cost_usd"])
            self.assertEqual(
                EXACT_RETURNED_MODEL_ID,
                outcome["provider_observation"]["resolved_model_id"],
            )
            self.assertFalse(outcome["release_authorization"])
            nested = outcome["result"]
            self.assertEqual(
                nested["result_digest"],
                worker_digest(
                    {key: value for key, value in nested.items() if key != "result_digest"}
                ),
            )
            evidence_files = list(evidence_root.iterdir())
            self.assertEqual(1, len(evidence_files))
            self.assertEqual(0, evidence_files[0].stat().st_mode & 0o077)
            self.assertNotIn(
                b"provider-secret-for-offline-test", evidence_files[0].read_bytes()
            )

            database = Database("sqlite+pysqlite:///:memory:")
            Base.metadata.create_all(database.engine)
            candidate = json.loads(
                (
                    ROOT
                    / "evidence/disease-agent-r2/2026-08-27-automation-policy-alpha2/qualification-candidate.attempt-004.synthetic.json"
                ).read_text(encoding="utf-8")
            )
            now = datetime.now(timezone.utc)
            with database.session() as session:
                session.add(
                    RuntimeRunRow(
                        run_id="run_provider_evaluation_test",
                        task_id="task_provider_evaluation_test",
                        grant_id="grant_provider_evaluation_test",
                        grant_digest="sha256:" + "a" * 64,
                        composition_digest="sha256:" + "b" * 64,
                        runtime_source_digest="sha256:" + "c" * 64,
                        invocation_digest="sha256:" + "d" * 64,
                        idempotency_key="provider-evaluation-test",
                        invocation={
                            "task_digest": candidate["task_digest"],
                            "operation": "run_public_r2_provider_attempt",
                        },
                        status="completed",
                        worker_identity="workload_r2_evaluation_runner",
                        cancel_reason_code=None,
                        failure_reason_code=None,
                        result_document=outcome,
                        result_digest=canonical_digest(outcome),
                        created_at=now,
                        expires_at=now + timedelta(minutes=5),
                        started_at=now,
                        closed_at=now,
                        revision=2,
                    )
                )
            context = {
                "stage": "domain_evaluation",
                "candidate": candidate,
            }
            domain = ProviderDomainEvaluationHandler(
                database, component_digest="sha256:" + "d" * 64
            )(context)
            company = ProviderCompanyEvaluationHandler(
                database, component_digest="sha256:" + "e" * 64
            )({**context, "stage": "company_evaluation"})
            self.assertEqual("pass", domain.observation.outcome)
            self.assertEqual("pass", company.observation.outcome)
            self.assertNotEqual(
                domain.observation.executor["component"]["digest"],
                company.observation.executor["component"]["digest"],
            )
            database.dispose()

    def test_version_drift_failure_preserves_only_sanitized_usage(self) -> None:
        values = [
            (
                {
                    "population": "adults with fictional stationery",
                    "intervention_or_exposure": "behavioral interventions",
                    "outcomes": ["sleep"],
                    "clinical_action_requested": False,
                },
                510,
                182,
            )
        ]
        with tempfile.TemporaryDirectory() as temporary:
            handler = ProviderBackedDiseaseR2Handler(
                provider_secret="provider-secret-for-offline-test",
                corpus_path=CORPUS,
                evidence_store=OwnerOnlyEvidenceStore(Path(temporary) / "evidence"),
                gateway_transport=FakeTransport(values),
            )
            # Override the fixture's exact ID to reproduce a real returned-model drift.
            handler.gateway_transport = _DriftTransport()
            with self.assertRaises(ProviderAttemptFailure) as raised:
                handler(
                    {
                        "task_id": "task_public_pilot_attempt_failure",
                        "grant_digest": "sha256:" + "a" * 64,
                        "composition_digest": "sha256:" + "b" * 64,
                        "runtime_source_digest": "sha256:" + "c" * 64,
                        "operation": "run_public_r2_provider_attempt",
                        "data_classification": "public",
                        "synthetic_only": False,
                        "production_authorization": False,
                    }
                )
            failure = raised.exception.failure_result
            self.assertEqual("r2_gateway_returned_model_drift", raised.exception.reason_code)
            self.assertEqual(510, failure["usage"]["input_tokens"])
            self.assertEqual(182, failure["usage"]["output_tokens"])
            self.assertEqual(["fixture-structured-v1"], failure["provider_observation"]["returned_model_ids"])
            self.assertRegex(failure["provider_observation_digest"], r"^sha256:[0-9a-f]{64}$")
            visible = json.dumps(failure, sort_keys=True)
            self.assertNotIn("provider-secret-for-offline-test", visible)
            self.assertNotIn("choices", visible)

    def test_successor_route_accepts_only_two_observed_exact_ids(self) -> None:
        route_ids = _returned_model_ids(
            ROOT
            / "references/model-route-revisions/"
            "disease-r2-fixture-fixture-structured-v1.public.v2.json"
        )
        self.assertEqual(PROPOSED_RETURNED_MODEL_IDS, route_ids)
        transport = ExactReturnedModelTransport(
            RecordingGatewayTransport(_DriftTransport()),
            allowed_returned_model_ids=route_ids,
        )
        response = transport.send(
            "https://models.paper-orbit.invalid/v1/chat/completions",
            {},
            b"{}",
            30,
        )
        self.assertEqual("fixture-structured-v1", json.loads(response.body)["model"])
        with self.assertRaisesRegex(
            ProviderHandlerError, "returned_model_allowlist_invalid"
        ):
            ExactReturnedModelTransport(
                RecordingGatewayTransport(_DriftTransport()),
                allowed_returned_model_ids=("fixture-structured-v1-*",),
            )


class _DriftTransport:
    def send(self, url, headers, body, timeout_seconds):
        del url, headers, body, timeout_seconds
        return GatewayHttpResponse(
            200,
            json.dumps(
                {
                    "model": "fixture-structured-v1",
                    "choices": [{"message": {"content": "{}"}}],
                    "usage": {"prompt_tokens": 510, "completion_tokens": 182},
                }
            ).encode(),
        )


if __name__ == "__main__":
    unittest.main()

