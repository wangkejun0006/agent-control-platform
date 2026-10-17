from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "candidate_support/disease_r2_execution_worker.py"
SPEC = importlib.util.spec_from_file_location("disease_r2_execution_worker", WORKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Disease R2 execution worker could not be loaded")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


class DiseaseR2ExecutionWorkerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.offline = json.loads(
            (
                ROOT
                / "evidence/disease-agent-r2/2026-08-26/offline-result.synthetic.json"
            ).read_text(encoding="utf-8")
        )

    def envelope(self) -> dict[str, object]:
        responses = [
            {
                "population": "adults with fictional stationery",
                "intervention_or_exposure": "behavioral interventions",
                "outcomes": ["sleep", "function", "uncertainty"],
                "clinical_action_requested": False,
            },
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
            {"claims": copy.deepcopy(self.offline["claims"])},
            copy.deepcopy(self.offline["synthesis"]),
        ]
        usage = ((1800, 110), (1900, 180), (3600, 340), (3700, 240))
        transcript = []
        for stage, response, token_usage in zip(
            worker.MODEL_STAGES, responses, usage
        ):
            transcript.append(
                {
                    "stage": stage,
                    "request_digest": "sha256:" + ("a" * 64),
                    "response_digest": worker.digest(response),
                    "returned_model_id": "fixture-structured-v1",
                    "response": response,
                    "usage": {
                        "input_tokens": token_usage[0],
                        "output_tokens": token_usage[1],
                    },
                    "attempts": 1,
                }
            )
        return {
            "envelope_version": "orbit.disease-r2-execution-envelope/1",
            "task_id": "tsk_orbit_disease_stationery_r2_exec001_syn",
            "grant_digest": "sha256:" + ("b" * 64),
            "composition_digest": "sha256:" + ("c" * 64),
            "runtime_source_digest": "sha256:" + ("d" * 64),
            "agent_release_digest": worker.AGENT_RELEASE_DIGEST,
            "literature_tool_release_digest": worker.TOOL_RELEASE_DIGEST,
            "model_route_digest": worker.MODEL_ROUTE_DIGEST,
            "corpus_ref": worker.CORPUS_REF,
            "corpus_revision": worker.CORPUS_REVISION,
            "model_transcript": transcript,
            "search_receipts": copy.deepcopy(self.offline["search_receipts"]),
            "fetch_receipt": copy.deepcopy(self.offline["fetch_receipt"]),
            "authority_boundary": {
                "agent_network_access": False,
                "agent_model_credentials": False,
                "host_filesystem_access": False,
                "nas_access": False,
                "fulltext_access": False,
                "personal_medical_data": False,
                "a2a_access": False,
                "release_authorization": False,
            },
        }

    def assert_reason(self, reason: str, envelope: dict[str, object]) -> None:
        with self.assertRaises(worker.DiseaseR2WorkerError) as caught:
            worker.process(worker.canonical_bytes(envelope))
        self.assertEqual(reason, caught.exception.reason_code)

    def test_sealed_exact_transcript_passes_without_release_authority(self) -> None:
        result = worker.process(worker.canonical_bytes(self.envelope()))
        self.assertEqual("R2 synthetic pass", result["status"])
        self.assertEqual(4, result["model_usage"]["calls"])
        self.assertFalse(result["release_authorization"])
        self.assertTrue(result["citation_refs"])

    def test_returned_model_drift_fails_closed(self) -> None:
        envelope = self.envelope()
        envelope["model_transcript"][0]["returned_model_id"] = "fixture-structured-v1-versioned"
        self.assert_reason("r2_worker_model_transcript_invalid", envelope)

    def test_secret_path_and_budget_injection_fail_closed(self) -> None:
        for mutation, reason in (
            (
                lambda value: value["model_transcript"][0]["response"].update(
                    {"secret": "sk-forbidden-value"}
                ),
                "r2_worker_secret_or_path_forbidden",
            ),
            (
                lambda value: value["model_transcript"][0]["usage"].update(
                    {"input_tokens": 12001}
                ),
                "r2_worker_model_budget_exceeded",
            ),
        ):
            with self.subTest(reason=reason):
                envelope = self.envelope()
                mutation(envelope)
                if reason == "r2_worker_secret_or_path_forbidden":
                    raw = json.dumps(envelope).encode()
                    with self.assertRaises(worker.DiseaseR2WorkerError) as caught:
                        worker.process(raw)
                    self.assertEqual(reason, caught.exception.reason_code)
                else:
                    self.assert_reason(reason, envelope)


if __name__ == "__main__":
    unittest.main()

