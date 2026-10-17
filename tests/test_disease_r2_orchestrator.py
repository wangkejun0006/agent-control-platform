from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

from candidate_support.disease_r2_literature_port import (
    CORPUS_REF,
    CORPUS_REVISION,
    FrozenPublicLiteraturePort,
)
from candidate_support.disease_r2_model_gateway import (
    DiseaseR2ModelGateway,
    GatewayHttpResponse,
    R2GatewayConfig,
)
from candidate_support.disease_r2_orchestrator import run_r2_ports

ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC = ROOT.parent / "orbit-health-system/scientific-research-platform"
CORPUS = (
    SCIENTIFIC
    / "evidence/disease-agent-r2/public-corpus/2026-08-26/"
    "normalized-records.public.jsonl"
)
SPEC = importlib.util.spec_from_file_location(
    "disease_r2_execution_worker",
    ROOT / "candidate_support/disease_r2_execution_worker.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("worker unavailable")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


class FakeTransport:
    def __init__(self, values):
        self.values = list(values)

    def send(self, url, headers, body, timeout_seconds):
        value, input_tokens, output_tokens = self.values.pop(0)
        return GatewayHttpResponse(
            200,
            json.dumps(
                {
                    "model": "fixture-structured-v1",
                    "choices": [
                        {"message": {"content": json.dumps(value)}}
                    ],
                    "usage": {
                        "prompt_tokens": input_tokens,
                        "completion_tokens": output_tokens,
                    },
                }
            ).encode(),
        )


class DiseaseR2OrchestratorTest(unittest.TestCase):
    def test_four_model_calls_two_tool_operations_and_worker_close(self) -> None:
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
                            "query_id": "q1",
                            "query_text": "fictional stationery adults cognitive behavioral therapy systematic review",
                        },
                        {
                            "query_id": "Q2",
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
        gateway = DiseaseR2ModelGateway(
            R2GatewayConfig(secret="secret-value-for-test"),
            FakeTransport(values),
            sleeper=lambda _: None,
        )
        outcome = run_r2_ports(
            gateway=gateway,
            literature=FrozenPublicLiteraturePort(CORPUS),
            worker=lambda source: worker.process(source),
            task_id="tsk_orbit_disease_r2_execution_syn",
            grant_digest="sha256:" + ("a" * 64),
            composition_digest="sha256:" + ("b" * 64),
            runtime_source_digest="sha256:" + ("c" * 64),
            agent_release_digest=worker.AGENT_RELEASE_DIGEST,
            literature_tool_release_digest=worker.TOOL_RELEASE_DIGEST,
            model_route_digest=worker.MODEL_ROUTE_DIGEST,
            corpus_ref=CORPUS_REF,
            corpus_revision=CORPUS_REVISION,
        )
        self.assertEqual("R2 synthetic pass", outcome["result"]["status"])
        self.assertEqual(4, len(outcome["model_calls"]))
        self.assertEqual(2, len(outcome["search_receipts"]))
        self.assertEqual(
            ["query_001", "query_002"],
            [item["query_id"] for item in outcome["search_receipts"]],
        )
        self.assertEqual("0.056100", outcome["cost"]["usd"])
        self.assertFalse(outcome["result"]["release_authorization"])


if __name__ == "__main__":
    unittest.main()

