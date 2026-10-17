from __future__ import annotations

import json
import unittest

from candidate_support.disease_r2_model_gateway import (
    BASE_URL,
    MODEL_ID,
    REQUEST_PATH,
    STAGES,
    DiseaseR2GatewayError,
    DiseaseR2ModelGateway,
    GatewayHttpResponse,
    R2GatewayConfig,
)

SCHEMA = {
    "type": "object",
    "properties": {"value": {"type": "string"}},
    "required": ["value"],
    "additionalProperties": False,
}


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def send(self, url, headers, body, timeout_seconds):
        self.calls.append((url, dict(headers), body, timeout_seconds))
        return self.responses.pop(0)


def response(
    *, model: str = MODEL_ID, input_tokens: int = 100, output_tokens: int = 10
) -> GatewayHttpResponse:
    return GatewayHttpResponse(
        200,
        json.dumps(
            {
                "model": model,
                "choices": [
                    {"message": {"content": json.dumps({"value": "ok"})}}
                ],
                "usage": {
                    "prompt_tokens": input_tokens,
                    "completion_tokens": output_tokens,
                },
            }
        ).encode(),
    )


class DiseaseR2ModelGatewayTest(unittest.TestCase):
    def gateway(self, transport: FakeTransport) -> DiseaseR2ModelGateway:
        return DiseaseR2ModelGateway(
            R2GatewayConfig(secret="secret-value-for-test"),
            transport,
            sleeper=lambda _: None,
        )

    def invoke(self, gateway: DiseaseR2ModelGateway, stage: str):
        return gateway.invoke(
            stage,
            (
                {"role": "system", "content": "Return only grounded JSON."},
                {"role": "user", "content": "public synthetic R2 input"},
            ),
            SCHEMA,
        )

    def assert_reason(self, reason: str, callback) -> None:
        with self.assertRaises(DiseaseR2GatewayError) as caught:
            callback()
        self.assertEqual(reason, caught.exception.reason_code)

    def test_four_calls_are_exact_route_budgeted_and_secret_safe(self) -> None:
        transport = FakeTransport([response() for _ in range(4)])
        gateway = self.gateway(transport)
        calls = [self.invoke(gateway, stage) for stage in STAGES]

        self.assertEqual(4, len(gateway.calls))
        self.assertEqual([stage for stage in STAGES], [call.stage for call in calls])
        self.assertTrue(all(call.returned_model_id == MODEL_ID for call in calls))
        for url, headers, body, timeout in transport.calls:
            self.assertEqual(BASE_URL + REQUEST_PATH, url)
            self.assertEqual(30, round(timeout))
            self.assertEqual("Bearer secret-value-for-test", headers["Authorization"])
            request = json.loads(body)
            self.assertEqual(MODEL_ID, request["model"])
            self.assertEqual(0, request["temperature"])
            self.assertTrue(request["response_format"]["json_schema"]["strict"])
        transcript = json.dumps(
            [call.transcript_document() for call in calls], sort_keys=True
        )
        self.assertNotIn("secret-value-for-test", transcript)
        self.assertNotIn(BASE_URL, transcript)

    def test_retry_is_bounded_and_returned_model_drift_fails(self) -> None:
        transport = FakeTransport([GatewayHttpResponse(429, b"{}"), response()])
        call = self.invoke(self.gateway(transport), STAGES[0])
        self.assertEqual(2, call.attempts)
        self.assertEqual(2, len(transport.calls))

        drift = self.gateway(FakeTransport([response(model="fixture-structured-v1-versioned")]))
        self.assert_reason(
            "r2_gateway_returned_model_drift",
            lambda: self.invoke(drift, STAGES[0]),
        )

    def test_stage_order_schema_and_reported_budget_fail_closed(self) -> None:
        gateway = self.gateway(FakeTransport([response()]))
        self.assert_reason(
            "r2_gateway_stage_order_invalid",
            lambda: self.invoke(gateway, STAGES[1]),
        )
        self.assert_reason(
            "r2_gateway_schema_invalid",
            lambda: gateway.invoke(
                STAGES[0],
                ({"role": "user", "content": "public"},),
                {**SCHEMA, "uniqueItems": True},
            ),
        )

        over = self.gateway(FakeTransport([response(input_tokens=2_001)]))
        self.assert_reason(
            "r2_gateway_reported_usage_exceeded",
            lambda: self.invoke(over, STAGES[0]),
        )


if __name__ == "__main__":
    unittest.main()

