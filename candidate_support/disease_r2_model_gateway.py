"""Bounded OpenAI-compatible Model Gateway port for one Disease R2 run."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

PROVIDER_ID = "fixture"
BASE_URL = "https://models.paper-orbit.invalid"
REQUEST_PATH = "/v1/chat/completions"
MODEL_ID = "fixture-structured-v1"
MODEL_ROUTE_DIGEST = (
    "sha256:8bc631ae8cf7fc7f2d07ac187eb5ca0d313de00818d77abfa7b2b4a04a5c74e7"
)
STAGES = (
    "question_decomposition",
    "query_generation",
    "evidence_mapping",
    "synthesis",
)
STAGE_LIMITS = {
    "question_decomposition": (2_000, 128),
    "query_generation": (2_000, 256),
    "evidence_mapping": (4_000, 384),
    "synthesis": (4_000, 256),
}
MAX_BILLED_INPUT_TOKENS = 24_000
MAX_BILLED_OUTPUT_TOKENS = 2_048
HARD_CAP_USD = Decimal("0.20")
HARD_CAP_CNY = Decimal("1.50")
INPUT_USD_PER_MILLION = Decimal("5.00")
OUTPUT_USD_PER_MILLION = Decimal("30.00")
CNY_PER_USD = Decimal("7.50")
_MAX_RESPONSE_BYTES = 512 * 1024


class DiseaseR2GatewayError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class R2GatewayConfig:
    secret: str
    timeout_seconds: int = 30
    max_retries: int = 1


@dataclass(frozen=True)
class GatewayHttpResponse:
    status_code: int
    body: bytes


class GatewayTransport(Protocol):
    def send(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> GatewayHttpResponse:
        ...


class UrllibGatewayTransport:
    def send(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> GatewayHttpResponse:
        raise DiseaseR2GatewayError("legacy_direct_model_transport_disabled_use_campaign_gateway")


@dataclass(frozen=True)
class R2GatewayCall:
    stage: str
    request_digest: str
    response_digest: str
    returned_model_id: str
    response: Mapping[str, Any]
    input_tokens: int
    output_tokens: int
    attempts: int
    cost_usd: str
    cost_cny: str

    def transcript_document(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "returned_model_id": self.returned_model_id,
            "response": dict(self.response),
            "usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
            },
            "attempts": self.attempts,
        }


class DiseaseR2ModelGateway:
    """Four-stage, single-flight, retry-bounded provider adapter."""

    def __init__(
        self,
        config: R2GatewayConfig,
        transport: GatewayTransport,
        *,
        sleeper=time.sleep,
    ) -> None:
        if (
            len(config.secret) < 8
            or any(character.isspace() for character in config.secret)
            or config.timeout_seconds != 30
            or config.max_retries != 1
        ):
            raise DiseaseR2GatewayError("r2_gateway_configuration_invalid")
        self._config = config
        self._transport = transport
        self._sleeper = sleeper
        self._lock = threading.Lock()
        self._calls: list[R2GatewayCall] = []
        self._reserved_input_tokens = 0
        self._reserved_output_tokens = 0

    @property
    def calls(self) -> tuple[R2GatewayCall, ...]:
        return tuple(self._calls)

    def invoke(
        self,
        stage: str,
        messages: Sequence[Mapping[str, str]],
        response_schema: Mapping[str, Any],
    ) -> R2GatewayCall:
        if stage not in STAGE_LIMITS or stage != STAGES[len(self._calls)]:
            raise DiseaseR2GatewayError("r2_gateway_stage_order_invalid")
        if not self._lock.acquire(blocking=False):
            raise DiseaseR2GatewayError("r2_gateway_concurrency_exceeded")
        try:
            return self._invoke_locked(stage, messages, response_schema)
        finally:
            self._lock.release()

    def _invoke_locked(
        self,
        stage: str,
        messages: Sequence[Mapping[str, str]],
        response_schema: Mapping[str, Any],
    ) -> R2GatewayCall:
        input_limit, output_limit = STAGE_LIMITS[stage]
        retries = self._config.max_retries + 1
        reserved_input = input_limit * retries
        reserved_output = output_limit * retries
        if (
            self._reserved_input_tokens + reserved_input > MAX_BILLED_INPUT_TOKENS
            or self._reserved_output_tokens + reserved_output > MAX_BILLED_OUTPUT_TOKENS
            or _cost_usd(
                self._reserved_input_tokens + reserved_input,
                self._reserved_output_tokens + reserved_output,
            )
            > HARD_CAP_USD
            or _cost_usd(
                self._reserved_input_tokens + reserved_input,
                self._reserved_output_tokens + reserved_output,
            )
            * CNY_PER_USD
            > HARD_CAP_CNY
        ):
            raise DiseaseR2GatewayError("r2_gateway_budget_preflight_exceeded")
        body_document = {
            "model": MODEL_ID,
            "temperature": 0,
            "max_tokens": output_limit,
            "messages": _validate_messages(messages),
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": f"orbit_disease_r2_{stage}",
                    "strict": True,
                    "schema": _validate_schema(response_schema),
                },
            },
        }
        body = _canonical(body_document)
        if len(body) > input_limit * 4:
            raise DiseaseR2GatewayError("r2_gateway_input_preflight_exceeded")
        request_digest = "sha256:" + hashlib.sha256(body).hexdigest()
        deadline = time.monotonic() + self._config.timeout_seconds
        response = None
        attempts = 0
        for attempt in range(retries):
            attempts += 1
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DiseaseR2GatewayError("r2_gateway_deadline_exceeded")
            response = self._transport.send(
                BASE_URL + REQUEST_PATH,
                {
                    "Authorization": f"Bearer {self._config.secret}",
                    "Content-Type": "application/json",
                },
                body,
                remaining,
            )
            if response.status_code == 200:
                break
            if attempt == 0 and (
                response.status_code in {408, 429}
                or 500 <= response.status_code <= 599
            ):
                self._sleeper(0)
                continue
            raise DiseaseR2GatewayError("r2_gateway_provider_rejected")
        if response is None or response.status_code != 200:
            raise DiseaseR2GatewayError("r2_gateway_provider_unavailable")
        model_id, content, input_tokens, output_tokens = _parse_response(response.body)
        if model_id != MODEL_ID:
            raise DiseaseR2GatewayError("r2_gateway_returned_model_drift")
        if input_tokens > input_limit or output_tokens > output_limit:
            raise DiseaseR2GatewayError("r2_gateway_reported_usage_exceeded")
        if len(self._calls) + 1 > 4:
            raise DiseaseR2GatewayError("r2_gateway_call_budget_exceeded")
        actual_input = sum(item.input_tokens for item in self._calls) + input_tokens
        actual_output = sum(item.output_tokens for item in self._calls) + output_tokens
        actual_usd = _cost_usd(actual_input, actual_output)
        if (
            actual_input > 12_000
            or actual_output > 1_024
            or actual_usd > HARD_CAP_USD
            or actual_usd * CNY_PER_USD > HARD_CAP_CNY
        ):
            raise DiseaseR2GatewayError("r2_gateway_actual_budget_exceeded")
        self._reserved_input_tokens += reserved_input
        self._reserved_output_tokens += reserved_output
        call_cost = _cost_usd(input_tokens, output_tokens)
        call = R2GatewayCall(
            stage=stage,
            request_digest=request_digest,
            response_digest="sha256:" + hashlib.sha256(_canonical(content)).hexdigest(),
            returned_model_id=model_id,
            response=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            attempts=attempts,
            cost_usd=_decimal_text(call_cost),
            cost_cny=_decimal_text(call_cost * CNY_PER_USD),
        )
        self._calls.append(call)
        return call


def _parse_response(source: bytes) -> tuple[str, dict[str, Any], int, int]:
    if len(source) > _MAX_RESPONSE_BYTES:
        raise DiseaseR2GatewayError("r2_gateway_response_too_large")
    try:
        value = json.loads(source, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiseaseR2GatewayError("r2_gateway_response_invalid") from error
    try:
        model_id = value["model"]
        choices = value["choices"]
        usage = value["usage"]
        content_source = choices[0]["message"]["content"]
        content = json.loads(content_source, object_pairs_hook=_unique_object)
        input_tokens = usage["prompt_tokens"]
        output_tokens = usage["completion_tokens"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        raise DiseaseR2GatewayError("r2_gateway_response_invalid") from error
    if (
        not isinstance(model_id, str)
        or not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(content, dict)
        or isinstance(input_tokens, bool)
        or not isinstance(input_tokens, int)
        or input_tokens < 0
        or isinstance(output_tokens, bool)
        or not isinstance(output_tokens, int)
        or output_tokens < 0
    ):
        raise DiseaseR2GatewayError("r2_gateway_response_invalid")
    return model_id, content, input_tokens, output_tokens


def _validate_messages(
    messages: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    if (
        not isinstance(messages, Sequence)
        or isinstance(messages, (str, bytes, bytearray))
        or not 1 <= len(messages) <= 3
    ):
        raise DiseaseR2GatewayError("r2_gateway_messages_invalid")
    result = []
    for message in messages:
        if (
            not isinstance(message, Mapping)
            or set(message) != {"role", "content"}
            or message["role"] not in {"system", "user"}
            or not isinstance(message["content"], str)
            or not message["content"]
            or len(message["content"].encode()) > 48 * 1024
        ):
            raise DiseaseR2GatewayError("r2_gateway_messages_invalid")
        result.append({"role": message["role"], "content": message["content"]})
    return result


def _validate_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(schema, Mapping):
        raise DiseaseR2GatewayError("r2_gateway_schema_invalid")
    encoded = _canonical(schema)
    if b'"uniqueItems"' in encoded or len(encoded) > 32 * 1024:
        raise DiseaseR2GatewayError("r2_gateway_schema_invalid")
    return json.loads(encoded)


def _cost_usd(input_tokens: int, output_tokens: int) -> Decimal:
    return (
        Decimal(input_tokens) * INPUT_USD_PER_MILLION
        + Decimal(output_tokens) * OUTPUT_USD_PER_MILLION
    ) / Decimal(1_000_000)


def _decimal_text(value: Decimal) -> str:
    return format(value.quantize(Decimal("0.000001")), "f")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError) as error:
        raise DiseaseR2GatewayError("r2_gateway_json_invalid") from error


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise DiseaseR2GatewayError("r2_gateway_duplicate_json_key")
        value[key] = item
    return value

