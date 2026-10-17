"""Exact, opt-in provider-backed Disease R2 Handler.

The module is importable and testable offline but is never registered by the
default Runner profile.  It composes the existing bounded WeMeta gateway,
frozen public Literature Port and no-network Disease Handler.  Provider raw
responses are written only to an owner-only, Git-ignored Evidence Store.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from typing import Any

from candidate_support.disease_r2_execution_worker import digest as worker_digest
from candidate_support.disease_r2_execution_worker import process
from candidate_support.disease_r2_literature_port import (
    CORPUS_REF,
    CORPUS_REVISION,
    FrozenPublicLiteraturePort,
)
from candidate_support.disease_r2_model_gateway import (
    BASE_URL,
    MODEL_ID,
    MODEL_ROUTE_DIGEST,
    REQUEST_PATH,
    DiseaseR2ModelGateway,
    GatewayHttpResponse,
    R2GatewayConfig,
    UrllibGatewayTransport,
)
from candidate_support.disease_r2_orchestrator import run_r2_ports

AGENT_RELEASE_DIGEST = (
    "sha256:e41c15f412b87c39654978a628ac7704b5cbbb2915f41b3b9d4426cf7aa4b04a"
)
LITERATURE_TOOL_RELEASE_DIGEST = (
    "sha256:775e2996c5302a28e24d2b8b7b104788e0a782688ba847ae63c8a8b729b48f0d"
)
EXACT_RETURNED_MODEL_ID = "fixture-structured-v1-2026-07-09"
PROPOSED_RETURNED_MODEL_IDS = (
    EXACT_RETURNED_MODEL_ID,
    MODEL_ID,
)
INPUT_USD_PER_MILLION = Decimal("5.00")
OUTPUT_USD_PER_MILLION = Decimal("30.00")
CNY_PER_USD = Decimal("7.50")


class ProviderHandlerError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ProviderAttemptFailure(ProviderHandlerError):
    """Failure carrying only a validated, non-secret usage envelope."""

    def __init__(self, reason_code: str, failure_result: Mapping[str, Any]) -> None:
        super().__init__(reason_code)
        self.failure_result = dict(failure_result)


class RecordingGatewayTransport:
    def __init__(self, transport=None) -> None:
        self.transport = transport or UrllibGatewayTransport()
        self.responses: list[dict[str, Any]] = []

    def send(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> GatewayHttpResponse:
        if url != BASE_URL + REQUEST_PATH:
            raise ProviderHandlerError("provider_endpoint_drift")
        response = self.transport.send(url, headers, body, timeout_seconds)
        self.responses.append(
            {
                "sequence": len(self.responses),
                "status_code": response.status_code,
                "request_digest": _digest_bytes(body),
                "response_digest": _digest_bytes(response.body),
                "response_body_base64": base64.b64encode(response.body).decode(),
            }
        )
        return response


class ExactReturnedModelTransport:
    """Validate one explicitly approved returned ID before alias projection."""

    def __init__(
        self,
        transport: RecordingGatewayTransport,
        *,
        allowed_returned_model_ids: tuple[str, ...] = (EXACT_RETURNED_MODEL_ID,),
    ) -> None:
        if (
            not allowed_returned_model_ids
            or len(set(allowed_returned_model_ids)) != len(allowed_returned_model_ids)
            or any("*" in value or not value for value in allowed_returned_model_ids)
        ):
            raise ProviderHandlerError("returned_model_allowlist_invalid")
        self.transport = transport
        self.allowed_returned_model_ids = allowed_returned_model_ids

    def send(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> GatewayHttpResponse:
        response = self.transport.send(url, headers, body, timeout_seconds)
        if response.status_code != 200:
            return response
        try:
            document = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProviderHandlerError("r2_gateway_response_invalid") from error
        if (
            not isinstance(document, dict)
            or document.get("model") not in self.allowed_returned_model_ids
        ):
            raise ProviderHandlerError("r2_gateway_returned_model_drift")
        projected = dict(document)
        projected["model"] = MODEL_ID
        return GatewayHttpResponse(
            status_code=200,
            body=json.dumps(
                projected,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode(),
        )


class OwnerOnlyEvidenceStore:
    def __init__(self, root: Path) -> None:
        if not root.is_absolute():
            raise ProviderHandlerError("provider_evidence_root_invalid")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        root.chmod(0o700)
        info = root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise ProviderHandlerError("provider_evidence_root_invalid")
        self.root = root

    def record(self, *, task_id: str, document: Mapping[str, Any]) -> str:
        source = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        if not 1 <= len(source) <= 8 * 1024 * 1024:
            raise ProviderHandlerError("provider_evidence_size_invalid")
        digest = _digest_bytes(source)
        safe_task = "".join(
            character if character.isalnum() or character == "_" else "_"
            for character in task_id
        )
        path = self.root / f"{safe_task}.{digest[7:23]}.provider-response.json"
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError:
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
                or _digest_bytes(path.read_bytes()) != digest
            ):
                raise ProviderHandlerError("provider_evidence_conflict")
            return digest
        try:
            written = 0
            while written < len(source):
                count = os.write(descriptor, source[written:])
                if count <= 0:
                    raise ProviderHandlerError("provider_evidence_write_failed")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return digest


class ProviderBackedDiseaseR2Handler:
    def __init__(
        self,
        *,
        provider_secret: str,
        corpus_path: Path,
        evidence_store: OwnerOnlyEvidenceStore,
        gateway_transport=None,
        allowed_returned_model_ids: tuple[str, ...] = (EXACT_RETURNED_MODEL_ID,),
    ) -> None:
        self.provider_secret = provider_secret
        self.literature = FrozenPublicLiteraturePort(corpus_path)
        self.evidence_store = evidence_store
        self.gateway_transport = gateway_transport
        self.allowed_returned_model_ids = allowed_returned_model_ids

    def __call__(self, invocation: Mapping[str, Any]) -> dict[str, Any]:
        if (
            invocation.get("operation") != "run_public_r2_provider_attempt"
            or invocation.get("data_classification") != "public"
            or invocation.get("synthetic_only") is not False
            or invocation.get("production_authorization") is not False
        ):
            raise ProviderHandlerError("provider_invocation_boundary_invalid")
        recording = RecordingGatewayTransport(self.gateway_transport)
        version_pinning = ExactReturnedModelTransport(
            recording,
            allowed_returned_model_ids=self.allowed_returned_model_ids,
        )
        gateway = DiseaseR2ModelGateway(
            R2GatewayConfig(secret=self.provider_secret), version_pinning
        )
        task_id = str(invocation["task_id"])
        provider_response_set_digest = None
        orchestrated = None
        failure: Exception | None = None
        try:
            orchestrated = run_r2_ports(
                gateway=gateway,
                literature=self.literature,
                worker=process,
                task_id=task_id,
                grant_digest=str(invocation["grant_digest"]),
                composition_digest=str(invocation["composition_digest"]),
                runtime_source_digest=str(invocation["runtime_source_digest"]),
                agent_release_digest=AGENT_RELEASE_DIGEST,
                literature_tool_release_digest=LITERATURE_TOOL_RELEASE_DIGEST,
                model_route_digest=MODEL_ROUTE_DIGEST,
                corpus_ref=CORPUS_REF,
                corpus_revision=CORPUS_REVISION,
            )
        except Exception as error:  # noqa: BLE001 - sanitize at provider boundary
            failure = error
        finally:
            if recording.responses:
                provider_response_set_digest = self.evidence_store.record(
                    task_id=task_id,
                    document={
                        "evidence_version": "orbit.provider-response-set/1",
                        "provider": "fixture",
                        "model": MODEL_ID,
                        "endpoint_origin_digest": _digest_bytes(
                            (BASE_URL + REQUEST_PATH).encode()
                        ),
                        "responses": recording.responses,
                        "production_authorization": False,
                        "release_authorization": False,
                    },
                )
        if failure is not None:
            reason = getattr(failure, "reason_code", "runtime_handler_failed_closed")
            if not isinstance(reason, str):
                reason = "runtime_handler_failed_closed"
            raise ProviderAttemptFailure(
                reason,
                _failure_result(
                    reason_code=reason,
                    responses=recording.responses,
                    provider_response_set_digest=provider_response_set_digest,
                ),
            ) from None
        if not isinstance(orchestrated, Mapping):
            raise ProviderHandlerError("runtime_handler_failed_closed")
        result = dict(orchestrated["result"])
        result["status"] = "R2 provider-backed public-corpus pass"
        result.pop("result_digest", None)
        result["result_digest"] = worker_digest(result)
        returned_model_ids = _returned_model_ids(recording.responses)
        return {
            "status": result["status"],
            "result": result,
            "usage": {
                "model_calls": len(orchestrated["model_calls"]),
                "request_attempts": sum(
                    item["attempts"] for item in orchestrated["model_calls"]
                ),
                "input_tokens": sum(
                    item["usage"]["input_tokens"]
                    for item in orchestrated["model_calls"]
                ),
                "output_tokens": sum(
                    item["usage"]["output_tokens"]
                    for item in orchestrated["model_calls"]
                ),
                "cost_usd": orchestrated["cost"]["usd"],
                "cost_cny": orchestrated["cost"]["cny"],
            },
            "provider_response_set_digest": provider_response_set_digest,
            "provider_observation": {
                "requested_model": MODEL_ID,
                "resolved_model_id": returned_model_ids[-1],
                "returned_model_ids": sorted(set(returned_model_ids)),
            },
            "production_authorization": False,
            "release_authorization": False,
        }


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _returned_model_ids(responses: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for response in responses:
        if response.get("status_code") != 200:
            continue
        try:
            model_id = json.loads(
                base64.b64decode(response["response_body_base64"])
            )["model"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(model_id, str):
            values.append(model_id)
    if not values:
        raise ProviderHandlerError("r2_gateway_response_invalid")
    return values


def _failure_result(
    *,
    reason_code: str,
    responses: list[dict[str, Any]],
    provider_response_set_digest: str | None,
) -> dict[str, Any]:
    input_tokens = 0
    output_tokens = 0
    returned_ids: list[str] = []
    for response in responses:
        if response.get("status_code") != 200:
            continue
        try:
            document = json.loads(base64.b64decode(response["response_body_base64"]))
            usage = document["usage"]
            model_id = document["model"]
            prompt_tokens = usage["prompt_tokens"]
            completion_tokens = usage["completion_tokens"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        if (
            not isinstance(model_id, str)
            or isinstance(prompt_tokens, bool)
            or not isinstance(prompt_tokens, int)
            or prompt_tokens < 0
            or isinstance(completion_tokens, bool)
            or not isinstance(completion_tokens, int)
            or completion_tokens < 0
        ):
            continue
        returned_ids.append(model_id)
        input_tokens += prompt_tokens
        output_tokens += completion_tokens
    cost_usd = (
        Decimal(input_tokens) * INPUT_USD_PER_MILLION
        + Decimal(output_tokens) * OUTPUT_USD_PER_MILLION
    ) / Decimal(1_000_000)
    observation = {
        "requested_model": MODEL_ID,
        "returned_model_ids": returned_ids,
        "response_count": len(responses),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }
    return {
        "status": "R2 provider-backed public-corpus failed",
        "failure_reason_code": reason_code,
        "usage": {
            "model_calls": len(returned_ids),
            "request_attempts": len(responses),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": format(cost_usd.quantize(Decimal("0.000001")), "f"),
            "cost_cny": format(
                (cost_usd * CNY_PER_USD).quantize(Decimal("0.000001")), "f"
            ),
        },
        "provider_observation": observation,
        "provider_observation_digest": _digest_bytes(
            json.dumps(
                observation,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ),
        "provider_response_set_digest": provider_response_set_digest,
        "production_authorization": False,
        "release_authorization": False,
    }

