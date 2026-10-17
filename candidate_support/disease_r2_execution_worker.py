"""Restricted Disease R2 worker for one sealed gateway/tool transcript.

The worker has no network and receives neither provider configuration nor
credentials.  Control Plane ports perform the reviewed model and literature
operations outside the container; this worker validates their exact bindings
and produces the Agent result projection.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Any

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 512 * 1024
AGENT_RELEASE_DIGEST = (
    "sha256:e41c15f412b87c39654978a628ac7704b5cbbb2915f41b3b9d4426cf7aa4b04a"
)
TOOL_RELEASE_DIGEST = (
    "sha256:775e2996c5302a28e24d2b8b7b104788e0a782688ba847ae63c8a8b729b48f0d"
)
MODEL_ROUTE_DIGEST = (
    "sha256:8bc631ae8cf7fc7f2d07ac187eb5ca0d313de00818d77abfa7b2b4a04a5c74e7"
)
CORPUS_REF = "dataset://public/disease-r2/fictional-stationery-literature/0.1.0"
CORPUS_REVISION = (
    "sha256:bb796b5aa76f930566e78c599eb197282595b26f2523f7b062374b7c261d6b30"
)
MODEL_ID = "fixture-structured-v1"
MODEL_STAGES = (
    "question_decomposition",
    "query_generation",
    "evidence_mapping",
    "synthesis",
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PHYSICAL = re.compile(r"^(?:/|~/|[A-Za-z]:[\\/]|file://|smb://|opaque://)")
_SECRET = re.compile(
    r"(?:BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|\bsk-[A-Za-z0-9_-]{8,})",
    re.IGNORECASE,
)
_FORBIDDEN_KEYS = {
    "api_key",
    "authorization",
    "credential",
    "credentials",
    "endpoint",
    "nas_path",
    "password",
    "physical_path",
    "secret",
    "storage_path",
}


class DiseaseR2WorkerError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def canonical_bytes(value: Any) -> bytes:
    _validate_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def process(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_INPUT_BYTES:
        raise DiseaseR2WorkerError("r2_worker_input_too_large")
    try:
        envelope = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except DiseaseR2WorkerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiseaseR2WorkerError("r2_worker_input_invalid") from error
    if not isinstance(envelope, dict) or set(envelope) != {
        "envelope_version",
        "task_id",
        "grant_digest",
        "composition_digest",
        "runtime_source_digest",
        "agent_release_digest",
        "literature_tool_release_digest",
        "model_route_digest",
        "corpus_ref",
        "corpus_revision",
        "model_transcript",
        "search_receipts",
        "fetch_receipt",
        "authority_boundary",
    }:
        raise DiseaseR2WorkerError("r2_worker_envelope_fields_invalid")
    _validate_json(envelope)
    for field, expected in (
        ("agent_release_digest", AGENT_RELEASE_DIGEST),
        ("literature_tool_release_digest", TOOL_RELEASE_DIGEST),
        ("model_route_digest", MODEL_ROUTE_DIGEST),
        ("corpus_ref", CORPUS_REF),
        ("corpus_revision", CORPUS_REVISION),
    ):
        if envelope[field] != expected:
            raise DiseaseR2WorkerError("r2_worker_binding_drift")
    for field in ("grant_digest", "composition_digest", "runtime_source_digest"):
        if not isinstance(envelope[field], str) or not _DIGEST.fullmatch(
            envelope[field]
        ):
            raise DiseaseR2WorkerError("r2_worker_digest_invalid")
    if envelope["authority_boundary"] != {
        "agent_network_access": False,
        "agent_model_credentials": False,
        "host_filesystem_access": False,
        "nas_access": False,
        "fulltext_access": False,
        "personal_medical_data": False,
        "a2a_access": False,
        "release_authorization": False,
    }:
        raise DiseaseR2WorkerError("r2_worker_authority_escalation")

    transcript = envelope["model_transcript"]
    if not isinstance(transcript, list) or len(transcript) != 4:
        raise DiseaseR2WorkerError("r2_worker_model_call_count_invalid")
    input_tokens = 0
    output_tokens = 0
    attempts = 0
    for expected_stage, entry in zip(MODEL_STAGES, transcript):
        if not isinstance(entry, dict) or set(entry) != {
            "stage",
            "request_digest",
            "response_digest",
            "returned_model_id",
            "response",
            "usage",
            "attempts",
        }:
            raise DiseaseR2WorkerError("r2_worker_model_transcript_invalid")
        usage = entry["usage"]
        if (
            entry["stage"] != expected_stage
            or entry["returned_model_id"] != MODEL_ID
            or not _DIGEST.fullmatch(str(entry["request_digest"]))
            or entry["response_digest"] != digest(entry["response"])
            or not isinstance(usage, dict)
            or set(usage) != {"input_tokens", "output_tokens"}
            or isinstance(usage["input_tokens"], bool)
            or not isinstance(usage["input_tokens"], int)
            or usage["input_tokens"] < 0
            or isinstance(usage["output_tokens"], bool)
            or not isinstance(usage["output_tokens"], int)
            or usage["output_tokens"] < 0
            or entry["attempts"] not in {1, 2}
        ):
            raise DiseaseR2WorkerError("r2_worker_model_transcript_invalid")
        input_tokens += usage["input_tokens"]
        output_tokens += usage["output_tokens"]
        attempts += entry["attempts"]
    if input_tokens > 12_000 or output_tokens > 1_024 or attempts > 8:
        raise DiseaseR2WorkerError("r2_worker_model_budget_exceeded")

    searches = envelope["search_receipts"]
    fetch = envelope["fetch_receipt"]
    if not isinstance(searches, list) or len(searches) != 2 or not isinstance(fetch, dict):
        raise DiseaseR2WorkerError("r2_worker_literature_receipt_invalid")
    for receipt in [*searches, fetch]:
        if (
            receipt.get("corpus_ref") != CORPUS_REF
            or receipt.get("corpus_revision") != CORPUS_REVISION
            or receipt.get("data_classification") != "public"
            or not _DIGEST.fullmatch(str(receipt.get("result_digest", "")))
        ):
            raise DiseaseR2WorkerError("r2_worker_literature_binding_drift")
    records = fetch.get("records")
    if not isinstance(records, list) or not 1 <= len(records) <= 8:
        raise DiseaseR2WorkerError("r2_worker_literature_receipt_invalid")
    record_refs = {
        record.get("record_ref") for record in records if isinstance(record, dict)
    }
    if (
        len(record_refs) != len(records)
        or any(
            not isinstance(ref, str) or not ref.startswith("artifact://public/pubmed/")
            for ref in record_refs
        )
    ):
        raise DiseaseR2WorkerError("r2_worker_literature_receipt_invalid")

    mapping = transcript[2]["response"]
    synthesis = transcript[3]["response"]
    claims = mapping.get("claims") if isinstance(mapping, dict) else None
    if (
        not isinstance(claims, list)
        or not claims
        or any(
            not isinstance(claim, dict)
            or not isinstance(claim.get("claim_id"), str)
            or not isinstance(claim.get("text"), str)
            or not isinstance(claim.get("evidence_refs"), list)
            or not claim["evidence_refs"]
            or not set(claim["evidence_refs"]).issubset(record_refs)
            or not isinstance(claim.get("certainty"), str)
            for claim in claims
        )
    ):
        raise DiseaseR2WorkerError("r2_worker_claim_evidence_invalid")
    claim_ids = {claim["claim_id"] for claim in claims}
    if (
        not isinstance(synthesis, dict)
        or not isinstance(synthesis.get("summary"), str)
        or not isinstance(synthesis.get("uncertainty"), list)
        or not synthesis["uncertainty"]
        or set(synthesis.get("claim_ids", [])) != claim_ids
        or "refuse" not in str(synthesis.get("clinical_boundary", "")).lower()
    ):
        raise DiseaseR2WorkerError("r2_worker_synthesis_boundary_invalid")

    result = {
        "result_version": "orbit.disease-r2-execution-result/1",
        "status": "R2 synthetic pass",
        "evidence_status": "public",
        "task_id": envelope["task_id"],
        "corpus_ref": CORPUS_REF,
        "corpus_revision": CORPUS_REVISION,
        "claims": claims,
        "synthesis": synthesis,
        "citation_refs": sorted(record_refs),
        "model_usage": {
            "calls": 4,
            "request_attempts": attempts,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
        "authority_boundary": envelope["authority_boundary"],
        "release_authorization": False,
        "preproduction_authorized": False,
        "production_authorized": False,
    }
    result["result_digest"] = digest(result)
    return result


def _validate_json(value: Any) -> None:
    if isinstance(value, float):
        raise DiseaseR2WorkerError("r2_worker_float_forbidden")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in _FORBIDDEN_KEYS:
                raise DiseaseR2WorkerError("r2_worker_secret_or_path_forbidden")
            _validate_json(item)
        return
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for item in value:
            _validate_json(item)
        return
    if isinstance(value, str) and (_PHYSICAL.match(value) or _SECRET.search(value)):
        raise DiseaseR2WorkerError("r2_worker_secret_or_path_forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise DiseaseR2WorkerError("r2_worker_duplicate_json_key")
        value[key] = item
    return value


def _reject_constant(_: str) -> None:
    raise DiseaseR2WorkerError("r2_worker_json_constant_forbidden")


def main() -> int:
    try:
        result = process(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
        encoded = canonical_bytes(result)
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise DiseaseR2WorkerError("r2_worker_output_too_large")
        sys.stdout.buffer.write(encoded + b"\n")
        return 0
    except Exception as error:  # noqa: BLE001 - container trust boundary
        reason = getattr(error, "reason_code", "r2_worker_failed_closed")
        if not isinstance(reason, str) or not reason.replace("_", "").isalnum():
            reason = "r2_worker_failed_closed"
        sys.stderr.write(reason + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

