"""Owner-only Task/Grant/Lease ledger for one local Disease R2 execution."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from orbit_agent_control_plane.ids import deterministic_id
from orbit_agent_control_plane.lifecycle_ledger import (
    append_jsonl_document,
    close_ledger,
    open_owner_only_ledger,
    read_jsonl_documents,
)

LEDGER_VERSION = "orbit.synthetic-disease-r2-execution-ledger/1"
GENESIS = "sha256:" + ("0" * 64)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$")
_RECORD_KEYS = {
    "ledger_version",
    "sequence",
    "record_id",
    "record_type",
    "task_id",
    "idempotency_key",
    "previous_record_hash",
    "payload",
    "record_hash",
}


class DiseaseR2ExecutionLedgerError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class DiseaseR2ExecutionState:
    task_id: str
    started: Mapping[str, Any]
    outcome: Mapping[str, Any] | None
    lease: Mapping[str, Any]
    terminal: Mapping[str, Any] | None


@dataclass(frozen=True)
class DiseaseR2ExecutionReplay:
    records_checked: int
    last_record_hash: str
    state: DiseaseR2ExecutionState | None


class SyntheticDiseaseR2ExecutionLedger:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def start(
        self, task_id: str, value: Mapping[str, Any], *, idempotency_key: str
    ) -> None:
        _validate_started(task_id, value)
        self._append("execution_started", task_id, value, idempotency_key)

    def record_outcome(
        self, task_id: str, value: Mapping[str, Any], *, idempotency_key: str
    ) -> None:
        replay = self.replay()
        if replay.state is None or replay.state.task_id != task_id:
            raise DiseaseR2ExecutionLedgerError("r2_execution_not_started")
        _validate_outcome(value)
        self._append("execution_outcome_recorded", task_id, value, idempotency_key)

    def close_lease(
        self, task_id: str, value: Mapping[str, Any], *, idempotency_key: str
    ) -> None:
        replay = self.replay()
        if replay.state is None or replay.state.outcome is None:
            raise DiseaseR2ExecutionLedgerError("r2_execution_outcome_missing")
        _validate_closed_lease(value, replay.state)
        self._append("worker_lease_closed", task_id, value, idempotency_key)

    def close_authority(
        self, task_id: str, value: Mapping[str, Any], *, idempotency_key: str
    ) -> None:
        replay = self.replay()
        if (
            replay.state is None
            or replay.state.outcome is None
            or replay.state.lease["status"] == "active"
        ):
            raise DiseaseR2ExecutionLedgerError("r2_execution_lease_not_closed")
        _validate_terminal_authority(value, replay.state)
        self._append("execution_authority_closed", task_id, value, idempotency_key)

    def replay(self) -> DiseaseR2ExecutionReplay:
        fd = open_owner_only_ledger(
            self.path,
            create=False,
            exclusive=False,
            error=DiseaseR2ExecutionLedgerError,
            label="Disease R2 execution ledger",
        )
        try:
            return _replay(fd)
        finally:
            close_ledger(fd)

    def _append(
        self,
        record_type: str,
        task_id: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
    ) -> None:
        if not _KEY.fullmatch(task_id) or not _KEY.fullmatch(idempotency_key):
            raise DiseaseR2ExecutionLedgerError("r2_execution_identifier_invalid")
        fd = open_owner_only_ledger(
            self.path,
            create=True,
            exclusive=True,
            error=DiseaseR2ExecutionLedgerError,
            label="Disease R2 execution ledger",
        )
        try:
            replay, records = _replay(fd, include_records=True)
            normalized = _normalize(payload)
            for record in records:
                if record["idempotency_key"] != idempotency_key:
                    continue
                if (
                    record["record_type"] == record_type
                    and record["task_id"] == task_id
                    and record["payload"] == normalized
                ):
                    return
                raise DiseaseR2ExecutionLedgerError("r2_execution_idempotency_conflict")
            content = {
                "ledger_version": LEDGER_VERSION,
                "sequence": len(records),
                "record_id": deterministic_id(
                    "r2run", record_type, task_id, idempotency_key, _digest(normalized)
                ),
                "record_type": record_type,
                "task_id": task_id,
                "idempotency_key": idempotency_key,
                "previous_record_hash": replay.last_record_hash,
                "payload": normalized,
            }
            document = {**content, "record_hash": _digest(content)}
            append_jsonl_document(
                fd,
                (_canonical(document) + "\n").encode(),
                max_ledger_bytes=8 * 1024 * 1024,
                max_record_bytes=256 * 1024,
                error=DiseaseR2ExecutionLedgerError,
                label="Disease R2 execution ledger",
            )
        finally:
            close_ledger(fd)


def _replay(
    fd: int, *, include_records: bool = False
) -> DiseaseR2ExecutionReplay | tuple[
    DiseaseR2ExecutionReplay, tuple[dict[str, Any], ...]
]:
    records = read_jsonl_documents(
        fd,
        max_ledger_bytes=8 * 1024 * 1024,
        max_record_bytes=256 * 1024,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
        error=DiseaseR2ExecutionLedgerError,
        label="Disease R2 execution ledger",
    )
    previous = GENESIS
    seen = set()
    state = None
    for sequence, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
            raise DiseaseR2ExecutionLedgerError("r2_execution_record_invalid")
        content = {key: value for key, value in record.items() if key != "record_hash"}
        if (
            record["ledger_version"] != LEDGER_VERSION
            or record["sequence"] != sequence
            or record["previous_record_hash"] != previous
            or record["record_hash"] != _digest(content)
            or record["idempotency_key"] in seen
        ):
            raise DiseaseR2ExecutionLedgerError("r2_execution_chain_invalid")
        seen.add(record["idempotency_key"])
        payload = record["payload"]
        if record["record_type"] == "execution_started":
            if state is not None:
                raise DiseaseR2ExecutionLedgerError("r2_execution_already_started")
            _validate_started(record["task_id"], payload)
            state = DiseaseR2ExecutionState(
                record["task_id"], payload, None, payload["worker_lease"], None
            )
        elif record["record_type"] == "execution_outcome_recorded":
            if state is None or state.outcome is not None or state.task_id != record["task_id"]:
                raise DiseaseR2ExecutionLedgerError("r2_execution_outcome_invalid")
            _validate_outcome(payload)
            state = DiseaseR2ExecutionState(
                state.task_id, state.started, payload, state.lease, state.terminal
            )
        elif record["record_type"] == "worker_lease_closed":
            if state is None or state.outcome is None or state.lease["status"] != "active":
                raise DiseaseR2ExecutionLedgerError("r2_execution_lease_invalid")
            _validate_closed_lease(payload, state)
            state = DiseaseR2ExecutionState(
                state.task_id, state.started, state.outcome, payload, state.terminal
            )
        elif record["record_type"] == "execution_authority_closed":
            if (
                state is None
                or state.outcome is None
                or state.lease["status"] == "active"
                or state.terminal is not None
            ):
                raise DiseaseR2ExecutionLedgerError(
                    "r2_execution_authority_closure_invalid"
                )
            _validate_terminal_authority(payload, state)
            state = DiseaseR2ExecutionState(
                state.task_id, state.started, state.outcome, state.lease, payload
            )
        else:
            raise DiseaseR2ExecutionLedgerError("r2_execution_record_type_invalid")
        previous = record["record_hash"]
    replay = DiseaseR2ExecutionReplay(len(records), previous, state)
    return (replay, records) if include_records else replay


def _validate_started(task_id: str, value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "task_id",
        "task_digest",
        "grant_id",
        "grant_digest",
        "composition_digest",
        "runtime_source_digest",
        "execution_approval_digest",
        "issued_at",
        "expires_at",
        "worker_lease",
        "synthetic_only",
        "release_authorization",
    }:
        raise DiseaseR2ExecutionLedgerError("r2_execution_start_invalid")
    lease = value["worker_lease"]
    if (
        value["task_id"] != task_id
        or any(
            not isinstance(value[name], str) or not _DIGEST.fullmatch(value[name])
            for name in (
                "task_digest",
                "grant_digest",
                "composition_digest",
                "runtime_source_digest",
                "execution_approval_digest",
            )
        )
        or value["synthetic_only"] is not True
        or value["release_authorization"] is not False
        or not isinstance(lease, Mapping)
        or set(lease) != {"lease_id", "status", "revision"}
        or lease["status"] != "active"
        or lease["revision"] != 0
    ):
        raise DiseaseR2ExecutionLedgerError("r2_execution_start_invalid")
    issued = _time(value["issued_at"])
    expires = _time(value["expires_at"])
    if not 1 <= (expires - issued).total_seconds() <= 900:
        raise DiseaseR2ExecutionLedgerError("r2_execution_lifetime_invalid")


def _validate_outcome(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "status",
        "evidence_digest",
        "result_digest",
        "reason_codes",
        "usage",
        "release_authorization",
    }:
        raise DiseaseR2ExecutionLedgerError("r2_execution_outcome_invalid")
    usage = value["usage"]
    if (
        value["status"] not in {"pass", "fail", "cancelled"}
        or not _DIGEST.fullmatch(str(value["evidence_digest"]))
        or (
            value["result_digest"] is not None
            and not _DIGEST.fullmatch(str(value["result_digest"]))
        )
        or not isinstance(value["reason_codes"], list)
        or not value["reason_codes"]
        or not isinstance(usage, Mapping)
        or set(usage)
        != {"calls", "attempts", "input_tokens", "output_tokens", "cost_usd", "cost_cny"}
        or any(
            isinstance(usage[name], bool) or not isinstance(usage[name], int)
            for name in ("calls", "attempts", "input_tokens", "output_tokens")
        )
        or usage["calls"] > 4
        or usage["attempts"] > 8
        or usage["input_tokens"] > 12_000
        or usage["output_tokens"] > 1_024
        or value["release_authorization"] is not False
    ):
        raise DiseaseR2ExecutionLedgerError("r2_execution_outcome_invalid")


def _validate_closed_lease(
    value: Mapping[str, Any], state: DiseaseR2ExecutionState
) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"lease_id", "status", "revision"}
        or value["lease_id"] != state.lease["lease_id"]
        or value["revision"] != 1
        or value["status"] not in {"completed", "failed", "cancelled"}
        or (value["status"] == "completed") != (state.outcome["status"] == "pass")
    ):
        raise DiseaseR2ExecutionLedgerError("r2_execution_lease_invalid")


def _validate_terminal_authority(
    value: Mapping[str, Any], state: DiseaseR2ExecutionState
) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "task",
        "grant",
        "execution_approval",
        "model_route",
        "release_authorization",
    }:
        raise DiseaseR2ExecutionLedgerError("r2_execution_authority_closure_invalid")
    task = value["task"]
    grant = value["grant"]
    approval = value["execution_approval"]
    route = value["model_route"]
    expected_task_status = {
        "pass": "completed",
        "fail": "failed",
        "cancelled": "cancelled",
    }[state.outcome["status"]]
    if (
        not isinstance(task, Mapping)
        or set(task) != {"task_id", "status", "revision"}
        or task["task_id"] != state.task_id
        or task["status"] != expected_task_status
        or task["revision"] != 1
        or not isinstance(grant, Mapping)
        or set(grant) != {"grant_id", "status", "effective", "revision"}
        or grant["grant_id"] != state.started["grant_id"]
        or grant["status"] != "consumed"
        or grant["effective"] is not False
        or grant["revision"] != 1
        or not isinstance(approval, Mapping)
        or set(approval) != {"digest", "status", "single_use"}
        or approval["digest"] != state.started["execution_approval_digest"]
        or approval["status"] != "consumed"
        or approval["single_use"] is not True
        or not isinstance(route, Mapping)
        or set(route) != {"digest", "status"}
        or not _DIGEST.fullmatch(str(route["digest"]))
        or route["status"] not in {"consumed", "consumption_failed"}
        or (state.outcome["status"] == "pass" and route["status"] != "consumed")
        or value["release_authorization"] is not False
    ):
        raise DiseaseR2ExecutionLedgerError("r2_execution_authority_closure_invalid")


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DiseaseR2ExecutionLedgerError("r2_execution_time_invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise DiseaseR2ExecutionLedgerError("r2_execution_time_invalid") from error


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode()).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _normalize(value: Any) -> Any:
    return json.loads(_canonical(value))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise DiseaseR2ExecutionLedgerError("r2_execution_duplicate_json_key")
        value[key] = item
    return value


def _reject_constant(_: str) -> None:
    raise DiseaseR2ExecutionLedgerError("r2_execution_json_constant_invalid")

