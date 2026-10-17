"""Owner-only local synthetic AutomationPolicy activation ledger."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..ids import deterministic_id
from ..lifecycle_ledger import (
    append_jsonl_document,
    close_ledger,
    open_owner_only_ledger,
    read_jsonl_documents,
)
from .automation import (
    ReceiptArtifact,
    canonical_digest,
    validate_policy_activation_receipt,
)

ACTIVATION_LEDGER_VERSION = "orbit.automation-policy-activation-ledger/1"
GENESIS_HASH = "sha256:" + ("0" * 64)


class PolicyActivationLedgerError(ValueError):
    def __init__(self, reason_code: str, message: str | None = None) -> None:
        super().__init__(message or reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class PolicyActivationState:
    policy_id: str
    policy_digest: str
    approval_digest: str
    receipt_id: str
    receipt_digest: str
    status: str
    expires_at: str
    record_hash: str
    records_checked: int
    release_authorization: bool = False


class LocalPolicyActivationLedger:
    """Local evidence only; never a formal Company Registry or production store."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def apply(
        self,
        *,
        policy: Mapping[str, Any],
        policy_digest: str,
        approval_decision: Mapping[str, Any],
        receipt: ReceiptArtifact,
        recorded_at: str,
    ) -> PolicyActivationState:
        validate_policy_activation_receipt(
            policy=policy,
            policy_digest=policy_digest,
            approval_decision=approval_decision,
            receipt=receipt,
        )
        approval_digest = canonical_digest(approval_decision)
        fd = open_owner_only_ledger(
            self.path,
            create=True,
            exclusive=True,
            error=PolicyActivationLedgerError,
            label="AutomationPolicy activation ledger",
        )
        try:
            records = _read(fd)
            state = _replay(records)
            if state is not None:
                if (
                    state.policy_digest != policy_digest
                    or state.approval_digest != approval_digest
                    or state.receipt_digest != receipt.digest
                ):
                    raise PolicyActivationLedgerError("policy_activation_conflict")
                return state
            metadata = receipt.document["metadata"]
            content = {
                "ledger_version": ACTIVATION_LEDGER_VERSION,
                "sequence": 0,
                "record_id": deterministic_id(
                    "policyact",
                    policy_digest,
                    approval_digest,
                    receipt.digest,
                ),
                "record_type": "automation_policy_activated",
                "previous_record_hash": GENESIS_HASH,
                "policy_id": metadata["policy_id"],
                "policy_digest": policy_digest,
                "approval_digest": approval_digest,
                "receipt_id": metadata["receipt_id"],
                "receipt_digest": receipt.digest,
                "status": metadata["status"],
                "expires_at": metadata["expires_at"],
                "recorded_at": recorded_at,
                "authority_boundary": {
                    "synthetic_only": True,
                    "runtime_started": False,
                    "formal_registration": False,
                    "preproduction_authorized": False,
                    "production_authorized": False,
                    "release_authorization": False,
                },
            }
            document = {**content, "record_hash": canonical_digest(content)}
            append_jsonl_document(
                fd,
                (_canonical(document) + "\n").encode("utf-8"),
                max_ledger_bytes=1024 * 1024,
                max_record_bytes=128 * 1024,
                error=PolicyActivationLedgerError,
                label="AutomationPolicy activation ledger",
            )
            return _state(document, records_checked=1)
        finally:
            close_ledger(fd)

    def replay(self) -> PolicyActivationState:
        fd = open_owner_only_ledger(
            self.path,
            create=False,
            exclusive=False,
            error=PolicyActivationLedgerError,
            label="AutomationPolicy activation ledger",
        )
        try:
            state = _replay(_read(fd))
        finally:
            close_ledger(fd)
        if state is None:
            raise PolicyActivationLedgerError("policy_activation_missing")
        return state


def _read(fd: int) -> tuple[dict[str, Any], ...]:
    return tuple(
        read_jsonl_documents(
            fd,
            max_ledger_bytes=1024 * 1024,
            max_record_bytes=128 * 1024,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: _reject_constant(),
            error=PolicyActivationLedgerError,
            label="AutomationPolicy activation ledger",
        )
    )


def _replay(records: tuple[dict[str, Any], ...]) -> PolicyActivationState | None:
    if not records:
        return None
    if len(records) != 1:
        raise PolicyActivationLedgerError("policy_activation_ledger_invalid")
    document = records[0]
    expected_fields = {
        "ledger_version",
        "sequence",
        "record_id",
        "record_type",
        "previous_record_hash",
        "policy_id",
        "policy_digest",
        "approval_digest",
        "receipt_id",
        "receipt_digest",
        "status",
        "expires_at",
        "recorded_at",
        "authority_boundary",
        "record_hash",
    }
    content = {key: value for key, value in document.items() if key != "record_hash"}
    boundary = document.get("authority_boundary")
    if (
        set(document) != expected_fields
        or document["ledger_version"] != ACTIVATION_LEDGER_VERSION
        or document["sequence"] != 0
        or document["record_type"] != "automation_policy_activated"
        or document["previous_record_hash"] != GENESIS_HASH
        or document["status"] != "active"
        or document["record_hash"] != canonical_digest(content)
        or not isinstance(boundary, dict)
        or set(boundary)
        != {
            "synthetic_only",
            "runtime_started",
            "formal_registration",
            "preproduction_authorized",
            "production_authorized",
            "release_authorization",
        }
        or boundary["synthetic_only"] is not True
        or any(
            value is not False
            for key, value in boundary.items()
            if key != "synthetic_only"
        )
    ):
        raise PolicyActivationLedgerError("policy_activation_ledger_invalid")
    return _state(document, records_checked=1)


def _state(
    document: Mapping[str, Any], *, records_checked: int
) -> PolicyActivationState:
    return PolicyActivationState(
        policy_id=document["policy_id"],
        policy_digest=document["policy_digest"],
        approval_digest=document["approval_digest"],
        receipt_id=document["receipt_id"],
        receipt_digest=document["receipt_digest"],
        status=document["status"],
        expires_at=document["expires_at"],
        record_hash=document["record_hash"],
        records_checked=records_checked,
    )


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyActivationLedgerError("policy_activation_duplicate_key")
        result[key] = value
    return result


def _reject_constant() -> None:
    raise PolicyActivationLedgerError("policy_activation_nonfinite_number")

