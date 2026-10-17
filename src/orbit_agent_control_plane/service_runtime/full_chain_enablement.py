"""Owner-only receipt for the single Disease/Dataset human checkpoint."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class FullChainEnablementError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def create_full_chain_enablement_receipt(
    *,
    review_package_path: Path,
    artifact_set_path: Path,
    approval_text: str,
    approved_by_human_ref: str,
    receipt_path: Path,
    provider_observation_path: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Create one receipt with independent, non-convertible internal scopes."""
    review = _read_json(review_package_path)
    artifact_set = _read_json(artifact_set_path)
    review_raw = _raw_digest(review_package_path)
    review_canonical = review.get("review_package_digest")
    execution_intent = review.get("execution_intent_digest")
    if (
        not isinstance(review_canonical, str)
        or not isinstance(execution_intent, str)
        or review_raw not in approval_text
        or review_canonical not in approval_text
        or execution_intent not in approval_text
        or "批准" not in approval_text
        or not approved_by_human_ref.startswith("human_")
    ):
        raise FullChainEnablementError("full_chain_approval_text_binding_invalid")
    bindings = artifact_set.get("digest_bindings")
    if not isinstance(bindings, Mapping) or bindings.get("approval_receipts") != []:
        raise FullChainEnablementError("full_chain_artifact_set_invalid")
    subjects = bindings.get("subjects")
    pending = bindings.get("pending_approval_scopes")
    if not isinstance(subjects, list) or not isinstance(pending, list):
        raise FullChainEnablementError("full_chain_artifact_set_invalid")
    subject_by_scope = {
        item["scope_kind"]: item
        for item in subjects
        if isinstance(item, Mapping)
        and isinstance(item.get("scope_kind"), str)
        and isinstance(item.get("subject_digest"), str)
    }
    if set(subject_by_scope) != set(pending) or len(subject_by_scope) != 5:
        raise FullChainEnablementError("full_chain_artifact_set_invalid")
    activated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(
        microsecond=0
    )
    receipt: dict[str, Any] = {
        "receipt_version": "orbit.full-chain-pilot-enablement-receipt/1",
        "status": "active",
        "review_package_raw_digest": review_raw,
        "review_package_digest": review_canonical,
        "execution_intent_digest": execution_intent,
        "automation_policy_digest": review.get("automation_policy_digest"),
        "artifact_set_raw_digest": _raw_digest(artifact_set_path),
        "approved_by_human_ref": approved_by_human_ref,
        "approval_text_digest": "sha256:"
        + hashlib.sha256(approval_text.encode()).hexdigest(),
        "activated_at": _time_text(activated),
        "expires_at": _time_text(activated + timedelta(minutes=30)),
        "dataset_execution_scope": "approved_single_use",
        "disease_execution_scope": "approved_single_pilot",
        "internal_scopes": [
            {
                "scope_kind": scope,
                "subject_id": subject_by_scope[scope]["subject_id"],
                "subject_digest": subject_by_scope[scope]["subject_digest"],
                "status": "approved_unconsumed",
                "convertible": False,
            }
            for scope in pending
        ],
        "formal_registry_authorized": False,
        "preproduction_authorized": False,
        "production_authorization": False,
        "release_authorization": False,
        "receipt_digest": "",
    }
    receipt["receipt_digest"] = _canonical_digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    _write_owner_only(receipt_path, receipt)
    if provider_observation_path is not None:
        observation = {
            "observation_version": "orbit.provider-observation/1",
            "provider": "fixture",
            "requested_model": "fixture-structured-v1",
            "resolved_model_id": "fixture-structured-v1-2026-07-09",
            "input_usd_per_million_tokens": "5.00",
            "output_usd_per_million_tokens": "30.00",
            "cached_input_usd_per_million_tokens": "0.50",
            "source": "approval://full-chain-pilot/" + receipt["receipt_digest"][7:23],
            "source_kind": "human_reviewed_import",
            "regression_status": "not_run",
            "observed_at": receipt["activated_at"],
            "expires_at": _time_text(activated + timedelta(hours=6)),
        }
        _write_owner_only(provider_observation_path, observation)
    return receipt


def validate_full_chain_enablement_receipt(
    *, review_package_path: Path, artifact_set_path: Path, receipt_path: Path
) -> dict[str, Any]:
    receipt = _read_owner_only(receipt_path)
    content = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    if (
        receipt.get("receipt_version")
        != "orbit.full-chain-pilot-enablement-receipt/1"
        or receipt.get("status") != "active"
        or receipt.get("review_package_raw_digest")
        != _raw_digest(review_package_path)
        or receipt.get("review_package_digest")
        != _read_json(review_package_path).get("review_package_digest")
        or receipt.get("artifact_set_raw_digest") != _raw_digest(artifact_set_path)
        or receipt.get("receipt_digest") != _canonical_digest(content)
        or receipt.get("production_authorization") is not False
        or receipt.get("release_authorization") is not False
    ):
        raise FullChainEnablementError("full_chain_enablement_receipt_invalid")
    expires_at = receipt.get("expires_at")
    if not isinstance(expires_at, str) or _parse_time(expires_at) <= datetime.now(
        timezone.utc
    ):
        raise FullChainEnablementError("full_chain_enablement_receipt_expired")
    return receipt


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FullChainEnablementError("full_chain_document_invalid") from error
    if not isinstance(value, dict):
        raise FullChainEnablementError("full_chain_document_invalid")
    return value


def _read_owner_only(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
    except OSError as error:
        raise FullChainEnablementError("full_chain_enablement_receipt_invalid") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise FullChainEnablementError("full_chain_enablement_receipt_invalid")
    return _read_json(path)


def _write_owner_only(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as error:
        existing = _read_owner_only(path)
        if existing != value:
            raise FullChainEnablementError("full_chain_enablement_receipt_conflict") from error
        return
    try:
        offset = 0
        while offset < len(encoded):
            count = os.write(descriptor, encoded[offset:])
            if count <= 0:
                raise FullChainEnablementError("full_chain_enablement_receipt_write_failed")
            offset += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_digest(value: object) -> str:
    source = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return "sha256:" + hashlib.sha256(source).hexdigest()


def _parse_time(value: str) -> datetime:
    if not value.endswith("Z"):
        raise FullChainEnablementError("full_chain_time_invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as error:
        raise FullChainEnablementError("full_chain_time_invalid") from error


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

