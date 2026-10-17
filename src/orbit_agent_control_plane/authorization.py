"""Fail-closed D0 synthetic Human Operator authorization checks.

The grant is unsigned synthetic test input. It exercises task/action/time and
confirmation boundaries, but it does not authenticate a human or create a
company-effective permission.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .control import CONTROL_ACTIONS
from .ids import deterministic_id


AUTHORIZATION_VERSION = "orbit.synthetic-operator-grant/1"
MAX_GRANT_BYTES = 64 * 1024
MAX_GRANT_LIFETIME_SECONDS = 15 * 60
_GRANT_ID_PATTERN = re.compile(r"^operator_grant_[a-z0-9][a-z0-9_-]{2,79}$")
_OPERATOR_PATTERN = re.compile(r"^human_operator_[a-z0-9][a-z0-9_-]{2,79}$")
_TASK_ID_PATTERN = re.compile(r"^task_[a-z0-9][a-z0-9_-]{2,79}$")
_GRANT_KEYS = frozenset(
    {
        "version",
        "grant_id",
        "operator_ref",
        "task_id",
        "allowed_actions",
        "issued_at",
        "expires_at",
        "evidence_status",
        "synthetic_only",
    }
)


class AuthorizationError(ValueError):
    """Synthetic authorization input is structurally unsafe or unsupported."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class SyntheticOperatorGrant:
    version: str
    grant_id: str
    operator_ref: str
    task_id: str
    allowed_actions: tuple[str, ...]
    issued_at: str
    expires_at: str
    evidence_status: str
    synthetic_only: bool


@dataclass(frozen=True)
class OperatorAuthorizationDecision:
    decision_id: str
    grant_snapshot: SyntheticOperatorGrant
    operator_ref: str
    task_id: str
    action: str
    request_reason: str
    checked_at: str
    confirmed_action: str
    allowed: bool
    reason_codes: tuple[str, ...]


def utc_now_text() -> str:
    """Return a second-resolution UTC timestamp for a local CLI decision."""

    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def authorize_control(
    grant: SyntheticOperatorGrant,
    *,
    operator_ref: str,
    task_id: str,
    action: str,
    request_reason: str,
    checked_at: str,
    confirmed_action: str,
) -> OperatorAuthorizationDecision:
    """Evaluate a synthetic control request without applying the transition."""

    issued, expires = _validate_grant(grant)
    checked = _parse_timestamp(checked_at, "authorization_checked_at_invalid")

    reason_codes: list[str] = []
    if not isinstance(operator_ref, str) or not _OPERATOR_PATTERN.fullmatch(
        operator_ref
    ):
        reason_codes.append("operator_ref_invalid")
    elif operator_ref != grant.operator_ref:
        reason_codes.append("operator_identity_mismatch")

    if not isinstance(task_id, str) or not _TASK_ID_PATTERN.fullmatch(task_id):
        reason_codes.append("operator_task_ref_invalid")
    elif task_id != grant.task_id:
        reason_codes.append("operator_grant_task_mismatch")

    if action not in CONTROL_ACTIONS or action not in grant.allowed_actions:
        reason_codes.append("control_action_not_allowed")

    if checked < issued:
        reason_codes.append("operator_grant_not_yet_valid")
    elif checked >= expires:
        reason_codes.append("operator_grant_expired")

    if not _valid_request_reason(request_reason):
        reason_codes.append("control_reason_invalid")
    if confirmed_action != action:
        reason_codes.append("operator_confirmation_mismatch")

    if not reason_codes:
        reason_codes.append("synthetic_operator_authorized")
    allowed = reason_codes == ["synthetic_operator_authorized"]
    decision_id = deterministic_id(
        "operator_authz",
        grant.grant_id,
        operator_ref,
        task_id,
        action,
        request_reason,
        checked_at,
        confirmed_action,
        *reason_codes,
    )
    return OperatorAuthorizationDecision(
        decision_id=decision_id,
        grant_snapshot=grant,
        operator_ref=operator_ref,
        task_id=task_id,
        action=action,
        request_reason=request_reason,
        checked_at=checked_at,
        confirmed_action=confirmed_action,
        allowed=allowed,
        reason_codes=tuple(reason_codes),
    )


def load_synthetic_operator_grant(path: Path | str) -> SyntheticOperatorGrant:
    """Load an owner-only regular JSON file containing no credential material."""

    grant_path = Path(path)
    if os.path.lexists(grant_path):
        try:
            if stat.S_ISLNK(os.lstat(grant_path).st_mode):
                raise AuthorizationError(
                    "operator_grant_symlink_forbidden",
                    "operator grant path may not be a symbolic link",
                )
        except OSError as error:
            raise AuthorizationError(
                "operator_grant_open_failed",
                "operator grant metadata is unavailable",
            ) from error
    else:
        raise AuthorizationError(
            "operator_grant_not_found",
            "operator grant file does not exist",
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(grant_path, flags)
    except OSError as error:
        raise AuthorizationError(
            "operator_grant_open_failed",
            "operator grant file could not be opened",
        ) from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise AuthorizationError(
                "operator_grant_not_regular_file",
                "operator grant must be a regular file",
            )
        if metadata.st_uid != os.geteuid():
            raise AuthorizationError(
                "operator_grant_owner_mismatch",
                "operator grant must be owned by the current local user",
            )
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise AuthorizationError(
                "operator_grant_permissions_too_broad",
                "operator grant permissions must be owner-only",
            )
        if metadata.st_size > MAX_GRANT_BYTES:
            raise AuthorizationError(
                "operator_grant_too_large",
                "operator grant exceeds the local size limit",
            )
        source = _read_exact(fd, metadata.st_size)
    finally:
        os.close(fd)

    try:
        document = json.loads(
            source.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except AuthorizationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationError(
            "operator_grant_invalid_json",
            "operator grant is not valid JSON",
        ) from error
    grant = _grant_from_document(document)
    _validate_grant(grant)
    return grant


def grant_from_mapping(document: Any) -> SyntheticOperatorGrant:
    """Strictly reconstruct a grant embedded in a ledger control record."""

    grant = _grant_from_document(document)
    _validate_grant(grant)
    return grant


def _grant_from_document(document: Any) -> SyntheticOperatorGrant:
    if not isinstance(document, dict):
        raise AuthorizationError(
            "operator_grant_invalid_shape",
            "operator grant must be a JSON object",
        )
    keys = frozenset(document)
    if keys != _GRANT_KEYS:
        raise AuthorizationError(
            "operator_grant_fields_invalid",
            "operator grant fields do not match the synthetic format",
        )
    actions = document["allowed_actions"]
    if (
        not isinstance(actions, list)
        or not actions
        or any(not isinstance(action, str) for action in actions)
    ):
        raise AuthorizationError(
            "operator_grant_action_invalid",
            "operator grant actions must be a non-empty string list",
        )
    return SyntheticOperatorGrant(
        version=document["version"],
        grant_id=document["grant_id"],
        operator_ref=document["operator_ref"],
        task_id=document["task_id"],
        allowed_actions=tuple(actions),
        issued_at=document["issued_at"],
        expires_at=document["expires_at"],
        evidence_status=document["evidence_status"],
        synthetic_only=document["synthetic_only"],
    )


def _validate_grant(grant: SyntheticOperatorGrant) -> tuple[datetime, datetime]:
    if grant.version != AUTHORIZATION_VERSION:
        raise AuthorizationError(
            "operator_grant_version_unsupported",
            "operator grant version is unsupported",
        )
    if not isinstance(grant.grant_id, str) or not _GRANT_ID_PATTERN.fullmatch(
        grant.grant_id
    ):
        raise AuthorizationError(
            "operator_grant_id_invalid",
            "operator grant id is invalid",
        )
    if not isinstance(grant.operator_ref, str) or not _OPERATOR_PATTERN.fullmatch(
        grant.operator_ref
    ):
        raise AuthorizationError(
            "operator_grant_operator_invalid",
            "operator grant operator reference is invalid",
        )
    if not isinstance(grant.task_id, str) or not _TASK_ID_PATTERN.fullmatch(
        grant.task_id
    ):
        raise AuthorizationError(
            "operator_grant_task_invalid",
            "operator grant task reference is invalid",
        )
    if (
        not isinstance(grant.allowed_actions, tuple)
        or not grant.allowed_actions
        or len(set(grant.allowed_actions)) != len(grant.allowed_actions)
        or any(action not in CONTROL_ACTIONS for action in grant.allowed_actions)
    ):
        raise AuthorizationError(
            "operator_grant_action_invalid",
            "operator grant actions must be unique supported controls without wildcards",
        )
    if grant.evidence_status != "synthetic" or grant.synthetic_only is not True:
        raise AuthorizationError(
            "operator_grant_not_synthetic",
            "only explicitly synthetic operator grants are allowed",
        )
    issued = _parse_timestamp(grant.issued_at, "operator_grant_issued_at_invalid")
    expires = _parse_timestamp(grant.expires_at, "operator_grant_expires_at_invalid")
    lifetime = (expires - issued).total_seconds()
    if lifetime <= 0:
        raise AuthorizationError(
            "operator_grant_time_window_invalid",
            "operator grant expiry must be later than issuance",
        )
    if lifetime > MAX_GRANT_LIFETIME_SECONDS:
        raise AuthorizationError(
            "operator_grant_not_short_lived",
            "synthetic operator grant lifetime may not exceed 15 minutes",
        )
    return issued, expires


def _parse_timestamp(value: Any, reason_code: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuthorizationError(reason_code, "authorization timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AuthorizationError(reason_code, "authorization timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise AuthorizationError(reason_code, "authorization timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _valid_request_reason(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 8 <= len(value) <= 240
        and value.strip() == value
        and value.isprintable()
        and "\n" not in value
        and "\r" not in value
    )


def _read_exact(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            raise AuthorizationError(
                "operator_grant_read_incomplete",
                "operator grant read ended unexpectedly",
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorizationError(
                "duplicate_json_key",
                "operator grant contains a duplicate JSON key",
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise AuthorizationError(
        "operator_grant_invalid_json",
        f"operator grant contains unsupported JSON constant {value}",
    )

