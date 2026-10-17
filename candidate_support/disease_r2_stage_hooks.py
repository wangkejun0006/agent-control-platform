"""Deterministic, non-authoritative stage hooks for Disease R2 candidates.

The hooks may advance static engineering checks, but they stop before any new
human approval scope.  They never create an effective Task/Grant, consume a
route approval, call a provider, start Docker, or write Company authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from .disease_r2_v4_preflight import (
    DiseaseR2V4PreflightError,
    read_json,
    verify_candidate,
)

RECEIPT_VERSION = "orbit.synthetic-stage-hook-receipt/1"
PIPELINE_VERSION = "orbit.synthetic-stage-hook-pipeline/1"


class DiseaseR2StageHookError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def run_pre_approval_hooks(
    *, review_package: Path, scope_ledger_path: Path
) -> dict[str, Any]:
    """Run static hooks and stop at the next human approval boundary."""
    review_package = review_package.resolve(strict=True)
    candidate_root = review_package.parent
    review = read_json(review_package)
    checks: list[dict[str, Any]] = []
    try:
        preflight = verify_candidate(
            review_package,
            runtime_root=candidate_root,
            scope_ledger_path=scope_ledger_path,
            require_execution_approval=False,
        )
        if preflight.get("status") != "PASS":
            raise DiseaseR2StageHookError("r2_stage_reference_graph_failed")
        checks.append(_check("reference_graph_and_scope_receipts", "pass"))
    except (DiseaseR2V4PreflightError, DiseaseR2StageHookError) as error:
        reason = getattr(error, "reason_code", "r2_stage_reference_graph_failed")
        checks.append(_check("reference_graph_and_scope_receipts", "blocked", reason))
        return _receipt(review, checks, "blocked", "candidate_remediation_required")

    try:
        _run_materialized_compatibility_hook(
            review_package=review_package,
            scope_ledger_path=scope_ledger_path,
            review=review,
        )
        checks.append(_check("runtime_entrypoint_compatibility", "pass"))
    except DiseaseR2StageHookError as error:
        checks.append(
            _check("runtime_entrypoint_compatibility", "blocked", error.reason_code)
        )
        return _receipt(review, checks, "blocked", "candidate_remediation_required")

    return _receipt(
        review,
        checks,
        "ready_for_human_gate",
        "human_execution_approval_required",
    )


def write_receipt_once(path: Path, receipt: Mapping[str, Any]) -> str:
    """Persist one owner-only local receipt without making it authoritative."""
    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    source = json.dumps(
        receipt,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if os.write(fd, source) != len(source):
            raise DiseaseR2StageHookError("r2_stage_receipt_short_write")
        os.fsync(fd)
    finally:
        os.close(fd)
    return "sha256:" + hashlib.sha256(source).hexdigest()


def _run_materialized_compatibility_hook(
    *,
    review_package: Path,
    scope_ledger_path: Path,
    review: Mapping[str, Any],
) -> None:
    artifacts = review.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise DiseaseR2StageHookError("r2_stage_artifact_graph_invalid")
    source_entry = artifacts.get("runtime_source_lock")
    if not isinstance(source_entry, Mapping):
        raise DiseaseR2StageHookError("r2_stage_source_lock_missing")
    source_path = _safe_relative(source_entry.get("path"))
    source_lock = read_json(review_package.parent / source_path)
    entrypoint = _safe_relative(source_lock.get("entrypoint"))
    runtime_entrypoint = review_package.parent / entrypoint
    if not runtime_entrypoint.is_file() or runtime_entrypoint.is_symlink():
        raise DiseaseR2StageHookError("r2_stage_runtime_entrypoint_missing")
    command = [
        sys.executable,
        str(runtime_entrypoint),
        "--static-compatibility-only",
        "--review-package",
        str(review_package),
        "--scope-ledger",
        str(scope_ledger_path.resolve(strict=True)),
    ]
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
    }
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DiseaseR2StageHookError(
            "r2_stage_runtime_compatibility_unavailable"
        ) from error
    if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 8192:
        raise DiseaseR2StageHookError("r2_stage_runtime_compatibility_failed")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise DiseaseR2StageHookError(
            "r2_stage_runtime_compatibility_invalid"
        ) from error
    expected = {
        "hook_version": "orbit.synthetic-stage-hook-result/1",
        "hook": "runtime_entrypoint_compatibility",
        "status": "pass",
        "review_package_digest": review.get("review_package_digest"),
        "runtime_source_lock_digest": review.get("runtime_source_lock_digest"),
        "external_calls": 0,
        "terminal_closure_supported": True,
        "runtime_started": False,
        "effective": False,
        "release_authorization": False,
    }
    if result != expected:
        raise DiseaseR2StageHookError("r2_stage_runtime_compatibility_invalid")


def _receipt(
    review: Mapping[str, Any],
    checks: list[dict[str, Any]],
    status: str,
    next_stage: str,
) -> dict[str, Any]:
    content = {
        "receipt_version": RECEIPT_VERSION,
        "pipeline_version": PIPELINE_VERSION,
        "subject_type": "r2_execution_candidate",
        "attempt_id": review.get("attempt_id"),
        "review_package_digest": review.get("review_package_digest"),
        "runtime_source_lock_digest": review.get("runtime_source_lock_digest"),
        "task_candidate_digest": review.get("task_candidate_digest"),
        "grant_candidate_digest": review.get("grant_candidate_digest"),
        "composition_candidate_digest": review.get("composition_candidate_digest"),
        "checks": checks,
        "status": status,
        "next_stage": next_stage,
        "human_intervention_required": next_stage.startswith("human_"),
        "authority_boundary": {
            "approval_created": False,
            "effective_task_created": False,
            "effective_grant_created": False,
            "route_consumed": False,
            "provider_called": False,
            "docker_started": False,
            "nas_accessed": False,
            "release_authorization": False,
        },
        "company_authoritative": False,
    }
    return {**content, "receipt_digest": _digest(content)}


def _check(name: str, status: str, reason_code: str | None = None) -> dict[str, Any]:
    return {"hook": name, "status": status, "reason_code": reason_code}


def _safe_relative(value: Any) -> Path:
    if not isinstance(value, str):
        raise DiseaseR2StageHookError("r2_stage_path_invalid")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise DiseaseR2StageHookError("r2_stage_path_invalid")
    return Path(*pure.parts)


def _digest(value: Any) -> str:
    source = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(source).hexdigest()

