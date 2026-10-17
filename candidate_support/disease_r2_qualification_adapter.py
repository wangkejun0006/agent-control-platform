"""Read-only adapter from Disease R2 pre-approval hooks to qualification stages.

The adapter preserves the existing R2 evidence and converts its legacy static
hook receipt into the generic Company qualification observation.  It never
creates authority, executes Docker, calls a provider, or mutates the candidate.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from orbit_agent_control_plane.qualification.automation import (
    StageCheck,
    StageObservation,
    StageSideEffects,
    canonical_digest,
)


class DiseaseR2QualificationAdapterError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def runtime_observation_from_stage_hook(
    *,
    receipt: Mapping[str, Any],
    started_at: str,
    completed_at: str,
    environment_profile_digest: str,
) -> StageObservation:
    """Convert a verified legacy hook receipt into runtime_realization evidence."""
    _validate_hook_receipt(receipt)
    status = receipt["status"]
    checks = tuple(
        StageCheck(
            name=item["hook"],
            status=item["status"],
            reason_code=item["reason_code"],
        )
        for item in receipt["checks"]
    )
    if status == "ready_for_human_gate":
        outcome = "pass"
        failure_class = "none"
        reason_codes = ("runtime_realization_static_checks_passed",)
    else:
        outcome = "blocked"
        failure_class = "engineering_compatibility"
        reason_codes = tuple(
            item["reason_code"]
            for item in receipt["checks"]
            if item["reason_code"] is not None
        )
        if not reason_codes:
            raise DiseaseR2QualificationAdapterError(
                "disease_r2_hook_failure_reason_missing"
            )
    return StageObservation(
        stage="runtime_realization",
        outcome=outcome,
        failure_class=failure_class,
        reason_codes=reason_codes,
        checks=checks,
        inputs=(
            {
                "role": "r2_execution_review_package",
                "ref": "artifact://disease_r2/execution_review_package",
                "digest": receipt["review_package_digest"],
            },
            {
                "role": "runtime_source_lock",
                "ref": "artifact://disease_r2/runtime_source_lock",
                "digest": receipt["runtime_source_lock_digest"],
            },
        ),
        executor={
            "component": {
                "id": "component_disease_r2_stage_hook_adapter",
                "version": "0.1.0",
                "digest": canonical_digest(
                    "candidate_support.disease_r2_qualification_adapter/0.1.0"
                ),
            },
            "deterministic": True,
            "environment_profile_digest": environment_profile_digest,
        },
        side_effects=StageSideEffects(),
        started_at=started_at,
        completed_at=completed_at,
    )


def _validate_hook_receipt(receipt: Mapping[str, Any]) -> None:
    if not isinstance(receipt, Mapping):
        raise DiseaseR2QualificationAdapterError("disease_r2_hook_receipt_invalid")
    required = {
        "receipt_version",
        "pipeline_version",
        "subject_type",
        "attempt_id",
        "review_package_digest",
        "runtime_source_lock_digest",
        "task_candidate_digest",
        "grant_candidate_digest",
        "composition_candidate_digest",
        "checks",
        "status",
        "next_stage",
        "human_intervention_required",
        "authority_boundary",
        "company_authoritative",
        "receipt_digest",
    }
    if set(receipt) != required:
        raise DiseaseR2QualificationAdapterError("disease_r2_hook_receipt_invalid")
    content = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    if (
        receipt["receipt_version"] != "orbit.synthetic-stage-hook-receipt/1"
        or receipt["pipeline_version"] != "orbit.synthetic-stage-hook-pipeline/1"
        or receipt["subject_type"] != "r2_execution_candidate"
        or receipt["receipt_digest"] != canonical_digest(content)
        or receipt["status"] not in {"blocked", "ready_for_human_gate"}
        or receipt["company_authoritative"] is not False
    ):
        raise DiseaseR2QualificationAdapterError("disease_r2_hook_receipt_invalid")
    authority = receipt["authority_boundary"]
    if not isinstance(authority, Mapping) or any(
        value is not False for value in authority.values()
    ):
        raise DiseaseR2QualificationAdapterError(
            "disease_r2_hook_authority_boundary_invalid"
        )
    checks = receipt["checks"]
    if not isinstance(checks, list) or not checks:
        raise DiseaseR2QualificationAdapterError("disease_r2_hook_checks_invalid")
    for item in checks:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"hook", "status", "reason_code"}
            or item["status"] not in {"pass", "blocked"}
        ):
            raise DiseaseR2QualificationAdapterError("disease_r2_hook_checks_invalid")

