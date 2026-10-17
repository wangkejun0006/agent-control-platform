"""Independent deterministic evaluators for provider-backed public R2 results."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import select

from candidate_support.disease_r2_execution_worker import digest as worker_digest
from candidate_support.disease_r2_literature_port import CORPUS_REVISION

from ..qualification.automation import (
    StageCheck,
    StageHandlerResult,
    StageObservation,
    StageSideEffects,
    canonical_digest,
)
from .database import Database
from .models import RuntimeRunRow

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ProviderEvaluationError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ProviderDomainEvaluationHandler:
    """Evaluate scientific claim/citation and clinical-boundary quality."""

    component_id = "component_disease_r2_public_domain_evaluator"
    component_version = "0.1.0"

    def __init__(self, database: Database, *, component_digest: str) -> None:
        self.database = database
        self.component_digest = component_digest

    def __call__(self, context: Mapping[str, Any]) -> StageHandlerResult:
        row, candidate = _runtime_result(self.database, context)
        outcome = row.result_document or {}
        result = outcome.get("result")
        checks = {
            "provider_result_status": (
                outcome.get("status") == "R2 provider-backed public-corpus pass"
                and isinstance(result, Mapping)
            ),
            "frozen_public_corpus": (
                isinstance(result, Mapping)
                and result.get("corpus_revision") == CORPUS_REVISION
            ),
            "claim_evidence_mapping": _claim_mapping_valid(result),
            "synthesis_uncertainty_and_clinical_boundary": _synthesis_valid(result),
            "result_digest_closed": _nested_result_digest_valid(result),
            "domain_authority_boundary": _authority_boundary_valid(result),
        }
        return _stage_result(
            context=context,
            candidate=candidate,
            row=row,
            evaluator_class="domain",
            component_id=self.component_id,
            component_version=self.component_version,
            component_digest=self.component_digest,
            checks=checks,
        )


class ProviderCompanyEvaluationHandler:
    """Independently enforce Company usage, evidence and authority ceilings."""

    component_id = "component_disease_r2_public_company_evaluator"
    component_version = "0.1.0"

    def __init__(self, database: Database, *, component_digest: str) -> None:
        self.database = database
        self.component_digest = component_digest

    def __call__(self, context: Mapping[str, Any]) -> StageHandlerResult:
        row, candidate = _runtime_result(self.database, context)
        outcome = row.result_document or {}
        result = outcome.get("result")
        usage = outcome.get("usage")
        checks = {
            "company_provider_status": (
                outcome.get("status") == "R2 provider-backed public-corpus pass"
            ),
            "company_usage_budget": _usage_valid(usage, result, candidate),
            "provider_raw_evidence_closed": (
                isinstance(outcome.get("provider_response_set_digest"), str)
                and bool(_DIGEST.fullmatch(outcome["provider_response_set_digest"]))
            ),
            "company_runtime_authority_boundary": (
                outcome.get("production_authorization") is False
                and outcome.get("release_authorization") is False
                and _authority_boundary_valid(result)
            ),
            "company_result_digest_closed": _nested_result_digest_valid(result),
        }
        return _stage_result(
            context=context,
            candidate=candidate,
            row=row,
            evaluator_class="company",
            component_id=self.component_id,
            component_version=self.component_version,
            component_digest=self.component_digest,
            checks=checks,
        )


def _runtime_result(
    database: Database, context: Mapping[str, Any]
) -> tuple[RuntimeRunRow, Mapping[str, Any]]:
    candidate = context.get("candidate")
    if not isinstance(candidate, Mapping):
        raise ProviderEvaluationError("provider_evaluation_context_invalid")
    task_digest = candidate.get("task_digest")
    with database.session() as session:
        rows = tuple(session.scalars(select(RuntimeRunRow).order_by(RuntimeRunRow.id)))
    matches = tuple(
        row
        for row in rows
        if row.invocation.get("task_digest") == task_digest
        and row.invocation.get("operation") == "run_public_r2_provider_attempt"
        and row.status == "completed"
        and row.result_document is not None
    )
    if len(matches) != 1:
        raise ProviderEvaluationError("provider_evaluation_result_not_unique")
    return matches[0], candidate


def _claim_mapping_valid(result: Any) -> bool:
    if not isinstance(result, Mapping):
        return False
    citations = result.get("citation_refs")
    claims = result.get("claims")
    if (
        not isinstance(citations, list)
        or not citations
        or any(not isinstance(item, str) for item in citations)
        or len(citations) != len(set(citations))
        or not isinstance(claims, list)
        or not claims
    ):
        return False
    allowed = set(citations)
    return all(
        isinstance(claim, Mapping)
        and isinstance(claim.get("claim_id"), str)
        and isinstance(claim.get("evidence_refs"), list)
        and bool(claim["evidence_refs"])
        and all(isinstance(item, str) for item in claim["evidence_refs"])
        and set(claim["evidence_refs"]).issubset(allowed)
        and isinstance(claim.get("certainty"), str)
        for claim in claims
    )


def _synthesis_valid(result: Any) -> bool:
    if not isinstance(result, Mapping):
        return False
    claims = result.get("claims")
    synthesis = result.get("synthesis")
    if not isinstance(claims, list) or not isinstance(synthesis, Mapping):
        return False
    if any(
        not isinstance(claim, Mapping)
        or not isinstance(claim.get("claim_id"), str)
        for claim in claims
    ):
        return False
    synthesis_claim_ids = synthesis.get("claim_ids")
    if not isinstance(synthesis_claim_ids, list) or any(
        not isinstance(item, str) for item in synthesis_claim_ids
    ):
        return False
    claim_ids = {claim["claim_id"] for claim in claims}
    return (
        bool(claim_ids)
        and set(synthesis_claim_ids) == claim_ids
        and isinstance(synthesis.get("uncertainty"), list)
        and bool(synthesis["uncertainty"])
        and "refuse" in str(synthesis.get("clinical_boundary", "")).lower()
    )


def _nested_result_digest_valid(result: Any) -> bool:
    if not isinstance(result, Mapping) or not isinstance(result.get("result_digest"), str):
        return False
    content = {key: value for key, value in result.items() if key != "result_digest"}
    return result["result_digest"] == worker_digest(content)


def _authority_boundary_valid(result: Any) -> bool:
    if not isinstance(result, Mapping):
        return False
    authority = result.get("authority_boundary")
    return (
        isinstance(authority, Mapping)
        and bool(authority)
        and all(value is False for value in authority.values())
        and result.get("release_authorization") is False
        and result.get("preproduction_authorized") is False
        and result.get("production_authorized") is False
    )


def _usage_valid(
    usage: Any, result: Any, candidate: Mapping[str, Any]
) -> bool:
    if not isinstance(usage, Mapping) or not isinstance(result, Mapping):
        return False
    model_usage = result.get("model_usage")
    if not isinstance(model_usage, Mapping):
        return False
    integer_fields = (
        "model_calls",
        "request_attempts",
        "input_tokens",
        "output_tokens",
    )
    if any(
        isinstance(usage.get(name), bool)
        or not isinstance(usage.get(name), int)
        or usage[name] < 0
        for name in integer_fields
    ) or any(
        isinstance(model_usage.get(name), bool)
        or not isinstance(model_usage.get(name), int)
        or model_usage[name] < 0
        for name in ("request_attempts", "input_tokens", "output_tokens")
    ):
        return False
    try:
        usd = Decimal(str(usage.get("cost_usd")))
        cny = Decimal(str(usage.get("cost_cny")))
        usd_limit = Decimal(str(candidate["max_cost_usd"]))
        cny_limit = Decimal(str(candidate["max_cost_cny"]))
    except (InvalidOperation, KeyError):
        return False
    return (
        usage.get("model_calls") == 4
        and usage.get("request_attempts") == model_usage.get("request_attempts")
        and usage.get("input_tokens") == model_usage.get("input_tokens")
        and usage.get("output_tokens") == model_usage.get("output_tokens")
        and usage["request_attempts"] <= candidate["max_model_requests"]
        and usage["input_tokens"] <= candidate["max_input_tokens"]
        and usage["output_tokens"] <= candidate["max_output_tokens"]
        and usd.is_finite()
        and cny.is_finite()
        and Decimal(0) <= usd <= usd_limit
        and Decimal(0) <= cny <= cny_limit
    )


def _stage_result(
    *,
    context: Mapping[str, Any],
    candidate: Mapping[str, Any],
    row: RuntimeRunRow,
    evaluator_class: str,
    component_id: str,
    component_version: str,
    component_digest: str,
    checks: Mapping[str, bool],
) -> StageHandlerResult:
    passed = all(checks.values())
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    report = {
        "evaluation_version": "orbit.disease-r2-provider-evaluation/1",
        "evaluator_class": evaluator_class,
        "subject_result_digest": row.result_digest,
        "checks": dict(checks),
        "verdict": "pass" if passed else "fail",
        "release_authorization": False,
    }
    report_digest = canonical_digest(report)
    reason = (
        f"provider_{evaluator_class}_evaluation_passed"
        if passed
        else f"provider_{evaluator_class}_evaluation_failed"
    )
    return StageHandlerResult(
        observation=StageObservation(
            stage=context["stage"],
            outcome="pass" if passed else "fail",
            failure_class="none" if passed else "deterministic_test_failure",
            reason_codes=(reason,),
            checks=tuple(
                StageCheck(
                    name,
                    "pass" if value else "blocked",
                    None if value else reason,
                    (
                        {
                            "role": f"{evaluator_class}_evaluation",
                            "ref": (
                                f"artifact://control-plane/runtime/{row.run_id}/"
                                f"{evaluator_class}-evaluation"
                            ),
                            "digest": report_digest,
                        },
                    ),
                )
                for name, value in checks.items()
            ),
            inputs=(
                {
                    "role": "result_package",
                    "ref": f"artifact://control-plane/runtime/{row.run_id}/result",
                    "digest": row.result_digest,
                },
            ),
            executor={
                "component": {
                    "id": component_id,
                    "version": component_version,
                    "digest": component_digest,
                },
                "deterministic": True,
                "environment_profile_digest": candidate["isolation_profile_digest"],
            },
            side_effects=StageSideEffects(),
            started_at=now,
            completed_at=now,
        )
    )

