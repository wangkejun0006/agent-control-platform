"""Failure disposition for the governed release automation loop.

The supervisor separates an execution stop from a human authorization
checkpoint.  A failed attempt always closes.  Engineering repair may continue
inside the approved AutomationPolicy, while scope, safety and budget changes
remain human decisions.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ..ids import deterministic_id
from ..qualification.automation import canonical_digest
from .database import Database
from .models import (
    AuditEventRow,
    AutomationSupervisorEventRow,
    OutboxEventRow,
)
from .repositories import ServiceRepositoryError

_AUTO_REMEDIABLE_REASONS = frozenset(
    {
        "r2_literature_query_invalid",
        "r2_query_plan_invalid",
        "r2_gateway_response_invalid",
        "r2_worker_result_invalid",
        "dataset_runtime_dependency_import_failed",
        "dataset_execution_closure_rejected",
        "dataset_signed_execution_grant_missing",
        "dataset_execution_result_binding_invalid",
    }
)
_AUTHORITY_STRENGTHENING_REASONS = frozenset(
    {"dataset_signed_execution_grant_missing"}
)
_TRANSIENT_MARKERS = (
    "timeout",
    "rate_limit",
    "http_429",
    "http_5",
    "connection",
    "temporarily_unavailable",
)
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class FailureContext:
    reason_code: str
    failure_class: str
    identical_failures: int = 1
    verified_remediation_cycles: int = 0
    total_attempts: int = 1
    max_total_attempts: int = 1
    budget_remaining: bool = True
    boundary_drift: bool = False
    secret_or_physical_path_exposed: bool = False
    forbidden_external_side_effect: bool = False


@dataclass(frozen=True)
class AutomationDisposition:
    action: str
    stop_current_attempt: bool
    human_checkpoint_required: bool
    human_checkpoint_scope: str | None
    reason_codes: tuple[str, ...]
    required_evidence: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        value = asdict(self)
        value["reason_codes"] = list(self.reason_codes)
        value["required_evidence"] = list(self.required_evidence)
        return value


class AutomationSupervisor:
    """Classify failures without converting attention into human approval."""

    def __init__(self, store: AutomationSupervisorStore | None = None) -> None:
        self.store = store

    @staticmethod
    def classify(context: FailureContext) -> AutomationDisposition:
        _validate_context(context)
        if context.secret_or_physical_path_exposed:
            return _human(
                "risk_waiver",
                "secret_or_physical_path_exposure",
            )
        if context.forbidden_external_side_effect:
            return _human("risk_waiver", "forbidden_external_side_effect")
        if context.boundary_drift or context.failure_class in {
            "policy_boundary",
            "unexplained_drift",
        }:
            return _human("execution_approval", "approved_scope_drift")
        if not context.budget_remaining or (
            context.total_attempts >= context.max_total_attempts
        ):
            return _human("risk_waiver", "pilot_budget_or_attempt_ceiling_reached")
        if context.failure_class == "transient_runtime" or any(
            marker in context.reason_code for marker in _TRANSIENT_MARKERS
        ):
            return AutomationDisposition(
                action="auto_retry",
                stop_current_attempt=True,
                human_checkpoint_required=False,
                human_checkpoint_scope=None,
                reason_codes=(context.reason_code, "transient_retry_allowed"),
                required_evidence=(
                    "closed_predecessor_attempt",
                    "remaining_budget_proof",
                ),
            )
        if (
            context.reason_code in _AUTO_REMEDIABLE_REASONS
            or context.failure_class
            in {
                "engineering_compatibility",
                "deterministic_test_failure",
                "quality_candidate_revision",
            }
        ):
            if (
                context.identical_failures >= 2
                and context.verified_remediation_cycles >= 2
            ):
                return _human(
                    "risk_waiver",
                    "verified_remediation_repeatedly_failed",
                )
            evidence = [
                "immutable_predecessor_failure",
                "same_runtime_family_source_lock",
                "unchanged_authority_boundaries",
                "offline_regression_pass",
            ]
            action = "auto_remediate"
            if context.reason_code in _AUTHORITY_STRENGTHENING_REASONS:
                action = "auto_remediate_authority_strengthening"
                evidence.extend(
                    (
                        "signed_grant_persisted_before_network",
                        "worker_lease_terminal_closure",
                    )
                )
            if context.identical_failures >= 2:
                action = "automation_pause_for_verified_remediation"
            return AutomationDisposition(
                action=action,
                stop_current_attempt=True,
                human_checkpoint_required=False,
                human_checkpoint_scope=None,
                reason_codes=(context.reason_code, "machine_remediation_allowed"),
                required_evidence=tuple(evidence),
            )
        return AutomationDisposition(
            action="automation_pause_for_classification",
            stop_current_attempt=True,
            human_checkpoint_required=False,
            human_checkpoint_scope=None,
            reason_codes=(context.reason_code, "failure_classification_required"),
            required_evidence=(
                "immutable_predecessor_failure",
                "sanitized_failure_observation",
            ),
        )

    def observe_failure(self, **values: Any) -> dict[str, Any]:
        if self.store is None:
            raise ValueError("automation_supervisor_store_unconfigured")
        return self.store.record_failure(supervisor=self, **values)

    def record_verified_remediation(self, **values: Any) -> dict[str, Any]:
        if self.store is None:
            raise ValueError("automation_supervisor_store_unconfigured")
        return self.store.record_verified_remediation(**values)

    def record_success(self, **values: Any) -> dict[str, Any]:
        if self.store is None:
            raise ValueError("automation_supervisor_store_unconfigured")
        return self.store.record_success(**values)

    def status(self, scope_ref: str) -> dict[str, Any]:
        if self.store is None:
            raise ValueError("automation_supervisor_store_unconfigured")
        return self.store.status(scope_ref)


class AutomationSupervisorStore:
    """Durable cross-run supervision history for one approved execution scope."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def record_verified_remediation(
        self,
        *,
        scope_ref: str,
        remediation_digest: str,
        runtime_source_digest: str,
        regression_evidence_digest: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        payload = {
            "remediation_digest": remediation_digest,
            "runtime_source_digest": runtime_source_digest,
            "regression_evidence_digest": regression_evidence_digest,
            "same_runtime_family": True,
            "authority_boundaries_unchanged": True,
            "release_authorization": False,
        }
        self._append(
            scope_ref=scope_ref,
            event_type="verified_remediation",
            idempotency_key=idempotency_key,
            payload=payload,
        )
        return self.status(scope_ref)

    def record_failure(
        self,
        *,
        supervisor: AutomationSupervisor,
        scope_ref: str,
        attempt_ref: str,
        failure_fingerprint: str,
        reason_code: str,
        failure_class: str,
        failure_evidence_digest: str,
        total_attempts: int,
        max_total_attempts: int,
        budget_remaining: bool,
        idempotency_key: str,
        boundary_drift: bool = False,
        secret_or_physical_path_exposed: bool = False,
        forbidden_external_side_effect: bool = False,
    ) -> dict[str, Any]:
        current = self.status(scope_ref)
        previous = current.get("last_failure")
        identical = (
            int(previous["identical_failures"]) + 1
            if isinstance(previous, dict)
            and previous.get("failure_fingerprint") == failure_fingerprint
            else 1
        )
        context = FailureContext(
            reason_code=reason_code,
            failure_class=failure_class,
            identical_failures=identical,
            verified_remediation_cycles=current["verified_remediation_cycles"],
            total_attempts=total_attempts,
            max_total_attempts=max_total_attempts,
            budget_remaining=budget_remaining,
            boundary_drift=boundary_drift,
            secret_or_physical_path_exposed=secret_or_physical_path_exposed,
            forbidden_external_side_effect=forbidden_external_side_effect,
        )
        disposition = supervisor.classify(context)
        payload = {
            "attempt_ref": attempt_ref,
            "failure_fingerprint": failure_fingerprint,
            "reason_code": reason_code,
            "failure_class": failure_class,
            "failure_evidence_digest": failure_evidence_digest,
            "identical_failures": identical,
            "verified_remediation_cycles": current["verified_remediation_cycles"],
            "total_attempts": total_attempts,
            "max_total_attempts": max_total_attempts,
            "budget_remaining": budget_remaining,
            "disposition": disposition.to_mapping(),
            "release_authorization": False,
        }
        self._append(
            scope_ref=scope_ref,
            event_type="failure_observed",
            idempotency_key=idempotency_key,
            payload=payload,
        )
        return self.status(scope_ref)

    def record_success(
        self,
        *,
        scope_ref: str,
        attempt_ref: str,
        result_evidence_digest: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._append(
            scope_ref=scope_ref,
            event_type="execution_succeeded",
            idempotency_key=idempotency_key,
            payload={
                "attempt_ref": attempt_ref,
                "result_evidence_digest": result_evidence_digest,
                "release_authorization": False,
            },
        )
        return self.status(scope_ref)

    def status(self, scope_ref: str) -> dict[str, Any]:
        _validate_scope_ref(scope_ref)
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(AutomationSupervisorEventRow)
                    .where(AutomationSupervisorEventRow.scope_ref == scope_ref)
                    .order_by(AutomationSupervisorEventRow.sequence)
                )
            )
        verified = sum(row.event_type == "verified_remediation" for row in rows)
        failures = [row for row in rows if row.event_type == "failure_observed"]
        succeeded = any(row.event_type == "execution_succeeded" for row in rows)
        last_failure = dict(failures[-1].payload) if failures else None
        disposition = last_failure.get("disposition") if last_failure else None
        checkpoint = (
            disposition.get("human_checkpoint_scope")
            if isinstance(disposition, dict)
            and disposition.get("human_checkpoint_required") is True
            else None
        )
        return {
            "scope_ref": scope_ref,
            "revision": len(rows),
            "status": (
                "completed"
                if succeeded
                else "human_checkpoint"
                if checkpoint is not None
                else "remediation_verified_awaiting_attempt"
                if rows and rows[-1].event_type == "verified_remediation"
                else "failure_observed"
                if last_failure is not None
                else "not_started"
            ),
            "verified_remediation_cycles": verified,
            "failure_events": len(failures),
            "last_failure": last_failure,
            "next_automation_action": disposition,
            "next_human_checkpoint": checkpoint,
            "event_digests": [row.event_digest for row in rows],
            "authority_claim": "none",
            "release_authorization": False,
        }

    def _append(
        self,
        *,
        scope_ref: str,
        event_type: str,
        idempotency_key: str,
        payload: Mapping[str, Any],
    ) -> bool:
        _validate_scope_ref(scope_ref)
        if (
            event_type
            not in {"verified_remediation", "failure_observed", "execution_succeeded"}
            or not 8 <= len(idempotency_key) <= 192
        ):
            raise ServiceRepositoryError("automation_supervisor_event_invalid")
        _validate_event_payload(event_type, payload)
        with self.database.session() as session:
            existing = session.scalar(
                select(AutomationSupervisorEventRow).where(
                    AutomationSupervisorEventRow.idempotency_key == idempotency_key
                )
            )
            if existing is not None:
                expected = canonical_digest(
                    {
                        "scope_ref": scope_ref,
                        "sequence": existing.sequence,
                        "event_type": event_type,
                        "payload": dict(payload),
                    }
                )
                if existing.event_digest != expected:
                    raise ServiceRepositoryError(
                        "automation_supervisor_idempotency_conflict"
                    )
                return False
            last = session.scalar(
                select(AutomationSupervisorEventRow)
                .where(AutomationSupervisorEventRow.scope_ref == scope_ref)
                .order_by(AutomationSupervisorEventRow.sequence.desc())
                .limit(1)
                .with_for_update()
            )
            if last is not None:
                last_disposition = last.payload.get("disposition")
                if last.event_type == "execution_succeeded" or (
                    isinstance(last_disposition, dict)
                    and last_disposition.get("human_checkpoint_required") is True
                ):
                    raise ServiceRepositoryError(
                        "automation_supervisor_scope_terminal"
                    )
            sequence = 0 if last is None else last.sequence + 1
            event_document = {
                "scope_ref": scope_ref,
                "sequence": sequence,
                "event_type": event_type,
                "payload": dict(payload),
            }
            event_digest = canonical_digest(event_document)
            recorded_at = datetime.now(timezone.utc)
            session.add(
                AutomationSupervisorEventRow(
                    scope_ref=scope_ref,
                    sequence=sequence,
                    event_type=event_type,
                    idempotency_key=idempotency_key,
                    event_digest=event_digest,
                    payload=dict(payload),
                    recorded_at=recorded_at,
                )
            )
            session.add(
                AuditEventRow(
                    audit_id=deterministic_id("audit", event_digest),
                    correlation_id=deterministic_id("supervision", scope_ref),
                    event_type=f"automation_supervisor_{event_type}",
                    actor_ref="component_governed_release_pipeline",
                    payload={
                        "scope_ref": scope_ref,
                        "event_digest": event_digest,
                        "release_authorization": False,
                    },
                    recorded_at=recorded_at,
                )
            )
            session.add(
                OutboxEventRow(
                    event_id=deterministic_id("outbox", event_digest),
                    topic=f"automation.supervisor.{event_type}",
                    aggregate_ref=scope_ref,
                    payload={
                        "event_digest": event_digest,
                        "release_authorization": False,
                    },
                    status="pending",
                    attempts=0,
                    created_at=recorded_at,
                    published_at=None,
                )
            )
            try:
                session.flush()
            except IntegrityError as error:
                raise ServiceRepositoryError(
                    "automation_supervisor_concurrent_append"
                ) from error
        return True


def _human(scope: str, reason: str) -> AutomationDisposition:
    return AutomationDisposition(
        action="human_checkpoint",
        stop_current_attempt=True,
        human_checkpoint_required=True,
        human_checkpoint_scope=scope,
        reason_codes=(reason,),
        required_evidence=("immutable_predecessor_failure",),
    )


def _validate_context(context: FailureContext) -> None:
    if (
        not context.reason_code
        or not context.failure_class
        or context.identical_failures < 1
        or context.verified_remediation_cycles < 0
        or context.total_attempts < 1
        or context.max_total_attempts < 1
    ):
        raise ValueError("automation_failure_context_invalid")


def _validate_scope_ref(scope_ref: str) -> None:
    if (
        not isinstance(scope_ref, str)
        or not 8 <= len(scope_ref) <= 240
        or "://" not in scope_ref
        or any(character.isspace() for character in scope_ref)
    ):
        raise ServiceRepositoryError("automation_supervisor_scope_invalid")


def _validate_event_payload(event_type: str, payload: Mapping[str, Any]) -> None:
    if payload.get("release_authorization") is not False:
        raise ServiceRepositoryError("automation_supervisor_event_invalid")
    digest_fields = {
        "verified_remediation": (
            "remediation_digest",
            "runtime_source_digest",
            "regression_evidence_digest",
        ),
        "failure_observed": ("failure_evidence_digest",),
        "execution_succeeded": ("result_evidence_digest",),
    }[event_type]
    if any(
        not isinstance(payload.get(name), str)
        or _DIGEST.fullmatch(payload[name]) is None
        for name in digest_fields
    ):
        raise ServiceRepositoryError("automation_supervisor_event_invalid")
    if event_type == "verified_remediation":
        if (
            payload.get("same_runtime_family") is not True
            or payload.get("authority_boundaries_unchanged") is not True
        ):
            raise ServiceRepositoryError("automation_supervisor_event_invalid")
    elif event_type == "failure_observed":
        if (
            not isinstance(payload.get("attempt_ref"), str)
            or not isinstance(payload.get("failure_fingerprint"), str)
            or _DIGEST.fullmatch(payload["failure_fingerprint"]) is None
            or not isinstance(payload.get("reason_code"), str)
            or _SAFE_CODE.fullmatch(payload["reason_code"]) is None
            or not isinstance(payload.get("failure_class"), str)
            or _SAFE_CODE.fullmatch(payload["failure_class"]) is None
            or not isinstance(payload.get("disposition"), dict)
        ):
            raise ServiceRepositoryError("automation_supervisor_event_invalid")
    elif not isinstance(payload.get("attempt_ref"), str):
        raise ServiceRepositoryError("automation_supervisor_event_invalid")

