"""Aggregated user view for the governed release qualification pipeline.

Internal Task, Grant, Lease, policy and receipt objects remain independent and
auditable.  This projection intentionally presents one Pilot stage, budget,
attempt history, next checkpoint and terminal result to the local operator.
It does not create approval intent or promote an Agent release.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

from sqlalchemy import select

from ..qualification.automation import BOUNDARY_NAMES, QualificationCandidate
from ..qualification.ledger import QualificationLedgerError
from .automation_supervisor import AutomationSupervisor, FailureContext
from .database import Database
from .models import RuntimeRunRow


class QualificationStoreView(Protocol):
    def replay(self): ...


class QualificationReconcilerView(Protocol):
    def run_until_checkpoint(self, run_id: str): ...


class ModelRoutePreflightView(Protocol):
    def deploy_preflight(self, route_id: str) -> dict[str, Any]: ...


@dataclass(frozen=True)
class PilotBudget:
    max_attempts: int = 3
    max_cost_usd: Decimal = Decimal("0.60")
    max_cost_cny: Decimal = Decimal("4.50")


class GovernedReleasePipeline:
    """Read-model and remediation guard for one approved Pilot envelope."""

    def __init__(
        self,
        *,
        database: Database,
        qualification_store: QualificationStoreView,
        model_route_reconciler: ModelRoutePreflightView | None = None,
        automation_supervisor: AutomationSupervisor | None = None,
        budget: PilotBudget | None = None,
    ) -> None:
        self.database = database
        self.qualification_store = qualification_store
        self.model_route_reconciler = model_route_reconciler
        self.automation_supervisor = automation_supervisor or AutomationSupervisor()
        self.budget = budget or PilotBudget()

    def deploy_preflight(
        self,
        *,
        route_id: str,
        expected_snapshot_digest: str,
    ) -> dict[str, Any]:
        """Require one exact ready Model Route snapshot before effective state."""
        if self.model_route_reconciler is None:
            raise ValueError("governed_pipeline_model_route_preflight_unconfigured")
        result = dict(self.model_route_reconciler.deploy_preflight(route_id))
        reasons = result.get("reason_codes")
        if (
            result.get("status") != "ready"
            or result.get("snapshot_digest") != expected_snapshot_digest
        ):
            reason = (
                reasons[0]
                if isinstance(reasons, list) and reasons
                else "model_route_snapshot_binding_invalid"
            )
            raise ValueError(f"governed_pipeline_model_route_preflight_blocked:{reason}")
        return {
            "route_id": route_id,
            "snapshot_digest": expected_snapshot_digest,
            "status": "ready",
            "provider_execution_started": False,
            "release_authorization": False,
        }

    def status(self, qualification_run_id: str) -> dict[str, Any]:
        try:
            state = self.qualification_store.replay().run(qualification_run_id)
        except QualificationLedgerError as error:
            raise ValueError("governed_pipeline_run_not_found") from error
        runtime_rows = self._runtime_rows(qualification_run_id)
        provider_attempts = sum(
            row.invocation.get("operation") == "run_public_r2_provider_attempt"
            for row in runtime_rows
        )
        usage = self._usage(state.execution_closures)
        next_checkpoint = self._next_checkpoint(
            qualification_status=state.status,
            explicit_scope=state.next_checkpoint_scope,
            total_attempts=provider_attempts,
            cost_usd=usage["cost_usd"],
            cost_cny=usage["cost_cny"],
        )
        next_automation_action = self._next_automation_action(
            state=state,
            provider_attempts=provider_attempts,
            cost_usd=usage["cost_usd"],
            cost_cny=usage["cost_cny"],
        )
        return {
            "pilot_id": qualification_run_id,
            "stage": state.current_stage,
            "status": state.status,
            "current_attempt": {
                "attempt_id": state.candidate.attempt_id,
                "attempt_number": state.candidate.attempt_number,
                "runtime_family": state.candidate.runtime_family,
            },
            "attempts_consumed": provider_attempts,
            "attempts_ceiling": self.budget.max_attempts,
            "budget": {
                "input_tokens": usage["input_tokens"],
                "output_tokens": usage["output_tokens"],
                "model_calls": usage["model_calls"],
                "request_attempts": usage["request_attempts"],
                "cost_usd": format(usage["cost_usd"], "f"),
                "cost_cny": format(usage["cost_cny"], "f"),
                "max_cost_usd": format(self.budget.max_cost_usd, "f"),
                "max_cost_cny": format(self.budget.max_cost_cny, "f"),
            },
            "runtime_runs": [self._runtime_projection(row) for row in runtime_rows],
            "automatic_remediation_history": [
                {
                    "receipt_id": item.document["metadata"]["receipt_id"],
                    "receipt_digest": item.digest,
                    "predecessor": item.document["spec"]["predecessor"][
                        "attempt_id"
                    ],
                    "successor": item.document["spec"]["successor"]["attempt_id"],
                }
                for item in state.remediation_receipts
            ],
            "receipt_set": {
                "policy_decisions": [item.digest for item in state.policy_decisions],
                "stage_receipts": [item.digest for item in state.stage_receipts],
                "remediation_receipts": [
                    item.digest for item in state.remediation_receipts
                ],
                "execution_closures": [
                    item.digest for item in state.execution_closures
                ],
            },
            "next_human_checkpoint": next_checkpoint,
            "next_automation_action": next_automation_action,
            "production_authorization": False,
            "release_authorization": False,
        }

    def advance_until_checkpoint(
        self,
        *,
        qualification_run_id: str,
        reconciler: QualificationReconcilerView,
    ):
        """Advance automatically only while the approved Pilot envelope holds."""
        projection = self.status(qualification_run_id)
        checkpoint = projection["next_human_checkpoint"]
        if checkpoint is not None:
            raise ValueError(f"governed_pipeline_checkpoint:{checkpoint}")
        if projection["attempts_consumed"] > self.budget.max_attempts:
            raise ValueError("governed_pipeline_attempt_budget_exhausted")
        return reconciler.run_until_checkpoint(qualification_run_id)

    def remediation_allowed(
        self,
        *,
        predecessor: QualificationCandidate,
        successor: QualificationCandidate,
        failure_class: str,
        attempts_consumed: int,
        verified_source_change: bool = False,
    ) -> tuple[bool, str]:
        if attempts_consumed >= self.budget.max_attempts:
            return False, "pilot_attempt_budget_exhausted"
        if failure_class not in {
            "engineering_compatibility",
            "deterministic_test_failure",
            "transient_runtime",
            "quality_candidate_revision",
        }:
            return False, "pilot_failure_requires_human_checkpoint"
        if (
            successor.attempt_number != predecessor.attempt_number + 1
            or successor.attempt_id == predecessor.attempt_id
            or successor.runtime_family != predecessor.runtime_family
            or successor.runtime_source_digest == predecessor.runtime_source_digest
        ):
            return False, "pilot_successor_attempt_invalid"
        if any(
            predecessor.boundary_digests[name] != successor.boundary_digests[name]
            for name in BOUNDARY_NAMES
        ):
            return False, "pilot_scope_change_requires_human_checkpoint"
        if (
            failure_class != "transient_runtime"
            and not verified_source_change
        ):
            return False, "pilot_verified_source_change_missing"
        return True, "same_runtime_family_remediation_allowed"

    def failure_disposition(
        self,
        *,
        reason_code: str,
        failure_class: str,
        identical_failures: int,
        verified_remediation_cycles: int,
        total_attempts: int,
        boundary_drift: bool = False,
        secret_or_physical_path_exposed: bool = False,
        forbidden_external_side_effect: bool = False,
    ) -> dict[str, Any]:
        """Return the operator disposition without creating authority."""
        return self.automation_supervisor.classify(
            FailureContext(
                reason_code=reason_code,
                failure_class=failure_class,
                identical_failures=identical_failures,
                verified_remediation_cycles=verified_remediation_cycles,
                total_attempts=total_attempts,
                max_total_attempts=self.budget.max_attempts,
                budget_remaining=total_attempts < self.budget.max_attempts,
                boundary_drift=boundary_drift,
                secret_or_physical_path_exposed=secret_or_physical_path_exposed,
                forbidden_external_side_effect=forbidden_external_side_effect,
            )
        ).to_mapping()

    def _runtime_rows(self, qualification_run_id: str) -> tuple[RuntimeRunRow, ...]:
        with self.database.session() as session:
            rows = tuple(
                session.scalars(select(RuntimeRunRow).order_by(RuntimeRunRow.id))
            )
        prefix = f"qualification:{qualification_run_id}:"
        return tuple(
            row
            for row in rows
            if str(row.invocation.get("idempotency_key", "")).startswith(prefix)
        )

    def _next_checkpoint(
        self,
        *,
        qualification_status: str,
        explicit_scope: str | None,
        total_attempts: int,
        cost_usd: Decimal,
        cost_cny: Decimal,
    ) -> str | None:
        if explicit_scope is not None:
            return explicit_scope
        if cost_usd >= self.budget.max_cost_usd or cost_cny >= self.budget.max_cost_cny:
            return "pilot_budget_expansion"
        if total_attempts >= self.budget.max_attempts and qualification_status != "completed":
            return "pilot_attempt_budget_exhausted"
        if qualification_status in {"failed", "quarantined"}:
            return "risk_or_scope_exception"
        return None

    def _next_automation_action(
        self,
        *,
        state,
        provider_attempts: int,
        cost_usd: Decimal,
        cost_cny: Decimal,
    ) -> dict[str, Any] | None:
        if state.status != "remediating" or state.last_stage_receipt is None:
            return None
        decision = state.last_stage_receipt.document["spec"]["decision"]
        reasons = tuple(decision["reason_codes"])
        reason_code = reasons[-1]
        identical = sum(
            tuple(item.document["spec"]["decision"]["reason_codes"])[-1]
            == reason_code
            for item in state.stage_receipts
            if item.document["spec"]["decision"]["reason_codes"]
        )
        disposition = self.automation_supervisor.classify(
            FailureContext(
                reason_code=reason_code,
                failure_class=decision["failure_class"],
                identical_failures=identical,
                verified_remediation_cycles=len(state.remediation_receipts),
                total_attempts=max(1, provider_attempts),
                max_total_attempts=self.budget.max_attempts,
                budget_remaining=(
                    provider_attempts < self.budget.max_attempts
                    and cost_usd < self.budget.max_cost_usd
                    and cost_cny < self.budget.max_cost_cny
                ),
            )
        )
        return disposition.to_mapping()

    @staticmethod
    def _usage(closures) -> dict[str, Any]:
        result: dict[str, Any] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "model_calls": 0,
            "request_attempts": 0,
            "cost_usd": Decimal(0),
            "cost_cny": Decimal(0),
        }
        for closure in closures:
            usage = closure.document["spec"]["usage"]
            for name in (
                "input_tokens",
                "output_tokens",
                "model_calls",
                "request_attempts",
            ):
                result[name] += int(usage[name])
            result["cost_usd"] += Decimal(usage["cost_usd"])
            result["cost_cny"] += Decimal(usage["cost_cny"])
        return result

    @staticmethod
    def _runtime_projection(row: RuntimeRunRow) -> dict[str, Any]:
        return {
            "run_id": row.run_id,
            "status": row.status,
            "worker_identity": row.worker_identity,
            "result_digest": row.result_digest,
            "failure_reason_code": row.failure_reason_code,
            "revision": row.revision,
        }

