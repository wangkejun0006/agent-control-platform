"""Company Control Plane console governance services.

The service keeps resource approval, current health, catalog eligibility, and
Task Execution Grant state independent.  It never edits or approves a
department Task and never reads provider secret bytes.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import select

from ..ids import deterministic_id
from ..qualification.automation import canonical_digest
from .control_console_models import (
    ControlConsoleCommandRow,
    ModelRouteDecisionRow,
    TaskScopeAuditRow,
)
from .database import Database
from .model_catalog import ModelCatalogService
from .model_route import (
    ModelRouteError,
    ModelRouteReconciler,
    _as_utc,
    _route_audit_references,
    _route_document,
)
from .model_route_credentials import ModelRouteCredentialService
from .models import (
    AuditEventRow,
    DepartmentCockpitObjectRow,
    ModelRouteRevisionRow,
    ModelRouteSnapshotRow,
    OutboxEventRow,
    ReceiptRow,
)
from .repositories import ServiceRepositoryError, SqlGrantRevocationRegistry

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{8,192}$")
_SAFE_ID = re.compile(r"^[a-z][A-Za-z0-9_:-]{2,159}$")
_ROLE = "role_control_plane_admin"


class ControlConsoleError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class ControlConsoleService:
    """Durable D0 implementation of the first company-console vertical slice."""

    def __init__(
        self,
        *,
        database: Database,
        model_routes: ModelRouteReconciler,
        grant_revocations: SqlGrantRevocationRegistry,
        credentials: ModelRouteCredentialService | None = None,
        model_catalog: ModelCatalogService | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.database = database
        self.model_routes = model_routes
        self.grant_revocations = grant_revocations
        self.credentials = credentials
        self.model_catalog = model_catalog
        self.now = now or _utcnow

    def _catalog(self) -> ModelCatalogService:
        if self.model_catalog is None:
            raise ControlConsoleError("model_catalog_unavailable")
        return self.model_catalog

    def list_model_provider_presets(self) -> dict[str, Any]:
        return self._catalog().list_provider_presets()

    def discover_provider_models(self, **values: Any) -> dict[str, Any]:
        return self._catalog().discover_provider_models(**values)

    def submit_provider_onboarding(self, **values: Any) -> dict[str, Any]:
        return self._catalog().submit_provider_onboarding(**values)

    def list_provider_onboarding(self):
        return self._catalog().list_provider_onboarding()

    def review_provider_onboarding(self, **values):
        return self._catalog().review_provider_onboarding(**values)

    def list_model_catalog_entries(self) -> dict[str, Any]:
        return self._catalog().list_catalog_entries()

    def create_model_catalog_entry(self, **values: Any) -> dict[str, Any]:
        return self._catalog().create_catalog_entry(**values)

    def bind_model_catalog_credential(self, **values: Any) -> dict[str, Any]:
        return self._catalog().bind_catalog_credential(**values)

    def qualify_model_catalog_api_key(
        self,
        *,
        entry_id: str,
        expected_entry_revision_digest: str,
        expected_binding_version: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        return self._catalog().qualify_catalog_api_key(
            entry_id=entry_id, expected_entry_revision_digest=expected_entry_revision_digest,
            expected_binding_version=expected_binding_version, idempotency_key=idempotency_key,
            actor_ref=actor_ref,
        )

    def publish_model_catalog_entry(self, **values: Any) -> dict[str, Any]:
        return self._catalog().publish_catalog_entry(**values)

    def retire_model_catalog_entry(self, **values: Any) -> dict[str, Any]:
        return self._catalog().retire_catalog_entry(**values)

    def list_agent_route_reviews(self) -> dict[str, Any]:
        return self._catalog().list_agent_route_reviews()

    def decide_agent_activation(self, **values: Any) -> dict[str, Any]:
        return self._catalog().decide_agent_activation(**values)

    # ---- Model Route reads -------------------------------------------------

    def list_model_routes(self) -> dict[str, Any]:
        with self.database.session() as session:
            route_ids = tuple(
                session.scalars(
                    select(ModelRouteRevisionRow.route_id)
                    .distinct()
                    .order_by(ModelRouteRevisionRow.route_id)
                )
            )
        return {
            "items": [self._route_summary(route_id) for route_id in route_ids],
            "resource_states_are_independent": True,
            "release_authorization": False,
        }

    def bind_model_route_api_key(self, **values: Any) -> dict[str, Any]:
        if self.credentials is None:
            raise ControlConsoleError("model_route_credentials_unavailable")
        return self.credentials.qualify_api_key_binding(**values)

    def request_model_route_account_login(self, **values: Any) -> dict[str, Any]:
        if self.credentials is None:
            raise ControlConsoleError("model_route_credentials_unavailable")
        return self.credentials.request_account_login(**values)

    def retire_model_route(
        self, *, route_id: str, expected_revision_digest: str, reason: str,
        idempotency_key: str, actor_ref: str,
    ) -> dict[str, Any]:
        if self.credentials is None:
            raise ControlConsoleError("model_route_credentials_unavailable")
        approval = self._approval_projection(route_id, expected_revision_digest)
        return self.credentials.retire(
            route_id=route_id,
            expected_revision_digest=expected_revision_digest,
            reason=reason,
            idempotency_key=idempotency_key,
            actor_ref=actor_ref,
            approval_status=str(approval["approval_status"]),
        )

    def model_route_revision(
        self, *, route_id: str, revision_digest: str
    ) -> dict[str, Any]:
        row = self._route_revision(route_id, revision_digest)
        return {
            "revision": self._route_public_revision(row),
            "revision_digest": row.revision_digest,
            "governance": self._approval_projection(route_id, revision_digest),
            "health": self._health_for_revision(route_id, revision_digest),
            "release_authorization": False,
        }

    def model_route_evidence(self, *, route_id: str) -> dict[str, Any]:
        with self.database.session() as session:
            revisions = tuple(
                session.scalars(
                    select(ModelRouteRevisionRow)
                    .where(ModelRouteRevisionRow.route_id == route_id)
                    .order_by(ModelRouteRevisionRow.id)
                )
            )
            decisions = tuple(
                session.scalars(
                    select(ModelRouteDecisionRow)
                    .where(ModelRouteDecisionRow.route_id == route_id)
                    .order_by(ModelRouteDecisionRow.id)
                )
            )
            receipt_ids = [row.receipt_id for row in decisions]
            receipts = (
                ()
                if not receipt_ids
                else tuple(
                    session.scalars(
                        select(ReceiptRow)
                        .where(ReceiptRow.receipt_id.in_(receipt_ids))
                        .order_by(ReceiptRow.id)
                    )
                )
            )
            snapshots = tuple(
                session.scalars(
                    select(ModelRouteSnapshotRow)
                    .where(ModelRouteSnapshotRow.route_id == route_id)
                    .order_by(ModelRouteSnapshotRow.id)
                )
            )
            audits = tuple(
                session.scalars(
                    select(AuditEventRow)
                    .where(AuditEventRow.correlation_id == route_id)
                    .order_by(AuditEventRow.id)
                )
            )
        if not revisions:
            raise ControlConsoleError("model_route_not_found")
        return {
            "route_id": route_id,
            "revisions": [
                {
                    "revision_digest": row.revision_digest,
                    "document": self._route_public_revision(row),
                    "created_at": _time_text(row.created_at),
                }
                for row in revisions
            ],
            "decisions": [self._decision_public(row) for row in decisions],
            "receipts": [
                {
                    "receipt_id": row.receipt_id,
                    "receipt_type": row.receipt_type,
                    "receipt_digest": row.receipt_digest,
                    "subject_ref": row.subject_ref,
                    "document": row.document,
                    "recorded_at": _time_text(row.recorded_at),
                }
                for row in receipts
            ],
            "snapshots": [
                {
                    **self._snapshot_public(row),
                    "snapshot_digest": row.snapshot_digest,
                    "created_at": _time_text(row.created_at),
                }
                for row in snapshots
            ],
            "audit_events": [
                {
                    "audit_id": row.audit_id,
                    "event_type": row.event_type,
                    "actor_ref": row.actor_ref,
                    "payload": row.payload,
                    "recorded_at": _time_text(row.recorded_at),
                }
                for row in audits
            ],
            "release_authorization": False,
        }

    # ---- Model Route mutations --------------------------------------------

    def submit_model_route_candidate(
        self,
        *,
        document: Mapping[str, Any],
        expected_latest_revision_digest: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        command = self._command(
            "model_route_candidate_submit",
            f"model-route://{document.get('route_id', 'invalid')}",
            {
                "document": dict(document),
                "expected_latest_revision_digest": expected_latest_revision_digest,
                "reason": reason,
            },
            idempotency_key,
        )
        if command is not None:
            return command
        self._validate_actor(actor_ref)
        self._validate_reason(reason)
        route_id = str(document.get("route_id", ""))
        latest = self.model_routes.store.latest_route(route_id)
        actual = "none" if latest is None else latest.revision_digest
        if expected_latest_revision_digest != actual:
            raise ControlConsoleError("model_route_expected_revision_drift")
        digest, appended = self.model_routes.store.record_route(document)
        response = {
            "route_id": route_id,
            "revision_digest": digest,
            "candidate_status": "recorded",
            "appended": appended,
            "approval_status": "not_reviewed",
            "eligible": False,
            "release_authorization": False,
        }
        self._record_command_and_audit(
            command_kind="model_route_candidate_submit",
            target_ref=f"model-route://{route_id}/{digest}",
            request={
                "document": dict(document),
                "expected_latest_revision_digest": expected_latest_revision_digest,
                "reason": reason,
            },
            idempotency_key=idempotency_key,
            response=response,
            actor_ref=actor_ref,
            event_type="model_route_candidate_recorded",
        )
        return response

    def record_provider_observation(
        self,
        *,
        route_id: str,
        expected_revision_digest: str,
        document: Mapping[str, Any],
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        request = {
            "route_id": route_id,
            "expected_revision_digest": expected_revision_digest,
            "document": dict(document),
            "reason": reason,
        }
        replay = self._command(
            "provider_observation_record", f"model-route://{route_id}", request,
            idempotency_key,
        )
        if replay is not None:
            return replay
        self._validate_actor(actor_ref)
        self._validate_reason(reason)
        route = self._expect_latest(route_id, expected_revision_digest)
        if (
            document.get("provider") != route.provider
            or document.get("requested_model") != route.requested_model
        ):
            raise ControlConsoleError("provider_observation_route_mismatch")
        digest, appended = self.model_routes.store.record_observation(document)
        response = {
            "route_id": route_id,
            "route_revision_digest": route.revision_digest,
            "observation_digest": digest,
            "appended": appended,
            "release_authorization": False,
        }
        self._record_command_and_audit(
            command_kind="provider_observation_record",
            target_ref=f"model-route://{route_id}",
            request=request,
            idempotency_key=idempotency_key,
            response=response,
            actor_ref=actor_ref,
            event_type="provider_observation_recorded",
        )
        return response

    def reconcile_model_route(
        self,
        *,
        route_id: str,
        expected_revision_digest: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        request = {
            "route_id": route_id,
            "expected_revision_digest": expected_revision_digest,
            "reason": reason,
        }
        replay = self._command(
            "model_route_reconcile", f"model-route://{route_id}", request,
            idempotency_key,
        )
        if replay is not None:
            return replay
        self._validate_actor(actor_ref)
        self._validate_reason(reason)
        self._expect_latest(route_id, expected_revision_digest)
        snapshot = dict(self.model_routes.reconcile(route_id))
        response = {
            **snapshot,
            "governance": self._approval_projection(
                route_id, expected_revision_digest
            ),
            "eligible": self._eligible(route_id, expected_revision_digest),
        }
        self._record_command_and_audit(
            command_kind="model_route_reconcile",
            target_ref=f"model-route://{route_id}",
            request=request,
            idempotency_key=idempotency_key,
            response=response,
            actor_ref=actor_ref,
            event_type="model_route_reconcile_requested",
        )
        return response

    def decide_model_route(
        self,
        *,
        route_id: str,
        expected_revision_digest: str,
        expected_snapshot_digest: str,
        decision: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
        actor_role_ref: str,
    ) -> dict[str, Any]:
        if decision not in {"approved", "rejected"}:
            raise ControlConsoleError("model_route_decision_invalid")
        self._validate_actor(actor_ref)
        if actor_role_ref != _ROLE:
            raise ControlConsoleError("model_route_actor_role_invalid")
        self._validate_reason(reason)
        request = {
            "route_id": route_id,
            "expected_revision_digest": expected_revision_digest,
            "expected_snapshot_digest": expected_snapshot_digest,
            "decision": decision,
            "reason": reason,
        }
        replay = self._command(
            "model_route_decision", f"model-route://{route_id}", request,
            idempotency_key,
        )
        if replay is not None:
            return replay
        self._expect_latest(route_id, expected_revision_digest)
        snapshot = self._latest_snapshot(route_id)
        if (
            snapshot is None
            or snapshot.snapshot_digest != expected_snapshot_digest
            or snapshot.route_revision_digest != expected_revision_digest
        ):
            raise ControlConsoleError("model_route_snapshot_binding_drift")
        existing = self._terminal_decision(route_id, expected_revision_digest)
        if existing is not None:
            raise ControlConsoleError("model_route_revision_already_decided")
        if decision == "approved":
            preflight = self.model_routes.deploy_preflight(route_id)
            if preflight["status"] != "ready":
                raise ControlConsoleError("model_route_preflight_blocked")
        now = self.now().astimezone(timezone.utc)
        decision_id = deterministic_id(
            "approval", route_id, expected_revision_digest, decision, idempotency_key
        )
        decision_document = {
            "apiVersion": "company-ai-os/v1alpha1",
            "kind": "ApprovalDecision",
            "metadata": {
                "approval_id": decision_id,
                "created_at": _time_text(now),
                "decided_by_human_ref": actor_ref,
                "decided_by_role_ref": actor_role_ref,
                "correlation_id": route_id,
                "task_id": deterministic_id("task", "model-route-governance", route_id),
            },
            "spec": {
                "decision": decision,
                "reason": reason,
                "scope_ref": (
                    f"model-route-approval://{route_id}/{expected_revision_digest}"
                ),
                "scope_digest": expected_revision_digest,
                "expires_at": None,
                "conditions": [
                    "decision_scope:model_route_approval",
                    f"snapshot_digest:{expected_snapshot_digest}",
                    "catalog_eligibility_is_not_execution_authority",
                ],
            },
        }
        decision_digest = canonical_digest(decision_document)
        receipt = self._model_route_receipt(
            decision_id=decision_id,
            decision_digest=decision_digest,
            route_id=route_id,
            route_revision_digest=expected_revision_digest,
            snapshot_digest=expected_snapshot_digest,
            action=decision,
            actor_ref=actor_ref,
            actor_role_ref=actor_role_ref,
            reason=reason,
            now=now,
        )
        response = {
            "route_id": route_id,
            "route_revision_digest": expected_revision_digest,
            "decision_id": decision_id,
            "decision_digest": decision_digest,
            "decision": decision,
            "receipt_id": receipt["receipt_id"],
            "receipt_digest": receipt["receipt_digest"],
            "eligible": decision == "approved" and self._snapshot_ready(snapshot),
            "execution_grant_issued": False,
            "release_authorization": False,
        }
        self._record_decision(
            decision_id=decision_id,
            decision_digest=decision_digest,
            idempotency_key=idempotency_key,
            route_id=route_id,
            route_revision_digest=expected_revision_digest,
            action=decision,
            snapshot_digest=expected_snapshot_digest,
            source_decision_id=None,
            actor_ref=actor_ref,
            actor_role_ref=actor_role_ref,
            reason=reason,
            decision_document=decision_document,
            receipt=receipt,
            response=response,
            request=request,
            now=now,
        )
        return response

    def revoke_model_route_approval(
        self,
        *,
        route_id: str,
        expected_revision_digest: str,
        expected_approval_decision_digest: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
        actor_role_ref: str,
    ) -> dict[str, Any]:
        self._validate_actor(actor_ref)
        if actor_role_ref != _ROLE:
            raise ControlConsoleError("model_route_actor_role_invalid")
        self._validate_reason(reason)
        request = {
            "route_id": route_id,
            "expected_revision_digest": expected_revision_digest,
            "expected_approval_decision_digest": expected_approval_decision_digest,
            "reason": reason,
        }
        replay = self._command(
            "model_route_approval_revoke", f"model-route://{route_id}", request,
            idempotency_key,
        )
        if replay is not None:
            return replay
        self._expect_latest(route_id, expected_revision_digest)
        approval = self._approved_decision(route_id, expected_revision_digest)
        if (
            approval is None
            or approval.decision_digest != expected_approval_decision_digest
        ):
            raise ControlConsoleError("model_route_approval_binding_drift")
        if self._revocation_decision(route_id, expected_revision_digest) is not None:
            raise ControlConsoleError("model_route_approval_already_revoked")
        now = self.now().astimezone(timezone.utc)
        decision_id = deterministic_id(
            "approval", "revoke", route_id, expected_revision_digest, idempotency_key
        )
        document = {
            "apiVersion": "company-ai-os/v1alpha1",
            "kind": "ApprovalDecision",
            "metadata": {
                "approval_id": decision_id,
                "created_at": _time_text(now),
                "decided_by_human_ref": actor_ref,
                "decided_by_role_ref": actor_role_ref,
                "correlation_id": route_id,
                "task_id": deterministic_id("task", "model-route-governance", route_id),
            },
            "spec": {
                "decision": "rejected",
                "reason": reason,
                "scope_ref": (
                    f"model-route-approval-revocation://{route_id}/"
                    f"{expected_revision_digest}"
                ),
                "scope_digest": expected_revision_digest,
                "expires_at": None,
                "conditions": [
                    "decision_scope:model_route_approval",
                    f"revokes_decision:{approval.decision_id}",
                    "deny_new_grant_and_composition_references",
                    "gateway_fail_closed_for_future_calls",
                ],
            },
        }
        decision_digest = canonical_digest(document)
        receipt = self._model_route_receipt(
            decision_id=decision_id,
            decision_digest=decision_digest,
            route_id=route_id,
            route_revision_digest=expected_revision_digest,
            snapshot_digest=approval.snapshot_digest,
            action="revoked",
            actor_ref=actor_ref,
            actor_role_ref=actor_role_ref,
            reason=reason,
            now=now,
        )
        response = {
            "route_id": route_id,
            "route_revision_digest": expected_revision_digest,
            "decision_id": decision_id,
            "decision_digest": decision_digest,
            "decision": "revoked",
            "revoked_approval_decision_id": approval.decision_id,
            "receipt_id": receipt["receipt_id"],
            "receipt_digest": receipt["receipt_digest"],
            "eligible": False,
            "new_grant_references_allowed": False,
            "release_authorization": False,
        }
        self._record_decision(
            decision_id=decision_id,
            decision_digest=decision_digest,
            idempotency_key=idempotency_key,
            route_id=route_id,
            route_revision_digest=expected_revision_digest,
            action="revoked",
            snapshot_digest=approval.snapshot_digest,
            source_decision_id=approval.decision_id,
            actor_ref=actor_ref,
            actor_role_ref=actor_role_ref,
            reason=reason,
            decision_document=document,
            receipt=receipt,
            response=response,
            request=request,
            now=now,
        )
        return response

    # ---- Task scope audit --------------------------------------------------

    def list_task_scope_audits(self) -> dict[str, Any]:
        with self.database.session() as session:
            tasks = tuple(
                session.scalars(
                    select(DepartmentCockpitObjectRow)
                    .where(DepartmentCockpitObjectRow.object_type == "task")
                    .order_by(DepartmentCockpitObjectRow.department_id, DepartmentCockpitObjectRow.object_id)
                )
            )
        return {
            "items": [self._task_audit_summary(row) for row in tasks],
            "task_mutation_allowed": False,
            "task_approval_allowed": False,
            "release_authorization": False,
        }

    def task_scope_audit_detail(
        self, *, task_id: str, revision: int
    ) -> dict[str, Any]:
        task = self._task_row(task_id)
        if task.revision != revision:
            raise ControlConsoleError("task_scope_audit_revision_not_found")
        with self.database.session() as session:
            audits = tuple(
                session.scalars(
                    select(TaskScopeAuditRow)
                    .where(
                        TaskScopeAuditRow.task_id == task_id,
                        TaskScopeAuditRow.task_revision == revision,
                    )
                    .order_by(TaskScopeAuditRow.id)
                )
            )
        return {
            "task": self._task_public(task),
            "audits": [self._task_audit_public(row) for row in audits],
            "task_content_changed": False,
            "department_approval_state_changed": False,
            "release_authorization": False,
        }

    def reconcile_task_scope(
        self,
        *,
        task_id: str,
        expected_revision: int,
        expected_task_digest: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        self._validate_actor(actor_ref)
        self._validate_reason(reason)
        request = {
            "task_id": task_id,
            "expected_revision": expected_revision,
            "expected_task_digest": expected_task_digest,
            "reason": reason,
        }
        replay = self._command(
            "task_scope_reconcile", f"task://{task_id}", request, idempotency_key
        )
        if replay is not None:
            return replay
        task = self._task_row(task_id)
        task_digest = canonical_digest(task.document)
        if task.revision != expected_revision or task_digest != expected_task_digest:
            raise ControlConsoleError("task_scope_expected_revision_drift")
        reasons = self._task_scope_reasons(task.document)
        outcome = "allow" if not reasons else "deny"
        grant_id = task.document.get("execution_grant_id")
        grant_action = "none"
        grant_revocation_revision = None
        if reasons and isinstance(grant_id, str):
            try:
                grant_revocation_revision = self.grant_revocations.revoke(
                    grant_id=grant_id,
                    reason_code="task_scope_violation",
                    revoked_by_ref="workload_task_scope_auditor",
                )
            except ServiceRepositoryError as error:
                raise ControlConsoleError(error.reason_code) from error
            grant_action = "revoked"
        elif reasons:
            grant_action = "block_issuance"
        now = self.now().astimezone(timezone.utc)
        record_id = deterministic_id(
            "task_scope_audit", task_id, str(expected_revision), idempotency_key
        )
        document = {
            "audit_version": "orbit.task-scope-audit/1",
            "audit_record_id": record_id,
            "task_id": task_id,
            "task_revision": expected_revision,
            "task_digest": task_digest,
            "decision": outcome,
            "reason_codes": sorted(reasons),
            "grant": {
                "grant_id": grant_id if isinstance(grant_id, str) else None,
                "action": grant_action,
                "revocation_revision": grant_revocation_revision,
            },
            "triggered_by": actor_ref,
            "decided_by": "workload_task_scope_auditor",
            "task_content_changed": False,
            "department_approval_state_changed": False,
            "recorded_at": _time_text(now),
            "release_authorization": False,
        }
        receipt = {
            "receipt_version": "orbit.task-scope-audit-receipt/1-internal",
            "receipt_id": deterministic_id("receipt", record_id),
            "subject_ref": f"task://{task_id}/revisions/{expected_revision}",
            "subject_digest": task_digest,
            "audit_record_id": record_id,
            "decision": outcome,
            "grant_action": grant_action,
            "evidence_only": True,
            "recorded_at": _time_text(now),
            "release_authorization": False,
        }
        receipt_digest = canonical_digest(receipt)
        response = {
            **document,
            "receipt_id": receipt["receipt_id"],
            "receipt_digest": receipt_digest,
        }
        with self.database.session() as session:
            session.add(
                TaskScopeAuditRow(
                    audit_record_id=record_id,
                    idempotency_key=idempotency_key,
                    task_id=task_id,
                    task_revision=expected_revision,
                    task_digest=task_digest,
                    outcome=outcome,
                    reason_codes=sorted(reasons),
                    grant_id=grant_id if isinstance(grant_id, str) else None,
                    grant_action=grant_action,
                    document=document,
                    receipt_id=receipt["receipt_id"],
                    receipt_digest=receipt_digest,
                    created_at=now,
                )
            )
            session.add(
                ReceiptRow(
                    receipt_id=receipt["receipt_id"],
                    receipt_type="orbit.task-scope-audit-receipt/1-internal",
                    receipt_digest=receipt_digest,
                    subject_ref=receipt["subject_ref"],
                    document=receipt,
                    recorded_at=now,
                )
            )
            session.add(
                AuditEventRow(
                    audit_id=deterministic_id("audit", record_id),
                    correlation_id=task_id,
                    event_type="task_scope_audit_reconciled",
                    actor_ref="workload_task_scope_auditor",
                    payload={
                        "audit_record_id": record_id,
                        "triggered_by": actor_ref,
                        "task_digest": task_digest,
                        "decision": outcome,
                        "reason_codes": sorted(reasons),
                        "grant_action": grant_action,
                        "task_content_changed": False,
                        "department_approval_state_changed": False,
                        "release_authorization": False,
                    },
                    recorded_at=now,
                )
            )
            session.add(
                ControlConsoleCommandRow(
                    idempotency_key=idempotency_key,
                    command_kind="task_scope_reconcile",
                    target_ref=f"task://{task_id}",
                    request_digest=canonical_digest(request),
                    response=response,
                    created_at=now,
                )
            )
        after = self._task_row(task_id)
        if canonical_digest(after.document) != task_digest or after.revision != expected_revision:
            raise ControlConsoleError("task_scope_audit_mutated_task")
        return response

    # ---- internal projections ---------------------------------------------

    def _route_public_revision(self, row: ModelRouteRevisionRow) -> dict[str, Any]:
        document = _route_document(row)
        display = (
            None
            if self.model_catalog is None
            else self.model_catalog.route_display_projection(
                route_id=row.route_id, revision_digest=row.revision_digest
            )
        )
        authentication_mode = (
            "api_key_ref"
            if document["route_version"] == "orbit.model-route-revision/1"
            else document["authentication"]["mode"]
        )
        return {
            "route_version": document["route_version"],
            "route_id": row.route_id,
            "provider_display_name": (
                display["provider_display_name"] if display else "既有公司连接"
            ),
            "model_display_name": (
                display["model_display_name"] if display else "既有模型路线"
            ),
            "model_version_label": (
                display["model_version_label"] if display else "只读兼容修订"
            ),
            "parameters": document["parameters"],
            "data_classification": document["data_classification"],
            "budget_policy": document["budget_policy"],
            "resolution_mode": document["resolution_mode"],
            "authentication_mode": authentication_mode,
            "credential_scope": document.get("credential_scope", "company"),
            "authorized_node_refs": document.get("authorized_node_refs", []),
            "qualification_evidence_refs": document.get(
                "qualification_evidence_refs", []
            ),
            "budget_control_mode": document.get(
                "budget_control_mode", "currency_and_usage"
            ),
            "runtime_binding": document["runtime_binding"],
            "policy_binding": document["policy_binding"],
            "status": document["status"],
            "raw_endpoint_visible": False,
            "provider_model_id_visible": False,
            "credential_ref_visible": False,
        }

    @staticmethod
    def _snapshot_public(row: ModelRouteSnapshotRow) -> dict[str, Any]:
        return {
            "snapshot_version": "orbit.model-route-snapshot-public/1",
            "route_id": row.route_id,
            "route_revision_digest": row.route_revision_digest,
            "observation_digest": row.observation_digest,
            "budget_policy": row.budget_policy,
            "worst_case_cost": row.worst_case_cost,
            "runtime_binding": row.runtime_binding,
            "policy_binding": row.policy_binding,
            "status": row.status,
            "reason_codes": row.reason_codes,
            "expires_at": _time_text(row.expires_at),
            "raw_endpoint_visible": False,
            "provider_model_id_visible": False,
            "credential_ref_visible": False,
            "release_authorization": False,
        }

    def _route_summary(self, route_id: str) -> dict[str, Any]:
        route = self.model_routes.store.latest_route(route_id)
        if route is None:
            raise ControlConsoleError("model_route_not_found")
        approval = self._approval_projection(route_id, route.revision_digest)
        health = self._health_for_revision(route_id, route.revision_digest)
        document = _route_document(route)
        authentication_mode = (
            "api_key_ref"
            if document["route_version"] == "orbit.model-route-revision/1"
            else document["authentication"]["mode"]
        )
        retired = (
            False
            if self.credentials is None
            else self.credentials.is_retired(route_id, route.revision_digest)
        )
        display = (
            None
            if self.model_catalog is None
            else self.model_catalog.route_display_projection(
                route_id=route_id, revision_digest=route.revision_digest
            )
        )
        return {
            "route_id": route_id,
            "revision_digest": route.revision_digest,
            "provider_display_name": (
                display["provider_display_name"]
                if display is not None
                else "既有公司连接"
            ),
            "model_display_name": (
                display["model_display_name"]
                if display is not None
                else "既有模型路线"
            ),
            "model_version_label": (
                display["model_version_label"]
                if display is not None
                else "只读兼容修订"
            ),
            "provider_model_id_visible": False,
            "raw_endpoint_visible": False,
            "credential_ref_visible": False,
            "candidate_status": route.status,
            "approval_status": approval["approval_status"],
            "approval_decision_id": approval["approval_decision_id"],
            "approval_decision_digest": approval["approval_decision_digest"],
            "eligible": (
                not retired
                and approval["approval_status"] == "approved"
                and health["status"] == "ready"
            ),
            "health": health,
            "route_version": document["route_version"],
            "authentication_mode": authentication_mode,
            "credential_scope": document.get("credential_scope", "company"),
            "authorized_node_refs": document.get("authorized_node_refs", []),
            "budget_control_mode": document.get(
                "budget_control_mode", "currency_and_usage"
            ),
            "credential_status": (
                "ready" if health.get("credential_healthy") else "needs_attention"
            ),
            "retired": retired,
            "execution_grant_issued": False,
            "release_authorization": False,
        }

    def _health_for_revision(self, route_id: str, revision_digest: str) -> dict[str, Any]:
        latest = self.model_routes.store.latest_route(route_id)
        if latest is None or latest.revision_digest != revision_digest:
            snapshot = self._snapshot_for_revision(route_id, revision_digest)
            return {
                "status": "historical",
                "snapshot_digest": None if snapshot is None else snapshot.snapshot_digest,
                "reason_codes": ["model_route_revision_not_latest"],
                "secret_healthy": None,
                "credential_healthy": None,
                "secret_binding_version": (
                    None if snapshot is None else snapshot.secret_binding_version
                ),
            }
        status = dict(self.model_routes.status(route_id))
        snapshot = self._latest_snapshot(route_id)
        return {
            "status": status["snapshot_status"],
            "snapshot_digest": status["snapshot_digest"],
            "snapshot_expires_at": status["snapshot_expires_at"],
            "reason_codes": status["reason_codes"],
            "secret_healthy": status["secret_healthy"],
            "credential_healthy": status["credential_healthy"],
            "authentication_mode": status["authentication_mode"],
            "secret_binding_version": (
                None if snapshot is None else snapshot.secret_binding_version
            ),
        }

    def _approval_projection(self, route_id: str, revision_digest: str) -> dict[str, Any]:
        approved = self._approved_decision(route_id, revision_digest)
        rejected = self._rejected_decision(route_id, revision_digest)
        revoked = self._revocation_decision(route_id, revision_digest)
        if revoked is not None:
            state = "revoked"
            selected = revoked
        elif approved is not None:
            state = "approved"
            selected = approved
        elif rejected is not None:
            state = "rejected"
            selected = rejected
        else:
            state = "not_reviewed"
            selected = None
        return {
            "decision_scope": "model_route_approval",
            "approval_status": state,
            "approval_decision_id": None if selected is None else selected.decision_id,
            "approval_decision_digest": None if selected is None else selected.decision_digest,
            "receipt_id": None if selected is None else selected.receipt_id,
            "historical_decision_preserved": True,
        }

    def _eligible(self, route_id: str, revision_digest: str) -> bool:
        projection = self._approval_projection(route_id, revision_digest)
        retired = (
            False
            if self.credentials is None
            else self.credentials.is_retired(route_id, revision_digest)
        )
        return (
            not retired
            and projection["approval_status"] == "approved"
            and self._health_for_revision(route_id, revision_digest)["status"]
            == "ready"
        )

    def _snapshot_ready(self, snapshot: ModelRouteSnapshotRow) -> bool:
        return (
            snapshot.status == "ready"
            and _as_utc(snapshot.expires_at) > self.now().astimezone(timezone.utc)
        )

    def _route_revision(self, route_id: str, digest: str) -> ModelRouteRevisionRow:
        with self.database.session() as session:
            row = session.scalar(
                select(ModelRouteRevisionRow).where(
                    ModelRouteRevisionRow.route_id == route_id,
                    ModelRouteRevisionRow.revision_digest == digest,
                )
            )
        if row is None:
            raise ControlConsoleError("model_route_revision_not_found")
        return row

    def _expect_latest(self, route_id: str, digest: str) -> ModelRouteRevisionRow:
        row = self.model_routes.store.latest_route(route_id)
        if row is None:
            raise ControlConsoleError("model_route_not_found")
        if row.revision_digest != digest:
            raise ControlConsoleError("model_route_expected_revision_drift")
        return row

    def _latest_snapshot(self, route_id: str) -> ModelRouteSnapshotRow | None:
        return self.model_routes.store.latest_snapshot(route_id)

    def _snapshot_for_revision(
        self, route_id: str, revision_digest: str
    ) -> ModelRouteSnapshotRow | None:
        with self.database.session() as session:
            return session.scalar(
                select(ModelRouteSnapshotRow)
                .where(
                    ModelRouteSnapshotRow.route_id == route_id,
                    ModelRouteSnapshotRow.route_revision_digest == revision_digest,
                )
                .order_by(ModelRouteSnapshotRow.id.desc())
                .limit(1)
            )

    def _decision(self, route_id: str, revision_digest: str, action: str) -> ModelRouteDecisionRow | None:
        with self.database.session() as session:
            return session.scalar(
                select(ModelRouteDecisionRow)
                .where(
                    ModelRouteDecisionRow.route_id == route_id,
                    ModelRouteDecisionRow.route_revision_digest == revision_digest,
                    ModelRouteDecisionRow.action == action,
                )
                .order_by(ModelRouteDecisionRow.id.desc())
                .limit(1)
            )

    def _approved_decision(self, route_id: str, digest: str) -> ModelRouteDecisionRow | None:
        return self._decision(route_id, digest, "approved")

    def _rejected_decision(self, route_id: str, digest: str) -> ModelRouteDecisionRow | None:
        return self._decision(route_id, digest, "rejected")

    def _revocation_decision(self, route_id: str, digest: str) -> ModelRouteDecisionRow | None:
        return self._decision(route_id, digest, "revoked")

    def _terminal_decision(self, route_id: str, digest: str) -> ModelRouteDecisionRow | None:
        return self._approved_decision(route_id, digest) or self._rejected_decision(route_id, digest)

    def _model_route_receipt(
        self, *, decision_id: str, decision_digest: str, route_id: str,
        route_revision_digest: str, snapshot_digest: str | None, action: str,
        actor_ref: str, actor_role_ref: str, reason: str, now: datetime,
    ) -> dict[str, Any]:
        route = _route_document(
            self._route_revision(route_id, route_revision_digest)
        )
        authentication_mode = (
            "api_key_ref"
            if route["route_version"] == "orbit.model-route-revision/1"
            else route["authentication"]["mode"]
        )
        document = {
            "receipt_version": "orbit.model-route-approval-receipt/0.1-draft",
            "receipt_id": deterministic_id("receipt", decision_id, decision_digest),
            "decision_scope": "model_route_approval",
            "decision": action,
            "decision_id": decision_id,
            "decision_digest": decision_digest,
            "route_id": route_id,
            "route_revision_digest": route_revision_digest,
            "snapshot_digest": snapshot_digest,
            "approval_envelope": {
                "provider": route["provider"],
                "endpoint_logical_id": route["endpoint"],
                "model_family": route["approved_scope"]["model_family"],
                "data_classification": route["data_classification"],
                "budget_limit": route["budget_policy"],
                "authentication_mode": authentication_mode,
                "credential_scope": route.get("credential_scope", "company"),
                "runtime_binding": route["runtime_binding"],
                "policy_binding": route["policy_binding"],
                "approved_scope": route["approved_scope"],
            },
            "actor_ref": actor_ref,
            "actor_role_ref": actor_role_ref,
            "reason": reason,
            "effect": {
                "catalog_eligible_if_healthy": action == "approved",
                "new_grant_or_composition_reference_allowed": action == "approved",
                "model_invocation_authorized": False,
                "execution_grant_issued": False,
                "task_changed": False,
            },
            "recorded_at": _time_text(now),
            "synthetic_only": True,
            "release_authorization": False,
        }
        return {
            **document,
            "receipt_digest": canonical_digest(document),
        }

    def _record_decision(
        self, *, decision_id: str, decision_digest: str, idempotency_key: str,
        route_id: str, route_revision_digest: str, action: str,
        snapshot_digest: str | None, source_decision_id: str | None,
        actor_ref: str, actor_role_ref: str, reason: str,
        decision_document: dict[str, Any], receipt: dict[str, Any],
        response: dict[str, Any], request: dict[str, Any], now: datetime,
    ) -> None:
        receipt_document = {
            key: value for key, value in receipt.items() if key != "receipt_digest"
        }
        with self.database.session() as session:
            session.add(
                ModelRouteDecisionRow(
                    decision_id=decision_id,
                    decision_digest=decision_digest,
                    idempotency_key=idempotency_key,
                    route_id=route_id,
                    route_revision_digest=route_revision_digest,
                    action=action,
                    snapshot_digest=snapshot_digest,
                    source_decision_id=source_decision_id,
                    actor_ref=actor_ref,
                    actor_role_ref=actor_role_ref,
                    reason=reason,
                    document=decision_document,
                    receipt_id=receipt["receipt_id"],
                    receipt_digest=receipt["receipt_digest"],
                    created_at=now,
                )
            )
            session.add(
                ReceiptRow(
                    receipt_id=receipt["receipt_id"],
                    receipt_type="orbit.model-route-approval-receipt/0.1-draft",
                    receipt_digest=receipt["receipt_digest"],
                    subject_ref=f"model-route://{route_id}/{route_revision_digest}",
                    document=receipt_document,
                    recorded_at=now,
                )
            )
            session.add(
                AuditEventRow(
                    audit_id=deterministic_id("audit", decision_id, decision_digest),
                    correlation_id=route_id,
                    event_type=f"model_route_approval_{action}",
                    actor_ref=actor_ref,
                    payload={
                        **_route_audit_references(
                            session,
                            route_id=route_id,
                            route_revision_digest=route_revision_digest,
                        ),
                        "decision_scope": "model_route_approval",
                        "decision_id": decision_id,
                        "decision_digest": decision_digest,
                        "route_revision_digest": route_revision_digest,
                        "snapshot_digest": snapshot_digest,
                        "receipt_id": receipt["receipt_id"],
                        "receipt_digest": receipt["receipt_digest"],
                        "release_authorization": False,
                    },
                    recorded_at=now,
                )
            )
            session.add(
                OutboxEventRow(
                    event_id=deterministic_id("outbox", decision_id, decision_digest),
                    topic=f"model_route.approval.{action}",
                    aggregate_ref=f"model-route://{route_id}/{route_revision_digest}",
                    payload={
                        "decision_id": decision_id,
                        "decision_digest": decision_digest,
                        "receipt_digest": receipt["receipt_digest"],
                        "eligible": response["eligible"],
                        "release_authorization": False,
                    },
                    status="pending",
                    attempts=0,
                    created_at=now,
                    published_at=None,
                )
            )
            session.add(
                ControlConsoleCommandRow(
                    idempotency_key=idempotency_key,
                    command_kind=(
                        "model_route_approval_revoke"
                        if action == "revoked" else "model_route_decision"
                    ),
                    target_ref=f"model-route://{route_id}",
                    request_digest=canonical_digest(request),
                    response=response,
                    created_at=now,
                )
            )

    def _command(
        self, command_kind: str, target_ref: str, request: Mapping[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any] | None:
        if not _IDEMPOTENCY.fullmatch(idempotency_key):
            raise ControlConsoleError("control_console_idempotency_key_invalid")
        with self.database.session() as session:
            row = session.scalar(
                select(ControlConsoleCommandRow).where(
                    ControlConsoleCommandRow.idempotency_key == idempotency_key
                )
            )
        if row is None:
            return None
        if (
            row.command_kind != command_kind
            or row.target_ref != target_ref
            or row.request_digest != canonical_digest(request)
        ):
            raise ControlConsoleError("control_console_idempotency_conflict")
        return {**row.response, "idempotent_replay": True}

    def _record_command_and_audit(
        self, *, command_kind: str, target_ref: str, request: Mapping[str, Any],
        idempotency_key: str, response: dict[str, Any], actor_ref: str,
        event_type: str,
    ) -> None:
        now = self.now().astimezone(timezone.utc)
        with self.database.session() as session:
            session.add(
                ControlConsoleCommandRow(
                    idempotency_key=idempotency_key,
                    command_kind=command_kind,
                    target_ref=target_ref.split("/sha256:")[0] if "/sha256:" in target_ref else target_ref,
                    request_digest=canonical_digest(request),
                    response=response,
                    created_at=now,
                )
            )
            session.add(
                AuditEventRow(
                    audit_id=deterministic_id("audit", command_kind, idempotency_key),
                    correlation_id=target_ref.split("//", 1)[-1].split("/", 1)[0],
                    event_type=event_type,
                    actor_ref=actor_ref,
                    payload={
                        **_route_audit_references(
                            session,
                            route_id=response["route_id"],
                            route_revision_digest=response.get(
                                "route_revision_digest", response.get("revision_digest")
                            ),
                        ),
                        "reason": request["reason"],
                        "response_digest": canonical_digest(response),
                        "release_authorization": False,
                    },
                    recorded_at=now,
                )
            )

    def _task_scope_reasons(self, task: Mapping[str, Any]) -> set[str]:
        reasons: set[str] = set()
        allowed_data = task.get("allowed_data_classifications", ["synthetic", "public"])
        if task.get("data_classification") not in allowed_data:
            reasons.add("task_data_classification_out_of_scope")
        if task.get("side_effects") is True:
            reasons.add("task_side_effect_out_of_scope")
        requested_tools = set(task.get("requested_tool_refs", []))
        allowed_tools = set(task.get("allowed_tool_refs", []))
        if requested_tools - allowed_tools:
            reasons.add("task_tool_scope_out_of_scope")
        requested_datasets = set(task.get("requested_dataset_refs", []))
        allowed_datasets = set(task.get("allowed_dataset_refs", []))
        if requested_datasets - allowed_datasets:
            reasons.add("task_data_scope_out_of_scope")
        requested_cost = self._money(task.get("requested_max_cost_usd"))
        allowed_cost = self._money(task.get("allowed_max_cost_usd"))
        if requested_cost is None or allowed_cost is None:
            reasons.add("task_budget_evidence_missing")
        elif requested_cost > allowed_cost:
            reasons.add("task_budget_out_of_scope")
        deadline = task.get("expires_at")
        if not isinstance(deadline, str):
            reasons.add("task_deadline_evidence_missing")
        else:
            try:
                parsed = datetime.fromisoformat(deadline.replace("Z", "+00:00"))
            except ValueError:
                reasons.add("task_deadline_invalid")
            else:
                if parsed <= self.now():
                    reasons.add("task_deadline_expired")
        route_id = task.get("model_route_id")
        route_digest = task.get("model_route_revision_digest")
        if not isinstance(route_id, str) or not isinstance(route_digest, str):
            reasons.add("task_model_route_revision_missing")
        else:
            try:
                if not self._eligible(route_id, route_digest):
                    reasons.add("task_model_route_not_eligible")
            except (ControlConsoleError, ModelRouteError):
                reasons.add("task_model_route_not_eligible")
        adapter_selectable = task.get("runtime_adapter_selectable")
        if adapter_selectable is not True:
            reasons.add("task_runtime_adapter_not_selectable")
        policy_allows = task.get("policy_allows_scope")
        if policy_allows is not True:
            reasons.add("task_policy_scope_denied")
        binding_allows = task.get("agent_binding_allows_scope")
        if binding_allows is not True:
            reasons.add("task_agent_binding_scope_denied")
        return reasons

    @staticmethod
    def _money(value: Any) -> Decimal | None:
        try:
            result = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError):
            return None
        return result if result >= 0 else None

    def _task_row(self, task_id: str) -> DepartmentCockpitObjectRow:
        with self.database.session() as session:
            row = session.scalar(
                select(DepartmentCockpitObjectRow).where(
                    DepartmentCockpitObjectRow.object_type == "task",
                    DepartmentCockpitObjectRow.object_id == task_id,
                )
            )
        if row is None:
            raise ControlConsoleError("task_scope_audit_task_not_found")
        return row

    def _task_audit_summary(self, task: DepartmentCockpitObjectRow) -> dict[str, Any]:
        with self.database.session() as session:
            audit = session.scalar(
                select(TaskScopeAuditRow)
                .where(TaskScopeAuditRow.task_id == task.object_id)
                .order_by(TaskScopeAuditRow.id.desc())
                .limit(1)
            )
        return {
            **self._task_public(task),
            "audit_status": "not_run" if audit is None else audit.outcome,
            "reason_codes": [] if audit is None else audit.reason_codes,
            "grant_action": "none" if audit is None else audit.grant_action,
            "task_approval_action_available": False,
        }

    @staticmethod
    def _task_public(task: DepartmentCockpitObjectRow) -> dict[str, Any]:
        document = task.document
        return {
            "task_id": task.object_id,
            "revision": task.revision,
            "task_digest": canonical_digest(document),
            "department_id": task.department_id,
            "title": document.get("title"),
            "authority_state": document.get("authority_state"),
            "data_classification": document.get("data_classification"),
            "execution_grant_id": document.get("execution_grant_id"),
        }

    @staticmethod
    def _task_audit_public(row: TaskScopeAuditRow) -> dict[str, Any]:
        return {
            **row.document,
            "receipt_id": row.receipt_id,
            "receipt_digest": row.receipt_digest,
        }

    @staticmethod
    def _decision_public(row: ModelRouteDecisionRow) -> dict[str, Any]:
        return {
            "decision_id": row.decision_id,
            "decision_digest": row.decision_digest,
            "action": row.action,
            "route_revision_digest": row.route_revision_digest,
            "snapshot_digest": row.snapshot_digest,
            "source_decision_id": row.source_decision_id,
            "actor_ref": row.actor_ref,
            "actor_role_ref": row.actor_role_ref,
            "reason": row.reason,
            "document": row.document,
            "receipt_id": row.receipt_id,
            "receipt_digest": row.receipt_digest,
            "created_at": _time_text(row.created_at),
        }

    @staticmethod
    def _validate_reason(reason: str) -> None:
        cleaned = " ".join(reason.split()) if isinstance(reason, str) else ""
        if len(cleaned) < 8 or len(cleaned) > 500 or "\x00" in reason:
            raise ControlConsoleError("control_console_reason_invalid")

    @staticmethod
    def _validate_actor(actor_ref: str) -> None:
        if not isinstance(actor_ref, str) or not actor_ref.startswith("human_") or not _SAFE_ID.fullmatch(actor_ref):
            raise ControlConsoleError("control_console_actor_invalid")

