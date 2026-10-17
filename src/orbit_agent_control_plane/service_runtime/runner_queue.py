"""Durable local Runner transport for qualification and public-data pilots.

The Control Plane writes an exact, signed invocation to PostgreSQL.  A
separate Runner process claims one row, executes one pre-registered handler,
and records ordered events plus one terminal result.  No Docker socket,
provider secret, or physical data path crosses this transport boundary.
"""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import re
import signal
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, Protocol

from sqlalchemy import func, select

from ..ids import deterministic_id
from .database import Database
from .models import RuntimeEventRow, RuntimeRunRow, SignedGrantRow
from .runtime_adapter import RuntimeAdapterError, RuntimeInvocation
from .security import Ed25519EvaluationGrantVerifier, ServiceSecurityError

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_PHYSICAL = re.compile(r"^(?:/|~/|[A-Za-z]:[\\/]|file://|smb://|opaque://)")
_SECRET = re.compile(
    r"(?:BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|\bsk-[A-Za-z0-9_-]{8,})",
    re.IGNORECASE,
)
_FORBIDDEN_KEYS = {
    "api_key",
    "authorization",
    "credential",
    "credentials",
    "endpoint",
    "nas_path",
    "password",
    "physical_path",
    "secret",
    "storage_path",
}
_TERMINAL = frozenset({"completed", "failed", "cancelled"})


class RunnerQueueError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class GrantRevocationView(Protocol):
    def is_revoked(self, *, grant_id: str, minimum_revision: int) -> bool: ...


class LeaseCoordinator(Protocol):
    def claim(self, *, run_id: str, worker_identity: str, ttl_seconds: int) -> str: ...

    def close(
        self, *, lease_id: str, worker_identity: str, outcome: str
    ) -> None: ...


class AuditRecorder(Protocol):
    def record(
        self,
        *,
        correlation_id: str,
        event_type: str,
        actor_ref: str,
        payload: Mapping[str, Any],
    ) -> str: ...


def canonical_bytes(value: Any) -> bytes:
    _validate_safe_json(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


class SqlSignedGrantRegistry:
    """Persist and verify short-lived evaluation Grants before Runner claim."""

    def __init__(
        self,
        database: Database,
        *,
        verifier: Ed25519EvaluationGrantVerifier,
        revocations: GrantRevocationView,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.database = database
        self.verifier = verifier
        self.revocations = revocations
        self.now = now or _utcnow

    def register(
        self,
        *,
        document: Mapping[str, Any],
        key_id: str,
        signature: str,
    ) -> bool:
        source = canonical_bytes(document)
        verified = self.verifier.verify_grant(
            canonical_grant=source,
            key_id=key_id,
            signature=signature,
        )
        metadata = verified["metadata"]
        spec = verified["spec"]
        grant_id = metadata.get("grant_id")
        grant_digest = spec.get("qualification_grant_digest")
        if (
            not isinstance(grant_id, str)
            or not grant_id.startswith("grant_")
            or not isinstance(grant_digest, str)
            or not _DIGEST.fullmatch(grant_digest)
        ):
            raise RunnerQueueError("runner_signed_grant_binding_invalid")
        issued_at = _time(metadata["issued_at"])
        expires_at = _time(metadata["expires_at"])
        with self.database.session() as session:
            existing = session.scalar(
                select(SignedGrantRow).where(SignedGrantRow.grant_id == grant_id)
            )
            if existing is not None:
                if (
                    existing.grant_digest != grant_digest
                    or existing.key_id != key_id
                    or existing.signature != signature
                    or existing.document != verified
                ):
                    raise RunnerQueueError("runner_signed_grant_conflict")
                return False
            session.add(
                SignedGrantRow(
                    grant_id=grant_id,
                    grant_digest=grant_digest,
                    key_id=key_id,
                    signature=signature,
                    document=dict(verified),
                    status="active",
                    issued_at=issued_at,
                    expires_at=expires_at,
                    consumed_at=None,
                    revision=0,
                )
            )
        return True

    def authorize(self, invocation: RuntimeInvocation) -> None:
        now = self.now().astimezone(timezone.utc)
        with self.database.session() as session:
            row = session.scalar(
                select(SignedGrantRow).where(
                    SignedGrantRow.grant_id == invocation.grant_id
                )
            )
            if row is None or row.status != "active":
                raise RunnerQueueError("runner_signed_grant_not_active")
            document = row.document
            spec = document["spec"]
            if (
                row.grant_digest != invocation.grant_digest
                or _as_utc(row.expires_at) <= now
                or _time(invocation.expires_at) > _as_utc(row.expires_at)
                or spec.get("task_digest") != invocation.task_digest
                or spec.get("composition_digest") != invocation.composition_digest
                or spec.get("runtime_source_digest")
                != invocation.runtime_source_digest
                or spec.get("runtime_artifact_digest")
                != invocation.runtime_artifact_digest
                or spec.get("runtime_image_digest")
                != invocation.runtime_image_digest
                or spec.get("isolation_profile_digest")
                != invocation.isolation_profile_digest
                or spec.get("department_id") != invocation.department_id
                or spec.get("agent_binding_ref") != invocation.agent_binding_ref
                or spec.get("agent_binding_digest")
                != invocation.agent_binding_digest
                or spec.get("invocation_digest")
                != canonical_digest(invocation.to_mapping())
                or spec.get("data_classification")
                != invocation.data_classification
                or spec.get("production_authorization") is not False
                or spec.get("release_authorization") is not False
            ):
                raise RunnerQueueError("runner_signed_grant_binding_invalid")
            try:
                self.verifier.verify_grant(
                    canonical_grant=canonical_bytes(document),
                    key_id=row.key_id,
                    signature=row.signature,
                )
            except ServiceSecurityError as error:
                raise RunnerQueueError("runner_signed_grant_signature_invalid") from error
        if self.revocations.is_revoked(
            grant_id=invocation.grant_id, minimum_revision=0
        ):
            raise RunnerQueueError("runner_signed_grant_revoked")

    def consume(self, *, grant_id: str) -> None:
        with self.database.session() as session:
            row = session.scalar(
                select(SignedGrantRow)
                .where(SignedGrantRow.grant_id == grant_id)
                .with_for_update()
            )
            if row is None:
                raise RunnerQueueError("runner_signed_grant_missing")
            if row.status == "consumed":
                return
            if row.status != "active":
                raise RunnerQueueError("runner_signed_grant_not_active")
            row.status = "consumed"
            row.consumed_at = self.now().astimezone(timezone.utc)
            row.revision += 1

    def status(self, grant_id: str) -> Mapping[str, Any] | None:
        with self.database.session() as session:
            row = session.scalar(
                select(SignedGrantRow).where(SignedGrantRow.grant_id == grant_id)
            )
            if row is None:
                return None
            return {
                "grant_id": row.grant_id,
                "grant_digest": row.grant_digest,
                "status": row.status,
                "expires_at": _as_utc(row.expires_at).isoformat(),
                "revision": row.revision,
            }


class SqlRunnerTransport:
    """RunnerTransport implementation backed by an idempotent SQL queue."""

    def __init__(
        self,
        database: Database,
        *,
        grants: SqlSignedGrantRegistry,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.database = database
        self.grants = grants
        self.now = now or _utcnow

    def start(self, *, invocation: RuntimeInvocation) -> str:
        self.grants.authorize(invocation)
        document = invocation.to_mapping()
        digest = canonical_digest(document)
        run_id = deterministic_id("run", invocation.idempotency_key, digest)
        with self.database.session() as session:
            existing = session.scalar(
                select(RuntimeRunRow).where(
                    RuntimeRunRow.idempotency_key == invocation.idempotency_key
                )
            )
            if existing is not None:
                if existing.invocation_digest != digest:
                    raise RuntimeAdapterError("runtime_idempotency_conflict")
                return existing.run_id
            session.add(
                RuntimeRunRow(
                    run_id=run_id,
                    task_id=invocation.task_id,
                    grant_id=invocation.grant_id,
                    grant_digest=invocation.grant_digest,
                    composition_digest=invocation.composition_digest,
                    runtime_source_digest=invocation.runtime_source_digest,
                    runtime_artifact_digest=invocation.runtime_artifact_digest,
                    runtime_image_digest=invocation.runtime_image_digest,
                    isolation_profile_digest=invocation.isolation_profile_digest,
                    input_snapshot_refs=(
                        list(invocation.input_snapshot_refs)
                        if invocation.container_bound
                        else None
                    ),
                    invocation_digest=digest,
                    idempotency_key=invocation.idempotency_key,
                    invocation=document,
                    status="queued",
                    worker_identity=None,
                    cancel_reason_code=None,
                    failure_reason_code=None,
                    result_document=None,
                    result_digest=None,
                    created_at=self.now().astimezone(timezone.utc),
                    expires_at=_time(invocation.expires_at),
                    started_at=None,
                    closed_at=None,
                    revision=0,
                )
            )
            session.flush()
            _append_event(
                session,
                run_id=run_id,
                event_type="runtime_queued",
                payload={
                    "invocation_digest": digest,
                    "grant_digest": invocation.grant_digest,
                },
                recorded_at=self.now().astimezone(timezone.utc),
            )
        return run_id

    def events(
        self, *, run_id: str, after_sequence: int
    ) -> Sequence[Mapping[str, Any]]:
        with self.database.session() as session:
            rows = tuple(
                session.scalars(
                    select(RuntimeEventRow)
                    .where(
                        RuntimeEventRow.run_id == run_id,
                        RuntimeEventRow.sequence > after_sequence,
                    )
                    .order_by(RuntimeEventRow.sequence)
                )
            )
        return tuple(_event_mapping(row) for row in rows)

    def cancel(self, *, run_id: str, reason_code: str) -> None:
        if not _REASON.fullmatch(reason_code):
            raise RuntimeAdapterError("runtime_cancel_invalid")
        with self.database.session() as session:
            row = session.scalar(
                select(RuntimeRunRow)
                .where(RuntimeRunRow.run_id == run_id)
                .with_for_update()
            )
            if row is None:
                raise RuntimeAdapterError("runtime_run_not_found")
            if row.status in _TERMINAL:
                return
            if row.cancel_reason_code not in {None, reason_code}:
                raise RuntimeAdapterError("runtime_cancel_conflict")
            row.cancel_reason_code = reason_code
            row.status = "cancel_requested"
            row.revision += 1
            _append_event(
                session,
                run_id=run_id,
                event_type="runtime_cancel_requested",
                payload={"reason_code": reason_code},
                recorded_at=self.now().astimezone(timezone.utc),
            )

    def result(self, *, run_id: str) -> Mapping[str, Any] | None:
        value = self.status(run_id)
        if value is None or value["status"] not in _TERMINAL:
            return None
        return {
            "run_id": run_id,
            "status": value["status"],
            "result": value["result"],
            "result_digest": value["result_digest"],
            "failure_reason_code": value["failure_reason_code"],
            "revision": value["revision"],
        }

    def status(self, run_id: str) -> Mapping[str, Any] | None:
        with self.database.session() as session:
            row = session.scalar(
                select(RuntimeRunRow).where(RuntimeRunRow.run_id == run_id)
            )
            if row is None:
                return None
            return {
                "run_id": row.run_id,
                "task_id": row.task_id,
                "grant_id": row.grant_id,
                "status": row.status,
                "worker_identity": row.worker_identity,
                "cancel_reason_code": row.cancel_reason_code,
                "failure_reason_code": row.failure_reason_code,
                "result": row.result_document,
                "result_digest": row.result_digest,
                "revision": row.revision,
                "release_authorization": False,
            }

    def health(self) -> Mapping[str, Any]:
        return {
            "status": "ready" if self.database.ping() else "not_ready",
            "transport": "postgresql_runner_queue",
            "release_authorization": False,
        }


class DurableRunnerWorker:
    """Claim and execute one queue item with terminal Lease and audit closure."""

    def __init__(
        self,
        database: Database,
        *,
        grants: SqlSignedGrantRegistry,
        leases: LeaseCoordinator,
        audit: AuditRecorder,
        handlers: Mapping[str, Callable[[Mapping[str, Any]], Mapping[str, Any]]],
        worker_identity: str = "workload_r2_evaluation_runner",
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not worker_identity.startswith("workload_") or not handlers:
            raise RunnerQueueError("runner_worker_configuration_invalid")
        self.database = database
        self.grants = grants
        self.leases = leases
        self.audit = audit
        self.handlers = dict(handlers)
        self.worker_identity = worker_identity
        self.now = now or _utcnow

    def run_once(self) -> str | None:
        claimed = self._claim()
        if claimed is None:
            return None
        run_id, invocation = claimed
        lease_id = self.leases.claim(
            run_id=run_id,
            worker_identity=self.worker_identity,
            ttl_seconds=max(5, min(300, invocation.timeout_seconds)),
        )
        outcome = "failed"
        try:
            status = self._status(run_id)
            if status == "cancel_requested":
                outcome = "cancelled"
                self._close(
                    run_id, outcome="cancelled", result=None,
                    reason_code="runtime_cancelled",
                )
                return run_id
            if _time(invocation.expires_at) <= self.now().astimezone(timezone.utc):
                self._close(
                    run_id,
                    outcome="failed",
                    result=None,
                    reason_code="runtime_invocation_expired",
                )
                return run_id
            self.grants.authorize(invocation)
            handler = self.handlers.get(invocation.operation)
            if handler is None:
                self._close(
                    run_id,
                    outcome="failed",
                    result=None,
                    reason_code="runtime_handler_not_registered",
                )
                return run_id
            execution_outcome, result, reason_code = self._execute_isolated(
                run_id=run_id,
                invocation=invocation,
                handler=handler,
            )
            if execution_outcome != "completed":
                outcome = execution_outcome
                self._close(
                    run_id,
                    outcome=execution_outcome,
                    result=result,
                    reason_code=reason_code,
                )
                return run_id
            if result is None:
                raise RunnerQueueError("runtime_handler_failed_closed")
            outcome = "completed"
            self._close(run_id, outcome=outcome, result=result)
            return run_id
        except Exception as error:  # noqa: BLE001 - Runner is a trust boundary
            reason = getattr(error, "reason_code", "runtime_handler_failed_closed")
            if not isinstance(reason, str) or not _REASON.fullmatch(reason):
                reason = "runtime_handler_failed_closed"
            self._close(run_id, outcome="failed", result=None, reason_code=reason)
            return run_id
        finally:
            self.grants.consume(grant_id=invocation.grant_id)
            self.leases.close(
                lease_id=lease_id,
                worker_identity=self.worker_identity,
                outcome=outcome,
            )
            self.audit.record(
                correlation_id=run_id,
                event_type="runtime_terminal",
                actor_ref=self.worker_identity,
                payload={"run_id": run_id, "outcome": outcome},
            )

    def _execute_isolated(
        self,
        *,
        run_id: str,
        invocation: RuntimeInvocation,
        handler: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    ) -> tuple[str, Mapping[str, Any] | None, str | None]:
        if os.name != "posix":
            raise RunnerQueueError("runtime_process_isolation_unavailable")
        context = multiprocessing.get_context("fork")
        parent_connection, child_connection = context.Pipe(duplex=False)
        process = context.Process(
            target=_handler_process,
            args=(handler, invocation.to_mapping(), child_connection),
            daemon=False,
        )
        process.start()
        child_connection.close()
        deadline = time.monotonic() + invocation.timeout_seconds
        try:
            while process.is_alive():
                if self._status(run_id) == "cancel_requested":
                    _terminate_process_group(process)
                    return "cancelled", None, "runtime_cancelled"
                if time.monotonic() >= deadline:
                    _terminate_process_group(process)
                    return "failed", None, "runtime_handler_timeout"
                process.join(0.05)
            process.join()
            if not parent_connection.poll():
                return "failed", None, "runtime_handler_failed_closed"
            message_type, payload = parent_connection.recv()
            if message_type == "error":
                if isinstance(payload, Mapping):
                    reason_code = payload.get("reason_code")
                    failure_result = payload.get("failure_result")
                    if (
                        isinstance(reason_code, str)
                        and _REASON.fullmatch(reason_code)
                        and isinstance(failure_result, Mapping)
                    ):
                        result = dict(failure_result)
                        _validate_runner_result(result)
                        return "failed", result, reason_code
                return "failed", None, str(payload)
            if message_type != "result" or not isinstance(payload, Mapping):
                return "failed", None, "runtime_handler_failed_closed"
            result = dict(payload)
            _validate_runner_result(result)
            if self._status(run_id) == "cancel_requested":
                return "cancelled", None, "runtime_cancelled"
            return "completed", result, None
        finally:
            parent_connection.close()
            if process.is_alive():
                _terminate_process_group(process)
            process.close()

    def _claim(self) -> tuple[str, RuntimeInvocation] | None:
        with self.database.session() as session:
            row = session.scalar(
                select(RuntimeRunRow)
                .where(RuntimeRunRow.status.in_(("queued", "cancel_requested")))
                .order_by(RuntimeRunRow.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if row is None:
                return None
            row.worker_identity = self.worker_identity
            if row.status == "queued":
                row.status = "running"
            row.started_at = self.now().astimezone(timezone.utc)
            row.revision += 1
            _append_event(
                session,
                run_id=row.run_id,
                event_type="runtime_claimed",
                payload={"worker_identity": self.worker_identity},
                recorded_at=self.now().astimezone(timezone.utc),
            )
            return row.run_id, RuntimeInvocation.from_mapping(row.invocation)

    def _status(self, run_id: str) -> str:
        with self.database.session() as session:
            row = session.scalar(
                select(RuntimeRunRow).where(RuntimeRunRow.run_id == run_id)
            )
            if row is None:
                raise RunnerQueueError("runtime_run_not_found")
            return row.status

    def _close(
        self,
        run_id: str,
        *,
        outcome: str,
        result: Mapping[str, Any] | None,
        reason_code: str | None = None,
    ) -> None:
        if outcome not in _TERMINAL:
            raise RunnerQueueError("runtime_outcome_invalid")
        with self.database.session() as session:
            row = session.scalar(
                select(RuntimeRunRow)
                .where(RuntimeRunRow.run_id == run_id)
                .with_for_update()
            )
            if row is None:
                raise RunnerQueueError("runtime_run_not_found")
            if row.status in _TERMINAL:
                return
            row.status = outcome
            row.result_document = None if result is None else dict(result)
            row.result_digest = None if result is None else canonical_digest(result)
            row.failure_reason_code = reason_code
            row.closed_at = self.now().astimezone(timezone.utc)
            row.revision += 1
            _append_event(
                session,
                run_id=run_id,
                event_type="runtime_" + outcome,
                payload={
                    "result_digest": row.result_digest,
                    "reason_code": reason_code,
                },
                recorded_at=self.now().astimezone(timezone.utc),
            )


def build_signed_grant_document(
    *,
    invocation: RuntimeInvocation,
    evidence_status: str,
    issued_at: str,
) -> dict[str, Any]:
    if evidence_status not in {"synthetic", "public"}:
        raise RunnerQueueError("runner_signed_grant_evidence_invalid")
    if (evidence_status == "synthetic") != invocation.synthetic_only:
        raise RunnerQueueError("runner_signed_grant_evidence_invalid")
    document = {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "ExecutionGrant",
        "metadata": {
            "grant_id": invocation.grant_id,
            "status": "active",
            "evidence_status": evidence_status,
            "synthetic_only": invocation.synthetic_only,
            "issued_at": issued_at,
            "expires_at": invocation.expires_at,
        },
        "spec": {
            "qualification_grant_digest": invocation.grant_digest,
            "task_digest": invocation.task_digest,
            "composition_digest": invocation.composition_digest,
            "runtime_source_digest": invocation.runtime_source_digest,
            "invocation_digest": canonical_digest(invocation.to_mapping()),
            "data_classification": invocation.data_classification,
            "production_authorization": False,
            "release_authorization": False,
        },
    }
    if invocation.container_bound:
        document["spec"].update(
            {
                "runtime_artifact_digest": invocation.runtime_artifact_digest,
                "runtime_image_digest": invocation.runtime_image_digest,
                "isolation_profile_digest": invocation.isolation_profile_digest,
                "department_id": invocation.department_id,
                "agent_binding_ref": invocation.agent_binding_ref,
                "agent_binding_digest": invocation.agent_binding_digest,
            }
        )
    canonical_bytes(document)
    return document


def _append_event(
    session,
    *,
    run_id: str,
    event_type: str,
    payload: Mapping[str, Any],
    recorded_at: datetime,
) -> None:
    maximum = session.scalar(
        select(func.max(RuntimeEventRow.sequence)).where(
            RuntimeEventRow.run_id == run_id
        )
    )
    sequence = 0 if maximum is None else int(maximum) + 1
    document = {
        "run_id": run_id,
        "sequence": sequence,
        "event_type": event_type,
        "payload": dict(payload),
    }
    session.add(
        RuntimeEventRow(
            run_id=run_id,
            sequence=sequence,
            event_type=event_type,
            event_digest=canonical_digest(document),
            payload=dict(payload),
            recorded_at=recorded_at,
        )
    )


def _event_mapping(row: RuntimeEventRow) -> Mapping[str, Any]:
    return {
        "run_id": row.run_id,
        "sequence": row.sequence,
        "event_type": row.event_type,
        "event_digest": row.event_digest,
        "payload": row.payload,
        "recorded_at": _as_utc(row.recorded_at).isoformat(),
    }


def _validate_runner_result(value: Mapping[str, Any]) -> None:
    if (
        not isinstance(value, Mapping)
        or value.get("release_authorization") is not False
        or value.get("production_authorization") is not False
    ):
        raise RunnerQueueError("runtime_result_invalid")
    _validate_safe_json(value)


def _handler_process(handler, invocation: Mapping[str, Any], connection) -> None:
    try:
        os.setsid()
        result = dict(handler(invocation))
        _validate_runner_result(result)
        connection.send(("result", result))
    except Exception as error:  # noqa: BLE001 - child process trust boundary
        reason = getattr(error, "reason_code", "runtime_handler_failed_closed")
        if not isinstance(reason, str) or not _REASON.fullmatch(reason):
            reason = "runtime_handler_failed_closed"
        failure_result = getattr(error, "failure_result", None)
        if isinstance(failure_result, Mapping):
            try:
                sanitized = dict(failure_result)
                _validate_runner_result(sanitized)
            except Exception:  # noqa: BLE001 - never leak invalid child data
                connection.send(("error", reason))
            else:
                connection.send(
                    (
                        "error",
                        {"reason_code": reason, "failure_result": sanitized},
                    )
                )
        else:
            connection.send(("error", reason))
    finally:
        connection.close()


def _terminate_process_group(process) -> None:
    if not process.is_alive():
        process.join()
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    process.join(1)
    if process.is_alive():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.join(1)
    if process.is_alive():
        raise RunnerQueueError("runtime_process_cleanup_failed")


def _validate_safe_json(value: Any) -> None:
    if isinstance(value, float):
        raise RunnerQueueError("runtime_json_float_forbidden")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in _FORBIDDEN_KEYS:
                raise RunnerQueueError("runtime_secret_or_path_forbidden")
            _validate_safe_json(item)
        return
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for item in value:
            _validate_safe_json(item)
        return
    if isinstance(value, str) and (_PHYSICAL.match(value) or _SECRET.search(value)):
        raise RunnerQueueError("runtime_secret_or_path_forbidden")
    if value is None or isinstance(value, (str, int, bool)):
        return
    raise RunnerQueueError("runtime_json_value_invalid")


def _time(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RunnerQueueError("runtime_time_invalid")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as error:
        raise RunnerQueueError("runtime_time_invalid") from error


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)

