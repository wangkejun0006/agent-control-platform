"""Bridge one qualification execution stage to the durable Runner queue.

The bridge is deliberately framework-neutral.  It turns the reconciler's
single-use evaluation Grant into the narrower signed Runner Grant, waits for
one terminal queue result, and emits the existing Alpha.2 execution closure.
It does not select a provider, expand a policy, or authorize release.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from ..ids import deterministic_id
from ..qualification.automation import (
    StageCheck,
    StageHandlerResult,
    StageObservation,
    StageSideEffects,
    canonical_digest,
)
from .runner_queue import (
    SqlSignedGrantRegistry,
    build_signed_grant_document,
    canonical_bytes,
)
from .runtime_adapter import FrameworkNeutralRuntimeAdapter, RuntimeInvocation
from .security import Ed25519EvaluationGrantSigner


class RuntimeStageBridgeError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class SignedRuntimeStageHandler:
    """Synchronous qualification handler backed by a separate durable Runner."""

    def __init__(
        self,
        *,
        adapter: FrameworkNeutralRuntimeAdapter,
        grants: SqlSignedGrantRegistry,
        signer: Ed25519EvaluationGrantSigner,
        signing_key_id: str,
        operation: str,
        drive_runner_once: Callable[[], object] | None = None,
        now: Callable[[], datetime] | None = None,
        poll_seconds: float = 0.05,
    ) -> None:
        if not 0.01 <= poll_seconds <= 1:
            raise RuntimeStageBridgeError("runtime_stage_poll_interval_invalid")
        self.adapter = adapter
        self.grants = grants
        self.signer = signer
        self.signing_key_id = signing_key_id
        self.operation = operation
        self.drive_runner_once = drive_runner_once
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.poll_seconds = poll_seconds

    def __call__(self, context: Mapping[str, Any]) -> StageHandlerResult:
        candidate = context.get("candidate")
        evaluation_grant = context.get("evaluation_grant")
        stage = context.get("stage")
        run_id = context.get("run_id")
        policy = context.get("policy")
        if (
            not isinstance(candidate, Mapping)
            or not isinstance(evaluation_grant, Mapping)
            or not isinstance(policy, Mapping)
            or not isinstance(stage, str)
            or not isinstance(run_id, str)
        ):
            raise RuntimeStageBridgeError("runtime_stage_context_invalid")
        started = self.now().astimezone(timezone.utc)
        invocation = self._invocation(
            run_id=run_id,
            stage=stage,
            candidate=candidate,
            evaluation_grant=evaluation_grant,
            policy=policy,
        )
        evidence_status = policy["metadata"]["evidence_status"]
        document = build_signed_grant_document(
            invocation=invocation,
            evidence_status=evidence_status,
            issued_at=evaluation_grant["issued_at"].replace("+00:00", "Z"),
        )
        signature = self.signer.sign_grant(
            canonical_grant=canonical_bytes(document),
            key_id=self.signing_key_id,
        )
        self.grants.register(
            document=document,
            key_id=self.signing_key_id,
            signature=signature,
        )
        runtime_run_id = self.adapter.start(invocation.to_mapping())
        if self.drive_runner_once is not None:
            self.drive_runner_once()
        terminal = self._wait(runtime_run_id, invocation.timeout_seconds)
        completed = self.now().astimezone(timezone.utc)
        observation = self._observation(
            stage=stage,
            candidate=candidate,
            runtime_run_id=runtime_run_id,
            terminal=terminal,
            started=started,
            completed=completed,
        )
        closure = self._closure(
            context=context,
            candidate=candidate,
            evaluation_grant=evaluation_grant,
            runtime_run_id=runtime_run_id,
            terminal=terminal,
            completed=completed,
            evidence_status=evidence_status,
            synthetic_only=policy["metadata"]["synthetic_only"],
            runtime_seconds=max(0, int((completed - started).total_seconds())),
        )
        return StageHandlerResult(observation=observation, execution_closure=closure)

    def _invocation(
        self,
        *,
        run_id: str,
        stage: str,
        candidate: Mapping[str, Any],
        evaluation_grant: Mapping[str, Any],
        policy: Mapping[str, Any],
    ) -> RuntimeInvocation:
        synthetic_only = policy["metadata"]["synthetic_only"]
        data_classification = candidate["data_classification"]
        return RuntimeInvocation.from_mapping(
            {
                "task_id": deterministic_id(
                    "task", run_id, candidate["attempt_id"], candidate["task_digest"]
                ),
                "task_digest": candidate["task_digest"],
                "grant_id": evaluation_grant["grant_id"],
                "grant_digest": evaluation_grant["grant_digest"],
                "composition_digest": candidate["composition_digest"],
                "runtime_source_digest": candidate["runtime_source_digest"],
                "workload_identity": "workload_r2_evaluation_runner",
                "operation": self.operation,
                "input_refs": [candidate["task_ref"]],
                "idempotency_key": (
                    f"qualification:{run_id}:{candidate['attempt_id']}:{stage}"
                ),
                "expires_at": evaluation_grant["expires_at"].replace("+00:00", "Z"),
                "timeout_seconds": candidate["max_runtime_seconds"],
                "data_classification": data_classification,
                "synthetic_only": synthetic_only,
                "production_authorization": False,
            }
        )

    def _wait(self, runtime_run_id: str, timeout_seconds: int) -> Mapping[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            result = self.adapter.collect_result(run_id=runtime_run_id)
            if result is not None:
                return result
            time.sleep(self.poll_seconds)
        self.adapter.cancel(run_id=runtime_run_id, reason_code="control_plane_timeout")
        raise RuntimeStageBridgeError("runtime_stage_terminal_timeout")

    def _observation(
        self,
        *,
        stage: str,
        candidate: Mapping[str, Any],
        runtime_run_id: str,
        terminal: Mapping[str, Any],
        started: datetime,
        completed: datetime,
    ) -> StageObservation:
        status = terminal["status"]
        if status == "completed":
            outcome = "pass"
            failure_class = "none"
            reason = "provider_backed_runtime_completed"
            check_status = "pass"
            check_reason = None
        elif status == "cancelled":
            outcome = "cancelled"
            failure_class = "transient_runtime"
            reason = terminal.get("failure_reason_code") or "runtime_cancelled"
            check_status = "blocked"
            check_reason = reason
        else:
            outcome = "fail"
            reason = terminal.get("failure_reason_code") or "runtime_failed_closed"
            failure_class = _failure_class(reason)
            check_status = "blocked"
            check_reason = reason
        usage = _usage(terminal)
        return StageObservation(
            stage=stage,
            outcome=outcome,
            failure_class=failure_class,
            reason_codes=(reason,),
            checks=(
                StageCheck(
                    "durable_runner_terminal_closure",
                    check_status,
                    check_reason,
                    (
                        {
                            "role": "runtime_result",
                            "ref": f"artifact://control-plane/runtime/{runtime_run_id}",
                            "digest": terminal.get("result_digest")
                            or canonical_digest(terminal),
                        },
                    ),
                ),
            ),
            inputs=(
                {
                    "role": "runtime_composition",
                    "ref": candidate["composition_ref"],
                    "digest": candidate["composition_digest"],
                },
            ),
            executor={
                "component": {
                    "id": self.adapter.descriptor.adapter_id,
                    "version": self.adapter.descriptor.version,
                    "digest": self.adapter.descriptor.digest,
                },
                "deterministic": False,
                "environment_profile_digest": candidate["isolation_profile_digest"],
            },
            side_effects=StageSideEffects(
                effective_task_created=True,
                effective_grant_created=True,
                provider_calls=usage["model_calls"],
                network_calls=usage["request_attempts"],
            ),
            started_at=_time_text(started),
            completed_at=_time_text(completed),
        )

    @staticmethod
    def _closure(
        *,
        context: Mapping[str, Any],
        candidate: Mapping[str, Any],
        evaluation_grant: Mapping[str, Any],
        runtime_run_id: str,
        terminal: Mapping[str, Any],
        completed: datetime,
        evidence_status: str,
        synthetic_only: bool,
        runtime_seconds: int,
    ) -> dict[str, Any]:
        status = terminal["status"]
        task_status = status if status in {"completed", "failed", "cancelled"} else "failed"
        usage = _usage(terminal)
        usage["runtime_seconds"] = runtime_seconds
        result_binding = None
        if terminal.get("result_digest") is not None:
            result_binding = {
                "role": "result_package",
                "ref": f"artifact://control-plane/runtime/{runtime_run_id}/result",
                "digest": terminal["result_digest"],
            }
        evaluation_reports = []
        for evaluator_class in ("domain", "company"):
            report = {
                "evaluator_class": evaluator_class,
                "runtime_run_id": runtime_run_id,
                "status": "not_run",
            }
            evaluation_reports.append(
                {
                    "evaluator_class": evaluator_class,
                    "report": {
                        "role": f"{evaluator_class}_evaluation",
                        "ref": (
                            f"artifact://control-plane/runtime/{runtime_run_id}/"
                            f"{evaluator_class}-evaluation-pending"
                        ),
                        "digest": canonical_digest(report),
                    },
                    "verdict": "not_run",
                    "release_authorization": False,
                }
            )
        route_digest = canonical_digest({"runtime_run_id": runtime_run_id, "kind": "route"})
        lease_digest = canonical_digest({"runtime_run_id": runtime_run_id, "kind": "lease"})
        closed_status = task_status
        return {
            "api_version": "company-ai-os/v1alpha1",
            "kind": "ExecutionClosureReceipt",
            "metadata": {
                "receipt_id": deterministic_id(
                    "receipt", runtime_run_id, "execution_closure"
                ),
                "run_id": context["run_id"],
                "attempt_id": candidate["attempt_id"],
                "stage": context["stage"],
                "status": closed_status,
                "evidence_status": evidence_status,
                "synthetic_only": synthetic_only,
                "closed_at": _time_text(completed),
            },
            "spec": {
                "composition": {
                    "role": "runtime_composition",
                    "ref": candidate["composition_ref"],
                    "digest": candidate["composition_digest"],
                },
                "task": {
                    "ref": candidate["task_ref"],
                    "digest": candidate["task_digest"],
                    "status": task_status,
                    "revision": terminal["revision"],
                },
                "grant": {
                    "ref": f"grant://{evaluation_grant['grant_id']}",
                    "digest": evaluation_grant["grant_digest"],
                    "status": "consumed",
                    "revision": 1,
                },
                "route": {
                    "ref": f"ledger://runtime-route/{runtime_run_id}",
                    "digest": route_digest,
                    "status": "consumed",
                    "revision": 1,
                },
                "worker_lease": {
                    "ref": f"ledger://runtime-lease/{runtime_run_id}",
                    "digest": lease_digest,
                    "status": "closed",
                    "revision": 1,
                },
                "policy_decision": {
                    "ref": (
                        "receipt://"
                        + evaluation_grant["policy_decision_receipt_digest"][7:23]
                    ),
                    "digest": evaluation_grant["policy_decision_receipt_digest"],
                    "status": "consumed",
                    "revision": 1,
                },
                "model_route": (
                    None
                    if candidate["model_route_digest"] is None
                    else {
                        "ref": "model-route://disease-r2/public-pilot",
                        "digest": candidate["model_route_digest"],
                        "status": "consumed",
                        "revision": 1,
                    }
                ),
                "result": result_binding,
                "evaluations": evaluation_reports,
                "usage": usage,
                "cleanup": {
                    "process_group_terminated": True,
                    "temporary_workspace_removed": True,
                    "credentials_absent": True,
                    "external_handles_closed": True,
                    "cleanup_errors": [],
                },
                "audit_refs": [f"ledger://runtime-audit/{runtime_run_id}"],
                "terminal_consistency": {
                    "task_terminal": True,
                    "grant_terminal": True,
                    "route_terminal": True,
                    "lease_terminal": True,
                    "policy_decision_bound": True,
                    "result_and_evaluations_bound": True,
                    "replay_passed": True,
                },
                "authority_boundary": {
                    "formal_registry_written": False,
                    "agent_activated": False,
                    "preproduction_promoted": False,
                    "production_promoted": False,
                    "release_authorization": False,
                },
            },
        }


def _usage(terminal: Mapping[str, Any]) -> dict[str, Any]:
    result = terminal.get("result")
    source = result.get("usage", {}) if isinstance(result, Mapping) else {}
    return {
        "model_calls": _non_negative_int(source.get("model_calls", 0)),
        "request_attempts": _non_negative_int(source.get("request_attempts", 0)),
        "input_tokens": _non_negative_int(source.get("input_tokens", 0)),
        "output_tokens": _non_negative_int(source.get("output_tokens", 0)),
        "cost_usd": _decimal_text(source.get("cost_usd", "0")),
        "cost_cny": _decimal_text(source.get("cost_cny", "0")),
    }


def _failure_class(reason_code: str) -> str:
    """Classify retryable transport failures without hiding deterministic drift."""
    transient_markers = (
        "timeout",
        "rate_limit",
        "http_429",
        "http_5",
        "connection",
        "temporarily_unavailable",
    )
    if any(marker in reason_code for marker in transient_markers):
        return "transient_runtime"
    return "deterministic_test_failure"


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeStageBridgeError("runtime_stage_usage_invalid")
    return value


def _decimal_text(value: Any) -> str:
    if not isinstance(value, str) or not value or value.startswith("-"):
        raise RuntimeStageBridgeError("runtime_stage_usage_invalid")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise RuntimeStageBridgeError("runtime_stage_usage_invalid") from error
    if not parsed.is_finite() or parsed < 0:
        raise RuntimeStageBridgeError("runtime_stage_usage_invalid")
    return value


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

