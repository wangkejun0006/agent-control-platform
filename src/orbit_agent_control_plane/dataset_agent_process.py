"""Process-boundary D0 integration for the single Scientific Dataset Agent.

The adapter never imports Scientific Research Platform domain code. It invokes
one locked synthetic CLI command with an allowlisted environment, validates the
entire JSON result, and maps it into company-level Result/Audit objects for an
independent Company Evaluator decision.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from .evaluator import CompanyEvaluator
from .ids import deterministic_id
from .models import (
    AuditEvent,
    ClosedLoopOutcome,
    RouteDecision,
    RoutingTarget,
    TaskControlSnapshot,
    TaskEnvelope,
    TaskResult,
)
from .router import CompanyTaskRouter


DATASET_AGENT_ID = "agt_orbit_research_dataset_scout_acquisition_syn"
DATASET_AGENT_CAPABILITY = "dataset_acquisition.request_create"
DATASET_AGENT_RESULT_SCHEMA = "orbit.dataset-agent-closed-loop/0.1"
DATASET_AGENT_RUNTIME_FAMILY = "thin_python_worker_design_candidate"
DATASET_AGENT_WORKER_ID = "worker_orbit_dataset_acquisition_deterministic_syn"
DATASET_AGENT_EVALUATOR_ID = "component_orbit_dataset_acquisition_evaluator_syn"
DATASET_TASK_LIMIT_BYTES = 20_000_000_000
DATASET_MONTH_LIMIT_BYTES = 100_000_000_000
IMPLEMENTATION_LOCK_PATH = (
    Path(__file__).resolve().parents[2]
    / "references"
    / "dataset-agent-implementation-lock.json"
)

_LOCK_KEYS = frozenset(
    {
        "lock_version",
        "repository_id",
        "implementation_commit",
        "python_module",
        "command",
        "agent_id",
        "capability",
        "result_schema_version",
        "model_route_ref",
        "data_classification",
        "synthetic_only",
        "network_access",
        "production_authorization",
    }
)
_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "task_id",
        "route_decision_ref",
        "execution_grant_ref",
        "model_route_ref",
        "status",
        "agent_id",
        "runtime_family",
        "scout",
        "receipt",
        "evaluation",
        "audit_events",
        "authority_boundary",
    }
)
_REQUEST_KEYS = frozenset(
    {
        "request_id",
        "task_id",
        "agent_id",
        "route_decision_ref",
        "execution_grant_ref",
        "model_route_ref",
        "dataset_id",
        "release",
        "source_ref",
        "artifact_name",
        "expected_size_bytes",
        "expected_sha256",
        "license_id",
        "classification",
        "registry_snapshot_digest",
        "monthly_used_before_bytes",
        "task_limit_bytes",
        "month_limit_bytes",
        "max_concurrency",
        "transfer_mode",
        "execution_authority",
        "schema_version",
    }
)
_SCOUT_KEYS = frozenset(
    {"status", "reason_codes", "rationale", "acquisition_request", "model_usage"}
)
_MODEL_USAGE_KEYS = frozenset(
    {
        "provider_id",
        "model_id",
        "input_tokens",
        "output_tokens",
        "cached_input_tokens",
        "cost_cny",
    }
)
_RECEIPT_KEYS = frozenset(
    {
        "receipt_id",
        "task_id",
        "idempotency_key",
        "worker_id",
        "request_digest",
        "dataset_id",
        "release",
        "status",
        "reason_codes",
        "actual_size_bytes",
        "actual_sha256",
        "transport",
        "storage_write_performed",
        "started_at",
        "completed_at",
    }
)
_EVALUATION_KEYS = frozenset(
    {
        "report_id",
        "task_id",
        "evaluator_component_id",
        "subject_agent_id",
        "receipt_id",
        "decision",
        "reason_codes",
        "approved_asset_release_created",
        "data_use_approved",
        "registry_publish_performed",
    }
)
_AUDIT_KEYS = frozenset(
    {"event_id", "sequence", "task_id", "event_type", "subject_id", "payload_digest"}
)
_AUTHORITY_KEYS = frozenset(
    {
        "synthetic_only",
        "effective_grant_created",
        "approved_asset_release_created",
        "runtime_selected",
        "model_route_selected",
    }
)
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_EXPECTED_AUDIT_TYPES = (
    "registry_metadata_observed",
    "scout_decision_recorded",
    "acquisition_receipt_recorded",
    "dataset_acquisition_evaluated",
)


class DatasetAgentProcessError(ValueError):
    """Fail-closed integration error carrying no subprocess content or path."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class DatasetAgentImplementationLock:
    lock_version: str
    repository_id: str
    implementation_commit: str
    python_module: str
    command: str
    agent_id: str
    capability: str
    result_schema_version: str
    model_route_ref: str
    data_classification: str
    synthetic_only: bool
    network_access: str
    production_authorization: bool


@dataclass(frozen=True)
class ProcessCapture:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class DatasetAgentExecutionEvidence:
    implementation_revision: str
    domain_schema_version: str
    agent_id: str
    runtime_family: str
    receipt_id: str
    receipt_status: str
    actual_size_bytes: int
    actual_sha256: str
    domain_evaluation_report_id: str
    domain_evaluation_decision: str
    domain_audit_event_refs: tuple[str, ...]
    model_provider_id: str
    model_id: str
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    model_cost_cny: str
    storage_write_performed: bool
    data_use_approved: bool
    registry_publish_performed: bool
    approved_asset_release_created: bool


@dataclass(frozen=True)
class DatasetAgentProcessExecution:
    result: TaskResult
    audit_event: AuditEvent
    evidence: DatasetAgentExecutionEvidence


@dataclass(frozen=True)
class DatasetCompanyLoopOutcome:
    status: str
    reason_codes: tuple[str, ...]
    company_outcome: ClosedLoopOutcome
    adapter_evidence: DatasetAgentExecutionEvidence | None


class ProcessRunnerPort(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> ProcessCapture:
        ...


class DatasetAgentExecutionPort(Protocol):
    def execute(
        self,
        task: TaskEnvelope,
        route_decision: RouteDecision,
    ) -> DatasetAgentProcessExecution:
        ...


class BoundedProcessRunner:
    """Run a fixed argv without a shell, bounding time and both output streams."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> ProcessCapture:
        if (
            not argv
            or timeout_seconds <= 0
            or max_stdout_bytes <= 0
            or max_stderr_bytes <= 0
        ):
            raise DatasetAgentProcessError(
                "dataset_agent_process_config_invalid",
                "process configuration is invalid",
            )
        try:
            process = subprocess.Popen(
                tuple(argv),
                cwd=cwd,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
            )
        except OSError as error:
            raise DatasetAgentProcessError(
                "dataset_agent_process_start_failed",
                "Dataset Agent process could not be started",
            ) from error
        if process.stdout is None or process.stderr is None:
            _stop_process(process)
            raise DatasetAgentProcessError(
                "dataset_agent_process_pipe_unavailable",
                "process output pipes are unavailable",
            )

        buffers: dict[str, bytearray] = {
            "stdout": bytearray(),
            "stderr": bytearray(),
        }
        limits = {"stdout": max_stdout_bytes, "stderr": max_stderr_bytes}
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = time.monotonic() + timeout_seconds
        try:
            while selector.get_map():
                if cancellation_probe is not None:
                    try:
                        cancelled = cancellation_probe()
                    except Exception as error:
                        _stop_process(process)
                        raise DatasetAgentProcessError(
                            "dataset_agent_cancellation_probe_failed",
                            "Dataset Agent cancellation state could not be verified",
                        ) from error
                    if cancelled:
                        _stop_process(process)
                        raise DatasetAgentProcessError(
                            "dataset_agent_process_cancelled",
                            "Dataset Agent process was cancelled by Task control",
                        )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _stop_process(process)
                    raise DatasetAgentProcessError(
                        "dataset_agent_process_timeout",
                        "Dataset Agent process exceeded the time limit",
                    )
                events = selector.select(min(remaining, 0.05))
                if not events:
                    continue
                for key, _ in events:
                    label = str(key.data)
                    chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    buffers[label].extend(chunk)
                    if len(buffers[label]) > limits[label]:
                        _stop_process(process)
                        raise DatasetAgentProcessError(
                            f"dataset_agent_{label}_limit_exceeded",
                            "Dataset Agent process output exceeded its size limit",
                        )
            returncode = process.wait(timeout=1)
        except DatasetAgentProcessError:
            raise
        except (OSError, subprocess.SubprocessError) as error:
            _stop_process(process)
            raise DatasetAgentProcessError(
                "dataset_agent_process_transport_error",
                "Dataset Agent process transport failed",
            ) from error
        finally:
            selector.close()
        return ProcessCapture(
            returncode=returncode,
            stdout=bytes(buffers["stdout"]),
            stderr=bytes(buffers["stderr"]),
        )


class DatasetAgentProcessAdapter:
    """Invoke and strictly validate the locked synthetic Dataset Agent CLI."""

    def __init__(
        self,
        project_root: Path | str,
        *,
        implementation_lock: DatasetAgentImplementationLock | None = None,
        runner: ProcessRunnerPort | None = None,
        timeout_seconds: float = 5.0,
        max_stdout_bytes: int = 512 * 1024,
        max_stderr_bytes: int = 64 * 1024,
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> None:
        self._project_root = Path(project_root)
        self._lock = implementation_lock or load_dataset_agent_implementation_lock()
        self._runner = runner or BoundedProcessRunner()
        self._timeout_seconds = timeout_seconds
        self._max_stdout_bytes = max_stdout_bytes
        self._max_stderr_bytes = max_stderr_bytes
        self._cancellation_probe = cancellation_probe
        if (
            timeout_seconds <= 0
            or timeout_seconds > 30
            or max_stdout_bytes <= 0
            or max_stdout_bytes > 2 * 1024 * 1024
            or max_stderr_bytes <= 0
            or max_stderr_bytes > 256 * 1024
        ):
            raise DatasetAgentProcessError(
                "dataset_agent_process_config_invalid",
                "Dataset Agent process limits are outside the D0 boundary",
            )

    def execute(
        self,
        task: TaskEnvelope,
        route_decision: RouteDecision,
    ) -> DatasetAgentProcessExecution:
        self._validate_company_input(task, route_decision)
        project_root = verify_dataset_agent_implementation(
            self._project_root,
            self._lock,
        )
        environment = {
            "PYTHONPATH": str(project_root / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
        }
        argv = (
            sys.executable,
            "-m",
            self._lock.python_module,
            self._lock.command,
            "--task-id",
            task.task_id,
            "--route-decision-ref",
            route_decision.decision_id,
            "--execution-grant-ref",
            task.grant_id,
            "--model-route-ref",
            self._lock.model_route_ref,
        )
        capture = self._runner.run(
            argv,
            cwd=project_root,
            environment=environment,
            timeout_seconds=self._timeout_seconds,
            max_stdout_bytes=self._max_stdout_bytes,
            max_stderr_bytes=self._max_stderr_bytes,
            cancellation_probe=self._cancellation_probe,
        )
        if capture.returncode != 0:
            raise DatasetAgentProcessError(
                "dataset_agent_process_failed",
                "Dataset Agent process returned a non-zero status",
            )
        document = _load_unique_json(capture.stdout)
        evidence = _validate_domain_result(
            document,
            task=task,
            route_decision=route_decision,
            implementation_lock=self._lock,
        )
        completion_audit = AuditEvent(
            event_id=deterministic_id(
                "audit",
                task.task_id,
                route_decision.decision_id,
                evidence.receipt_id,
                *evidence.domain_audit_event_refs,
            ),
            task_id=task.task_id,
            event_type="dataset_agent_process_completed",
            subject_ref=DATASET_AGENT_ID,
        )
        result = TaskResult(
            result_id=deterministic_id(
                "result",
                task.task_id,
                DATASET_AGENT_ID,
                evidence.receipt_id,
                completion_audit.event_id,
            ),
            task_id=task.task_id,
            target_id=DATASET_AGENT_ID,
            status="completed",
            output_ref=(
                f"artifact://synthetic/{task.task_id}/"
                f"dataset-acquisition-receipt/{evidence.receipt_id}"
            ),
            audit_event_refs=(completion_audit.event_id,),
            side_effects=(),
        )
        return DatasetAgentProcessExecution(result, completion_audit, evidence)

    def _validate_company_input(
        self,
        task: TaskEnvelope,
        route_decision: RouteDecision,
    ) -> None:
        checks = (
            (not task.task_id.startswith("task_synthetic_"), "dataset_task_id_not_synthetic"),
            (task.capability != self._lock.capability, "dataset_capability_mismatch"),
            (
                task.data_classification != self._lock.data_classification,
                "dataset_classification_mismatch",
            ),
            (not task.grant_active, "dataset_execution_grant_inactive"),
            (route_decision.task_id != task.task_id, "dataset_route_task_mismatch"),
            (route_decision.status != "routed", "dataset_route_not_routed"),
            (route_decision.target_id != self._lock.agent_id, "dataset_route_target_mismatch"),
        )
        for failed, reason_code in checks:
            if failed:
                raise DatasetAgentProcessError(
                    reason_code,
                    "company task or route is outside the Dataset Agent D0 boundary",
                )


class DatasetAgentCompanyLoop:
    """Company Router -> process Adapter -> independent Company Evaluator."""

    def __init__(
        self,
        adapter: DatasetAgentExecutionPort,
        *,
        router: CompanyTaskRouter | None = None,
        evaluator: CompanyEvaluator | None = None,
    ) -> None:
        self._adapter = adapter
        self._router = router or CompanyTaskRouter()
        self._evaluator = evaluator or CompanyEvaluator()
        self._target = RoutingTarget(
            target_id=DATASET_AGENT_ID,
            capabilities=frozenset({DATASET_AGENT_CAPABILITY}),
            allowed_data_classifications=frozenset({"public"}),
        )

    def run(
        self,
        task: TaskEnvelope,
        *,
        control_snapshot: TaskControlSnapshot | None = None,
        control_audit_events: tuple[AuditEvent, ...] = (),
    ) -> DatasetCompanyLoopOutcome:
        route_decision = self._router.route(
            task,
            (self._target,),
            control_snapshot,
            control_audit_events,
        )
        route_audit = AuditEvent(
            event_id=f"audit_{route_decision.decision_id}",
            task_id=task.task_id,
            event_type="route_decision_recorded",
            subject_ref=self._router.agent_id,
        )
        if route_decision.status != "routed":
            company_outcome = ClosedLoopOutcome(
                task=task,
                route_decision=route_decision,
                result=None,
                evaluation=None,
                audit_events=control_audit_events + (route_audit,),
                control_snapshot=control_snapshot,
            )
            return DatasetCompanyLoopOutcome(
                "blocked",
                route_decision.reason_codes,
                company_outcome,
                None,
            )

        try:
            execution = self._adapter.execute(task, route_decision)
        except DatasetAgentProcessError as error:
            company_outcome = ClosedLoopOutcome(
                task=task,
                route_decision=route_decision,
                result=None,
                evaluation=None,
                audit_events=control_audit_events + (route_audit,),
                control_snapshot=control_snapshot,
            )
            return DatasetCompanyLoopOutcome(
                "blocked",
                (error.reason_code,),
                company_outcome,
                None,
            )

        audits = control_audit_events + (route_audit, execution.audit_event)
        evaluation = self._evaluator.evaluate(
            task=task,
            route_decision=route_decision,
            result=execution.result,
            audit_events=audits,
            subject_agent_id=DATASET_AGENT_ID,
        )
        company_outcome = ClosedLoopOutcome(
            task=task,
            route_decision=route_decision,
            result=execution.result,
            evaluation=evaluation,
            audit_events=audits,
            control_snapshot=control_snapshot,
        )
        status = "pass" if evaluation.verdict == "pass" else "fail"
        return DatasetCompanyLoopOutcome(
            status,
            evaluation.reason_codes,
            company_outcome,
            execution.evidence,
        )


def load_dataset_agent_implementation_lock(
    path: Path | str = IMPLEMENTATION_LOCK_PATH,
) -> DatasetAgentImplementationLock:
    lock_path = Path(path)
    try:
        source = lock_path.read_bytes()
    except OSError as error:
        raise DatasetAgentProcessError(
            "dataset_agent_lock_unavailable",
            "Dataset Agent implementation lock is unavailable",
        ) from error
    document = _load_unique_json(source)
    _exact_keys(document, _LOCK_KEYS, "implementation lock")
    lock = DatasetAgentImplementationLock(
        lock_version=_string(document["lock_version"], "lock version"),
        repository_id=_string(document["repository_id"], "repository id"),
        implementation_commit=_string(
            document["implementation_commit"], "implementation commit"
        ),
        python_module=_string(document["python_module"], "python module"),
        command=_string(document["command"], "command"),
        agent_id=_string(document["agent_id"], "agent id"),
        capability=_string(document["capability"], "capability"),
        result_schema_version=_string(
            document["result_schema_version"], "result schema version"
        ),
        model_route_ref=_string(document["model_route_ref"], "model route ref"),
        data_classification=_string(
            document["data_classification"], "data classification"
        ),
        synthetic_only=_boolean(document["synthetic_only"], "synthetic only"),
        network_access=_string(document["network_access"], "network access"),
        production_authorization=_boolean(
            document["production_authorization"], "production authorization"
        ),
    )
    if (
        lock.lock_version != "0.1.0"
        or lock.repository_id != "orbit-scientific-research-platform"
        or not _COMMIT_PATTERN.fullmatch(lock.implementation_commit)
        or lock.python_module != "orbit_scientific_research_platform.dataset_agent"
        or lock.command != "synthetic-demo"
        or lock.agent_id != DATASET_AGENT_ID
        or lock.capability != DATASET_AGENT_CAPABILITY
        or lock.result_schema_version != DATASET_AGENT_RESULT_SCHEMA
        or lock.model_route_ref != "model_route_synthetic_fixture_v1"
        or lock.data_classification != "public"
        or lock.synthetic_only is not True
        or lock.network_access != "forbidden"
        or lock.production_authorization is not False
    ):
        raise DatasetAgentProcessError(
            "dataset_agent_lock_boundary_invalid",
            "Dataset Agent implementation lock exceeds the approved D0 boundary",
        )
    return lock


def verify_dataset_agent_implementation(
    project_root: Path | str,
    implementation_lock: DatasetAgentImplementationLock,
) -> Path:
    supplied = Path(project_root)
    if supplied.is_symlink():
        raise DatasetAgentProcessError(
            "dataset_agent_project_symlink_forbidden",
            "Dataset Agent project root may not be a symbolic link",
        )
    try:
        root = supplied.resolve(strict=True)
    except OSError as error:
        raise DatasetAgentProcessError(
            "dataset_agent_project_unavailable",
            "Dataset Agent project root is unavailable",
        ) from error
    module_main = (
        root
        / "src"
        / Path(implementation_lock.python_module.replace(".", "/"))
        / "__main__.py"
    )
    if not root.is_dir() or not module_main.is_file() or not (root / "pyproject.toml").is_file():
        raise DatasetAgentProcessError(
            "dataset_agent_project_shape_invalid",
            "Dataset Agent project does not contain the locked module",
        )
    git = shutil.which("git")
    if git is None:
        raise DatasetAgentProcessError(
            "dataset_agent_git_unavailable",
            "Git is required to verify the Dataset Agent implementation revision",
        )
    try:
        top = subprocess.run(
            (git, "-C", str(root), "rev-parse", "--show-toplevel"),
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout.strip()
        revision = subprocess.run(
            (git, "-C", str(root), "rev-parse", "HEAD"),
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout.strip()
        status = subprocess.run(
            (git, "-C", str(root), "status", "--porcelain=v1", "--untracked-files=normal"),
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise DatasetAgentProcessError(
            "dataset_agent_revision_verification_failed",
            "Dataset Agent implementation revision could not be verified",
        ) from error
    if Path(top).resolve() != root:
        raise DatasetAgentProcessError(
            "dataset_agent_repository_root_mismatch",
            "Dataset Agent path is not the repository root",
        )
    if revision != implementation_lock.implementation_commit:
        raise DatasetAgentProcessError(
            "dataset_agent_revision_mismatch",
            "Dataset Agent implementation does not match the lock",
        )
    if status:
        raise DatasetAgentProcessError(
            "dataset_agent_worktree_not_clean",
            "Dataset Agent implementation worktree must be clean",
        )
    return root


def dataset_synthetic_task() -> TaskEnvelope:
    return TaskEnvelope(
        task_id="task_synthetic_company_dataset_d0_syn",
        capability=DATASET_AGENT_CAPABILITY,
        data_classification="public",
        grant_id="grant_synthetic_company_dataset_d0_syn",
        grant_active=True,
        requested_target_id=DATASET_AGENT_ID,
    )


def create_dataset_agent_company_loop(
    project_root: Path | str,
    *,
    cancellation_probe: Callable[[], bool] | None = None,
) -> DatasetAgentCompanyLoop:
    return DatasetAgentCompanyLoop(
        DatasetAgentProcessAdapter(
            project_root,
            cancellation_probe=cancellation_probe,
        )
    )


def dataset_loop_document(outcome: DatasetCompanyLoopOutcome) -> dict[str, Any]:
    return {
        "status": outcome.status,
        "evidence_status": "synthetic",
        "company_authoritative": False,
        "reason_codes": list(outcome.reason_codes),
        "company_outcome": asdict(outcome.company_outcome),
        "adapter_evidence": (
            None if outcome.adapter_evidence is None else asdict(outcome.adapter_evidence)
        ),
    }


def _validate_domain_result(
    value: Any,
    *,
    task: TaskEnvelope,
    route_decision: RouteDecision,
    implementation_lock: DatasetAgentImplementationLock,
) -> DatasetAgentExecutionEvidence:
    document = _mapping(value, "Dataset Agent result")
    _exact_keys(document, _TOP_LEVEL_KEYS, "Dataset Agent result")
    exact_values = (
        ("schema_version", implementation_lock.result_schema_version),
        ("task_id", task.task_id),
        ("route_decision_ref", route_decision.decision_id),
        ("execution_grant_ref", task.grant_id),
        ("model_route_ref", implementation_lock.model_route_ref),
        ("status", "completed"),
        ("agent_id", implementation_lock.agent_id),
        ("runtime_family", DATASET_AGENT_RUNTIME_FAMILY),
    )
    for key, expected in exact_values:
        if _string(document[key], key) != expected:
            raise DatasetAgentProcessError(
                "dataset_agent_result_binding_mismatch",
                "Dataset Agent result is not bound to the company invocation",
            )

    authority = _mapping(document["authority_boundary"], "authority boundary")
    _exact_keys(authority, _AUTHORITY_KEYS, "authority boundary")
    if (
        _boolean(authority["synthetic_only"], "synthetic only") is not True
        or _boolean(authority["effective_grant_created"], "effective grant") is not False
        or _boolean(authority["approved_asset_release_created"], "approved release")
        is not False
        or _boolean(authority["runtime_selected"], "runtime selected") is not False
        or _boolean(authority["model_route_selected"], "model route selected") is not False
    ):
        raise DatasetAgentProcessError(
            "dataset_agent_authority_boundary_violated",
            "Dataset Agent result claimed authority outside the D0 boundary",
        )

    scout = _mapping(document["scout"], "scout")
    _exact_keys(scout, _SCOUT_KEYS, "scout")
    if _string(scout["status"], "scout status") != "acquisition_request":
        raise DatasetAgentProcessError(
            "dataset_agent_scout_not_completed",
            "Dataset Agent scout did not produce an acquisition request",
        )
    _empty_string_list(scout["reason_codes"], "scout reason codes")
    _string(scout["rationale"], "scout rationale")

    request = _mapping(scout["acquisition_request"], "acquisition request")
    _exact_keys(request, _REQUEST_KEYS, "acquisition request")
    request_exact = (
        ("task_id", task.task_id),
        ("agent_id", implementation_lock.agent_id),
        ("route_decision_ref", route_decision.decision_id),
        ("execution_grant_ref", task.grant_id),
        ("model_route_ref", implementation_lock.model_route_ref),
        ("classification", "public"),
        ("transfer_mode", "synthetic_in_memory"),
        ("execution_authority", "deterministic_acquisition_worker_only"),
        ("schema_version", "orbit.acquisition-request/0.1"),
    )
    for key, expected in request_exact:
        if _string(request[key], key) != expected:
            raise DatasetAgentProcessError(
                "dataset_agent_request_binding_mismatch",
                "Acquisition request is outside the company-routed D0 boundary",
            )
    dataset_id = _string(request["dataset_id"], "dataset id")
    release = _string(request["release"], "release")
    _string(request["request_id"], "request id")
    _string(request["artifact_name"], "artifact name")
    _string(request["license_id"], "license id")
    source_ref = _string(request["source_ref"], "source ref")
    if not source_ref.startswith("synthetic://"):
        raise DatasetAgentProcessError(
            "dataset_agent_source_not_synthetic",
            "Acquisition request source is not synthetic",
        )
    expected_size = _integer(request["expected_size_bytes"], "expected size")
    monthly_used = _integer(request["monthly_used_before_bytes"], "monthly used")
    if (
        expected_size <= 0
        or expected_size > DATASET_TASK_LIMIT_BYTES
        or monthly_used < 0
        or monthly_used + expected_size > DATASET_MONTH_LIMIT_BYTES
        or _integer(request["task_limit_bytes"], "task limit")
        != DATASET_TASK_LIMIT_BYTES
        or _integer(request["month_limit_bytes"], "month limit")
        != DATASET_MONTH_LIMIT_BYTES
        or _integer(request["max_concurrency"], "max concurrency") != 1
    ):
        raise DatasetAgentProcessError(
            "dataset_agent_budget_boundary_violated",
            "Acquisition request exceeded size or concurrency limits",
        )
    expected_sha256 = _sha256(request["expected_sha256"], "expected sha256")
    _sha256(request["registry_snapshot_digest"], "registry snapshot digest")

    model_usage = _mapping(scout["model_usage"], "model usage")
    _exact_keys(model_usage, _MODEL_USAGE_KEYS, "model usage")
    input_tokens = _nonnegative_integer(model_usage["input_tokens"], "input tokens")
    output_tokens = _nonnegative_integer(model_usage["output_tokens"], "output tokens")
    cached_tokens = _nonnegative_integer(
        model_usage["cached_input_tokens"], "cached input tokens"
    )
    if cached_tokens > input_tokens:
        raise DatasetAgentProcessError(
            "dataset_agent_model_usage_invalid",
            "Dataset Agent model usage is inconsistent",
        )
    model_cost = _decimal_string(model_usage["cost_cny"], "model cost")
    if model_cost != Decimal("0"):
        raise DatasetAgentProcessError(
            "dataset_agent_fixture_cost_nonzero",
            "The deterministic D0 fixture unexpectedly reported a cost",
        )
    provider_id = _string(model_usage["provider_id"], "model provider id")
    model_id = _string(model_usage["model_id"], "model id")
    if provider_id != "synthetic-deterministic" or model_id != "structured-model-fixture-v1":
        raise DatasetAgentProcessError(
            "dataset_agent_model_fixture_mismatch",
            "Dataset Agent did not use the locked deterministic model fixture",
        )

    receipt = _mapping(document["receipt"], "receipt")
    _exact_keys(receipt, _RECEIPT_KEYS, "receipt")
    _empty_string_list(receipt["reason_codes"], "receipt reason codes")
    receipt_id = _string(receipt["receipt_id"], "receipt id")
    receipt_exact = (
        ("task_id", task.task_id),
        ("worker_id", DATASET_AGENT_WORKER_ID),
        ("dataset_id", dataset_id),
        ("release", release),
        ("status", "verified"),
        ("transport", "synthetic_in_memory"),
    )
    for key, expected in receipt_exact:
        if _string(receipt[key], key) != expected:
            raise DatasetAgentProcessError(
                "dataset_agent_receipt_binding_mismatch",
                "Dataset Agent receipt is not bound to the acquisition request",
            )
    _string(receipt["idempotency_key"], "idempotency key")
    _string(receipt["started_at"], "started at")
    _string(receipt["completed_at"], "completed at")
    actual_size = _integer(receipt["actual_size_bytes"], "actual size")
    actual_sha256 = _sha256(receipt["actual_sha256"], "actual sha256")
    request_digest = sha256(
        json.dumps(
            request,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    if (
        _string(receipt["request_digest"], "request digest") != request_digest
        or actual_size != expected_size
        or actual_sha256 != expected_sha256
        or _boolean(receipt["storage_write_performed"], "storage write") is not False
    ):
        raise DatasetAgentProcessError(
            "dataset_agent_receipt_verification_failed",
            "Dataset Agent receipt failed deterministic verification",
        )

    evaluation = _mapping(document["evaluation"], "domain evaluation")
    _exact_keys(evaluation, _EVALUATION_KEYS, "domain evaluation")
    _empty_string_list(evaluation["reason_codes"], "domain evaluation reasons")
    evaluation_exact = (
        ("task_id", task.task_id),
        ("evaluator_component_id", DATASET_AGENT_EVALUATOR_ID),
        ("subject_agent_id", implementation_lock.agent_id),
        ("receipt_id", receipt_id),
        ("decision", "pass"),
    )
    for key, expected in evaluation_exact:
        if _string(evaluation[key], key) != expected:
            raise DatasetAgentProcessError(
                "dataset_agent_domain_evaluation_invalid",
                "Dataset Agent domain evaluation is invalid",
            )
    evaluation_report_id = _string(evaluation["report_id"], "evaluation report id")
    release_created = _boolean(
        evaluation["approved_asset_release_created"], "approved release created"
    )
    data_use_approved = _boolean(evaluation["data_use_approved"], "data use approved")
    registry_published = _boolean(
        evaluation["registry_publish_performed"], "registry publish performed"
    )
    if release_created or data_use_approved or registry_published:
        raise DatasetAgentProcessError(
            "dataset_agent_domain_authority_violated",
            "Dataset Agent domain evaluation claimed approval or publication",
        )

    audit_values = document["audit_events"]
    if not isinstance(audit_values, list) or len(audit_values) != 4:
        raise DatasetAgentProcessError(
            "dataset_agent_audit_sequence_invalid",
            "Dataset Agent audit sequence must contain exactly four events",
        )
    audit_refs: list[str] = []
    for expected_sequence, expected_type, raw_event in zip(
        range(1, 5), _EXPECTED_AUDIT_TYPES, audit_values
    ):
        event = _mapping(raw_event, "domain audit event")
        _exact_keys(event, _AUDIT_KEYS, "domain audit event")
        if (
            _integer(event["sequence"], "audit sequence") != expected_sequence
            or _string(event["task_id"], "audit task id") != task.task_id
            or _string(event["event_type"], "audit event type") != expected_type
        ):
            raise DatasetAgentProcessError(
                "dataset_agent_audit_sequence_invalid",
                "Dataset Agent audit sequence is invalid",
            )
        event_id = _string(event["event_id"], "audit event id")
        _string(event["subject_id"], "audit subject id")
        _sha256(event["payload_digest"], "audit payload digest")
        audit_refs.append(event_id)
    if len(set(audit_refs)) != len(audit_refs):
        raise DatasetAgentProcessError(
            "dataset_agent_audit_sequence_invalid",
            "Dataset Agent audit event ids are not unique",
        )

    return DatasetAgentExecutionEvidence(
        implementation_revision=implementation_lock.implementation_commit,
        domain_schema_version=implementation_lock.result_schema_version,
        agent_id=implementation_lock.agent_id,
        runtime_family=DATASET_AGENT_RUNTIME_FAMILY,
        receipt_id=receipt_id,
        receipt_status="verified",
        actual_size_bytes=actual_size,
        actual_sha256=actual_sha256,
        domain_evaluation_report_id=evaluation_report_id,
        domain_evaluation_decision="pass",
        domain_audit_event_refs=tuple(audit_refs),
        model_provider_id=provider_id,
        model_id=model_id,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_input_tokens=cached_tokens,
        model_cost_cny=str(model_usage["cost_cny"]),
        storage_write_performed=False,
        data_use_approved=False,
        registry_publish_performed=False,
        approved_asset_release_created=False,
    )


def _load_unique_json(source: bytes) -> Any:
    try:
        return json.loads(
            source.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except DatasetAgentProcessError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DatasetAgentProcessError(
            "dataset_agent_invalid_json",
            "Dataset Agent process did not return valid JSON",
        ) from error


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise DatasetAgentProcessError(
            "dataset_agent_result_shape_invalid",
            f"{label} must be an object",
        )
    return value


def _exact_keys(value: Any, expected: frozenset[str], label: str) -> None:
    mapping = _mapping(value, label)
    if frozenset(mapping) != expected:
        raise DatasetAgentProcessError(
            "dataset_agent_result_fields_invalid",
            f"{label} fields do not match the locked result contract",
        )


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DatasetAgentProcessError(
            "dataset_agent_result_type_invalid",
            f"{label} must be a non-empty string",
        )
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise DatasetAgentProcessError(
            "dataset_agent_result_type_invalid",
            f"{label} must be a boolean",
        )
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int:
        raise DatasetAgentProcessError(
            "dataset_agent_result_type_invalid",
            f"{label} must be an integer",
        )
    return value


def _nonnegative_integer(value: Any, label: str) -> int:
    result = _integer(value, label)
    if result < 0:
        raise DatasetAgentProcessError(
            "dataset_agent_result_type_invalid",
            f"{label} may not be negative",
        )
    return result


def _sha256(value: Any, label: str) -> str:
    result = _string(value, label)
    if not _SHA256_PATTERN.fullmatch(result):
        raise DatasetAgentProcessError(
            "dataset_agent_result_type_invalid",
            f"{label} must be a lowercase SHA-256 digest",
        )
    return result


def _decimal_string(value: Any, label: str) -> Decimal:
    text = _string(value, label)
    try:
        result = Decimal(text)
    except (InvalidOperation, ValueError) as error:
        raise DatasetAgentProcessError(
            "dataset_agent_result_type_invalid",
            f"{label} must be a decimal string",
        ) from error
    if not result.is_finite() or result < 0:
        raise DatasetAgentProcessError(
            "dataset_agent_result_type_invalid",
            f"{label} must be a non-negative finite decimal",
        )
    return result


def _empty_string_list(value: Any, label: str) -> None:
    if not isinstance(value, list) or value:
        raise DatasetAgentProcessError(
            "dataset_agent_result_type_invalid",
            f"{label} must be an empty list",
        )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DatasetAgentProcessError(
                "dataset_agent_duplicate_json_key",
                "Dataset Agent result contains a duplicate JSON key",
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise DatasetAgentProcessError(
        "dataset_agent_invalid_json_constant",
        "Dataset Agent result contains an unsupported JSON constant",
    )


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=1)
    except subprocess.SubprocessError:
        pass
    for stream in (process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()

