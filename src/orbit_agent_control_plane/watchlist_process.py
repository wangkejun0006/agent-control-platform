"""Locked Registry and Scientific process adapters for one synthetic Watchlist Task."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .dataset_agent_process import BoundedProcessRunner, DatasetAgentProcessError
from .models import RouteDecision, TaskEnvelope
from .runtime_source import (
    DatasetRuntimeSourceEvidence,
    LockedRuntimeSourceSpec,
    materialize_locked_runtime_source,
    verify_locked_runtime_source,
)


WATCHLIST_LOCK_PATH = (
    Path(__file__).resolve().parents[2]
    / "references"
    / "dataset-watchlist-implementation-lock.json"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{2,79}$")
_EVENT_ID = re.compile(r"^watch_event_[0-9a-f]{24}$")
_LOCK_KEYS = frozenset(
    {
        "lock_version",
        "task_schema_version",
        "registry",
        "scientific",
        "coordinator_target_id",
        "dataset_agent_id",
        "capability",
        "model_route_ref",
        "data_classification",
        "synthetic_only",
        "network_access",
        "max_concurrency",
        "task_limit_bytes",
        "month_limit_bytes",
        "max_model_cost_cny",
        "production_authorization",
    }
)
_REPOSITORY_KEYS = frozenset(
    {
        "repository_id",
        "implementation_commit",
        "python_module",
        "command",
    }
)
_EVENT_KEYS = frozenset(
    {
        "schema_version",
        "event_id",
        "run_id",
        "ledger_sequence",
        "previous_record_hash",
        "target",
        "observed_at",
        "change_state",
        "candidate_changed",
        "change_reasons",
        "agent_eligible",
        "eligibility_reasons",
        "previous_snapshot_digest",
        "snapshot_digest",
        "snapshot",
        "registry_write_performed",
        "model_invocation_performed",
        "record_hash",
    }
)
_SNAPSHOT_KEYS = frozenset(
    {
        "dataset_id",
        "source_kind",
        "synthetic",
        "release",
        "source_ref",
        "manifest_ref",
        "artifact_name",
        "observed_at",
        "declared_size_bytes",
        "official_sha256",
        "license_id",
        "access_mode",
    }
)
_RESULT_KEYS = frozenset(
    {
        "schema_version",
        "watchlist_event_ref",
        "watchlist_snapshot_digest",
        "task_binding",
        "status",
        "reason_codes",
        "model_invocation_count",
        "worker_invocation_count",
        "closed_loop_result",
        "model_audit",
        "registry_write_performed",
        "real_data_download_performed",
    }
)
_BINDING_KEYS = frozenset(
    {
        "task_id",
        "route_decision_ref",
        "execution_grant_ref",
        "monthly_used_before_bytes",
        "monthly_limit_bytes",
        "max_concurrency",
        "model_route_ref",
        "max_model_cost_cny",
    }
)


class WatchlistProcessError(ValueError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class RepositoryProcessLock:
    repository_id: str
    implementation_commit: str
    python_module: str
    command: str
    schema_version: str

    def runtime_spec(self) -> LockedRuntimeSourceSpec:
        module_path = "src/" + self.python_module.replace(".", "/")
        required = module_path + ("/__init__.py" if self.python_module.endswith("dataset_agent") else ".py")
        return LockedRuntimeSourceSpec(
            repository_id=self.repository_id,
            implementation_commit=self.implementation_commit,
            required_paths=(required,),
        )


@dataclass(frozen=True)
class WatchlistImplementationLock:
    lock_version: str
    task_schema_version: str
    registry: RepositoryProcessLock
    scientific: RepositoryProcessLock
    coordinator_target_id: str
    dataset_agent_id: str
    capability: str
    model_route_ref: str
    data_classification: str
    synthetic_only: bool
    network_access: str
    max_concurrency: int
    task_limit_bytes: int
    month_limit_bytes: int
    max_model_cost_cny: str
    production_authorization: bool

    @property
    def bundle_revision(self) -> str:
        material = (
            self.registry.implementation_commit
            + "\x1f"
            + self.scientific.implementation_commit
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class WatchlistRuntimeBundleEvidence:
    registry: DatasetRuntimeSourceEvidence
    scientific: DatasetRuntimeSourceEvidence
    bundle_revision: str


def load_watchlist_implementation_lock(
    path: Path | str = WATCHLIST_LOCK_PATH,
) -> WatchlistImplementationLock:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_unique)
    except WatchlistProcessError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WatchlistProcessError(
            "watchlist_lock_unavailable", "Watchlist implementation lock is unavailable"
        ) from error
    _exact_keys(document, _LOCK_KEYS, "Watchlist lock")
    registry_value = _mapping(document["registry"], "Registry lock")
    scientific_value = _mapping(document["scientific"], "Scientific lock")
    _exact_keys(
        registry_value,
        _REPOSITORY_KEYS | {"event_schema_version"},
        "Registry lock",
    )
    _exact_keys(
        scientific_value,
        _REPOSITORY_KEYS | {"result_schema_version"},
        "Scientific lock",
    )
    registry = _repository_lock(registry_value, "event_schema_version")
    scientific = _repository_lock(scientific_value, "result_schema_version")
    lock = WatchlistImplementationLock(
        lock_version=_string(document["lock_version"], "lock version"),
        task_schema_version=_string(document["task_schema_version"], "task schema"),
        registry=registry,
        scientific=scientific,
        coordinator_target_id=_string(document["coordinator_target_id"], "coordinator"),
        dataset_agent_id=_string(document["dataset_agent_id"], "Dataset Agent"),
        capability=_string(document["capability"], "capability"),
        model_route_ref=_string(document["model_route_ref"], "model route"),
        data_classification=_string(document["data_classification"], "classification"),
        synthetic_only=_boolean(document["synthetic_only"], "synthetic boundary"),
        network_access=_string(document["network_access"], "network boundary"),
        max_concurrency=_integer(document["max_concurrency"], "concurrency"),
        task_limit_bytes=_integer(document["task_limit_bytes"], "task limit"),
        month_limit_bytes=_integer(document["month_limit_bytes"], "month limit"),
        max_model_cost_cny=_string(document["max_model_cost_cny"], "model budget"),
        production_authorization=_boolean(
            document["production_authorization"], "production authorization"
        ),
    )
    if (
        lock.lock_version != "0.2.0"
        or lock.task_schema_version != "orbit.company-watchlist-task/0.1"
        or lock.registry.repository_id != "orbit-dataset-acquisition-registry"
        or lock.registry.python_module
        != "orbit_dataset_acquisition_registry.watchlist_fixture_cli"
        or lock.registry.command != "check"
        or lock.registry.schema_version != "orbit.watchlist-event/0.1"
        or lock.scientific.repository_id != "orbit-scientific-research-platform"
        or lock.scientific.python_module
        != "orbit_scientific_research_platform.dataset_agent"
        or lock.scientific.command != "watchlist-run"
        or lock.scientific.schema_version != "orbit.dataset-watchlist-run/0.2"
        or lock.data_classification != "synthetic"
        or not lock.synthetic_only
        or lock.network_access != "forbidden"
        or lock.max_concurrency != 1
        or lock.task_limit_bytes != 20_000_000_000
        or lock.month_limit_bytes != 100_000_000_000
        or lock.max_model_cost_cny != "0.100000"
        or lock.production_authorization
    ):
        raise WatchlistProcessError(
            "watchlist_lock_boundary_invalid", "Watchlist lock exceeds the D0 boundary"
        )
    for repository in (lock.registry, lock.scientific):
        if not _GIT_COMMIT.fullmatch(repository.implementation_commit):
            raise WatchlistProcessError(
                "watchlist_lock_revision_invalid", "Watchlist Revision is invalid"
            )
    return lock


def materialize_watchlist_runtime_bundle(
    registry_source_repository: Path | str,
    scientific_source_repository: Path | str,
    runtime_root: Path | str,
    *,
    implementation_lock: WatchlistImplementationLock | None = None,
) -> WatchlistRuntimeBundleEvidence:
    lock = implementation_lock or load_watchlist_implementation_lock()
    registry = materialize_locked_runtime_source(
        registry_source_repository, runtime_root, lock.registry.runtime_spec()
    )
    scientific = materialize_locked_runtime_source(
        scientific_source_repository, runtime_root, lock.scientific.runtime_spec()
    )
    return WatchlistRuntimeBundleEvidence(registry, scientific, lock.bundle_revision)


def verify_watchlist_runtime_bundle(
    registry_runtime_source: Path | str,
    scientific_runtime_source: Path | str,
    *,
    implementation_lock: WatchlistImplementationLock | None = None,
) -> WatchlistRuntimeBundleEvidence:
    lock = implementation_lock or load_watchlist_implementation_lock()
    return WatchlistRuntimeBundleEvidence(
        verify_locked_runtime_source(registry_runtime_source, lock.registry.runtime_spec()),
        verify_locked_runtime_source(scientific_runtime_source, lock.scientific.runtime_spec()),
        lock.bundle_revision,
    )


def watchlist_runtime_bundle_document(
    evidence: WatchlistRuntimeBundleEvidence,
) -> dict[str, Any]:
    return {
        "status": "ready",
        "evidence_status": "local_d0_runtime_source",
        "production_authorization": False,
        "bundle_revision": evidence.bundle_revision,
        "registry": asdict(evidence.registry),
        "scientific": asdict(evidence.scientific),
    }


class WatchlistProcessAdapter:
    def __init__(
        self,
        registry_runtime_source: Path | str,
        scientific_runtime_source: Path | str,
        *,
        implementation_lock: WatchlistImplementationLock | None = None,
        runner: BoundedProcessRunner | None = None,
    ) -> None:
        self.lock = implementation_lock or load_watchlist_implementation_lock()
        self.registry_root = Path(registry_runtime_source)
        self.scientific_root = Path(scientific_runtime_source)
        self.runner = runner or BoundedProcessRunner()
        self.registry_invocation_count = 0
        self.scientific_invocation_count = 0

    def observe(
        self,
        *,
        target: str,
        run_id: str,
        watchlist_ledger: Path | str,
        fixture: Path | str,
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        verify_watchlist_runtime_bundle(
            self.registry_root,
            self.scientific_root,
            implementation_lock=self.lock,
        )
        fixture_path = _secure_input_file(fixture)
        ledger_path = Path(watchlist_ledger)
        if not ledger_path.is_absolute():
            raise WatchlistProcessError(
                "watchlist_ledger_path_invalid", "Watchlist ledger path must be absolute"
            )
        argv = (
            sys.executable,
            "-m",
            self.lock.registry.python_module,
            self.lock.registry.command,
            "--target",
            target,
            "--run-id",
            run_id,
            "--ledger",
            str(ledger_path),
            "--fixture",
            str(fixture_path),
            "--json",
        )
        self.registry_invocation_count += 1
        capture = self._run(
            argv,
            self.registry_root,
            cancellation_probe,
            "watchlist_registry_process_failed",
            allowed_returncodes=(0,),
        )
        event = _load_unique_json(capture.stdout)
        return validate_watchlist_event(event, expected_target=target, expected_run_id=run_id)

    def evaluate(
        self,
        event: Mapping[str, Any],
        *,
        task: TaskEnvelope,
        route_decision: RouteDecision,
        monthly_used_before_bytes: int,
        cancellation_probe: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        verify_watchlist_runtime_bundle(
            self.registry_root,
            self.scientific_root,
            implementation_lock=self.lock,
        )
        with tempfile.TemporaryDirectory(prefix="orbit-watchlist-event-") as temporary:
            event_path = Path(temporary) / "event.json"
            event_path.write_text(_canonical_json(event), encoding="utf-8")
            os.chmod(event_path, 0o600)
            argv = (
                sys.executable,
                "-m",
                self.lock.scientific.python_module,
                self.lock.scientific.command,
                "--event",
                str(event_path),
                "--model-mode",
                "fixture",
                "--task-id",
                task.task_id,
                "--route-decision-ref",
                route_decision.decision_id,
                "--execution-grant-ref",
                task.grant_id,
                "--monthly-used-before-bytes",
                str(monthly_used_before_bytes),
                "--max-model-cost-cny",
                self.lock.max_model_cost_cny,
            )
            self.scientific_invocation_count += 1
            capture = self._run(
                argv,
                self.scientific_root,
                cancellation_probe,
                "watchlist_scientific_process_failed",
                allowed_returncodes=(0, 1),
            )
        result = _load_unique_json(capture.stdout)
        return validate_scientific_watchlist_result(
            result,
            event=event,
            task=task,
            route_decision=route_decision,
            monthly_used_before_bytes=monthly_used_before_bytes,
            implementation_lock=self.lock,
        )

    def _run(
        self,
        argv: tuple[str, ...],
        root: Path,
        cancellation_probe: Callable[[], bool] | None,
        failure_code: str,
        allowed_returncodes: tuple[int, ...],
    ) -> Any:
        try:
            capture = self.runner.run(
                argv,
                cwd=root,
                environment={
                    "PYTHONPATH": str(root / "src"),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONHASHSEED": "0",
                },
                timeout_seconds=5,
                max_stdout_bytes=512 * 1024,
                max_stderr_bytes=64 * 1024,
                cancellation_probe=cancellation_probe,
            )
        except DatasetAgentProcessError as error:
            code = (
                "watchlist_task_cancelled"
                if error.reason_code == "dataset_agent_process_cancelled"
                else failure_code
            )
            raise WatchlistProcessError(code, "Watchlist process failed closed") from error
        if capture.returncode not in allowed_returncodes:
            raise WatchlistProcessError(failure_code, "Watchlist process failed closed")
        return capture


def validate_watchlist_event(
    value: Any,
    *,
    expected_target: str,
    expected_run_id: str,
) -> dict[str, Any]:
    event = _mapping(value, "Watchlist event")
    _exact_keys(event, _EVENT_KEYS, "Watchlist event")
    snapshot = _mapping(event["snapshot"], "Watchlist snapshot")
    _exact_keys(snapshot, _SNAPSHOT_KEYS, "Watchlist snapshot")
    if (
        event["schema_version"] != "orbit.watchlist-event/0.1"
        or event["target"] != expected_target
        or event["run_id"] != expected_run_id
        or snapshot["dataset_id"] != expected_target
        or snapshot["synthetic"] is not True
        or snapshot["source_kind"] != "synthetic_recorded"
        or not str(snapshot["source_ref"]).startswith("synthetic://")
        or not str(snapshot["manifest_ref"]).startswith("synthetic://")
        or event["registry_write_performed"] is not False
        or event["model_invocation_performed"] is not False
    ):
        raise WatchlistProcessError(
            "watchlist_event_boundary_invalid", "Watchlist event exceeds D0 boundary"
        )
    unsigned = dict(event)
    supplied_hash = unsigned.pop("record_hash")
    if supplied_hash != _sha256_payload(unsigned):
        raise WatchlistProcessError(
            "watchlist_event_hash_invalid", "Watchlist event hash is invalid"
        )
    semantic = dict(snapshot)
    semantic.pop("observed_at")
    if event["snapshot_digest"] != _sha256_payload(semantic):
        raise WatchlistProcessError(
            "watchlist_snapshot_hash_invalid", "Watchlist snapshot hash is invalid"
        )
    if not _EVENT_ID.fullmatch(_string(event["event_id"], "event id")):
        raise WatchlistProcessError(
            "watchlist_event_identity_invalid", "Watchlist event identity is invalid"
        )
    expected_event_id = "watch_event_" + _sha256_payload(
        {
            "run_id": expected_run_id,
            "target": expected_target,
            "digest": event["snapshot_digest"],
        }
    )[:24]
    if event["event_id"] != expected_event_id:
        raise WatchlistProcessError(
            "watchlist_event_identity_invalid", "Watchlist event identity is invalid"
        )
    changed = _boolean(event["candidate_changed"], "candidate changed")
    state = _string(event["change_state"], "change state")
    eligible = _boolean(event["agent_eligible"], "Agent eligibility")
    if state not in {"baseline_initialized", "no_change", "changed"} or changed != (
        state == "changed"
    ):
        raise WatchlistProcessError(
            "watchlist_event_state_invalid", "Watchlist change state is invalid"
        )
    reasons = _string_list(event["eligibility_reasons"], "eligibility reasons")
    if eligible == bool(reasons):
        raise WatchlistProcessError(
            "watchlist_event_eligibility_invalid", "Watchlist eligibility is inconsistent"
        )
    size = snapshot["declared_size_bytes"]
    checksum = snapshot["official_sha256"]
    if eligible and (
        type(size) is not int
        or size <= 0
        or size > 20_000_000_000
        or not isinstance(checksum, str)
        or not _SHA256.fullmatch(checksum)
        or not snapshot["license_id"]
        or snapshot["access_mode"] != "public_ungated"
    ):
        raise WatchlistProcessError(
            "watchlist_event_eligibility_invalid", "Eligible Watchlist evidence is incomplete"
        )
    return event


def validate_scientific_watchlist_result(
    value: Any,
    *,
    event: Mapping[str, Any],
    task: TaskEnvelope,
    route_decision: RouteDecision,
    monthly_used_before_bytes: int,
    implementation_lock: WatchlistImplementationLock,
) -> dict[str, Any]:
    result = _mapping(value, "Scientific Watchlist result")
    _exact_keys(result, _RESULT_KEYS, "Scientific Watchlist result")
    binding = _mapping(result["task_binding"], "Scientific task binding")
    _exact_keys(binding, _BINDING_KEYS, "Scientific task binding")
    if (
        result["schema_version"] != implementation_lock.scientific.schema_version
        or result["watchlist_event_ref"] != event["event_id"]
        or result["watchlist_snapshot_digest"] != event["snapshot_digest"]
        or binding["task_id"] != task.task_id
        or binding["route_decision_ref"] != route_decision.decision_id
        or binding["execution_grant_ref"] != task.grant_id
        or binding["monthly_used_before_bytes"] != monthly_used_before_bytes
        or binding["monthly_limit_bytes"] != implementation_lock.month_limit_bytes
        or binding["max_concurrency"] != 1
        or binding["model_route_ref"] != implementation_lock.model_route_ref
        or binding["max_model_cost_cny"] != implementation_lock.max_model_cost_cny
        or result["registry_write_performed"] is not False
        or result["real_data_download_performed"] is not False
        or result["model_audit"] != []
    ):
        raise WatchlistProcessError(
            "watchlist_result_binding_invalid", "Scientific result binding is invalid"
        )
    status = _string(result["status"], "Scientific status")
    if status not in {"completed", "skipped", "blocked"}:
        raise WatchlistProcessError(
            "watchlist_result_status_invalid", "Scientific result status is invalid"
        )
    model_count = _integer(result["model_invocation_count"], "model invocation count")
    worker_count = _integer(result["worker_invocation_count"], "worker invocation count")
    if model_count not in {0, 1} or worker_count not in {0, 1} or worker_count > model_count:
        raise WatchlistProcessError(
            "watchlist_result_invocation_invalid", "Scientific invocation count is invalid"
        )
    if status == "skipped":
        if model_count != 0 or worker_count != 0 or result["closed_loop_result"] is not None:
            raise WatchlistProcessError(
                "watchlist_result_skip_invalid", "Skipped Scientific result is invalid"
            )
        return result
    closed = _mapping(result["closed_loop_result"], "Dataset closed loop")
    if (
        closed.get("task_id") != task.task_id
        or closed.get("route_decision_ref") != route_decision.decision_id
        or closed.get("execution_grant_ref") != task.grant_id
        or closed.get("model_route_ref") != implementation_lock.model_route_ref
        or closed.get("agent_id") != implementation_lock.dataset_agent_id
    ):
        raise WatchlistProcessError(
            "watchlist_result_domain_binding_invalid", "Dataset result binding is invalid"
        )
    authority = _mapping(closed.get("authority_boundary"), "authority boundary")
    if authority != {
        "synthetic_only": True,
        "effective_grant_created": False,
        "approved_asset_release_created": False,
        "runtime_selected": False,
        "model_route_selected": False,
    }:
        raise WatchlistProcessError(
            "watchlist_result_authority_invalid", "Dataset result claimed authority"
        )
    if status == "completed":
        scout = _mapping(closed.get("scout"), "Scout outcome")
        request = _mapping(scout.get("acquisition_request"), "Acquisition request")
        receipt = _mapping(closed.get("receipt"), "Acquisition receipt")
        evaluation = _mapping(closed.get("evaluation"), "Dataset evaluation")
        if (
            model_count != 1
            or worker_count != 1
            or request.get("monthly_used_before_bytes") != monthly_used_before_bytes
            or request.get("expected_size_bytes") != event["snapshot"]["declared_size_bytes"]
            or request.get("max_concurrency") != 1
            or receipt.get("storage_write_performed") is not False
            or receipt.get("status") != "verified"
            or evaluation.get("decision") != "pass"
            or evaluation.get("approved_asset_release_created") is not False
            or evaluation.get("data_use_approved") is not False
            or evaluation.get("registry_publish_performed") is not False
        ):
            raise WatchlistProcessError(
                "watchlist_result_domain_invalid", "Completed Dataset result is invalid"
            )
    return result


def _secure_input_file(path: Path | str) -> Path:
    supplied = Path(path)
    if supplied.is_symlink():
        raise WatchlistProcessError(
            "watchlist_fixture_symlink_forbidden", "Watchlist fixture may not be a symlink"
        )
    try:
        resolved = supplied.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise WatchlistProcessError(
            "watchlist_fixture_unavailable", "Watchlist fixture is unavailable"
        ) from error
    if (
        not resolved.is_file()
        or metadata.st_uid != os.getuid()
        or metadata.st_size > 256 * 1024
    ):
        raise WatchlistProcessError(
            "watchlist_fixture_invalid", "Watchlist fixture is invalid"
        )
    return resolved


def _repository_lock(value: Mapping[str, Any], schema_key: str) -> RepositoryProcessLock:
    return RepositoryProcessLock(
        repository_id=_string(value["repository_id"], "repository id"),
        implementation_commit=_string(value["implementation_commit"], "Revision"),
        python_module=_string(value["python_module"], "Python module"),
        command=_string(value["command"], "command"),
        schema_version=_string(value[schema_key], "schema version"),
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256_payload(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _load_unique_json(source: bytes) -> Any:
    try:
        return json.loads(
            source.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=_reject_constant,
        )
    except WatchlistProcessError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WatchlistProcessError(
            "watchlist_process_invalid_json", "Watchlist process returned invalid JSON"
        ) from error


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WatchlistProcessError(
                "watchlist_duplicate_json_key", "Watchlist JSON contains duplicate keys"
            )
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise WatchlistProcessError(
        "watchlist_invalid_json_constant", "Watchlist JSON contains invalid constants"
    )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WatchlistProcessError("watchlist_shape_invalid", f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], keys: frozenset[str], label: str) -> None:
    if set(value) != keys:
        raise WatchlistProcessError("watchlist_shape_invalid", f"{label} fields are invalid")


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WatchlistProcessError("watchlist_type_invalid", f"{label} must be a string")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise WatchlistProcessError("watchlist_type_invalid", f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise WatchlistProcessError("watchlist_type_invalid", f"{label} must be an integer")
    return value


def _string_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise WatchlistProcessError("watchlist_type_invalid", f"{label} must be strings")
    return tuple(value)

