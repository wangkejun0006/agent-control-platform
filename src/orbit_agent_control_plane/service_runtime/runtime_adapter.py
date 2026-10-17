"""Framework-neutral Runtime Adapter port for service-mode dispatch.

The Control Plane owns validation and immutable bindings.  A separately
deployed runner transport owns process/container execution.  This module does
not open a network connection, mount a host path, or load a model credential.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from urllib.parse import urlsplit


class RuntimeAdapterError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
_REFERENCE_ID = re.compile(r"^(?:task|tsk|grant|workload)_[A-Za-z0-9_:-]{3,120}$")
_DEPARTMENT_ID = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_AGENT_BINDING_ID = re.compile(r"^agent_binding_[A-Za-z0-9_:-]{3,120}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,192}$")
_LOGICAL_SCHEMES = frozenset({"artifact", "dataset", "task", "grant", "policy"})


@dataclass(frozen=True)
class RuntimeAdapterDescriptor:
    adapter_id: str
    version: str
    digest: str
    runtime_family: str
    conformance_profiles: tuple[str, ...]
    supported_operations: tuple[str, ...]
    supports_checkpoint_restore: bool
    evidence_status: str
    synthetic_only: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RuntimeAdapterDescriptor:
        expected = {
            "adapter_id",
            "version",
            "digest",
            "runtime_family",
            "conformance_profiles",
            "supported_operations",
            "supports_checkpoint_restore",
            "evidence_status",
            "synthetic_only",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise RuntimeAdapterError("runtime_adapter_descriptor_invalid")
        profiles = _tokens(value["conformance_profiles"])
        operations = _tokens(value["supported_operations"])
        if (
            not _TOKEN.fullmatch(str(value["adapter_id"]))
            or not _VERSION.fullmatch(str(value["version"]))
            or not _DIGEST.fullmatch(str(value["digest"]))
            or not _TOKEN.fullmatch(str(value["runtime_family"]))
            or type(value["supports_checkpoint_restore"]) is not bool
            or value["evidence_status"]
            not in {
                "architecture_reference",
                "synthetic",
                "public",
                "verified_runtime",
            }
            or type(value["synthetic_only"]) is not bool
        ):
            raise RuntimeAdapterError("runtime_adapter_descriptor_invalid")
        return cls(
            adapter_id=value["adapter_id"],
            version=value["version"],
            digest=value["digest"],
            runtime_family=value["runtime_family"],
            conformance_profiles=profiles,
            supported_operations=operations,
            supports_checkpoint_restore=value["supports_checkpoint_restore"],
            evidence_status=value["evidence_status"],
            synthetic_only=value["synthetic_only"],
        )


@dataclass(frozen=True)
class RuntimeInvocation:
    task_id: str
    task_digest: str
    grant_id: str
    grant_digest: str
    composition_digest: str
    runtime_source_digest: str
    runtime_artifact_digest: str | None
    runtime_image_digest: str | None
    isolation_profile_digest: str | None
    input_snapshot_refs: tuple[str, ...]
    department_id: str | None
    agent_binding_ref: str | None
    agent_binding_digest: str | None
    workload_identity: str
    operation: str
    input_refs: tuple[str, ...]
    idempotency_key: str
    expires_at: str
    timeout_seconds: int
    data_classification: str
    synthetic_only: bool
    production_authorization: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RuntimeInvocation:
        legacy = {
            "task_id",
            "task_digest",
            "grant_id",
            "grant_digest",
            "composition_digest",
            "runtime_source_digest",
            "workload_identity",
            "operation",
            "input_refs",
            "idempotency_key",
            "expires_at",
            "timeout_seconds",
            "synthetic_only",
        }
        current = legacy | {"data_classification", "production_authorization"}
        container_current = current | {
            "runtime_artifact_digest",
            "runtime_image_digest",
            "isolation_profile_digest",
            "input_snapshot_refs",
            "department_id",
            "agent_binding_ref",
            "agent_binding_digest",
        }
        if not isinstance(value, Mapping) or (
            set(value) != legacy
            and set(value) != current
            and set(value) != container_current
        ):
            raise RuntimeAdapterError("runtime_invocation_invalid")
        synthetic_only = value["synthetic_only"]
        data_classification = value.get(
            "data_classification", "synthetic" if synthetic_only is True else None
        )
        production_authorization = value.get("production_authorization", False)
        input_refs = value["input_refs"]
        if not isinstance(input_refs, list) or not input_refs:
            raise RuntimeAdapterError("runtime_invocation_invalid")
        normalized_refs = tuple(_logical_ref(item) for item in input_refs)
        container_bound = set(value) == container_current
        snapshot_refs: tuple[str, ...] = ()
        if container_bound:
            raw_snapshots = value["input_snapshot_refs"]
            if not isinstance(raw_snapshots, list) or not raw_snapshots:
                raise RuntimeAdapterError("runtime_input_snapshot_refs_invalid")
            snapshot_refs = tuple(_logical_ref(item) for item in raw_snapshots)
            if len(set(snapshot_refs)) != len(snapshot_refs):
                raise RuntimeAdapterError("runtime_input_snapshot_refs_invalid")
            if (
                not isinstance(value["department_id"], str)
                or not _DEPARTMENT_ID.fullmatch(value["department_id"])
                or not isinstance(value["agent_binding_ref"], str)
                or not _AGENT_BINDING_ID.fullmatch(value["agent_binding_ref"])
            ):
                raise RuntimeAdapterError("runtime_invocation_scope_invalid")
        timeout = value["timeout_seconds"]
        if (
            not isinstance(value["task_id"], str)
            or not _REFERENCE_ID.fullmatch(value["task_id"])
            or not value["task_id"].startswith(("task_", "tsk_"))
            or not isinstance(value["grant_id"], str)
            or not _REFERENCE_ID.fullmatch(value["grant_id"])
            or not value["grant_id"].startswith("grant_")
            or not isinstance(value["workload_identity"], str)
            or not _REFERENCE_ID.fullmatch(value["workload_identity"])
            or not value["workload_identity"].startswith("workload_")
            or not isinstance(value["operation"], str)
            or not _TOKEN.fullmatch(value["operation"])
            or not isinstance(value["idempotency_key"], str)
            or not _IDEMPOTENCY_KEY.fullmatch(value["idempotency_key"])
            or type(timeout) is not int
            or not 1 <= timeout <= 900
            or type(synthetic_only) is not bool
            or data_classification not in {"synthetic", "public"}
            or (synthetic_only is False and data_classification != "public")
            or production_authorization is not False
        ):
            raise RuntimeAdapterError("runtime_invocation_invalid")
        for field in (
            "task_digest",
            "grant_digest",
            "composition_digest",
            "runtime_source_digest",
        ):
            if not isinstance(value[field], str) or not _DIGEST.fullmatch(value[field]):
                raise RuntimeAdapterError("runtime_invocation_digest_invalid")
        if container_bound:
            for field in (
                "runtime_artifact_digest",
                "runtime_image_digest",
                "isolation_profile_digest",
                "agent_binding_digest",
            ):
                if not isinstance(value[field], str) or not _DIGEST.fullmatch(
                    value[field]
                ):
                    raise RuntimeAdapterError("runtime_invocation_digest_invalid")
        expires_at = _parse_time(value["expires_at"])
        remaining = expires_at - datetime.now(timezone.utc)
        if remaining <= timedelta(0) or remaining > timedelta(seconds=900):
            raise RuntimeAdapterError("runtime_invocation_expired")
        return cls(
            task_id=value["task_id"],
            task_digest=value["task_digest"],
            grant_id=value["grant_id"],
            grant_digest=value["grant_digest"],
            composition_digest=value["composition_digest"],
            runtime_source_digest=value["runtime_source_digest"],
            runtime_artifact_digest=(
                value["runtime_artifact_digest"] if container_bound else None
            ),
            runtime_image_digest=(
                value["runtime_image_digest"] if container_bound else None
            ),
            isolation_profile_digest=(
                value["isolation_profile_digest"] if container_bound else None
            ),
            input_snapshot_refs=snapshot_refs,
            department_id=value["department_id"] if container_bound else None,
            agent_binding_ref=(
                value["agent_binding_ref"] if container_bound else None
            ),
            agent_binding_digest=(
                value["agent_binding_digest"] if container_bound else None
            ),
            workload_identity=value["workload_identity"],
            operation=value["operation"],
            input_refs=normalized_refs,
            idempotency_key=value["idempotency_key"],
            expires_at=value["expires_at"],
            timeout_seconds=timeout,
            data_classification=data_classification,
            synthetic_only=synthetic_only,
            production_authorization=False,
        )

    def to_mapping(self) -> dict[str, Any]:
        value = {
            "task_id": self.task_id,
            "task_digest": self.task_digest,
            "grant_id": self.grant_id,
            "grant_digest": self.grant_digest,
            "composition_digest": self.composition_digest,
            "runtime_source_digest": self.runtime_source_digest,
            "workload_identity": self.workload_identity,
            "operation": self.operation,
            "input_refs": list(self.input_refs),
            "idempotency_key": self.idempotency_key,
            "expires_at": self.expires_at,
            "timeout_seconds": self.timeout_seconds,
            "data_classification": self.data_classification,
            "synthetic_only": self.synthetic_only,
            "production_authorization": False,
        }
        if self.runtime_artifact_digest is not None:
            value.update(
                {
                    "runtime_artifact_digest": self.runtime_artifact_digest,
                    "runtime_image_digest": self.runtime_image_digest,
                    "isolation_profile_digest": self.isolation_profile_digest,
                    "input_snapshot_refs": list(self.input_snapshot_refs),
                    "department_id": self.department_id,
                    "agent_binding_ref": self.agent_binding_ref,
                    "agent_binding_digest": self.agent_binding_digest,
                }
            )
        return value

    @property
    def container_bound(self) -> bool:
        return self.runtime_artifact_digest is not None


class RunnerTransport(Protocol):
    """Transport to a separately isolated runner; implementations own mTLS."""

    def start(self, *, invocation: RuntimeInvocation) -> str: ...

    def events(
        self, *, run_id: str, after_sequence: int
    ) -> Sequence[Mapping[str, Any]]: ...

    def cancel(self, *, run_id: str, reason_code: str) -> None: ...

    def result(self, *, run_id: str) -> Mapping[str, Any] | None: ...

    def health(self) -> Mapping[str, Any]: ...


class FrameworkNeutralRuntimeAdapter:
    """Exact-binding adapter independent of LangGraph, Codex, or Hermes."""

    def __init__(
        self,
        *,
        descriptor: RuntimeAdapterDescriptor,
        transport: RunnerTransport,
    ) -> None:
        self.descriptor = descriptor
        self.transport = transport

    def describe_capabilities(self) -> dict[str, Any]:
        return {
            "adapter_id": self.descriptor.adapter_id,
            "version": self.descriptor.version,
            "digest": self.descriptor.digest,
            "runtime_family": self.descriptor.runtime_family,
            "conformance_profiles": list(self.descriptor.conformance_profiles),
            "supported_operations": list(self.descriptor.supported_operations),
            "supports_checkpoint_restore": self.descriptor.supports_checkpoint_restore,
            "evidence_status": self.descriptor.evidence_status,
            "synthetic_only": self.descriptor.synthetic_only,
        }

    def validate(self, value: Mapping[str, Any]) -> RuntimeInvocation:
        invocation = RuntimeInvocation.from_mapping(value)
        if invocation.operation not in self.descriptor.supported_operations:
            raise RuntimeAdapterError("runtime_operation_not_supported")
        if self.descriptor.synthetic_only and not invocation.synthetic_only:
            raise RuntimeAdapterError("runtime_adapter_authority_invalid")
        return invocation

    def start(self, value: Mapping[str, Any]) -> str:
        return self.transport.start(invocation=self.validate(value))

    def stream_events(
        self, *, run_id: str, after_sequence: int
    ) -> tuple[Mapping[str, Any], ...]:
        if not run_id.startswith("run_") or after_sequence < -1:
            raise RuntimeAdapterError("runtime_event_cursor_invalid")
        return tuple(
            self.transport.events(run_id=run_id, after_sequence=after_sequence)
        )

    def cancel(self, *, run_id: str, reason_code: str) -> None:
        if not run_id.startswith("run_") or not _TOKEN.fullmatch(reason_code):
            raise RuntimeAdapterError("runtime_cancel_invalid")
        self.transport.cancel(run_id=run_id, reason_code=reason_code)

    def collect_result(self, *, run_id: str) -> Mapping[str, Any] | None:
        if not run_id.startswith("run_"):
            raise RuntimeAdapterError("runtime_result_request_invalid")
        return self.transport.result(run_id=run_id)

    def health(self) -> Mapping[str, Any]:
        return self.transport.health()


class RuntimeAdapterRegistry:
    """Explicit registry; never imports arbitrary entry points or plugins."""

    def __init__(self) -> None:
        self._adapters: dict[tuple[str, str, str], FrameworkNeutralRuntimeAdapter] = {}

    def register(self, adapter: FrameworkNeutralRuntimeAdapter) -> None:
        descriptor = adapter.descriptor
        key = (descriptor.adapter_id, descriptor.version, descriptor.digest)
        if key in self._adapters:
            if self._adapters[key] is not adapter:
                raise RuntimeAdapterError("runtime_adapter_registration_conflict")
            return
        self._adapters[key] = adapter

    def resolve(
        self, *, adapter_id: str, version: str, digest: str
    ) -> FrameworkNeutralRuntimeAdapter:
        try:
            return self._adapters[(adapter_id, version, digest)]
        except KeyError as error:
            raise RuntimeAdapterError("runtime_adapter_not_registered") from error


class DisabledRunnerTransport:
    """Fail-closed bootstrap used until an isolated runner is explicitly bound."""

    def start(self, *, invocation: RuntimeInvocation) -> str:
        del invocation
        raise RuntimeAdapterError("runner_transport_not_configured")

    def events(
        self, *, run_id: str, after_sequence: int
    ) -> Sequence[Mapping[str, Any]]:
        del run_id, after_sequence
        raise RuntimeAdapterError("runner_transport_not_configured")

    def cancel(self, *, run_id: str, reason_code: str) -> None:
        del run_id, reason_code
        raise RuntimeAdapterError("runner_transport_not_configured")

    def result(self, *, run_id: str) -> Mapping[str, Any] | None:
        del run_id
        raise RuntimeAdapterError("runner_transport_not_configured")

    def health(self) -> Mapping[str, Any]:
        return {
            "status": "not_configured",
            "release_authorization": False,
        }


def _tokens(value: Any) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(
            not isinstance(item, str) or not _TOKEN.fullmatch(item) for item in value
        )
        or len(set(value)) != len(value)
    ):
        raise RuntimeAdapterError("runtime_adapter_tokens_invalid")
    return tuple(value)


def _logical_ref(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise RuntimeAdapterError("runtime_input_ref_invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in _LOGICAL_SCHEMES
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or ".." in parsed.path.split("/")
    ):
        raise RuntimeAdapterError("runtime_input_ref_invalid")
    return value


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RuntimeAdapterError("runtime_invocation_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeAdapterError("runtime_invocation_time_invalid") from error
    return parsed.astimezone(timezone.utc)

