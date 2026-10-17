"""Container engine request construction for the D0 WSL runner boundary.

The Control Plane never opens a Docker socket.  This module only validates and
constructs a JSON-safe request for a separately deployed rootless Runner.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

from .runtime_adapter import RuntimeInvocation

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{2,95}$")
_FORBIDDEN_SOURCE = re.compile(
    r"^(?:/|~[/\\]|[A-Za-z]:[\\/]|file://|smb://|nfs://|docker://)",
    re.IGNORECASE,
)
_ALLOWED_SOURCE_SCHEMES = frozenset({"artifact", "dataset", "task"})
CONTAINER_ISOLATION_CONSUMER_PROFILE = {
    "schema_id": "urn:company-ai-os:draft:schema:container-isolation-profile:0.3",
    "schema_digest": "sha256:370c024e09b4893d6fa740cfd87a18932a50a7b85ac794d2952ad2df05ca9911",
    "authority": "architecture_draft_consumer_lock",
}


class ContainerEngineError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class ContainerIsolationProfile:
    profile_digest: str
    uid: int
    gid: int
    seccomp_profile_digest: str
    cpu_quota_millis: int
    memory_mb: int
    pids_limit: int
    tmpfs_mb: int
    timeout_seconds: int
    relay_ref: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ContainerIsolationProfile:
        if (
            not isinstance(value, Mapping)
            or set(value)
            != {"api_version", "kind", "metadata", "spec", "authority_boundary"}
            or value.get("api_version") != "company-ai-os/v1alpha3-draft"
            or value.get("kind") != "ContainerIsolationProfile"
        ):
            raise ContainerEngineError("container_isolation_profile_invalid")
        metadata = value["metadata"]
        spec = value["spec"]
        boundary = value["authority_boundary"]
        if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping) or not isinstance(boundary, Mapping):
            raise ContainerEngineError("container_isolation_profile_invalid")
        expected_spec = {"engine", "identity", "filesystem", "linux_security", "network", "resources", "lifecycle", "profile_digest"}
        if set(spec) != expected_spec:
            raise ContainerEngineError("container_isolation_profile_invalid")
        engine = spec["engine"]
        user = spec["identity"]
        filesystem = spec["filesystem"]
        security = spec["linux_security"]
        resources = spec["resources"]
        network = spec["network"]
        lifecycle = spec["lifecycle"]
        if (
            set(metadata) != {"profile_id", "version", "evidence_status", "synthetic_only", "created_at"}
            or not _SAFE_NAME.fullmatch(metadata["profile_id"])
            or not _semantic_version(metadata["version"])
            or metadata["evidence_status"] not in {"architecture_reference", "synthetic_d0"}
            or metadata["synthetic_only"] is not True
            or not _date_time(metadata["created_at"])
            or not isinstance(engine, Mapping)
            or engine != {"family": "rootless-docker", "rootless": True, "socket_mounted_into_task": False, "privileged": False}
            or not isinstance(user, Mapping)
            or set(user) != {"run_as_non_root", "uid", "gid", "supplemental_groups_allowed"}
            or user["run_as_non_root"] is not True
            or user["supplemental_groups_allowed"] is not False
            or type(user["uid"]) is not int
            or type(user["gid"]) is not int
            or not 1 <= user["uid"] <= 65535
            or not 1 <= user["gid"] <= 65535
            or not isinstance(filesystem, Mapping)
            or set(filesystem) != {"root_read_only", "host_paths_mounted", "windows_drives_mounted", "docker_socket_mounted", "secret_volumes_mounted", "mounts"}
            or filesystem["root_read_only"] is not True
            or any(filesystem[item] is not False for item in ("host_paths_mounted", "windows_drives_mounted", "docker_socket_mounted", "secret_volumes_mounted"))
            or not _valid_mount_classes(filesystem["mounts"])
            or not isinstance(security, Mapping)
            or set(security) != {"no_new_privileges", "drop_all_capabilities", "added_capabilities", "seccomp_profile_ref", "seccomp_profile_digest"}
            or security["no_new_privileges"] is not True
            or security["drop_all_capabilities"] is not True
            or security["added_capabilities"] != []
            or not _logical_policy_ref(security["seccomp_profile_ref"])
            or not _digest(security["seccomp_profile_digest"])
            or not isinstance(resources, Mapping)
            or set(resources)
            != {
                "cpu_millis", "memory_mib", "pids", "workspace_mib", "tmpfs_mib", "runtime_seconds",
            }
            or not isinstance(network, Mapping)
            or network != {"mode": "task_gateway_relay_only", "host_network": False, "published_ports": [], "direct_internet": False, "allowed_logical_destinations": ["gateway://task-relay"]}
            or network["host_network"] is not False
            or not isinstance(lifecycle, Mapping)
            or lifecycle.get("task_exclusive") is not True
            or lifecycle.get("cross_task_memory") is not False
            or lifecycle.get("needs_input_retention_seconds") != 600
            or lifecycle.get("terminal_cleanup_required") is not True
            or set(lifecycle)
            != {
                "task_exclusive",
                "cross_task_memory",
                "needs_input_retention_seconds",
                "checkpoint_classes",
                "terminal_cleanup_required",
            }
            or not isinstance(lifecycle.get("checkpoint_classes"), list)
            or not lifecycle["checkpoint_classes"]
            or not set(lifecycle["checkpoint_classes"]).issubset({"checkpoint", "result_draft", "diff", "artifact"})
            or set(boundary) != {"execution_grant_issued", "task_state_changed", "deployment_activated", "production_authorized", "release_authorization"}
            or any(item is not False for item in boundary.values())
            or not _digest(spec["profile_digest"])
            or spec["profile_digest"] != _embedded_profile_digest(value)
        ):
            raise ContainerEngineError("container_isolation_profile_invalid")
        limits = {
            "cpu_millis": (100, 8000),
            "memory_mib": (128, 16384),
            "pids": (16, 512),
            "workspace_mib": (16, 10240),
            "tmpfs_mib": (16, 2048),
            "runtime_seconds": (1, 900),
        }
        for key, (minimum, maximum) in limits.items():
            item = resources[key]
            if type(item) is not int or not minimum <= item <= maximum:
                raise ContainerEngineError("container_isolation_profile_invalid")
        return cls(
            profile_digest=spec["profile_digest"],
            uid=user["uid"],
            gid=user["gid"],
            seccomp_profile_digest=security["seccomp_profile_digest"],
            cpu_quota_millis=resources["cpu_millis"],
            memory_mb=resources["memory_mib"],
            pids_limit=resources["pids"],
            tmpfs_mb=resources["tmpfs_mib"],
            timeout_seconds=resources["runtime_seconds"],
            relay_ref="gateway://task-relay",
        )


class ContainerEngineAdapter(Protocol):
    def build_task_request(
        self,
        *,
        invocation: RuntimeInvocation,
        isolation_profile: Mapping[str, Any],
        container_name: str,
    ) -> Mapping[str, Any]: ...


class RootlessDockerEngineAdapter:
    """Construct a non-executing rootless-Docker engine request."""

    engine_id = "rootless-docker"

    def build_task_request(
        self,
        *,
        invocation: RuntimeInvocation,
        isolation_profile: Mapping[str, Any],
        container_name: str,
    ) -> Mapping[str, Any]:
        if not invocation.container_bound:
            raise ContainerEngineError("container_runtime_binding_missing")
        if not _SAFE_NAME.fullmatch(container_name):
            raise ContainerEngineError("container_name_invalid")
        profile = ContainerIsolationProfile.from_mapping(isolation_profile)
        if profile.profile_digest != invocation.isolation_profile_digest:
            raise ContainerEngineError("container_isolation_profile_drift")
        if profile.timeout_seconds != invocation.timeout_seconds:
            raise ContainerEngineError("container_timeout_binding_drift")
        mounts = _mounts(invocation.input_snapshot_refs, invocation.task_id)
        return {
            "engine": self.engine_id,
            "operation": "create_task_container",
            "shell": False,
            "execute": False,
            "contract_consumer": CONTAINER_ISOLATION_CONSUMER_PROFILE,
            "container_name": container_name,
            "image_digest": invocation.runtime_image_digest,
            "task_id": invocation.task_id,
            "user": {"uid": profile.uid, "gid": profile.gid},
            "root_filesystem_read_only": True,
            "security": {
                "cap_drop": ["ALL"],
                "no_new_privileges": True,
                "seccomp_profile_digest": profile.seccomp_profile_digest,
                "privileged": False,
                "docker_socket_mounted": False,
            },
            "resources": {
                "cpu_quota_millis": profile.cpu_quota_millis,
                "memory_mb": profile.memory_mb,
                "pids_limit": profile.pids_limit,
                "tmpfs_mb": profile.tmpfs_mb,
                "timeout_seconds": profile.timeout_seconds,
            },
            "network": {
                "mode": "task_relay_only",
                "relay_ref": f"relay://task/{invocation.task_id}",
                "host_network": False,
                "published_ports": [],
            },
            "mounts": mounts,
            "production_authorization": False,
            "release_authorization": False,
        }


def _mounts(snapshot_refs: Sequence[str], task_id: str) -> list[dict[str, Any]]:
    if not snapshot_refs:
        raise ContainerEngineError("container_input_snapshot_missing")
    result: list[dict[str, Any]] = []
    for index, source_ref in enumerate(snapshot_refs):
        _logical_source(source_ref)
        result.append(
            {
                "kind": "input_snapshot",
                "source_ref": source_ref,
                "target": f"/orbit/input/{index:03d}",
                "read_only": True,
            }
        )
    result.append(
        {
            "kind": "task_workspace",
            "source_ref": f"task://{task_id}/workspace",
            "target": "/orbit/workspace",
            "read_only": False,
        }
    )
    return result


def _logical_source(value: Any) -> None:
    if not isinstance(value, str) or len(value) > 512 or _FORBIDDEN_SOURCE.match(value):
        raise ContainerEngineError("container_mount_source_invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme not in _ALLOWED_SOURCE_SCHEMES
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or ".." in parsed.path.split("/")
        or "docker.sock" in value.lower()
        or "/mnt/" in value.lower()
        or "nas" in value.lower()
    ):
        raise ContainerEngineError("container_mount_source_invalid")


def _digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _semantic_version(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", value
    ) is not None


def _date_time(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        __import__("datetime").datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _logical_policy_ref(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"(?:artifact|policy|gateway)://[a-z0-9][a-z0-9._/-]{2,190}", value
    ) is not None


def _valid_mount_classes(value: Any) -> bool:
    if not isinstance(value, list) or not 2 <= len(value) <= 3:
        return False
    classes = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"class", "access", "source_kind", "cross_task_shared"} or item["cross_task_shared"] is not False:
            return False
        classes.add(item["class"])
        expected = {
            "input_snapshot": ("read_only", "logical_artifact"),
            "task_workspace": ("read_write", "task_volume"),
            "task_tmpfs": ("read_write", "tmpfs"),
        }.get(item["class"])
        if expected is None or (item["access"], item["source_kind"]) != expected:
            return False
    return {"input_snapshot", "task_workspace"}.issubset(classes)


def _embedded_profile_digest(value: Mapping[str, Any]) -> str:
    normalized = json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
    del normalized["spec"]["profile_digest"]
    source = json.dumps(normalized, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(source).hexdigest()

