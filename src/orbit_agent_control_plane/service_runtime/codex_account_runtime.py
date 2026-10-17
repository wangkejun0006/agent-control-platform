"""Fail-closed preflight for the node-local Codex account Runtime Adapter.

This module never reads an account cache and never calls Codex.  It turns
already-verified Control Plane bindings into a secret-free, single-task
adapter request.  The node-side adapter remains responsible for resolving the
credential binding from its owner-only store.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Callable

from .runtime_adapter import RuntimeInvocation

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][A-Za-z0-9_:-]{2,159}$")


class CodexAccountRuntimeError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class CodexAccountRuntimeAdapter:
    """Construct a non-executing request for one qualified Codex task."""

    adapter_id = "codex_account_runtime_adapter"
    version = "0.1.0-d0.1"
    maximum_input_tokens = 20_000
    maximum_output_tokens = 4_000
    maximum_turns = 6
    maximum_duration_seconds = 900
    maximum_concurrency = 1

    def __init__(self, *, now: Callable[[], datetime] | None = None) -> None:
        self.now = now or (lambda: datetime.now(timezone.utc))

    def build_task_request(
        self,
        *,
        invocation: RuntimeInvocation,
        run_id: str,
        node_id: str,
        lease: Mapping[str, Any],
        verified_grant: Mapping[str, Any],
        route_revision: Mapping[str, Any],
        route_revision_digest: str,
        account_qualification: Mapping[str, Any],
        requested_budget: Mapping[str, Any],
        active_task_count: int,
        output_schema_ref: str,
    ) -> Mapping[str, Any]:
        now = self.now().astimezone(timezone.utc)
        if (
            not invocation.container_bound
            or invocation.department_id != "technology_center"
            or invocation.operation != "codex_read_only_review"
            or invocation.production_authorization is not False
            or invocation.synthetic_only is not True
            or not isinstance(run_id, str)
            or not run_id.startswith("run_")
            or not isinstance(node_id, str)
            or not node_id.startswith("node_")
            or not _DIGEST.fullmatch(route_revision_digest)
        ):
            raise CodexAccountRuntimeError("codex_account_invocation_scope_invalid")
        invocation_digest = canonical_digest(invocation.to_mapping())
        self._validate_lease(
            lease=lease,
            run_id=run_id,
            invocation_digest=invocation_digest,
            now=now,
        )
        self._validate_grant(
            grant=verified_grant,
            invocation=invocation,
            invocation_digest=invocation_digest,
            now=now,
        )
        credential_ref = self._validate_route(
            route=route_revision,
            route_revision_digest=route_revision_digest,
            node_id=node_id,
        )
        self._validate_qualification(
            qualification=account_qualification,
            route_id=route_revision["route_id"],
            route_revision_digest=route_revision_digest,
            credential_ref=credential_ref,
            node_id=node_id,
            now=now,
        )
        budget = self._validate_budget(
            requested_budget=requested_budget,
            active_task_count=active_task_count,
        )
        if (
            not isinstance(output_schema_ref, str)
            or not output_schema_ref.startswith("artifact://")
            or len(output_schema_ref) > 500
        ):
            raise CodexAccountRuntimeError("codex_account_output_schema_invalid")
        return {
            "adapter_id": self.adapter_id,
            "adapter_version": self.version,
            "operation": "codex_exec_read_only",
            "execute": False,
            "run_id": run_id,
            "task_id": invocation.task_id,
            "grant_id": invocation.grant_id,
            "lease_id": lease["lease_id"],
            "node_id": node_id,
            "department_id": invocation.department_id,
            "agent_binding_ref": invocation.agent_binding_ref,
            "route_id": route_revision["route_id"],
            "route_revision_digest": route_revision_digest,
            "credential_binding_ref": credential_ref,
            "credential_resolution": "node_local_adapter_only",
            "credential_mounted_into_task_container": False,
            "session_mode": "temporary_noninteractive",
            "event_format": "jsonl",
            "output_schema_ref": output_schema_ref,
            "sandbox": {
                "mode": "read_only",
                "source_snapshot_refs": list(invocation.input_snapshot_refs),
                "detached_head_required": True,
                "git_remote_allowed": False,
                "source_write_allowed": False,
                "commit_allowed": False,
                "merge_allowed": False,
                "push_allowed": False,
                "host_paths_allowed": False,
                "docker_socket_allowed": False,
            },
            "budget": budget,
            "single_task_handle": True,
            "handle_revoked_at_task_end": True,
            "execution_grant_verified": True,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }

    @staticmethod
    def _validate_lease(
        *, lease: Mapping[str, Any], run_id: str, invocation_digest: str,
        now: datetime,
    ) -> None:
        expected = {
            "claimed", "lease_id", "run_id", "invocation_digest", "expires_at",
            "status", "production_authorization", "release_authorization",
        }
        if (
            not isinstance(lease, Mapping)
            or set(lease) != expected
            or lease.get("claimed") is not True
            or lease.get("status") != "active"
            or lease.get("run_id") != run_id
            or lease.get("invocation_digest") != invocation_digest
            or not isinstance(lease.get("lease_id"), str)
            or not str(lease["lease_id"]).startswith("lease_")
            or lease.get("production_authorization") is not False
            or lease.get("release_authorization") is not False
            or _time(lease.get("expires_at")) <= now
        ):
            raise CodexAccountRuntimeError("codex_account_lease_invalid")

    @staticmethod
    def _validate_grant(
        *, grant: Mapping[str, Any], invocation: RuntimeInvocation,
        invocation_digest: str, now: datetime,
    ) -> None:
        expected = {
            "grant_id", "grant_digest", "task_id", "invocation_digest", "status",
            "signature_verified", "revoked", "expires_at", "production_authorization",
            "release_authorization",
        }
        if (
            not isinstance(grant, Mapping)
            or set(grant) != expected
            or grant.get("grant_id") != invocation.grant_id
            or grant.get("grant_digest") != invocation.grant_digest
            or grant.get("task_id") != invocation.task_id
            or grant.get("invocation_digest") != invocation_digest
            or grant.get("status") != "active"
            or grant.get("signature_verified") is not True
            or grant.get("revoked") is not False
            or grant.get("production_authorization") is not False
            or grant.get("release_authorization") is not False
            or _time(grant.get("expires_at")) <= now
        ):
            raise CodexAccountRuntimeError("codex_account_execution_grant_invalid")

    def _validate_route(
        self, *, route: Mapping[str, Any], route_revision_digest: str,
        node_id: str,
    ) -> str:
        authentication = route.get("authentication") if isinstance(route, Mapping) else None
        budget = route.get("budget_policy") if isinstance(route, Mapping) else None
        if (
            not isinstance(route, Mapping)
            or route.get("route_version") != "orbit.model-route-revision/2"
            or route.get("status") != "active"
            or route.get("data_classification") != "synthetic"
            or route.get("budget_control_mode") != "usage_limits"
            or not isinstance(authentication, Mapping)
            or authentication.get("mode") != "oauth_ref"
            or not isinstance(authentication.get("credential_binding_ref"), str)
            or not str(authentication["credential_binding_ref"]).startswith("oauth://company/")
            or route.get("credential_scope") != "company"
            or node_id not in route.get("authorized_node_refs", [])
            or not isinstance(route.get("qualification_evidence_refs"), list)
            or not route["qualification_evidence_refs"]
            or not isinstance(route.get("route_id"), str)
            or not _ID.fullmatch(route["route_id"])
            or not isinstance(budget, Mapping)
            or budget != {
                "max_input_tokens": self.maximum_input_tokens,
                "max_output_tokens": self.maximum_output_tokens,
                "max_turns": self.maximum_turns,
                "max_duration_seconds": self.maximum_duration_seconds,
                "max_concurrency": self.maximum_concurrency,
            }
            or canonical_digest(route) != route_revision_digest
        ):
            raise CodexAccountRuntimeError("codex_account_model_route_invalid")
        return str(authentication["credential_binding_ref"])

    @staticmethod
    def _validate_qualification(
        *, qualification: Mapping[str, Any], route_id: str,
        route_revision_digest: str, credential_ref: str, node_id: str,
        now: datetime,
    ) -> None:
        expected = {
            "status", "route_id", "route_revision_digest", "credential_binding_ref",
            "node_id", "codex_cli_revision", "adapter_capability_digest",
            "verified_at", "expires_at", "runtime_started", "model_called",
            "production_authorization", "release_authorization",
        }
        if (
            not isinstance(qualification, Mapping)
            or set(qualification) != expected
            or qualification.get("status") != "qualified"
            or qualification.get("route_id") != route_id
            or qualification.get("route_revision_digest") != route_revision_digest
            or qualification.get("credential_binding_ref") != credential_ref
            or qualification.get("node_id") != node_id
            or not isinstance(qualification.get("codex_cli_revision"), str)
            or not qualification["codex_cli_revision"].startswith("codex-cli/")
            or not _DIGEST.fullmatch(str(qualification.get("adapter_capability_digest")))
            or _time(qualification.get("expires_at")) <= now
            or _time(qualification.get("verified_at")) > now
            or qualification.get("runtime_started") is not False
            or qualification.get("model_called") is not False
            or qualification.get("production_authorization") is not False
            or qualification.get("release_authorization") is not False
        ):
            raise CodexAccountRuntimeError("codex_account_qualification_invalid")

    def _validate_budget(
        self, *, requested_budget: Mapping[str, Any], active_task_count: int,
    ) -> Mapping[str, int]:
        expected = {
            "max_input_tokens", "max_output_tokens", "max_turns",
            "max_duration_seconds", "max_concurrency",
        }
        maximums = {
            "max_input_tokens": self.maximum_input_tokens,
            "max_output_tokens": self.maximum_output_tokens,
            "max_turns": self.maximum_turns,
            "max_duration_seconds": self.maximum_duration_seconds,
            "max_concurrency": self.maximum_concurrency,
        }
        if (
            not isinstance(requested_budget, Mapping)
            or set(requested_budget) != expected
            or any(type(requested_budget[key]) is not int for key in expected)
            or any(not 1 <= requested_budget[key] <= maximums[key] for key in expected)
            or type(active_task_count) is not int
            or active_task_count < 0
            or active_task_count >= self.maximum_concurrency
        ):
            raise CodexAccountRuntimeError("codex_account_budget_exceeded")
        return {key: int(requested_budget[key]) for key in sorted(expected)}


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CodexAccountRuntimeError("codex_account_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CodexAccountRuntimeError("codex_account_time_invalid") from error
    return parsed.astimezone(timezone.utc)

