"""Credential qualification without making authentication an execution grant."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from ..ids import deterministic_id
from ..qualification.automation import canonical_digest
from .control_console_models import (
    ControlConsoleCommandRow,
    ModelRouteCredentialBindingRow,
    ModelRouteRetirementRow,
    RuntimeAdapterCapabilityReportRow,
)
from .database import Database
from .model_route import ModelRouteError, OwnerOnlyFileSecretProvider, _route_document
from .models import AuditEventRow, ModelRouteRevisionRow, ReceiptRow

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{2,239}$")
_OAUTH_REF = re.compile(r"^oauth://[a-z0-9][a-z0-9/_-]{2,190}$")
_SECRET_REF = re.compile(r"^secret://[a-z0-9][a-z0-9/_-]{2,190}$")
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
_SECRET_VALUE = re.compile(
    r"(?:BEGIN .*PRIVATE KEY|\bsk-[A-Za-z0-9_-]{8,}|\bBearer\s+[A-Za-z0-9._~-]{8,})",
    re.IGNORECASE,
)


class ModelRouteCredentialService:
    """Records only sanitized qualification and receipt evidence."""

    def __init__(
        self,
        *,
        database: Database,
        secret_provider: OwnerOnlyFileSecretProvider | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.database = database
        self.secret_provider = secret_provider
        self.now = now or (lambda: datetime.now(timezone.utc))

    def qualify_api_key_binding(
        self,
        *,
        route_id: str,
        expected_revision_digest: str,
        expected_binding_version: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        route = self._route(route_id, expected_revision_digest)
        document = _route_document(route)
        authentication = document.get("authentication")
        if (
            document.get("route_version") != "orbit.model-route-revision/2"
            or not isinstance(authentication, dict)
            or authentication.get("mode") != "api_key_ref"
        ):
            raise ModelRouteError("model_route_api_key_binding_not_allowed")
        logical_ref = str(authentication["credential_binding_ref"])
        if not _SECRET_REF.fullmatch(logical_ref) or self.secret_provider is None:
            raise ModelRouteError("model_route_secret_provider_unconfigured")
        health = self.secret_provider.health(logical_ref)
        if (
            not health.get("healthy")
            or health.get("binding_version") != expected_binding_version
            or not _DIGEST.fullmatch(str(health.get("secret_fingerprint", "")))
        ):
            raise ModelRouteError("model_route_secret_binding_version_mismatch")
        request = {
            "route_id": route_id,
            "expected_revision_digest": expected_revision_digest,
            "expected_binding_version": expected_binding_version,
            "reason": reason,
        }
        replay = self._command(
            "model_route_api_key_qualify", logical_ref, request, idempotency_key
        )
        if replay is not None:
            return replay
        return self._record_binding(
            route=document,
            binding_id=deterministic_id(
                "binding", route_id, expected_binding_version
            ),
            idempotency_key=idempotency_key,
            status="qualified",
            secret_fingerprint=str(health["secret_fingerprint"]),
            secret_version=str(health["binding_version"]),
            qualification_evidence_refs=[],
            actor_ref=actor_ref,
            request=request,
            reason=reason,
            expires_at=None,
        )

    def request_account_login(
        self,
        *,
        route_id: str,
        expected_revision_digest: str,
        node_id: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        route = _route_document(self._route(route_id, expected_revision_digest))
        authentication = route.get("authentication", {})
        if (
            route.get("route_version") != "orbit.model-route-revision/2"
            or authentication.get("mode") != "oauth_ref"
            or node_id not in route.get("authorized_node_refs", [])
        ):
            raise ModelRouteError("model_route_account_login_scope_invalid")
        request = {
            "route_id": route_id,
            "expected_revision_digest": expected_revision_digest,
            "node_id": node_id,
            "reason": reason,
        }
        replay = self._command("model_route_account_login_request", route_id, request, idempotency_key)
        if replay is not None:
            return replay
        response = {
            "login_request_id": deterministic_id("login-request", route_id, node_id, idempotency_key),
            "route_id": route_id,
            "route_revision_digest": expected_revision_digest,
            "node_id": node_id,
            "authentication_mode": "oauth_ref",
            "status": "awaiting_node_login",
            "credential_value_returned": False,
            "execution_grant_issued": False,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }
        self._record_command(
            command_kind="model_route_account_login_request",
            target_ref=route_id,
            request=request,
            response=response,
            idempotency_key=idempotency_key,
            actor_ref=actor_ref,
            event_type="model_route_account_login_requested",
        )
        return response

    def record_account_login_receipt(
        self,
        *,
        node_id: str,
        document: Mapping[str, Any],
        idempotency_key: str,
        workload_identity: str,
    ) -> dict[str, Any]:
        value = dict(document)
        expected = {
            "receipt_version", "route_id", "route_revision_digest",
            "credential_binding_ref", "node_id", "codex_cli_revision",
            "login_status", "verified_at", "expires_at", "runtime_started",
            "model_called", "production_authorization", "release_authorization",
        }
        if (
            set(value) != expected
            or value.get("receipt_version") != "orbit.codex-account-login-receipt/1"
            or value.get("node_id") != node_id
            or value.get("login_status") not in {"qualified", "logged_out", "expired"}
            or value.get("runtime_started") is not False
            or value.get("model_called") is not False
            or value.get("production_authorization") is not False
            or value.get("release_authorization") is not False
            or not _OAUTH_REF.fullmatch(str(value.get("credential_binding_ref", "")))
            or not _SAFE.fullmatch(str(value.get("codex_cli_revision", "")))
        ):
            raise ModelRouteError("model_route_account_login_receipt_invalid")
        route = _route_document(
            self._route(str(value["route_id"]), str(value["route_revision_digest"]))
        )
        if (
            route.get("authentication", {}).get("mode") != "oauth_ref"
            or route["authentication"]["credential_binding_ref"]
            != value["credential_binding_ref"]
            or node_id not in route.get("authorized_node_refs", [])
        ):
            raise ModelRouteError("model_route_account_login_scope_invalid")
        verified = _time(value["verified_at"])
        expires = _time(value["expires_at"])
        if verified >= expires:
            raise ModelRouteError("model_route_account_login_time_invalid")
        report = self._latest_adapter_report(node_id)
        if (
            value["login_status"] == "qualified"
            and (
                report is None
                or report.status != "verified"
                or "oauth_ref" not in report.authentication_modes
                or _utc(report.expires_at) <= self.now()
            )
        ):
            raise ModelRouteError("model_route_adapter_capability_missing")
        request = {
            "node_id": node_id,
            "route_id": value["route_id"],
            "route_revision_digest": value["route_revision_digest"],
            "receipt_digest": canonical_digest(value),
        }
        replay = self._command("model_route_account_login_receipt", node_id, request, idempotency_key)
        if replay is not None:
            return replay
        status = "qualified" if value["login_status"] == "qualified" else "unavailable"
        return self._record_binding(
            route=route,
            binding_id=deterministic_id("binding", node_id, idempotency_key),
            idempotency_key=idempotency_key,
            status=status,
            secret_fingerprint=None,
            secret_version=str(value["codex_cli_revision"]),
            qualification_evidence_refs=([] if report is None else [report.capability_digest]),
            actor_ref=workload_identity,
            request=request,
            reason="node submitted a sanitized company account login receipt",
            expires_at=expires,
        )

    def record_adapter_capability_report(
        self,
        *,
        node_id: str,
        document: Mapping[str, Any],
        authentication_modes: list[str],
        expires_at: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        value = dict(document)
        _validate_adapter_capability_report(value)
        if (
            not authentication_modes
            or len(authentication_modes) != len(set(authentication_modes))
            or any(item not in {"api_key_ref", "oauth_ref"} for item in authentication_modes)
        ):
            raise ModelRouteError("runtime_adapter_capability_report_invalid")
        expires = _time(expires_at)
        if expires <= self.now():
            raise ModelRouteError("runtime_adapter_capability_report_expired")
        digest = canonical_digest(value)
        request = {
            "node_id": node_id,
            "capability_digest": digest,
            "authentication_modes": authentication_modes,
            "expires_at": expires_at,
        }
        replay = self._command("runtime_adapter_capability_report", node_id, request, idempotency_key)
        if replay is not None:
            return replay
        metadata = value["metadata"]
        spec = value.get("spec", {})
        adapter_ref = spec.get("runtime_adapter_ref", {})
        runtime_ref = spec.get("runtime_revision_ref", {})
        adapter_id = _versioned_ref(adapter_ref)
        adapter_revision_digest = str(runtime_ref.get("digest", ""))
        if not _DIGEST.fullmatch(adapter_revision_digest):
            raise ModelRouteError("runtime_adapter_capability_report_invalid")
        response = {
            "report_id": metadata["report_id"],
            "node_id": node_id,
            "capability_digest": digest,
            "authentication_modes": sorted(set(authentication_modes)),
            "status": "verified",
            "expires_at": expires_at,
            "execution_grant_issued": False,
            "release_authorization": False,
        }
        with self.database.session() as session:
            session.add(RuntimeAdapterCapabilityReportRow(
                report_id=str(metadata["report_id"]),
                idempotency_key=idempotency_key,
                node_id=node_id,
                adapter_id=adapter_id,
                adapter_revision_digest=adapter_revision_digest,
                authentication_modes=sorted(set(authentication_modes)),
                capability_digest=digest,
                document=value,
                status="verified",
                recorded_at=self.now(),
                expires_at=expires,
            ))
            session.add(ControlConsoleCommandRow(
                idempotency_key=idempotency_key,
                command_kind="runtime_adapter_capability_report",
                target_ref=f"runtime-node://{node_id}",
                request_digest=canonical_digest(request),
                response=response,
                created_at=self.now(),
            ))
        return response

    def health(self, route: Mapping[str, Any]) -> Mapping[str, Any]:
        authentication = route.get("authentication", {})
        binding_ref = authentication.get("credential_binding_ref")
        with self.database.session() as session:
            row = session.scalar(
                select(ModelRouteCredentialBindingRow)
                .where(
                    ModelRouteCredentialBindingRow.route_id == route["route_id"],
                    ModelRouteCredentialBindingRow.credential_binding_ref == binding_ref,
                )
                .order_by(ModelRouteCredentialBindingRow.id.desc())
                .limit(1)
            )
        if row is None or row.status not in {"bound", "qualified"}:
            raise ModelRouteError("model_route_credential_qualification_missing")
        if row.revoked_at is not None:
            raise ModelRouteError("model_route_credential_revoked")
        if row.expires_at is not None and _utc(row.expires_at) <= self.now():
            raise ModelRouteError("model_route_credential_expired")
        if authentication.get("mode") == "oauth_ref" and (
            row.status != "qualified" or not row.authorized_node_refs
        ):
            raise ModelRouteError("model_route_account_login_not_qualified")
        return {
            "healthy": True,
            "binding_version": row.secret_version or row.binding_id,
            "authentication_mode": row.authentication_mode,
            "authorized_node_refs": row.authorized_node_refs,
        }

    def retire(
        self, *, route_id: str, expected_revision_digest: str, reason: str,
        idempotency_key: str, actor_ref: str, approval_status: str,
    ) -> dict[str, Any]:
        self._route(route_id, expected_revision_digest)
        if approval_status == "approved":
            raise ModelRouteError("model_route_approval_must_be_revoked_before_retirement")
        request = {
            "route_id": route_id,
            "expected_revision_digest": expected_revision_digest,
            "reason": reason,
        }
        replay = self._command("model_route_retire", route_id, request, idempotency_key)
        if replay is not None:
            return replay
        now = self.now()
        retirement_id = deterministic_id("retirement", route_id, idempotency_key)
        receipt_document = {
            "receipt_version": "orbit.model-route-retirement-receipt/1",
            "receipt_id": deterministic_id("receipt", retirement_id),
            "retirement_id": retirement_id,
            "route_id": route_id,
            "route_revision_digest": expected_revision_digest,
            "effect": "deny_new_task_references_preserve_history",
            "actor_ref": actor_ref,
            "reason": reason,
            "recorded_at": _text(now),
            "execution_grant_issued": False,
            "release_authorization": False,
        }
        digest = canonical_digest(receipt_document)
        response = {
            "retirement_id": retirement_id,
            "route_id": route_id,
            "route_revision_digest": expected_revision_digest,
            "status": "retired",
            "receipt_id": receipt_document["receipt_id"],
            "receipt_digest": digest,
            "history_preserved": True,
            "execution_grant_issued": False,
            "release_authorization": False,
        }
        with self.database.session() as session:
            session.add(ModelRouteRetirementRow(
                retirement_id=retirement_id,
                idempotency_key=idempotency_key,
                route_id=route_id,
                route_revision_digest=expected_revision_digest,
                reason=reason,
                actor_ref=actor_ref,
                receipt_id=str(receipt_document["receipt_id"]),
                receipt_digest=digest,
                recorded_at=now,
            ))
            session.add(ReceiptRow(
                receipt_id=str(receipt_document["receipt_id"]),
                receipt_type="orbit.model-route-retirement-receipt/1",
                receipt_digest=digest,
                subject_ref=f"model-route://{route_id}/{expected_revision_digest}",
                document=receipt_document,
                recorded_at=now,
            ))
            session.add(ControlConsoleCommandRow(
                idempotency_key=idempotency_key,
                command_kind="model_route_retire",
                target_ref=f"model-route://{route_id}",
                request_digest=canonical_digest(request),
                response=response,
                created_at=now,
            ))
        return response

    def is_retired(self, route_id: str, revision_digest: str) -> bool:
        with self.database.session() as session:
            return session.scalar(select(ModelRouteRetirementRow).where(
                ModelRouteRetirementRow.route_id == route_id,
                ModelRouteRetirementRow.route_revision_digest == revision_digest,
            ).limit(1)) is not None

    def _record_binding(
        self, *, route: Mapping[str, Any], binding_id: str, idempotency_key: str,
        status: str, secret_fingerprint: str | None, secret_version: str | None,
        qualification_evidence_refs: list[str], actor_ref: str,
        request: Mapping[str, Any], reason: str, expires_at: datetime | None,
    ) -> dict[str, Any]:
        now = self.now()
        authentication = route["authentication"]
        response = {
            "binding_id": binding_id,
            "route_id": route["route_id"],
            "route_revision_digest": canonical_digest(route),
            "authentication_mode": authentication["mode"],
            "credential_scope": route["credential_scope"],
            "authorized_node_refs": route["authorized_node_refs"],
            "status": status,
            "secret_fingerprint": secret_fingerprint,
            "secret_value_returned": False,
            "expires_at": None if expires_at is None else _text(expires_at),
            "execution_grant_issued": False,
            "runtime_started": False,
            "model_called": False,
            "production_authorization": False,
            "release_authorization": False,
        }
        with self.database.session() as session:
            session.add(ModelRouteCredentialBindingRow(
                binding_id=binding_id,
                idempotency_key=idempotency_key,
                route_id=str(route["route_id"]),
                route_revision_digest=canonical_digest(route),
                authentication_mode=str(authentication["mode"]),
                credential_binding_ref=str(authentication["credential_binding_ref"]),
                credential_scope=str(route["credential_scope"]),
                authorized_node_refs=list(route["authorized_node_refs"]),
                qualification_evidence_refs=qualification_evidence_refs,
                status=status,
                secret_fingerprint=secret_fingerprint,
                secret_version=secret_version,
                actor_ref=actor_ref,
                recorded_at=now,
                expires_at=expires_at,
                revoked_at=None,
            ))
            session.add(ControlConsoleCommandRow(
                idempotency_key=idempotency_key,
                command_kind=("model_route_api_key_bind" if authentication["mode"] == "api_key_ref" else "model_route_account_login_receipt"),
                target_ref=f"model-route://{route['route_id']}",
                request_digest=canonical_digest(request),
                response=response,
                created_at=now,
            ))
            session.add(AuditEventRow(
                audit_id=deterministic_id("audit", binding_id),
                correlation_id=str(route["route_id"]),
                event_type="model_route_credential_qualification_recorded",
                actor_ref=actor_ref,
                payload={
                    "authentication_mode": authentication["mode"],
                    "status": status,
                    "reason": reason,
                    "secret_value_recorded": False,
                    "execution_grant_issued": False,
                    "release_authorization": False,
                },
                recorded_at=now,
            ))
        return response

    def _record_command(
        self, *, command_kind: str, target_ref: str, request: Mapping[str, Any],
        response: dict[str, Any], idempotency_key: str, actor_ref: str,
        event_type: str,
    ) -> None:
        now = self.now()
        with self.database.session() as session:
            session.add(ControlConsoleCommandRow(
                idempotency_key=idempotency_key,
                command_kind=command_kind,
                target_ref=f"model-route://{target_ref}",
                request_digest=canonical_digest(request),
                response=response,
                created_at=now,
            ))
            session.add(AuditEventRow(
                audit_id=deterministic_id("audit", command_kind, idempotency_key),
                correlation_id=target_ref,
                event_type=event_type,
                actor_ref=actor_ref,
                payload={
                    "request_digest": canonical_digest(request),
                    "execution_grant_issued": False,
                    "release_authorization": False,
                },
                recorded_at=now,
            ))

    def _command(
        self, kind: str, target: str, request: Mapping[str, Any], key: str
    ) -> dict[str, Any] | None:
        with self.database.session() as session:
            row = session.scalar(select(ControlConsoleCommandRow).where(
                ControlConsoleCommandRow.idempotency_key == key
            ))
        if row is None:
            return None
        if row.command_kind != kind or row.request_digest != canonical_digest(request):
            raise ModelRouteError("control_console_idempotency_conflict")
        return {**row.response, "idempotent_replay": True}

    def _route(self, route_id: str, digest: str) -> ModelRouteRevisionRow:
        with self.database.session() as session:
            row = session.scalar(select(ModelRouteRevisionRow).where(
                ModelRouteRevisionRow.route_id == route_id,
                ModelRouteRevisionRow.revision_digest == digest,
            ))
        if row is None:
            raise ModelRouteError("model_route_revision_not_found")
        return row

    def _latest_adapter_report(self, node_id: str) -> RuntimeAdapterCapabilityReportRow | None:
        with self.database.session() as session:
            return session.scalar(select(RuntimeAdapterCapabilityReportRow).where(
                RuntimeAdapterCapabilityReportRow.node_id == node_id
            ).order_by(RuntimeAdapterCapabilityReportRow.id.desc()).limit(1))


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ModelRouteError("model_route_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ModelRouteError("model_route_time_invalid") from error
    if parsed.tzinfo is None:
        raise ModelRouteError("model_route_time_invalid")
    return parsed.astimezone(timezone.utc)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _text(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _versioned_ref(value: Any) -> str:
    if not isinstance(value, dict):
        raise ModelRouteError("runtime_adapter_capability_report_invalid")
    candidate = value.get("ref") or value.get("id")
    if not isinstance(candidate, str) or not _SAFE.fullmatch(candidate):
        raise ModelRouteError("runtime_adapter_capability_report_invalid")
    return candidate


def _validate_adapter_capability_report(value: Mapping[str, Any]) -> None:
    if (
        set(value) != {"api_version", "kind", "metadata", "spec"}
        or value.get("api_version") != "company-ai-os/v1alpha1"
        or value.get("kind") != "AdapterCapabilityReport"
    ):
        raise ModelRouteError("runtime_adapter_capability_report_invalid")
    metadata = value.get("metadata")
    spec = value.get("spec")
    if (
        not isinstance(metadata, Mapping)
        or set(metadata) != {
            "report_id", "version", "status", "evidence_status", "synthetic_only",
            "observed_at",
        }
        or not _SAFE.fullmatch(str(metadata.get("report_id", "")))
        or not _SEMVER.fullmatch(str(metadata.get("version", "")))
        or metadata.get("status") != "verified"
        or metadata.get("evidence_status") not in {"synthetic", "verified_runtime"}
        or metadata.get("synthetic_only") is not True
    ):
        raise ModelRouteError("runtime_adapter_capability_report_invalid")
    _time(metadata.get("observed_at"))
    if (
        not isinstance(spec, Mapping)
        or set(spec) != {
            "runtime_adapter_ref", "runtime_revision_ref", "conformance_profile_ref",
            "capabilities", "unsupported_capabilities", "evidence_refs", "limitations",
        }
    ):
        raise ModelRouteError("runtime_adapter_capability_report_invalid")
    for ref_name in (
        "runtime_adapter_ref", "runtime_revision_ref", "conformance_profile_ref",
    ):
        ref = spec.get(ref_name)
        if (
            not isinstance(ref, Mapping)
            or set(ref) != {"id", "version", "digest"}
            or not _SAFE.fullmatch(str(ref.get("id", "")))
            or not _SEMVER.fullmatch(str(ref.get("version", "")))
            or not _DIGEST.fullmatch(str(ref.get("digest", "")))
        ):
            raise ModelRouteError("runtime_adapter_capability_report_invalid")
    allowed_capabilities = {
        "dispatch", "authentication", "idempotency", "cancel", "timeout",
        "checkpoint", "resume", "stream_events", "tool_interception",
        "result_reference", "audit_correlation", "sandbox_mapping",
    }
    allowed_support = {"supported", "partial", "unsupported", "not_tested"}
    allowed_evidence = {
        "vendor_documentation", "static_mapping", "synthetic_test", "runtime_test",
    }
    capabilities = spec.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        raise ModelRouteError("runtime_adapter_capability_report_invalid")
    for item in capabilities:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"capability", "support", "evidence_kind", "evidence_ref"}
            or item.get("capability") not in allowed_capabilities
            or item.get("support") not in allowed_support
            or item.get("evidence_kind") not in allowed_evidence
            or not isinstance(item.get("evidence_ref"), str)
            or not 3 <= len(item["evidence_ref"]) <= 240
        ):
            raise ModelRouteError("runtime_adapter_capability_report_invalid")
    for field, maximum in (
        ("unsupported_capabilities", 240),
        ("evidence_refs", 240),
        ("limitations", 500),
    ):
        items = spec.get(field)
        if (
            not isinstance(items, list)
            or not items
            or len(items) != len(set(items))
            or any(
                not isinstance(item, str) or not 3 <= len(item) <= maximum
                for item in items
            )
        ):
            raise ModelRouteError("runtime_adapter_capability_report_invalid")
    _reject_sensitive_values(value)


def _reject_sensitive_values(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in {
                "api_key", "authorization", "credential", "password", "secret",
                "auth_json", "access_token", "refresh_token", "private_key",
            }:
                raise ModelRouteError(
                    "runtime_adapter_capability_report_sensitive"
                )
            _reject_sensitive_values(item)
    elif isinstance(value, list):
        for item in value:
            _reject_sensitive_values(item)
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise ModelRouteError("runtime_adapter_capability_report_sensitive")

