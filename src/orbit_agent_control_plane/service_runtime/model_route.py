"""Durable, non-secret Model Route reconciliation and preflight snapshots.

This module deliberately stops before provider-backed execution.  It persists
immutable configuration and sanitized observations, verifies a logical Secret
binding without exposing its bytes, and emits an immutable deployment snapshot.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import urllib.request
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from contextlib import nullcontext

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..ids import deterministic_id
from ..qualification.automation import canonical_digest
from .database import Database
from .model_catalog_models import DepartmentAgentProposalRow
from .models import (
    AuditEventRow,
    ModelRouteRevisionRow,
    ModelRouteSnapshotRow,
    OutboxEventRow,
    ProviderObservationRow,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{1,190}$")
_SECRET_REF = re.compile(r"^secret://[a-z0-9][a-z0-9/_-]{2,190}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_ROUTE_FIELDS = {
    "route_version",
    "route_id",
    "provider",
    "endpoint",
    "requested_model",
    "parameters",
    "data_classification",
    "budget_policy",
    "resolution_mode",
    "secret_ref",
    "approved_scope",
    "runtime_binding",
    "policy_binding",
    "status",
}
_ROUTE_V2_FIELDS = (
    _ROUTE_FIELDS
    - {"secret_ref"}
    | {
        "authentication",
        "credential_scope",
        "authorized_node_refs",
        "qualification_evidence_refs",
        "budget_control_mode",
    }
)
_OBSERVATION_FIELDS = {
    "observation_version",
    "provider",
    "requested_model",
    "resolved_model_id",
    "input_usd_per_million_tokens",
    "output_usd_per_million_tokens",
    "cached_input_usd_per_million_tokens",
    "source",
    "source_kind",
    "regression_status",
    "observed_at",
    "expires_at",
}
_BUDGET_FIELDS = {
    "max_input_tokens",
    "max_output_tokens",
    "max_cost_usd",
    "max_cost_cny",
    "cny_per_usd",
}
_USAGE_BUDGET_FIELDS = {
    "max_input_tokens",
    "max_output_tokens",
    "max_turns",
    "max_duration_seconds",
    "max_concurrency",
}
_AUTHENTICATION_FIELDS = {"mode", "credential_binding_ref"}
_APPROVED_SCOPE_FIELDS = {
    "provider",
    "endpoint",
    "model_family",
    "resolved_model_ids",
    "data_classification",
    "permissions",
}


class ModelRouteError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class SecretProvider(Protocol):
    def health(self, logical_ref: str) -> Mapping[str, Any]: ...

    def read(self, logical_ref: str) -> bytes: ...


class CredentialHealthProvider(Protocol):
    def health(self, route: Mapping[str, Any]) -> Mapping[str, Any]: ...


class UnavailableCredentialHealthProvider:
    def health(self, route: Mapping[str, Any]) -> Mapping[str, Any]:
        del route
        raise ModelRouteError("model_route_credential_qualification_missing")


class ProviderObserver(Protocol):
    def observe(self, route: Mapping[str, Any]) -> Mapping[str, Any]: ...


class UnavailableSecretProvider:
    def health(self, logical_ref: str) -> Mapping[str, Any]:
        del logical_ref
        raise ModelRouteError("model_route_secret_provider_unconfigured")

    def read(self, logical_ref: str) -> bytes:
        del logical_ref
        raise ModelRouteError("model_route_secret_provider_unconfigured")


class OwnerOnlyFileSecretProvider:
    """Resolve logical refs through one ignored, owner-only binding file."""

    BINDING_VERSION = "orbit.model-route-secret-bindings/1"

    def __init__(self, bindings_path: Path) -> None:
        self.bindings_path = Path(bindings_path)

    def health(self, logical_ref: str) -> Mapping[str, Any]:
        binding = self._binding(logical_ref)
        secret_value = self._validate_secret_file(
            Path(binding["path"]), read_bytes=True
        )
        return {
            "logical_ref": logical_ref,
            "binding_version": binding["version"],
            "secret_fingerprint": "sha256:"
            + hashlib.sha256(secret_value).hexdigest(),
            "healthy": True,
        }

    def read(self, logical_ref: str) -> bytes:
        binding = self._binding(logical_ref)
        return self._validate_secret_file(Path(binding["path"]), read_bytes=True)

    def promote_next(self, family_ref: str) -> Mapping[str, Any]:
        """Atomically swap current/next bindings after validating next."""
        if not _SECRET_REF.fullmatch(family_ref + "/current"):
            raise ModelRouteError("model_route_secret_family_ref_invalid")
        document = self._load_bindings()
        current_ref = family_ref + "/current"
        next_ref = family_ref + "/next"
        bindings = document["bindings"]
        if current_ref not in bindings or next_ref not in bindings:
            raise ModelRouteError("model_route_secret_rotation_slot_missing")
        self._validate_secret_file(Path(bindings[next_ref]["path"]), read_bytes=False)
        updated = {
            **document,
            "bindings": {
                **bindings,
                current_ref: bindings[next_ref],
                next_ref: bindings[current_ref],
            },
        }
        _atomic_owner_only_json(self.bindings_path, updated)
        return self.health(current_ref)

    def bind(
        self, logical_ref: str, secret_value: bytes, *, version: str
    ) -> Mapping[str, Any]:
        """Persist secret bytes once and atomically update the logical binding.

        The returned projection contains only a fingerprint and version.  Secret
        bytes never enter the database or an audit payload.
        """
        if not _SECRET_REF.fullmatch(logical_ref) or not _TOKEN.fullmatch(version):
            raise ModelRouteError("model_route_secret_binding_invalid")
        if not 12 <= len(secret_value) <= 64 * 1024 or b"\x00" in secret_value:
            raise ModelRouteError("model_route_secret_value_invalid")
        parent = self.bindings_path.parent
        try:
            metadata = parent.lstat()
        except OSError as error:
            raise ModelRouteError("model_route_secret_directory_invalid") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ModelRouteError("model_route_secret_directory_invalid")
        secret_dir = parent / "values"
        secret_dir.mkdir(mode=0o700, exist_ok=True)
        secret_dir.chmod(0o700)
        if secret_dir.is_symlink() or secret_dir.stat().st_uid != os.geteuid():
            raise ModelRouteError("model_route_secret_directory_invalid")
        fingerprint = "sha256:" + hashlib.sha256(secret_value).hexdigest()
        safe_name = hashlib.sha256(f"{logical_ref}:{version}".encode()).hexdigest()
        target = secret_dir / safe_name
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(target, flags, 0o600)
            try:
                os.write(descriptor, secret_value)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except FileExistsError as error:
            raise ModelRouteError("model_route_secret_version_conflict") from error
        try:
            document = self._load_or_empty_bindings()
            updated = {
                **document,
                "bindings": {
                    **document["bindings"],
                    logical_ref: {"path": str(target), "version": version},
                },
            }
            _atomic_owner_only_json(self.bindings_path, updated)
        except Exception:
            try:
                target.unlink()
            except OSError:
                pass
            raise
        return {
            "logical_ref": logical_ref,
            "binding_version": version,
            "secret_fingerprint": fingerprint,
            "healthy": True,
        }

    def _load_or_empty_bindings(self) -> dict[str, Any]:
        if not self.bindings_path.exists():
            return {"binding_version": self.BINDING_VERSION, "bindings": {}}
        return self._load_bindings()

    def _binding(self, logical_ref: str) -> Mapping[str, str]:
        if not _SECRET_REF.fullmatch(logical_ref):
            raise ModelRouteError("model_route_secret_ref_invalid")
        document = self._load_bindings()
        binding = document["bindings"].get(logical_ref)
        if not isinstance(binding, dict) or set(binding) != {"path", "version"}:
            raise ModelRouteError("model_route_secret_binding_missing")
        path = binding.get("path")
        version = binding.get("version")
        if (
            not isinstance(path, str)
            or not Path(path).is_absolute()
            or not isinstance(version, str)
            or not _TOKEN.fullmatch(version)
        ):
            raise ModelRouteError("model_route_secret_binding_invalid")
        return {"path": path, "version": version}

    def _load_bindings(self) -> dict[str, Any]:
        self._validate_metadata(self.bindings_path, max_bytes=64 * 1024)
        try:
            document = json.loads(
                self.bindings_path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=lambda _: _reject_constant(),
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            del error
            raise ModelRouteError("model_route_secret_bindings_invalid") from None
        if (
            not isinstance(document, dict)
            or set(document) != {"binding_version", "bindings"}
            or document["binding_version"] != self.BINDING_VERSION
            or not isinstance(document["bindings"], dict)
            or not document["bindings"]
        ):
            raise ModelRouteError("model_route_secret_bindings_invalid")
        return document

    def _validate_secret_file(self, path: Path, *, read_bytes: bool) -> bytes:
        initial = self._validate_metadata(path, max_bytes=64 * 1024)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            del error
            raise ModelRouteError("model_route_secret_file_invalid") from None
        try:
            opened = os.fstat(descriptor)
            _validate_owner_file_metadata(opened, max_bytes=64 * 1024)
            if (initial.st_dev, initial.st_ino) != (opened.st_dev, opened.st_ino):
                raise ModelRouteError("model_route_secret_file_changed")
            if not read_bytes:
                return b""
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                value = handle.read(64 * 1024 + 1)
            if not 1 <= len(value) <= 64 * 1024:
                raise ModelRouteError("model_route_secret_file_invalid")
            return value
        finally:
            os.close(descriptor)

    @staticmethod
    def _validate_metadata(path: Path, *, max_bytes: int) -> os.stat_result:
        try:
            metadata = path.lstat()
        except OSError as error:
            del error
            raise ModelRouteError("model_route_secret_file_invalid") from None
        _validate_owner_file_metadata(metadata, max_bytes=max_bytes)
        return metadata


class FixtureProviderObserver:
    def __init__(self, observation: Mapping[str, Any]) -> None:
        self.observation = _validate_observation(dict(observation))

    def observe(self, route: Mapping[str, Any]) -> Mapping[str, Any]:
        if (
            self.observation["provider"] != route["provider"]
            or self.observation["requested_model"] != route["requested_model"]
        ):
            raise ModelRouteError("model_route_fixture_observation_mismatch")
        return dict(self.observation)


class WeMetaProviderObserver:
    """Adapter for an explicitly supplied official machine-readable source.

    No default source is guessed.  The transport is injected so tests and the
    service do not accidentally perform provider network access.
    """

    def __init__(
        self,
        *,
        machine_source_url: str | None,
        transport: Callable[[str, str], Mapping[str, Any]] | None = None,
    ) -> None:
        self.machine_source_url = machine_source_url
        self.transport = transport

    def observe(self, route: Mapping[str, Any]) -> Mapping[str, Any]:
        if self.machine_source_url is None or self.transport is None:
            raise ModelRouteError("fixture_machine_source_unconfigured")
        parsed = urlsplit(self.machine_source_url)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.hostname != "models.paper-orbit.invalid"
            or not parsed.path.startswith("/")
        ):
            raise ModelRouteError("fixture_machine_source_not_allowed")
        try:
            raw = dict(self.transport(self.machine_source_url, route["requested_model"]))
        except ModelRouteError:
            raise
        except Exception as error:
            raise ModelRouteError("fixture_machine_source_unavailable") from error
        expected = {
            "source_version",
            "provider",
            "requested_model",
            "resolved_model_id",
            "input_usd_per_million_tokens",
            "output_usd_per_million_tokens",
            "cached_input_usd_per_million_tokens",
            "observed_at",
            "expires_at",
        }
        if set(raw) != expected or raw.get("source_version") != "fixture.model-price/1":
            raise ModelRouteError("fixture_machine_source_format_unverified")
        return _validate_observation(
            {
                "observation_version": "orbit.provider-observation/1",
                "provider": raw["provider"],
                "requested_model": raw["requested_model"],
                "resolved_model_id": raw["resolved_model_id"],
                "input_usd_per_million_tokens": raw[
                    "input_usd_per_million_tokens"
                ],
                "output_usd_per_million_tokens": raw[
                    "output_usd_per_million_tokens"
                ],
                "cached_input_usd_per_million_tokens": raw[
                    "cached_input_usd_per_million_tokens"
                ],
                "source": self.machine_source_url,
                "source_kind": "official_machine_readable",
                "regression_status": "not_run",
                "observed_at": raw["observed_at"],
                "expires_at": raw["expires_at"],
            }
        )


def urllib_json_transport(url: str, requested_model: str) -> Mapping[str, Any]:
    """Read explicit JSON only; credentials, cookies and browser state are absent."""
    separator = "&" if "?" in url else "?"
    target = f"{url}{separator}model={requested_model}"
    request = urllib.request.Request(
        target,
        headers={"Accept": "application/json", "User-Agent": "orbit-control-plane/0.1"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/json":
            raise ModelRouteError("fixture_machine_source_unavailable")
        payload = response.read(256 * 1024 + 1)
    if len(payload) > 256 * 1024:
        raise ModelRouteError("fixture_machine_source_response_too_large")
    value = json.loads(
        payload,
        object_pairs_hook=_unique_object,
        parse_constant=lambda _: _reject_constant(),
    )
    if not isinstance(value, dict):
        raise ModelRouteError("fixture_machine_source_format_unverified")
    return value


class ModelRouteStore:
    def __init__(self, database: Database) -> None:
        self.database = database

    def record_route(self, document: Mapping[str, Any], *, session: Session | None = None) -> tuple[str, bool]:
        value = _validate_route(dict(document))
        digest = canonical_digest(value)
        with (self.database.session() if session is None else nullcontext(session)) as session:
            existing = session.scalar(
                select(ModelRouteRevisionRow).where(
                    ModelRouteRevisionRow.revision_digest == digest
                )
            )
            if existing is not None:
                if _route_document(existing) != value:
                    raise ModelRouteError("model_route_revision_digest_conflict")
                return digest, False
            session.add(
                ModelRouteRevisionRow(
                    route_id=value["route_id"],
                    revision_digest=digest,
                    provider=value["provider"],
                    endpoint=value["endpoint"],
                    requested_model=value["requested_model"],
                    parameters=value["parameters"],
                    data_classification=value["data_classification"],
                    budget_policy=value["budget_policy"],
                    resolution_mode=value["resolution_mode"],
                    secret_ref=value.get("secret_ref"),
                    route_version=value["route_version"],
                    authentication=value.get("authentication"),
                    credential_scope=value.get("credential_scope"),
                    authorized_node_refs=value.get("authorized_node_refs"),
                    qualification_evidence_refs=value.get(
                        "qualification_evidence_refs"
                    ),
                    budget_control_mode=value.get("budget_control_mode"),
                    approved_scope=value["approved_scope"],
                    runtime_binding=value["runtime_binding"],
                    policy_binding=value["policy_binding"],
                    status=value["status"],
                    created_at=_utcnow(),
                )
            )
        return digest, True

    def record_observation(self, document: Mapping[str, Any]) -> tuple[str, bool]:
        value = _validate_observation(dict(document))
        digest = canonical_digest(value)
        with self.database.session() as session:
            existing = session.scalar(
                select(ProviderObservationRow).where(
                    ProviderObservationRow.observation_digest == digest
                )
            )
            if existing is not None:
                if _observation_document(existing) != value:
                    raise ModelRouteError("provider_observation_digest_conflict")
                return digest, False
            session.add(
                ProviderObservationRow(
                    provider=value["provider"],
                    requested_model=value["requested_model"],
                    resolved_model_id=value["resolved_model_id"],
                    input_usd_per_million_tokens=value[
                        "input_usd_per_million_tokens"
                    ],
                    output_usd_per_million_tokens=value[
                        "output_usd_per_million_tokens"
                    ],
                    cached_input_usd_per_million_tokens=value[
                        "cached_input_usd_per_million_tokens"
                    ],
                    source=value["source"],
                    source_kind=value["source_kind"],
                    regression_status=value["regression_status"],
                    observed_at=_time(value["observed_at"]),
                    expires_at=_time(value["expires_at"]),
                    observation_digest=digest,
                    created_at=_utcnow(),
                )
            )
        return digest, True

    def latest_route(self, route_id: str) -> ModelRouteRevisionRow | None:
        with self.database.session() as session:
            return session.scalar(
                select(ModelRouteRevisionRow)
                .where(ModelRouteRevisionRow.route_id == route_id)
                .order_by(ModelRouteRevisionRow.id.desc())
                .limit(1)
            )

    def latest_observation(
        self, *, provider: str, requested_model: str
    ) -> ProviderObservationRow | None:
        with self.database.session() as session:
            return session.scalar(
                select(ProviderObservationRow)
                .where(
                    ProviderObservationRow.provider == provider,
                    ProviderObservationRow.requested_model == requested_model,
                )
                .order_by(
                    ProviderObservationRow.observed_at.desc(),
                    ProviderObservationRow.id.desc(),
                )
                .limit(1)
            )

    def latest_snapshot(self, route_id: str) -> ModelRouteSnapshotRow | None:
        with self.database.session() as session:
            return session.scalar(
                select(ModelRouteSnapshotRow)
                .where(ModelRouteSnapshotRow.route_id == route_id)
                .order_by(ModelRouteSnapshotRow.id.desc())
                .limit(1)
            )

    def record_snapshot(self, document: Mapping[str, Any]) -> tuple[str, bool]:
        value = dict(document)
        digest = canonical_digest(value)
        with self.database.session() as session:
            existing = session.scalar(
                select(ModelRouteSnapshotRow).where(
                    ModelRouteSnapshotRow.snapshot_digest == digest
                )
            )
            if existing is not None:
                if _snapshot_document(existing) != value:
                    raise ModelRouteError("model_route_snapshot_digest_conflict")
                return digest, False
            row = ModelRouteSnapshotRow(
                route_id=value["route_id"],
                route_revision_digest=value["route_revision_digest"],
                observation_digest=value["observation_digest"],
                secret_ref=value["secret_ref"],
                secret_binding_version=value["secret_binding_version"],
                requested_model=value["requested_model"],
                resolved_model_id=value["resolved_model_id"],
                endpoint=value["endpoint"],
                budget_policy=value["budget_policy"],
                worst_case_cost=value["worst_case_cost"],
                runtime_binding=value["runtime_binding"],
                policy_binding=value["policy_binding"],
                status=value["status"],
                reason_codes=value["reason_codes"],
                expires_at=_time(value["expires_at"]),
                snapshot_digest=digest,
                created_at=_utcnow(),
            )
            session.add(row)
            event_id = deterministic_id("outbox", "model-route-snapshot", digest)
            audit_id = deterministic_id("audit", "model-route-snapshot", digest)
            session.add(
                OutboxEventRow(
                    event_id=event_id,
                    topic="model_route.snapshot.recorded",
                    aggregate_ref=f"model-route://{value['route_id']}",
                    payload={
                        "route_id": value["route_id"],
                        "snapshot_digest": digest,
                        "status": value["status"],
                        "reason_codes": value["reason_codes"],
                    },
                    status="pending",
                    attempts=0,
                    created_at=_utcnow(),
                    published_at=None,
                )
            )
            session.add(
                AuditEventRow(
                    audit_id=audit_id,
                    correlation_id=value["route_id"],
                    event_type="model_route_snapshot_recorded",
                    actor_ref="workload_model_route_reconciler",
                    payload={
                        **_route_audit_references(
                            session,
                            route_id=value["route_id"],
                            route_revision_digest=value["route_revision_digest"],
                        ),
                        "route_revision_digest": value["route_revision_digest"],
                        "observation_digest": value["observation_digest"],
                        "snapshot_digest": digest,
                        "status": value["status"],
                        "reason_codes": value["reason_codes"],
                        "secret_healthy": value["secret_binding_version"] is not None,
                        "release_authorization": False,
                    },
                    recorded_at=_utcnow(),
                )
            )
        return digest, True


class ModelRouteReconciler:
    OBSERVATION_TTL = timedelta(hours=6)
    DEPLOYMENT_MAX_OBSERVATION_AGE = timedelta(minutes=30)

    def __init__(
        self,
        *,
        store: ModelRouteStore,
        secret_provider: SecretProvider | None = None,
        provider_observer: ProviderObserver | None = None,
        credential_health_provider: CredentialHealthProvider | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.secret_provider = secret_provider or UnavailableSecretProvider()
        self.provider_observer = provider_observer
        self.credential_health_provider = (
            credential_health_provider or UnavailableCredentialHealthProvider()
        )
        self.now = now or _utcnow

    def reconcile(self, route_id: str, *, refresh: bool = False) -> Mapping[str, Any]:
        now = self.now().astimezone(timezone.utc)
        row = self.store.latest_route(route_id)
        if row is None:
            raise ModelRouteError("model_route_revision_not_found")
        route = _route_document(row)
        reasons: set[str] = set()
        secret_version: str | None = None
        try:
            if route["route_version"] == "orbit.model-route-revision/1":
                credential = self.secret_provider.health(route["secret_ref"])
            elif route["authentication"]["mode"] == "api_key_ref":
                credential = self.secret_provider.health(
                    route["authentication"]["credential_binding_ref"]
                )
            else:
                credential = self.credential_health_provider.health(route)
            if credential.get("healthy") is not True:
                raise ModelRouteError("model_route_credential_unhealthy")
            secret_version = str(credential["binding_version"])
        except ModelRouteError as error:
            reasons.add(error.reason_code)

        observation_row = self.store.latest_observation(
            provider=route["provider"], requested_model=route["requested_model"]
        )
        if refresh or observation_row is None or _as_utc(observation_row.expires_at) <= now:
            if self.provider_observer is not None:
                try:
                    observed = self.provider_observer.observe(route)
                    self.store.record_observation(observed)
                    observation_row = self.store.latest_observation(
                        provider=route["provider"],
                        requested_model=route["requested_model"],
                    )
                except ModelRouteError as error:
                    reasons.add(error.reason_code)
            elif observation_row is None:
                reasons.add("provider_observation_missing")
            else:
                reasons.add("provider_observation_expired")

        observation = (
            None if observation_row is None else _observation_document(observation_row)
        )
        if observation_row is not None:
            if _as_utc(observation_row.expires_at) <= now:
                reasons.add("provider_observation_expired")
            if _as_utc(observation_row.expires_at) - _as_utc(
                observation_row.observed_at
            ) > self.OBSERVATION_TTL:
                reasons.add("provider_observation_ttl_excessive")
            reasons.update(_route_observation_reasons(route, observation))

        worst = _worst_case_cost(route["budget_policy"], observation)
        if (
            route.get("budget_control_mode") != "usage_limits"
            and worst["within_hard_cap"] is not True
        ):
            reasons.add("model_route_budget_hard_cap_exceeded")
        reasons.update(_approved_scope_reasons(route))
        status = "ready" if not reasons else "blocked"
        expires_at = (
            _as_utc(observation_row.expires_at)
            if observation_row is not None
            else now + timedelta(minutes=5)
        )
        snapshot = {
            "snapshot_version": "orbit.model-route-snapshot/1",
            "route_id": route["route_id"],
            "route_revision_digest": row.revision_digest,
            "observation_digest": (
                None
                if observation_row is None
                else observation_row.observation_digest
            ),
            "secret_ref": (
                route.get("secret_ref")
                or route.get("authentication", {}).get("credential_binding_ref")
            ),
            "secret_binding_version": secret_version,
            "requested_model": route["requested_model"],
            "resolved_model_id": (
                None if observation is None else observation["resolved_model_id"]
            ),
            "endpoint": route["endpoint"],
            "budget_policy": route["budget_policy"],
            "worst_case_cost": worst,
            "runtime_binding": route["runtime_binding"],
            "policy_binding": route["policy_binding"],
            "status": status,
            "reason_codes": sorted(reasons),
            "expires_at": _time_text(expires_at),
            "release_authorization": False,
        }
        digest, appended = self.store.record_snapshot(snapshot)
        return {
            **snapshot,
            "snapshot_digest": digest,
            "appended": appended,
        }

    def status(self, route_id: str) -> Mapping[str, Any]:
        now = self.now().astimezone(timezone.utc)
        route = self.store.latest_route(route_id)
        if route is None:
            raise ModelRouteError("model_route_revision_not_found")
        observation = self.store.latest_observation(
            provider=route.provider, requested_model=route.requested_model
        )
        snapshot = self.store.latest_snapshot(route_id)
        secret_healthy = False
        secret_reason: str | None = None
        try:
            route_document = _route_document(route)
            if route_document["route_version"] == "orbit.model-route-revision/1":
                credential = self.secret_provider.health(route.secret_ref)
            elif route_document["authentication"]["mode"] == "api_key_ref":
                credential = self.secret_provider.health(
                    route_document["authentication"]["credential_binding_ref"]
                )
            else:
                credential = self.credential_health_provider.health(route_document)
            secret_healthy = credential.get("healthy") is True
        except ModelRouteError as error:
            secret_reason = error.reason_code
        reasons = [] if snapshot is None else list(snapshot.reason_codes)
        if secret_reason is not None:
            reasons.append(secret_reason)
        if observation is not None and _as_utc(observation.expires_at) <= now:
            reasons.append("provider_observation_expired")
        if snapshot is not None and _as_utc(snapshot.expires_at) <= now:
            reasons.append("model_route_snapshot_expired")
        reasons = sorted(set(reasons))
        effective_snapshot_status = (
            "not_created"
            if snapshot is None
            else "blocked"
            if reasons
            else snapshot.status
        )
        return {
            "route_id": route.route_id,
            "route_revision_digest": route.revision_digest,
            "requested_model": route.requested_model,
            "resolved_model_id": (
                None if observation is None else observation.resolved_model_id
            ),
            "endpoint": route.endpoint,
            "observation_digest": (
                None if observation is None else observation.observation_digest
            ),
            "observed_at": (
                None if observation is None else _time_text(observation.observed_at)
            ),
            "observation_expires_at": (
                None if observation is None else _time_text(observation.expires_at)
            ),
            "credential_healthy": secret_healthy,
            "secret_healthy": secret_healthy,
            "authentication_mode": (
                "api_key_ref"
                if route_document["route_version"] == "orbit.model-route-revision/1"
                else route_document["authentication"]["mode"]
            ),
            "snapshot_digest": (
                None if snapshot is None else snapshot.snapshot_digest
            ),
            "snapshot_status": effective_snapshot_status,
            "snapshot_expires_at": (
                None if snapshot is None else _time_text(snapshot.expires_at)
            ),
            "reason_codes": reasons,
            "next_human_checkpoint": (
                None
                if effective_snapshot_status == "ready"
                else "model_route_scope_or_source_resolution"
            ),
            "release_authorization": False,
        }

    def deploy_preflight(self, route_id: str) -> Mapping[str, Any]:
        now = self.now().astimezone(timezone.utc)
        snapshot = self.store.latest_snapshot(route_id)
        reasons: set[str] = set()
        if snapshot is None:
            reasons.add("model_route_snapshot_missing")
        else:
            if snapshot.status != "ready":
                reasons.update(snapshot.reason_codes)
            if _as_utc(snapshot.expires_at) <= now:
                reasons.add("model_route_snapshot_expired")
            observation = (
                None
                if snapshot.observation_digest is None
                else self._observation_by_digest(snapshot.observation_digest)
            )
            if observation is None:
                reasons.add("provider_observation_missing")
            else:
                if now - _as_utc(observation.observed_at) > self.DEPLOYMENT_MAX_OBSERVATION_AGE:
                    reasons.add("provider_observation_too_old_for_deployment")
                if _as_utc(observation.expires_at) <= now:
                    reasons.add("provider_observation_expired")
            route = self.store.latest_route(route_id)
            route_document = None if route is None else _route_document(route)
            try:
                if route_document is None:
                    raise ModelRouteError("model_route_revision_not_found")
                if route_document["route_version"] == "orbit.model-route-revision/1":
                    health = self.secret_provider.health(snapshot.secret_ref)
                elif route_document["authentication"]["mode"] == "api_key_ref":
                    health = self.secret_provider.health(
                        route_document["authentication"]["credential_binding_ref"]
                    )
                else:
                    health = self.credential_health_provider.health(route_document)
                if health.get("binding_version") != snapshot.secret_binding_version:
                    reasons.add(
                        "model_route_secret_binding_drift"
                        if route_document["route_version"]
                        == "orbit.model-route-revision/1"
                        else "model_route_credential_binding_drift"
                    )
            except ModelRouteError as error:
                reasons.add(error.reason_code)
        ready = not reasons
        return {
            "route_id": route_id,
            "snapshot_digest": (
                None if snapshot is None else snapshot.snapshot_digest
            ),
            "status": "ready" if ready else "blocked",
            "reason_codes": sorted(reasons),
            "provider_execution_started": False,
            "release_authorization": False,
        }

    def _observation_by_digest(self, digest: str) -> ProviderObservationRow | None:
        with self.store.database.session() as session:
            return session.scalar(
                select(ProviderObservationRow).where(
                    ProviderObservationRow.observation_digest == digest
                )
            )


def read_internal_document(path: Path) -> dict[str, Any]:
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise ModelRouteError("model_route_document_invalid")
    try:
        value = json.loads(
            candidate.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: _reject_constant(),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ModelRouteError("model_route_document_invalid") from error
    if not isinstance(value, dict):
        raise ModelRouteError("model_route_document_invalid")
    return value


def _validate_route(value: dict[str, Any]) -> dict[str, Any]:
    version = value.get("route_version")
    if version == "orbit.model-route-revision/1":
        if set(value) != _ROUTE_FIELDS:
            raise ModelRouteError("model_route_revision_invalid")
    elif version == "orbit.model-route-revision/2":
        if set(value) != _ROUTE_V2_FIELDS:
            raise ModelRouteError("model_route_revision_invalid")
    else:
        raise ModelRouteError("model_route_revision_invalid")
    if (
        not isinstance(value["route_id"], str)
        or not _TOKEN.fullmatch(value["route_id"])
        or not isinstance(value["provider"], str)
        or not _TOKEN.fullmatch(value["provider"])
        or not isinstance(value["requested_model"], str)
        or not _TOKEN.fullmatch(value["requested_model"])
        or "*" in value["requested_model"]
        or value["resolution_mode"] not in {"pinned", "provider_verified_alias"}
        or value["status"] not in {"active", "proposed"}
        or value["data_classification"] not in {"synthetic", "public", "internal"}
        or not isinstance(value["parameters"], dict)
    ):
        raise ModelRouteError("model_route_revision_invalid")
    if version == "orbit.model-route-revision/1":
        if not _SECRET_REF.fullmatch(str(value["secret_ref"])):
            raise ModelRouteError("model_route_revision_invalid")
        _validate_budget(value["budget_policy"])
    else:
        _validate_route_v2_authentication(value)
        _validate_usage_budget(
            value["budget_policy"], mode=value["budget_control_mode"]
        )
    _validate_endpoint(value["endpoint"])
    scope = value["approved_scope"]
    if not isinstance(scope, dict) or set(scope) != _APPROVED_SCOPE_FIELDS:
        raise ModelRouteError("model_route_approved_scope_invalid")
    if (
        not isinstance(scope["permissions"], list)
        or not scope["permissions"]
        or any(not isinstance(item, str) or not _TOKEN.fullmatch(item) for item in scope["permissions"])
        or len(set(scope["permissions"])) != len(scope["permissions"])
        or not isinstance(scope["resolved_model_ids"], list)
        or not scope["resolved_model_ids"]
        or any(
            not isinstance(item, str) or not _TOKEN.fullmatch(item) or "*" in item
            for item in scope["resolved_model_ids"]
        )
        or not isinstance(scope["model_family"], str)
        or not _TOKEN.fullmatch(scope["model_family"])
        or "*" in scope["model_family"]
    ):
        raise ModelRouteError("model_route_approved_scope_invalid")
    for binding in (value["runtime_binding"], value["policy_binding"]):
        if (
            not isinstance(binding, dict)
            or set(binding) != {"ref", "digest"}
            or not isinstance(binding["ref"], str)
            or not _TOKEN.fullmatch(binding["ref"])
            or not isinstance(binding["digest"], str)
            or not _DIGEST.fullmatch(binding["digest"])
        ):
            raise ModelRouteError("model_route_binding_invalid")
    return _json_roundtrip(value)


def _validate_route_v2_authentication(value: Mapping[str, Any]) -> None:
    authentication = value["authentication"]
    if (
        not isinstance(authentication, dict)
        or set(authentication) != _AUTHENTICATION_FIELDS
        or authentication.get("mode") not in {"api_key_ref", "oauth_ref"}
        or not isinstance(authentication.get("credential_binding_ref"), str)
        or not re.fullmatch(
            r"^(secret|oauth)://[a-z0-9][a-z0-9/_-]{2,190}$",
            authentication["credential_binding_ref"],
        )
        or value["credential_scope"] not in {"company", "department"}
        or value["budget_control_mode"]
        not in {"currency_and_usage", "usage_limits"}
    ):
        raise ModelRouteError("model_route_authentication_invalid")
    nodes = value["authorized_node_refs"]
    evidence = value["qualification_evidence_refs"]
    if (
        not isinstance(nodes, list)
        or len(nodes) != len(set(nodes))
        or any(not isinstance(item, str) or not _TOKEN.fullmatch(item) for item in nodes)
        or not isinstance(evidence, list)
        or len(evidence) != len(set(evidence))
        or any(
            not isinstance(item, str)
            or not (_TOKEN.fullmatch(item) or _DIGEST.fullmatch(item))
            for item in evidence
        )
    ):
        raise ModelRouteError("model_route_authentication_invalid")
    if authentication["mode"] == "oauth_ref":
        if (
            not authentication["credential_binding_ref"].startswith("oauth://")
            or value["credential_scope"] != "company"
            or not nodes
            or value["budget_control_mode"] != "usage_limits"
        ):
            raise ModelRouteError("model_route_authentication_invalid")
    elif (
        not authentication["credential_binding_ref"].startswith("secret://")
        or value["budget_control_mode"] != "currency_and_usage"
    ):
        raise ModelRouteError("model_route_authentication_invalid")


def _validate_usage_budget(value: Any, *, mode: str) -> None:
    if mode == "currency_and_usage":
        expected = _BUDGET_FIELDS | {
            "max_turns",
            "max_duration_seconds",
            "max_concurrency",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ModelRouteError("model_route_budget_invalid")
        _validate_budget({key: value[key] for key in _BUDGET_FIELDS})
    else:
        if not isinstance(value, dict) or set(value) != _USAGE_BUDGET_FIELDS:
            raise ModelRouteError("model_route_budget_invalid")
        if (
            value.get("max_input_tokens") != 20_000
            or value.get("max_output_tokens") != 4_000
            or value.get("max_turns") != 6
            or value.get("max_duration_seconds") != 900
            or value.get("max_concurrency") != 1
        ):
            raise ModelRouteError("model_route_account_budget_boundary_invalid")
    if (
        not isinstance(value.get("max_turns"), int)
        or not 1 <= value["max_turns"] <= 64
        or not isinstance(value.get("max_duration_seconds"), int)
        or not 60 <= value["max_duration_seconds"] <= 3600
        or not isinstance(value.get("max_concurrency"), int)
        or value["max_concurrency"] != 1
    ):
        raise ModelRouteError("model_route_budget_invalid")


def _validate_observation(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != _OBSERVATION_FIELDS or value.get("observation_version") != "orbit.provider-observation/1":
        raise ModelRouteError("provider_observation_invalid")
    if (
        not isinstance(value["provider"], str)
        or not _TOKEN.fullmatch(value["provider"])
        or not isinstance(value["requested_model"], str)
        or not _TOKEN.fullmatch(value["requested_model"])
        or not isinstance(value["resolved_model_id"], str)
        or not _TOKEN.fullmatch(value["resolved_model_id"])
        or "*" in value["resolved_model_id"]
        or value["source_kind"] not in {
            "official_machine_readable",
            "human_reviewed_import",
            "deterministic_fixture",
        }
        or value["regression_status"] not in {"pass", "fail", "not_run"}
        or not isinstance(value["source"], str)
        or not value["source"]
    ):
        raise ModelRouteError("provider_observation_invalid")
    for key in (
        "input_usd_per_million_tokens",
        "output_usd_per_million_tokens",
        "cached_input_usd_per_million_tokens",
    ):
        _nonnegative_decimal(value[key], "provider_observation_price_invalid")
    observed = _time(value["observed_at"])
    expires = _time(value["expires_at"])
    if not observed < expires:
        raise ModelRouteError("provider_observation_time_invalid")
    return _json_roundtrip(value)


def _approved_scope_reasons(route: Mapping[str, Any]) -> set[str]:
    scope = route["approved_scope"]
    reasons = set()
    if scope["provider"] != route["provider"]:
        reasons.add("model_route_provider_drift")
    if scope["endpoint"] != route["endpoint"]:
        reasons.add("model_route_endpoint_drift")
    if scope["data_classification"] != route["data_classification"]:
        reasons.add("model_route_data_classification_drift")
    parameters = route["parameters"]
    if parameters.get("permissions") != scope["permissions"]:
        reasons.add("model_route_permission_drift")
    return reasons


def _route_observation_reasons(
    route: Mapping[str, Any], observation: Mapping[str, Any]
) -> set[str]:
    reasons = set()
    if observation["provider"] != route["provider"]:
        reasons.add("provider_observation_provider_mismatch")
    if observation["requested_model"] != route["requested_model"]:
        reasons.add("provider_observation_requested_model_mismatch")
    resolved = observation["resolved_model_id"]
    scope = route["approved_scope"]
    if route["resolution_mode"] == "pinned":
        if resolved not in scope["resolved_model_ids"]:
            reasons.add("model_route_resolved_model_not_pinned")
    else:
        same_family = resolved == scope["model_family"] or resolved.startswith(
            scope["model_family"] + "-"
        )
        explicitly_approved = resolved in scope["resolved_model_ids"]
        if not same_family:
            reasons.add("model_route_model_family_drift")
        elif not explicitly_approved and observation["regression_status"] != "pass":
            reasons.add("model_route_family_regression_required")
    return reasons


def _worst_case_cost(
    budget: Mapping[str, Any], observation: Mapping[str, Any] | None
) -> dict[str, Any]:
    if not _BUDGET_FIELDS.issubset(budget):
        return {
            "usd": None,
            "cny": None,
            "within_hard_cap": None,
            "cost_evidence_status": "not_applicable_account_subscription",
        }
    if observation is None:
        return {
            "usd": None,
            "cny": None,
            "within_hard_cap": False,
        }
    input_cost = Decimal(budget["max_input_tokens"]) * Decimal(
        observation["input_usd_per_million_tokens"]
    ) / Decimal(1_000_000)
    output_cost = Decimal(budget["max_output_tokens"]) * Decimal(
        observation["output_usd_per_million_tokens"]
    ) / Decimal(1_000_000)
    usd = input_cost + output_cost
    cny = usd * Decimal(budget["cny_per_usd"])
    return {
        "usd": format(usd.quantize(Decimal("0.000001")), "f"),
        "cny": format(cny.quantize(Decimal("0.000001")), "f"),
        "within_hard_cap": (
            usd <= Decimal(budget["max_cost_usd"])
            and cny <= Decimal(budget["max_cost_cny"])
        ),
    }


def _validate_budget(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != _BUDGET_FIELDS:
        raise ModelRouteError("model_route_budget_invalid")
    if (
        not isinstance(value["max_input_tokens"], int)
        or not 1 <= value["max_input_tokens"] <= 10_000_000
        or not isinstance(value["max_output_tokens"], int)
        or not 1 <= value["max_output_tokens"] <= 1_000_000
    ):
        raise ModelRouteError("model_route_budget_invalid")
    for key in ("max_cost_usd", "max_cost_cny", "cny_per_usd"):
        if _nonnegative_decimal(value[key], "model_route_budget_invalid") <= 0:
            raise ModelRouteError("model_route_budget_invalid")


def _validate_endpoint(value: Any) -> None:
    if not isinstance(value, str):
        raise ModelRouteError("model_route_endpoint_invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path
    ):
        raise ModelRouteError("model_route_endpoint_invalid")


def _route_audit_references(
    session: Session, *, route_id: str, route_revision_digest: str
) -> dict[str, Any]:
    """Associate audit scope only through one accepted, exact proposal revision."""
    references: dict[str, Any] = {
        "route_id": route_id,
        "route_revision_digest": route_revision_digest,
    }
    proposals = tuple(session.scalars(
        select(DepartmentAgentProposalRow)
        .where(
            DepartmentAgentProposalRow.model_route_id == route_id,
            DepartmentAgentProposalRow.model_route_revision_digest == route_revision_digest,
        )
        .limit(2)
    ))
    # Global routes, unmatched revisions and ambiguous associations remain
    # company-only. Neither the actor nor a policy URI establishes a department.
    if len(proposals) != 1:
        return references
    proposal = proposals[0]
    if proposal.department_id not in {
        "product_center", "technology_center", "market_center"
    }:
        return references
    references.update({
        "department_id": proposal.department_id,
        "proposal_id": proposal.proposal_id,
        "package_digest": proposal.package_digest,
        "agent_definition_ref": proposal.document["package"]["agent_definition"]["ref"],
        "agent_definition_digest": proposal.agent_definition_digest,
        "agent_binding_ref": proposal.document["package"]["agent_binding"]["ref"],
        "agent_binding_digest": proposal.agent_binding_digest,
    })
    return references


def _route_document(row: ModelRouteRevisionRow) -> dict[str, Any]:
    version = row.route_version or "orbit.model-route-revision/1"
    value = {
        "route_version": version,
        "route_id": row.route_id,
        "provider": row.provider,
        "endpoint": row.endpoint,
        "requested_model": row.requested_model,
        "parameters": row.parameters,
        "data_classification": row.data_classification,
        "budget_policy": row.budget_policy,
        "resolution_mode": row.resolution_mode,
        "approved_scope": row.approved_scope,
        "runtime_binding": row.runtime_binding,
        "policy_binding": row.policy_binding,
        "status": row.status,
    }
    if version == "orbit.model-route-revision/1":
        value["secret_ref"] = row.secret_ref
    else:
        value.update(
            {
                "authentication": row.authentication,
                "credential_scope": row.credential_scope,
                "authorized_node_refs": row.authorized_node_refs,
                "qualification_evidence_refs": row.qualification_evidence_refs,
                "budget_control_mode": row.budget_control_mode,
            }
        )
    return value


def _observation_document(row: ProviderObservationRow) -> dict[str, Any]:
    return {
        "observation_version": "orbit.provider-observation/1",
        "provider": row.provider,
        "requested_model": row.requested_model,
        "resolved_model_id": row.resolved_model_id,
        "input_usd_per_million_tokens": row.input_usd_per_million_tokens,
        "output_usd_per_million_tokens": row.output_usd_per_million_tokens,
        "cached_input_usd_per_million_tokens": row.cached_input_usd_per_million_tokens,
        "source": row.source,
        "source_kind": row.source_kind,
        "regression_status": row.regression_status,
        "observed_at": _time_text(row.observed_at),
        "expires_at": _time_text(row.expires_at),
    }


def _snapshot_document(row: ModelRouteSnapshotRow) -> dict[str, Any]:
    return {
        "snapshot_version": "orbit.model-route-snapshot/1",
        "route_id": row.route_id,
        "route_revision_digest": row.route_revision_digest,
        "observation_digest": row.observation_digest,
        "secret_ref": row.secret_ref,
        "secret_binding_version": row.secret_binding_version,
        "requested_model": row.requested_model,
        "resolved_model_id": row.resolved_model_id,
        "endpoint": row.endpoint,
        "budget_policy": row.budget_policy,
        "worst_case_cost": row.worst_case_cost,
        "runtime_binding": row.runtime_binding,
        "policy_binding": row.policy_binding,
        "status": row.status,
        "reason_codes": row.reason_codes,
        "expires_at": _time_text(row.expires_at),
        "release_authorization": False,
    }


def _validate_owner_file_metadata(metadata: os.stat_result, *, max_bytes: int) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= max_bytes
    ):
        raise ModelRouteError("model_route_secret_file_invalid")


def _atomic_owner_only_json(path: Path, value: Mapping[str, Any]) -> None:
    encoded = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        try:
            descriptor = os.open(temporary, flags, 0o600)
            try:
                offset = 0
                while offset < len(encoded):
                    written = os.write(descriptor, encoded[offset:])
                    if written <= 0:
                        raise ModelRouteError(
                            "model_route_secret_rotation_write_failed"
                        )
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
        except OSError as error:
            del error
            raise ModelRouteError(
                "model_route_secret_rotation_write_failed"
            ) from None
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _nonnegative_decimal(value: Any, reason: str) -> Decimal:
    if not isinstance(value, str):
        raise ModelRouteError(reason)
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ModelRouteError(reason) from error
    if not parsed.is_finite() or parsed < 0:
        raise ModelRouteError(reason)
    return parsed


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


def _time_text(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _json_roundtrip(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def _reject_constant() -> None:
    raise ValueError("non_finite_json_number")

