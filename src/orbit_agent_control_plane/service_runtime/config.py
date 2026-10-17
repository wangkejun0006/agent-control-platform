"""Strict environment parsing for the service-mode Control Plane."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


class ServiceConfigurationError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


_TOKEN = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_ALLOWED_KEYS = {
    "ORBIT_SERVICE_MODE",
    "ORBIT_SERVICE_DATABASE_URL",
    "ORBIT_SERVICE_DATABASE_URL_FILE",
    "ORBIT_SERVICE_POLICY_PATH",
    "ORBIT_SERVICE_REVIEW_PACKAGE_PATH",
    "ORBIT_SERVICE_PROFILE_PATH",
    "ORBIT_SERVICE_ADAPTER_EVIDENCE_PATH",
    "ORBIT_SERVICE_OIDC_ISSUER",
    "ORBIT_SERVICE_OIDC_AUDIENCE",
    "ORBIT_SERVICE_OIDC_ADMIN_SUBJECT_DIGESTS",
    "ORBIT_SERVICE_OIDC_ALLOWED_ROLES",
    "ORBIT_SERVICE_OIDC_PUBLIC_KEY_REF",
    "ORBIT_SERVICE_OIDC_REQUIRED_KEY_ID",
    "ORBIT_SERVICE_WORKLOAD_CA_REF",
    "ORBIT_SERVICE_WORKLOAD_ALLOWED_IDENTITIES",
    "ORBIT_SERVICE_GRANT_SIGNING_KEY_REF",
    "ORBIT_SERVICE_GRANT_SIGNING_KEY_ID",
    "ORBIT_SERVICE_GRANT_VERIFICATION_KEY_PATH",
    "ORBIT_SERVICE_LOCAL_STATE_ROOT",
    "ORBIT_SERVICE_SECRET_BINDINGS_PATH",
    "ORBIT_SERVICE_MODEL_ROUTE_SECRET_BINDINGS_PATH",
    "ORBIT_SERVICE_WORKLOAD_TRUST_DOMAIN",
    "ORBIT_SERVICE_MUTATIONS_ENABLED",
    "ORBIT_SERVICE_HOST",
    "ORBIT_SERVICE_PORT",
}


@dataclass(frozen=True)
class ServiceSettings:
    mode: str
    database_url: str = field(repr=False)
    policy_path: Path
    review_package_path: Path
    profile_path: Path
    adapter_evidence_path: Path | None
    oidc_issuer: str | None
    oidc_audience: str | None
    oidc_required_key_id: str | None
    oidc_allowed_roles: tuple[str, ...]
    oidc_admin_subject_digests: tuple[str, ...]
    oidc_public_key_ref: str | None
    workload_ca_ref: str | None
    workload_allowed_identities: tuple[str, ...]
    grant_signing_key_ref: str | None
    grant_signing_key_id: str | None
    secret_bindings_path: Path | None
    workload_trust_domain: str | None
    mutations_enabled: bool
    host: str
    port: int
    grant_verification_key_path: Path | None = None
    local_state_root: Path | None = None
    model_route_secret_bindings_path: Path | None = None

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> ServiceSettings:
        source = dict(os.environ if environment is None else environment)
        unknown = sorted(
            key
            for key in source
            if key.startswith("ORBIT_SERVICE_") and key not in _ALLOWED_KEYS
        )
        if unknown:
            raise ServiceConfigurationError("service_environment_unknown_key")
        mode = source.get("ORBIT_SERVICE_MODE", "local_synthetic")
        if mode not in {
            "local_synthetic",
            "local_trusted_operator",
            "preproduction_candidate",
        }:
            raise ServiceConfigurationError("service_mode_invalid")
        database_url = _database_url(source)
        _validate_database_url(database_url, mode=mode)
        policy_path = _required_path(source, "ORBIT_SERVICE_POLICY_PATH")
        review_path = _required_path(source, "ORBIT_SERVICE_REVIEW_PACKAGE_PATH")
        profile_path = _required_path(source, "ORBIT_SERVICE_PROFILE_PATH")
        evidence_value = source.get("ORBIT_SERVICE_ADAPTER_EVIDENCE_PATH")
        evidence_path = Path(evidence_value) if evidence_value else None
        mutations_enabled = _boolean(
            source.get("ORBIT_SERVICE_MUTATIONS_ENABLED", "false")
        )
        oidc_issuer = _optional_https_origin(source.get("ORBIT_SERVICE_OIDC_ISSUER"))
        oidc_audience = _optional_token(source.get("ORBIT_SERVICE_OIDC_AUDIENCE"))
        oidc_required_key_id = _optional_token(
            source.get("ORBIT_SERVICE_OIDC_REQUIRED_KEY_ID")
        )
        oidc_allowed_roles = _token_list(
            source.get("ORBIT_SERVICE_OIDC_ALLOWED_ROLES")
        )
        oidc_admin_subject_digests = _digest_list(
            source.get("ORBIT_SERVICE_OIDC_ADMIN_SUBJECT_DIGESTS")
        )
        oidc_public_key_ref = _optional_secret_ref(
            source.get("ORBIT_SERVICE_OIDC_PUBLIC_KEY_REF")
        )
        workload_ca_ref = _optional_secret_ref(
            source.get("ORBIT_SERVICE_WORKLOAD_CA_REF")
        )
        workload_allowed_identities = _token_list(
            source.get("ORBIT_SERVICE_WORKLOAD_ALLOWED_IDENTITIES")
        )
        signing_key_ref = _optional_secret_ref(
            source.get("ORBIT_SERVICE_GRANT_SIGNING_KEY_REF")
        )
        signing_key_id = _optional_token(
            source.get("ORBIT_SERVICE_GRANT_SIGNING_KEY_ID")
        )
        verification_key_value = source.get(
            "ORBIT_SERVICE_GRANT_VERIFICATION_KEY_PATH"
        )
        verification_key_path = (
            Path(verification_key_value) if verification_key_value else None
        )
        local_state_value = source.get("ORBIT_SERVICE_LOCAL_STATE_ROOT")
        local_state_root = Path(local_state_value) if local_state_value else None
        if (
            verification_key_path is not None
            and not verification_key_path.is_absolute()
        ) or (local_state_root is not None and not local_state_root.is_absolute()):
            raise ServiceConfigurationError("service_local_operator_path_invalid")
        secret_bindings_value = source.get("ORBIT_SERVICE_SECRET_BINDINGS_PATH")
        secret_bindings_path = (
            Path(secret_bindings_value) if secret_bindings_value else None
        )
        if secret_bindings_path is not None and not secret_bindings_path.is_absolute():
            raise ServiceConfigurationError("service_secret_bindings_path_invalid")
        model_route_bindings_value = source.get(
            "ORBIT_SERVICE_MODEL_ROUTE_SECRET_BINDINGS_PATH"
        )
        model_route_secret_bindings_path = (
            Path(model_route_bindings_value)
            if model_route_bindings_value
            else None
        )
        if (
            model_route_secret_bindings_path is not None
            and not model_route_secret_bindings_path.is_absolute()
        ):
            raise ServiceConfigurationError(
                "service_model_route_secret_bindings_path_invalid"
            )
        trust_domain = source.get("ORBIT_SERVICE_WORKLOAD_TRUST_DOMAIN")
        if trust_domain is not None and not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.-]{1,93}[a-z0-9])?", trust_domain
        ):
            raise ServiceConfigurationError("service_workload_trust_domain_invalid")
        if mode == "local_trusted_operator" and mutations_enabled:
            raise ServiceConfigurationError("service_local_operator_api_read_only")
        if mutations_enabled and not all(
            (
                oidc_issuer,
                oidc_audience,
                oidc_required_key_id,
                oidc_allowed_roles,
                oidc_admin_subject_digests,
                oidc_public_key_ref,
                workload_ca_ref,
                workload_allowed_identities,
                signing_key_ref,
                signing_key_id,
                secret_bindings_path,
                trust_domain,
            )
        ):
            raise ServiceConfigurationError("service_mutation_identity_incomplete")
        if mode == "preproduction_candidate" and not mutations_enabled:
            raise ServiceConfigurationError("service_preproduction_mutations_disabled")
        host = source.get("ORBIT_SERVICE_HOST", "127.0.0.1")
        if mode in {"local_synthetic", "local_trusted_operator"} and host not in {
            "127.0.0.1",
            "::1",
            "localhost",
        }:
            raise ServiceConfigurationError("service_local_bind_invalid")
        try:
            port = int(source.get("ORBIT_SERVICE_PORT", "8431"))
        except ValueError as error:
            raise ServiceConfigurationError("service_port_invalid") from error
        if not 1024 <= port <= 65535:
            raise ServiceConfigurationError("service_port_invalid")
        return cls(
            mode=mode,
            database_url=database_url,
            policy_path=policy_path,
            review_package_path=review_path,
            profile_path=profile_path,
            adapter_evidence_path=evidence_path,
            oidc_issuer=oidc_issuer,
            oidc_audience=oidc_audience,
            oidc_required_key_id=oidc_required_key_id,
            oidc_allowed_roles=oidc_allowed_roles,
            oidc_admin_subject_digests=oidc_admin_subject_digests,
            oidc_public_key_ref=oidc_public_key_ref,
            workload_ca_ref=workload_ca_ref,
            workload_allowed_identities=workload_allowed_identities,
            grant_signing_key_ref=signing_key_ref,
            grant_signing_key_id=signing_key_id,
            secret_bindings_path=secret_bindings_path,
            workload_trust_domain=trust_domain,
            mutations_enabled=mutations_enabled,
            host=host,
            port=port,
            grant_verification_key_path=verification_key_path,
            local_state_root=local_state_root,
            model_route_secret_bindings_path=model_route_secret_bindings_path,
        )


def _validate_database_url(value: str, *, mode: str) -> None:
    if not value:
        raise ServiceConfigurationError("service_database_url_missing")
    parsed = urlsplit(value)
    if parsed.scheme != "postgresql+psycopg":
        raise ServiceConfigurationError("service_database_url_invalid")
    query_values = parse_qs(parsed.query, strict_parsing=True)
    socket_host = query_values.get("host", [None])
    socket_path = socket_host[0] if len(socket_host) == 1 else None
    if parsed.hostname is None:
        allowed_socket_roots = (
            "/private/tmp/",
            "/tmp/",
            "/private/var/folders/",
            "/var/folders/",
        )
        persistent_loopback_socket = (
            "/Users/Shared/OrbitControlPlane/sockets"
        )
        if (
            mode not in {"local_synthetic", "local_trusted_operator"}
            or not isinstance(socket_path, str)
            or (
                not socket_path.startswith(allowed_socket_roots)
                and socket_path != persistent_loopback_socket
            )
        ):
            raise ServiceConfigurationError("service_database_url_invalid")
        return
    if mode in {"local_synthetic", "local_trusted_operator"}:
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1", "postgres"}:
            raise ServiceConfigurationError("service_local_database_host_invalid")
        return
    if query_values.get("sslmode") != ["verify-full"]:
        raise ServiceConfigurationError("service_database_tls_required")


def _database_url(source: Mapping[str, str]) -> str:
    inline = source.get("ORBIT_SERVICE_DATABASE_URL")
    file_value = source.get("ORBIT_SERVICE_DATABASE_URL_FILE")
    if bool(inline) == bool(file_value):
        raise ServiceConfigurationError("service_database_source_invalid")
    if inline:
        return inline
    path = Path(file_value or "")
    try:
        info = path.lstat()
    except OSError as error:
        raise ServiceConfigurationError(
            "service_database_secret_file_invalid"
        ) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or info.st_size > 4096
    ):
        raise ServiceConfigurationError("service_database_secret_file_invalid")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise ServiceConfigurationError(
            "service_database_secret_file_invalid"
        ) from error
    return value


def _required_path(source: Mapping[str, str], key: str) -> Path:
    value = source.get(key)
    if not value:
        raise ServiceConfigurationError("service_artifact_path_missing")
    path = Path(value)
    if not path.is_absolute():
        raise ServiceConfigurationError("service_artifact_path_not_absolute")
    return path


def _boolean(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise ServiceConfigurationError("service_boolean_invalid")


def _optional_https_origin(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ServiceConfigurationError("service_oidc_issuer_invalid")
    return value.rstrip("/")


def _optional_token(value: str | None) -> str | None:
    if value is None:
        return None
    if not _TOKEN.fullmatch(value):
        raise ServiceConfigurationError("service_identity_token_invalid")
    return value


def _optional_secret_ref(value: str | None) -> str | None:
    if value is None:
        return None
    if not value.startswith("secret://") or len(value) > 240 or ".." in value:
        raise ServiceConfigurationError("service_secret_ref_invalid")
    return value


def _token_list(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    parts = tuple(value.split(","))
    if (
        not parts
        or any(not _TOKEN.fullmatch(item) for item in parts)
        or len(set(parts)) != len(parts)
    ):
        raise ServiceConfigurationError("service_identity_list_invalid")
    return parts


def _digest_list(value: str | None) -> tuple[str, ...]:
    if value is None:
        return ()
    parts = tuple(value.split(","))
    if (
        not parts
        or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in parts)
        or len(set(parts)) != len(parts)
    ):
        raise ServiceConfigurationError("service_identity_digest_list_invalid")
    return parts

