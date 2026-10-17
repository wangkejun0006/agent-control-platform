"""Uvicorn factory entrypoint."""

from __future__ import annotations

import json
from pathlib import Path

import uvicorn

from .api import create_app, load_service_runtime
from .config import ServiceSettings
from .security import (
    Ed25519EvaluationGrantSigner,
    FileSecretReferenceResolver,
    MtlsWorkloadIdentityVerifier,
    OidcHumanIdentityVerifier,
)


def app_factory():
    settings = ServiceSettings.from_environment()
    repository_root = Path(__file__).resolve().parents[3]
    human_verifier = None
    workload_verifier = None
    grant_signer = None
    if settings.mutations_enabled:
        bindings = _secret_bindings(settings.secret_bindings_path)
        identity = "workload_control_plane_service"
        resolver = FileSecretReferenceResolver(
            bindings,
            access_policy={logical_ref: (identity,) for logical_ref in bindings},
        )
        human_verifier = OidcHumanIdentityVerifier(
            issuer=settings.oidc_issuer or "",
            audience=settings.oidc_audience or "",
            public_key_pem=resolver.resolve_for_workload(
                logical_ref=settings.oidc_public_key_ref or "",
                workload_identity=identity,
            ),
            required_key_id=settings.oidc_required_key_id or "",
            allowed_subject_digests=settings.oidc_admin_subject_digests,
            allowed_roles=settings.oidc_allowed_roles,
        )
        workload_verifier = MtlsWorkloadIdentityVerifier(
            ca_certificate_pem=resolver.resolve_for_workload(
                logical_ref=settings.workload_ca_ref or "",
                workload_identity=identity,
            ),
            trust_domain=settings.workload_trust_domain or "",
            allowed_workload_names=settings.workload_allowed_identities,
        )
        grant_signer = Ed25519EvaluationGrantSigner(
            private_key_pem=resolver.resolve_for_workload(
                logical_ref=settings.grant_signing_key_ref or "",
                workload_identity=identity,
            ),
            key_id=settings.grant_signing_key_id or "",
        )
    runtime = load_service_runtime(
        settings=settings,
        repository_root=repository_root,
        human_verifier=human_verifier,
        workload_verifier=workload_verifier,
        grant_signer=grant_signer,
    )
    return create_app(runtime)


def run() -> None:
    """Run the service with strict configuration and no implicit reload."""
    settings = ServiceSettings.from_environment()
    uvicorn.run(
        "orbit_agent_control_plane.service_runtime.main:app_factory",
        factory=True,
        host=settings.host,
        port=settings.port,
        access_log=False,
        reload=False,
    )


def _secret_bindings(path: Path | None) -> dict[str, Path]:
    if path is None or path.is_symlink() or not path.is_file():
        raise ValueError("service_secret_bindings_invalid")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: _reject_constant(),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("service_secret_bindings_invalid") from error
    if not isinstance(value, dict) or not value:
        raise TypeError("service_secret_bindings_invalid")
    result: dict[str, Path] = {}
    for logical_ref, physical_path in value.items():
        if not isinstance(logical_ref, str) or not isinstance(physical_path, str):
            raise TypeError("service_secret_bindings_invalid")
        path_value = Path(physical_path)
        if not path_value.is_absolute():
            raise ValueError("service_secret_bindings_invalid")
        result[logical_ref] = path_value
    return result


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("service_secret_bindings_duplicate_key")
        value[key] = item
    return value


def _reject_constant() -> None:
    raise ValueError("service_secret_bindings_nonfinite_number")

