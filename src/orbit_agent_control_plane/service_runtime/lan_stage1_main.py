"""UDS-only entrypoint and CLI-only LAN bootstrap command.

Importing this module has no side effects.  The command never starts both
surfaces in one process and never accepts a bootstrap password value in argv
or an environment variable.  Automation may provide an owner-only password
file whose path is passed in argv.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import stat
from pathlib import Path

import uvicorn

from .codex_installation import CodexInstallationService
from .control_console import ControlConsoleService
from .database import Database
from .department_cockpit import (
    DepartmentCockpitService,
    LangGraphPlanningTransport,
    SqlCompanyModelRouteCatalog,
)
from .governance_catalogs import GovernanceCatalogService
from .lan_stage1 import (
    DatabaseArtifactDownloadAuthority,
    FileArtifactBundleResolver,
    FileDepartmentDeviceBundleResolver,
    LanCertificateChainVerifier,
    LanHumanIdentityService,
    LanNodeService,
    LanP256CertificateIssuer,
    LanStage1Error,
    LanWorkloadIdentityService,
)
from .lan_stage1_api import create_human_app, create_workload_app
from .model_catalog import ModelCatalogService
from .model_key_validation import ModelKeyTestStore
from .model_route import (
    ModelRouteReconciler,
    ModelRouteStore,
    OwnerOnlyFileSecretProvider,
)
from .model_route_credentials import ModelRouteCredentialService
from .repositories import SqlGrantRevocationRegistry
from .runtime_artifacts import RuntimeArtifactService


def app_factory():
    entrypoint = os.environ.get("ORBIT_LAN_ENTRYPOINT")
    database = Database(_database_url_from_file())
    identity = LanHumanIdentityService(database)
    trust_domain = os.environ.get("ORBIT_LAN_TRUST_DOMAIN", "orbit.local")
    public_ca = _public_ca_certificate()
    workloads = LanWorkloadIdentityService(
        database,
        trust_domain=trust_domain,
        issuer=LanP256CertificateIssuer(
            ca_certificate_pem=public_ca,
            ca_private_key_pem=_issuer_private_key(),
        ),
        direct_mtls_verifier=LanCertificateChainVerifier(
            ca_certificate_pem=public_ca,
            trust_domain=trust_domain,
        ),
    )
    runtime_artifacts = RuntimeArtifactService(
        database=database,
        grant_revocations=SqlGrantRevocationRegistry(database),
        authorized_node_scopes=_runtime_node_scopes(),
    )
    deployment_release_lock_digest = _deployment_release_lock_digest()
    artifact_root = _artifact_root()
    nodes = LanNodeService(
        database,
        runtime_artifacts=runtime_artifacts,
        bundle_resolver=FileArtifactBundleResolver(artifact_root),
        artifact_download_authority=DatabaseArtifactDownloadAuthority(
            database,
            expected_lock_digest=deployment_release_lock_digest,
        ),
        department_device_bundle_resolver=FileDepartmentDeviceBundleResolver(
            artifact_root
        ),
        deployment_release_lock_digest=deployment_release_lock_digest,
    )
    secret_bindings_path = _model_secret_bindings_path()
    secret_provider = (
        None
        if secret_bindings_path is None
        else OwnerOnlyFileSecretProvider(secret_bindings_path)
    )
    credential_service = ModelRouteCredentialService(
        database=database,
        secret_provider=secret_provider,
    )
    model_routes = ModelRouteReconciler(
        store=ModelRouteStore(database),
        secret_provider=secret_provider,
        credential_health_provider=credential_service,
    )
    model_catalog = ModelCatalogService(
        database=database,
        model_routes=model_routes,
        key_tests=ModelKeyTestStore(secret_provider) if secret_provider is not None else None,
        require_live_key_test=True,
    )
    control_console = ControlConsoleService(
        database=database,
        model_routes=model_routes,
        grant_revocations=SqlGrantRevocationRegistry(database),
        credentials=credential_service,
        model_catalog=model_catalog,
    )
    codex_installation = CodexInstallationService(
        database=database,
        approved_release_manifest_digest=_optional_digest(
            "ORBIT_CODEX_CLI_RELEASE_MANIFEST_DIGEST"
        ),
        approved_archive_digest=_optional_digest(
            "ORBIT_CODEX_CLI_ARCHIVE_DIGEST"
        ),
    )
    if entrypoint == "human":
        origins = tuple(
            item.strip()
            for item in os.environ.get("ORBIT_LAN_ALLOWED_ORIGINS", "").split(",")
            if item.strip()
        )
        repository_root = Path(__file__).resolve().parents[3]
        governance_catalogs = GovernanceCatalogService(
            database=database,
            repository_root=repository_root,
        )
        governance_catalogs.bootstrap()
        checkpoint_path = _planning_checkpoint_path()
        planning_transport = LangGraphPlanningTransport(checkpoint_path=checkpoint_path)
        checkpoint_path.chmod(0o600)
        cockpit = DepartmentCockpitService(
            database=database,
            transport=planning_transport,
            model_route_catalog=SqlCompanyModelRouteCatalog(database),
            agent_proposals=model_catalog,
        )
        app = create_human_app(
            identity=identity,
            workloads=workloads,
            nodes=nodes,
            allowed_origins=origins,
            cockpit=cockpit,
            governance_catalogs=governance_catalogs,
            control_console=control_console,
            codex_installation=codex_installation,
            model_route_authoring_context=_model_route_authoring_context(
                repository_root
            ),
        )
        app.router.add_event_handler("shutdown", planning_transport.close)
        return app
    if entrypoint == "workload":
        return create_workload_app(
            workloads=workloads,
            nodes=nodes,
            credentials=credential_service,
            codex_installation=codex_installation,
        )
    raise LanStage1Error("lan_entrypoint_invalid")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="orbit-agent-control-plane-lan")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("surface", choices=("human", "workload"))
    serve.add_argument("--uds", required=True, type=Path)
    bootstrap = subparsers.add_parser("bootstrap-admin")
    bootstrap.add_argument("--username", required=True)
    bootstrap.add_argument("--display-name", required=True)
    bootstrap.add_argument("--password-file", type=Path)
    maintenance_status = subparsers.add_parser("maintenance-status")
    maintenance_status.add_argument("--node-id")
    enqueue_maintenance = subparsers.add_parser("enqueue-maintenance")
    enqueue_maintenance.add_argument("--node-id", required=True)
    enqueue_maintenance.add_argument("--handler-id", required=True)
    enqueue_maintenance.add_argument("--asset-name", required=True)
    enqueue_maintenance.add_argument("--asset-digest", required=True)
    enqueue_maintenance.add_argument("--idempotency-key", required=True)
    enqueue_maintenance.add_argument("--actor-ref", required=True)
    args = parser.parse_args(argv)
    if args.command == "bootstrap-admin":
        if args.password_file is None:
            password = getpass.getpass("LAN bootstrap password: ")
            confirmation = getpass.getpass("Confirm password: ")
            if password != confirmation:
                parser.error("passwords do not match")
        else:
            password = _bootstrap_password_from_file(args.password_file)
        database = Database(_database_url_from_file())
        try:
            principal = LanHumanIdentityService(database).bootstrap_admin_cli_only(
                username=args.username,
                password=password,
                display_name=args.display_name,
            )
        finally:
            database.dispose()
        print(principal["account_id"])
        return 0
    if args.command in {"maintenance-status", "enqueue-maintenance"}:
        database = Database(_database_url_from_file())
        try:
            nodes = LanNodeService(database)
            if args.command == "maintenance-status":
                value = nodes.maintenance_status(node_id=args.node_id)
            else:
                value = nodes.enqueue_maintenance_job(
                    node_id=args.node_id,
                    handler_id=args.handler_id,
                    asset_name=args.asset_name,
                    asset_digest=args.asset_digest,
                    idempotency_key=args.idempotency_key,
                    actor_ref=args.actor_ref,
                )
        finally:
            database.dispose()
        print(json.dumps(value, ensure_ascii=False, sort_keys=True))
        return 0
    uds = args.uds
    if not uds.is_absolute() or uds.exists():
        parser.error("--uds must be an absent absolute path")
    parent = uds.parent
    info = parent.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        parser.error("UDS parent must be owner-only")
    os.environ["ORBIT_LAN_ENTRYPOINT"] = args.surface
    uvicorn.run(
        "orbit_agent_control_plane.service_runtime.lan_stage1_main:app_factory",
        factory=True,
        uds=str(uds),
        access_log=False,
        reload=False,
        proxy_headers=False,
    )
    return 0


def _bootstrap_password_from_file(path: Path) -> str:
    if not path.is_absolute() or path.is_symlink():
        raise LanStage1Error("lan_bootstrap_password_file_invalid")
    try:
        info = path.lstat()
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise LanStage1Error("lan_bootstrap_password_file_invalid") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
        or not 13 <= info.st_size <= 4096
        or not raw.endswith("\n")
        or raw.count("\n") != 1
        or "\r" in raw
        or "\x00" in raw
        or len(raw[:-1]) < 12
    ):
        raise LanStage1Error("lan_bootstrap_password_file_invalid")
    return raw[:-1]


def _database_url_from_file() -> str:
    raw_path = os.environ.get("ORBIT_LAN_DATABASE_URL_FILE")
    if not raw_path:
        raise LanStage1Error("lan_database_url_file_required")
    path = Path(raw_path)
    if not path.is_absolute():
        raise LanStage1Error("lan_database_url_file_invalid")
    try:
        info = path.lstat()
    except OSError as error:
        raise LanStage1Error("lan_database_url_file_invalid") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_size > 4096
    ):
        raise LanStage1Error("lan_database_url_file_invalid")
    value = path.read_text(encoding="utf-8").strip()
    if not value.startswith(("postgresql+psycopg://", "postgresql://")):
        raise LanStage1Error("lan_database_url_must_be_postgresql")
    return value


def _deployment_release_lock_digest() -> str:
    value = os.environ.get("ORBIT_LAN_DEPLOYMENT_RELEASE_LOCK_DIGEST", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise LanStage1Error("lan_deployment_release_lock_digest_required")
    return value


def _optional_digest(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise LanStage1Error("lan_codex_cli_digest_invalid")
    return value


def _planning_checkpoint_path() -> Path:
    raw_path = os.environ.get("ORBIT_LAN_PLANNING_CHECKPOINT_PATH")
    if not raw_path:
        raise LanStage1Error("lan_planning_checkpoint_path_required")
    path = Path(raw_path)
    if not path.is_absolute() or path.is_symlink():
        raise LanStage1Error("lan_planning_checkpoint_path_invalid")
    try:
        parent = path.parent.lstat()
    except OSError as error:
        raise LanStage1Error("lan_planning_checkpoint_path_invalid") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise LanStage1Error("lan_planning_checkpoint_path_invalid")
    if path.exists():
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise LanStage1Error("lan_planning_checkpoint_path_invalid")
    return path


def _artifact_root() -> Path:
    raw_path = os.environ.get("ORBIT_LAN_ARTIFACT_ROOT")
    if not raw_path:
        raise LanStage1Error("lan_artifact_root_required")
    return Path(raw_path)


def _model_secret_bindings_path() -> Path | None:
    raw_path = os.environ.get("ORBIT_LAN_MODEL_SECRET_BINDINGS_FILE")
    if not raw_path:
        return None
    path = Path(raw_path)
    if not path.is_absolute() or path.is_symlink():
        raise LanStage1Error("lan_model_secret_bindings_file_invalid")
    try:
        parent = path.parent.lstat()
    except OSError as error:
        raise LanStage1Error("lan_model_secret_bindings_file_invalid") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise LanStage1Error("lan_model_secret_bindings_file_invalid")
    if path.exists():
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise LanStage1Error("lan_model_secret_bindings_file_invalid")
    return path


def _model_route_authoring_context(repository_root: Path) -> dict[str, object]:
    path = repository_root / "references/stage1-lan-d0-model-route-authoring-profile.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LanStage1Error("lan_model_route_authoring_context_invalid") from error
    if (
        not isinstance(value, dict)
        or value.get("profile_version")
        != "orbit.stage1-lan-model-route-authoring-profile/1"
        or value.get("authority_claim") != "none"
        or value.get("synthetic_only") is not True
        or value.get("production_authorization") is not False
        or value.get("release_authorization") is not False
    ):
        raise LanStage1Error("lan_model_route_authoring_context_invalid")
    return value


def _runtime_node_scopes() -> dict[str, dict[str, object]]:
    raw_path = os.environ.get("ORBIT_LAN_RUNTIME_NODE_SCOPES_FILE")
    if not raw_path:
        raise LanStage1Error("lan_runtime_node_scopes_file_required")
    path = Path(raw_path)
    if not path.is_absolute():
        raise LanStage1Error("lan_runtime_node_scopes_file_invalid")
    try:
        info = path.lstat()
    except OSError as error:
        raise LanStage1Error("lan_runtime_node_scopes_file_invalid") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) & 0o077
        or not 2 <= info.st_size <= 64 * 1024
    ):
        raise LanStage1Error("lan_runtime_node_scopes_file_invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LanStage1Error("lan_runtime_node_scopes_file_invalid") from error
    if not isinstance(value, dict):
        raise LanStage1Error("lan_runtime_node_scopes_file_invalid")
    return value


def _public_ca_certificate() -> bytes:
    raw_path = os.environ.get("ORBIT_LAN_WORKLOAD_CA_FILE")
    if not raw_path:
        raise LanStage1Error("lan_workload_ca_file_required")
    path = Path(raw_path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise LanStage1Error("lan_workload_ca_file_invalid")
    value = path.read_bytes()
    if not 1 <= len(value) <= 128 * 1024:
        raise LanStage1Error("lan_workload_ca_file_invalid")
    return value


def _issuer_private_key() -> bytes:
    raw_path = os.environ.get("ORBIT_LAN_WORKLOAD_CA_KEY_FILE")
    if not raw_path:
        raise LanStage1Error("lan_workload_ca_key_file_required")
    path = Path(raw_path)
    if not path.is_absolute():
        raise LanStage1Error("lan_workload_ca_key_file_invalid")
    try:
        info = path.lstat()
    except OSError as error:
        raise LanStage1Error("lan_workload_ca_key_file_invalid") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_size > 64 * 1024
    ):
        raise LanStage1Error("lan_workload_ca_key_file_invalid")
    return path.read_bytes()


if __name__ == "__main__":
    raise SystemExit(main())

