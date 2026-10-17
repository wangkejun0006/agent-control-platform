"""Model Route reconciliation and explicitly authorized catalog key acceptance."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

from .database import Database
from .model_key_validation import (
    KeyTestError,
    ModelKeyTestStore,
    owner_document,
    validate_policy,
)
from .model_route import (
    ModelRouteError,
    ModelRouteReconciler,
    ModelRouteStore,
    OwnerOnlyFileSecretProvider,
    UnavailableSecretProvider,
    WeMetaProviderObserver,
    read_internal_document,
    urllib_json_transport,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="model-route")
    parser.add_argument(
        "operation",
        choices=(
            "import-route",
            "import-observation",
            "reconcile",
            "status",
            "deploy-preflight",
            "bind-secret",
            "test-bind-secret",
            "promote-secret-next",
        ),
    )
    parser.add_argument("--key-test-policy", type=Path)
    parser.add_argument("--entry-revision-digest")
    parser.add_argument("--route-id")
    parser.add_argument("--document", type=Path)
    parser.add_argument("--secret-bindings", type=Path)
    parser.add_argument("--secret-family-ref")
    parser.add_argument("--secret-version")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--fixture-machine-source-url")
    return parser


def run(args: argparse.Namespace) -> tuple[int, dict[str, object]]:
    if args.operation != "test-bind-secret" and (args.key_test_policy or args.entry_revision_digest):
        raise ModelRouteError("model_route_cli_argument_conflict")
    if args.operation == "test-bind-secret":
        _require_bind_arguments(args)
        if not args.key_test_policy or not args.entry_revision_digest or not sys.stdin.isatty():
            raise ModelRouteError("model_route_key_test_interactive_policy_required")
        policy = owner_document(args.key_test_policy)
        validate_policy(policy, datetime.now(timezone.utc))
        print(f"将发送一次合成验证请求；最多预留 ${policy['reservation_microusd'] / 1_000_000:.6f}，计入策略总预算，失败不自动重试。", file=sys.stderr)
        # The explicit owner-only policy is the cost authorization. No defaults
        # enable network access, and the database/browser never receives this key.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("API Key（隐藏输入，最小请求成功后才保存）: ")
            confirmation = getpass.getpass("再次输入同一 API Key: ")
        if value != confirmation:
            raise ModelRouteError("model_route_secret_confirmation_mismatch")
        result = ModelKeyTestStore(OwnerOnlyFileSecretProvider(args.secret_bindings)).test_and_bind(
            logical_ref=args.secret_family_ref, version=args.secret_version, secret=value.encode(),
            entry_revision_digest=args.entry_revision_digest, policy=policy,
        )
        del value, confirmation
        return (0 if result["status"] == "verified_and_saved" else 1), result
    if args.operation == "bind-secret":
        _require_bind_arguments(args)
        if args.secret_family_ref.startswith("secret://company/model-catalog/"):
            raise ModelRouteError("model_route_catalog_key_test_required")
        secret_value = getpass.getpass("Model Route secret (input hidden): ")
        confirmation = getpass.getpass("Confirm secret (input hidden): ")
        if secret_value != confirmation:
            raise ModelRouteError("model_route_secret_confirmation_mismatch")
        health = OwnerOnlyFileSecretProvider(args.secret_bindings).bind(
            args.secret_family_ref,
            secret_value.encode("utf-8"),
            version=args.secret_version,
        )
        return 0, {
            "status": "provisioned",
            "logical_ref": health["logical_ref"],
            "binding_version": health["binding_version"],
            "secret_fingerprint": health["secret_fingerprint"],
            "secret_value_returned": False,
            "release_authorization": False,
        }
    database_url = os.environ.get("ORBIT_MODEL_ROUTE_DATABASE_URL")
    if not database_url:
        raise ModelRouteError("model_route_database_url_missing")
    database = Database(database_url)
    try:
        store = ModelRouteStore(database)
        if args.operation in {"import-route", "import-observation"}:
            _require_import_arguments(args)
            document = read_internal_document(args.document)
            if args.operation == "import-route":
                digest, appended = store.record_route(document)
                kind = "route_revision"
            else:
                digest, appended = store.record_observation(document)
                kind = "provider_observation"
            return 0, {
                "status": "recorded",
                "kind": kind,
                "digest": digest,
                "appended": appended,
                "release_authorization": False,
            }
        if args.operation == "promote-secret-next":
            _require_rotation_arguments(args)
            health = OwnerOnlyFileSecretProvider(args.secret_bindings).promote_next(
                args.secret_family_ref
            )
            return 0, {
                "status": "switched",
                "logical_ref": health["logical_ref"],
                "binding_version": health["binding_version"],
                "secret_healthy": True,
                "release_authorization": False,
            }
        _require_reconcile_arguments(args)
        secret_provider = (
            UnavailableSecretProvider()
            if args.secret_bindings is None
            else OwnerOnlyFileSecretProvider(args.secret_bindings)
        )
        observer = None
        if args.fixture_machine_source_url is not None:
            observer = WeMetaProviderObserver(
                machine_source_url=args.fixture_machine_source_url,
                transport=urllib_json_transport,
            )
        if args.refresh and observer is None:
            raise ModelRouteError("fixture_machine_source_unconfigured")
        reconciler = ModelRouteReconciler(
            store=store,
            secret_provider=secret_provider,
            provider_observer=observer,
        )
        if args.operation == "reconcile":
            result = dict(reconciler.reconcile(args.route_id, refresh=args.refresh))
        elif args.operation == "status":
            _reject_refresh_arguments(args)
            result = dict(reconciler.status(args.route_id))
        else:
            _reject_refresh_arguments(args)
            result = dict(reconciler.deploy_preflight(args.route_id))
        ready = result.get("status") == "ready" or result.get(
            "snapshot_status"
        ) == "ready"
        return (0 if ready else 1), result
    finally:
        database.dispose()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        exit_code, document = run(args)
    except (ModelRouteError, KeyTestError) as error:
        exit_code = 1
        document = {
            "status": "blocked",
            "reason_code": str(error),
            "provider_execution_started": False,
            "release_authorization": False,
        }
    print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))
    return exit_code


def _require_import_arguments(args: argparse.Namespace) -> None:
    if (
        args.document is None
        or args.route_id is not None
        or args.secret_bindings is not None
        or args.secret_family_ref is not None
        or args.secret_version is not None
        or args.refresh
        or args.fixture_machine_source_url is not None
    ):
        raise ModelRouteError("model_route_cli_argument_conflict")


def _require_rotation_arguments(args: argparse.Namespace) -> None:
    if (
        args.secret_bindings is None
        or not args.secret_family_ref
        or args.secret_version is not None
        or args.route_id is not None
        or args.document is not None
        or args.refresh
        or args.fixture_machine_source_url is not None
    ):
        raise ModelRouteError("model_route_cli_argument_conflict")


def _require_reconcile_arguments(args: argparse.Namespace) -> None:
    if (
        not args.route_id
        or args.document is not None
        or args.secret_family_ref is not None
        or args.secret_version is not None
    ):
        raise ModelRouteError("model_route_cli_argument_conflict")


def _require_bind_arguments(args: argparse.Namespace) -> None:
    if (
        args.secret_bindings is None
        or not args.secret_family_ref
        or not args.secret_version
        or args.route_id is not None
        or args.document is not None
        or args.refresh
        or args.fixture_machine_source_url is not None
    ):
        raise ModelRouteError("model_route_cli_argument_conflict")


def _reject_refresh_arguments(args: argparse.Namespace) -> None:
    if args.refresh or args.fixture_machine_source_url is not None:
        raise ModelRouteError("model_route_cli_argument_conflict")


if __name__ == "__main__":
    raise SystemExit(main())

