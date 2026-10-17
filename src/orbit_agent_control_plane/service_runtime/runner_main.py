"""Separate durable Runner process for the local Pilot queue.

The first published service baseline intentionally registers only a
deterministic fixture handler.  Provider-backed handlers are bound by the
exact Pilot Enablement package after human approval; an unknown operation is
failed closed and never gains generic network or shell capability.
"""

from __future__ import annotations

import argparse
import os
import stat
import time
from pathlib import Path

from .config import ServiceSettings
from .database import Database
from .disease_r2_provider_handler import (
    OwnerOnlyEvidenceStore,
    ProviderBackedDiseaseR2Handler,
)
from .model_route import _validate_route, read_internal_document
from .repositories import (
    SqlAuditExporter,
    SqlGrantRevocationRegistry,
    SqlWorkerLeaseCoordinator,
)
from .runner_queue import DurableRunnerWorker, SqlSignedGrantRegistry
from .security import Ed25519EvaluationGrantVerifier


def run() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--once", action="store_true")
    group.add_argument("--serve", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    args = parser.parse_args()
    if not 0.1 <= args.poll_seconds <= 10:
        raise SystemExit("runner_poll_interval_invalid")
    settings = ServiceSettings.from_environment()
    if (
        settings.mode != "local_trusted_operator"
        or settings.grant_verification_key_path is None
        or settings.grant_signing_key_id is None
    ):
        raise SystemExit("runner_local_pilot_configuration_invalid")
    database = Database(settings.database_url)
    revocations = SqlGrantRevocationRegistry(database)
    grants = SqlSignedGrantRegistry(
        database,
        verifier=Ed25519EvaluationGrantVerifier(
            public_key_pem=settings.grant_verification_key_path.read_bytes(),
            key_id=settings.grant_signing_key_id,
        ),
        revocations=revocations,
    )
    handlers = {"run_public_r2_fixture": _fixture_handler}
    profile = os.environ.get("ORBIT_RUNNER_HANDLER_PROFILE", "fixture")
    if profile == "provider_backed_public_pilot":
        secret_path = _required_absolute_path("ORBIT_RUNNER_PROVIDER_SECRET_PATH")
        corpus_path = _required_absolute_path("ORBIT_RUNNER_CORPUS_PATH")
        evidence_root = _required_absolute_path("ORBIT_RUNNER_EVIDENCE_ROOT")
        model_route_path = _required_absolute_path("ORBIT_RUNNER_MODEL_ROUTE_PATH")
        handlers["run_public_r2_provider_attempt"] = ProviderBackedDiseaseR2Handler(
            provider_secret=_read_protected_text(secret_path),
            corpus_path=corpus_path,
            evidence_store=OwnerOnlyEvidenceStore(evidence_root),
            allowed_returned_model_ids=_returned_model_ids(model_route_path),
        )
    elif profile != "fixture":
        raise SystemExit("runner_handler_profile_invalid")
    worker = DurableRunnerWorker(
        database,
        grants=grants,
        leases=SqlWorkerLeaseCoordinator(database),
        audit=SqlAuditExporter(database),
        handlers=handlers,
    )
    try:
        if args.once:
            worker.run_once()
            return
        while True:
            if worker.run_once() is None:
                time.sleep(args.poll_seconds)
    finally:
        database.dispose()


def _fixture_handler(invocation: dict) -> dict:
    return {
        "artifact_ref": (
            "artifact://disease-r2/public-pilot/fixture/" + invocation["task_id"]
        ),
        "evidence_status": "synthetic",
        "model_requests": 0,
        "network_calls": 0,
        "production_authorization": False,
        "release_authorization": False,
    }


def _required_absolute_path(name: str) -> Path:
    value = os.environ.get(name)
    if value is None or not Path(value).is_absolute():
        raise SystemExit("runner_provider_path_invalid")
    return Path(value)


def _read_protected_text(path: Path) -> str:
    try:
        info = path.lstat()
    except OSError as error:
        raise SystemExit("runner_provider_secret_invalid") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or not 8 <= info.st_size <= 64 * 1024
    ):
        raise SystemExit("runner_provider_secret_invalid")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise SystemExit("runner_provider_secret_invalid") from error
    if not 8 <= len(value.encode()) <= 64 * 1024 or "\n" in value:
        raise SystemExit("runner_provider_secret_invalid")
    return value


def _returned_model_ids(path: Path) -> tuple[str, ...]:
    try:
        route = _validate_route(read_internal_document(path))
    except ValueError as error:
        raise SystemExit("runner_model_route_invalid") from error
    scope = route["approved_scope"]
    if (
        route["provider"] != "fixture"
        or route["endpoint"] != "https://models.paper-orbit.invalid/v1/chat/completions"
        or route["requested_model"] != "fixture-structured-v1"
        or route["data_classification"] != "public"
        or scope["permissions"] != ["model.invoke"]
    ):
        raise SystemExit("runner_model_route_invalid")
    return tuple(scope["resolved_model_ids"])

