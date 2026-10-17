"""FastAPI surface for D0 Runtime Artifact and node evidence services."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from .runtime_artifacts import RuntimeArtifactError, RuntimeArtifactService

Guard = Callable[..., dict[str, Any]]
_ADMIN = frozenset({"role_control_plane_admin"})
_DIGEST = r"^sha256:[0-9a-f]{64}$"
_EXPECTED = r"^(none|sha256:[0-9a-f]{64})$"
_IDEMPOTENCY = r"^[A-Za-z0-9._:-]{8,192}$"


class RuntimeArtifactCandidateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict[str, Any]
    expected_latest_revision_digest: str = Field(pattern=_EXPECTED)
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class RuntimeArtifactRevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision_digest: str = Field(pattern=_DIGEST)
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class RuntimeArtifactEvidenceDigests(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sbom_digest: str = Field(pattern=_DIGEST)
    build_provenance_digest: str = Field(pattern=_DIGEST)
    vulnerability_report_digest: str = Field(pattern=_DIGEST)
    license_report_digest: str = Field(pattern=_DIGEST)


class RuntimeArtifactQualificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    manifest_digest: str = Field(pattern=_DIGEST)
    runtime_source_digest: str = Field(pattern=_DIGEST)
    runtime_realization_digest: str = Field(pattern=_DIGEST)
    runtime_image_digest: str = Field(pattern=_DIGEST)
    isolation_profile_digest: str = Field(pattern=_DIGEST)
    adapter_digest: str = Field(pattern=_DIGEST)
    bundle_digest: str = Field(pattern=_DIGEST)
    evidence_digests: RuntimeArtifactEvidenceDigests
    reason: str = Field(min_length=8, max_length=500)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class NodeDocumentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    document: dict[str, Any]
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


class LeaseClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_capability_report_digest: str = Field(pattern=_DIGEST)
    idempotency_key: str = Field(pattern=_IDEMPOTENCY)


def install_runtime_artifact_routes(
    app: FastAPI,
    *,
    service: RuntimeArtifactService,
    authenticate_human: Guard,
    require_mutating_human: Guard,
    require_workload: Guard | None,
) -> None:
    def read_admin(request: Request) -> dict[str, Any]:
        return authenticate_human(request, required_roles=_ADMIN)

    def write_admin(request: Request) -> dict[str, Any]:
        return require_mutating_human(request, required_roles=_ADMIN)

    def workload(request: Request) -> dict[str, Any]:
        if require_workload is None:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "runtime_node_api_not_configured",
            )
        return require_workload(request)

    @app.get("/v1/runtime-artifacts")
    def runtime_artifacts(request: Request) -> dict[str, Any]:
        read_admin(request)
        return _call(service.list_artifacts)

    @app.post("/v1/runtime-artifact-candidates", status_code=201)
    def record_candidate(
        body: RuntimeArtifactCandidateRequest, request: Request
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.record_candidate(
                document=body.document,
                expected_latest_revision_digest=body.expected_latest_revision_digest,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.get("/v1/runtime-artifacts/{artifact_id}/revisions/{revision_digest}")
    def artifact_revision(
        artifact_id: str, revision_digest: str, request: Request
    ) -> dict[str, Any]:
        read_admin(request)
        return _call(
            lambda: service.revision(
                artifact_id=artifact_id, revision_digest=revision_digest
            )
        )

    @app.get(
        "/v1/runtime-artifacts/{artifact_id}/revisions/{revision_digest}/bundle"
    )
    def artifact_bundle(
        artifact_id: str, revision_digest: str, request: Request
    ) -> dict[str, Any]:
        read_admin(request)
        return _call(
            lambda: service.bundle_metadata(
                artifact_id=artifact_id, revision_digest=revision_digest
            )
        )

    @app.get("/v1/runtime-artifacts/{artifact_id}/bundle")
    def artifact_bundle_compat(
        artifact_id: str, revision_digest: str, request: Request
    ) -> dict[str, Any]:
        read_admin(request)
        return _call(
            lambda: service.bundle_metadata(
                artifact_id=artifact_id, revision_digest=revision_digest
            )
        )

    @app.post("/v1/runtime-artifacts/{artifact_id}/revocations", status_code=201)
    def revoke_artifact(
        artifact_id: str,
        body: RuntimeArtifactRevocationRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_admin(request)
        return _call(
            lambda: service.revoke(
                artifact_id=artifact_id,
                expected_revision_digest=body.expected_revision_digest,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post(
        "/v1/runtime-artifacts/{artifact_id}/revisions/{revision_digest}/qualifications",
        status_code=201,
    )
    def qualify_artifact_d0(
        artifact_id: str,
        revision_digest: str,
        body: RuntimeArtifactQualificationRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = write_admin(request)
        bindings = body.model_dump(
            exclude={"reason", "idempotency_key"}, mode="json"
        )
        return _call(
            lambda: service.qualify_d0(
                artifact_id=artifact_id,
                revision_digest=revision_digest,
                expected_bindings=bindings,
                reason=body.reason,
                idempotency_key=body.idempotency_key,
                actor_ref=principal["human_ref"],
            )
        )

    @app.post(
        "/v1/runtime-nodes/{node_id}/capability-reports", status_code=201
    )
    def capability_report(
        node_id: str, body: NodeDocumentRequest, request: Request
    ) -> dict[str, Any]:
        principal = workload(request)
        return _call(
            lambda: service.record_capability_report(
                node_id=node_id,
                document=body.document,
                idempotency_key=body.idempotency_key,
                workload_identity=principal["workload_identity"],
            )
        )

    @app.post(
        "/v1/runtime-nodes/{node_id}/artifact-import-receipts", status_code=201
    )
    def artifact_import_receipt(
        node_id: str, body: NodeDocumentRequest, request: Request
    ) -> dict[str, Any]:
        principal = workload(request)
        return _call(
            lambda: service.record_import_receipt(
                node_id=node_id,
                document=body.document,
                idempotency_key=body.idempotency_key,
                workload_identity=principal["workload_identity"],
            )
        )

    @app.post("/v1/runtime-nodes/{node_id}/lease-claims", status_code=201)
    def lease_claim(
        node_id: str, body: LeaseClaimRequest, request: Request
    ) -> dict[str, Any]:
        principal = workload(request)
        return _call(
            lambda: service.claim_lease(
                node_id=node_id,
                expected_capability_report_digest=(
                    body.expected_capability_report_digest
                ),
                idempotency_key=body.idempotency_key,
                workload_identity=principal["workload_identity"],
            )
        )

    def append_evidence(
        node_id: str,
        run_id: str,
        evidence_type: str,
        body: NodeDocumentRequest,
        request: Request,
    ) -> dict[str, Any]:
        principal = workload(request)
        return _call(
            lambda: service.append_run_evidence(
                node_id=node_id,
                run_id=run_id,
                evidence_type=evidence_type,
                document=body.document,
                idempotency_key=body.idempotency_key,
                workload_identity=principal["workload_identity"],
            )
        )

    @app.post("/v1/runtime-runs/{run_id}/container-events", status_code=201)
    def container_event(
        run_id: str,
        node_id: str,
        body: NodeDocumentRequest,
        request: Request,
    ) -> dict[str, Any]:
        return append_evidence(
            node_id, run_id, "container_event", body, request
        )

    @app.post("/v1/runtime-runs/{run_id}/checkpoint-receipts", status_code=201)
    def checkpoint_receipt(
        run_id: str,
        node_id: str,
        body: NodeDocumentRequest,
        request: Request,
    ) -> dict[str, Any]:
        return append_evidence(
            node_id, run_id, "checkpoint_receipt", body, request
        )

    @app.post("/v1/runtime-runs/{run_id}/cleanup-receipts", status_code=201)
    def cleanup_receipt(
        run_id: str,
        node_id: str,
        body: NodeDocumentRequest,
        request: Request,
    ) -> dict[str, Any]:
        return append_evidence(
            node_id, run_id, "cleanup_receipt", body, request
        )

    @app.post("/v1/model-gateway/token-exchanges", status_code=403)
    def model_gateway_exchange(
        node_id: str, body: NodeDocumentRequest, request: Request
    ) -> dict[str, Any]:
        principal = workload(request)
        return _call(
            lambda: service.exchange_model_token(
                node_id=node_id,
                document=body.document,
                idempotency_key=body.idempotency_key,
                workload_identity=principal["workload_identity"],
            )
        )


def _call(callback: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return callback()
    except RuntimeArtifactError as error:
        reason = error.reason_code
        if reason.endswith("_not_found"):
            code = status.HTTP_404_NOT_FOUND
        elif any(
            marker in reason
            for marker in ("drift", "conflict", "already_", "blocked")
        ):
            code = status.HTTP_409_CONFLICT
        else:
            code = status.HTTP_422_UNPROCESSABLE_CONTENT
        raise HTTPException(code, reason) from error

