"""D0 Runtime Artifact, node capability, and container evidence services.

No method in this module reads a bundle, opens a network connection, starts a
container, reads a provider secret, or issues a production authorization.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select

from ..ids import deterministic_id
from .control_console_models import ControlConsoleCommandRow
from .database import Database
from .models import AuditEventRow, ReceiptRow, RuntimeRunRow, SignedGrantRow
from .repositories import SqlGrantRevocationRegistry
from .runtime_artifact_models import (
    ModelGatewayTokenExchangeRow,
    RuntimeArtifactImportReceiptRow,
    RuntimeArtifactRevisionRow,
    RuntimeArtifactRevocationRow,
    RuntimeContainerEvidenceRow,
    RuntimeNodeCapabilityReportRow,
    RuntimeNodeLeaseClaimRow,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][A-Za-z0-9_:-]{2,159}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{8,192}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_SECRET = re.compile(
    r"(?:BEGIN .*PRIVATE KEY|\bsk-[A-Za-z0-9_-]{8,})", re.IGNORECASE
)
_PHYSICAL = re.compile(
    r"^(?:/|~[/\\]|[A-Za-z]:[\\/]|file://|smb://|nfs://)", re.IGNORECASE
)
_ARTIFACT_FIELDS = {"api_version", "kind", "metadata", "spec", "authority_boundary"}
RUNTIME_ARTIFACT_CONSUMER_PROFILE = {
    "schema_id": "urn:company-ai-os:draft:schema:runtime-artifact-manifest:0.3",
    "schema_digest": "sha256:7bf80718c2ee1d13bc2f4ba0bd1226110c47c3b1bce4e949e9edc0a91c0ad744",
    "authority": "architecture_draft_consumer_lock",
}
RUNTIME_ARTIFACT_IMPORT_RECEIPT_CONSUMER_PROFILE = {
    "schema_id": "urn:company-ai-os:draft:schema:runtime-artifact-import-receipt:0.3",
    "schema_digest": "sha256:6b194c1be1a1da9d79ce56674214602cb2a44275c13de046ee80ce94fc251c7b",
    "authority": "architecture_draft_consumer_lock",
}


class RuntimeArtifactError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class RuntimeArtifactService:
    def __init__(
        self,
        *,
        database: Database,
        grant_revocations: SqlGrantRevocationRegistry,
        authorized_node_scopes: Mapping[str, Mapping[str, Any]] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.database = database
        self.grant_revocations = grant_revocations
        self.authorized_node_scopes = _authorized_node_scopes(
            authorized_node_scopes or {}
        )
        self.now = now or (lambda: datetime.now(timezone.utc))

    # ---- company-admin catalog -----------------------------------------

    def list_artifacts(self) -> dict[str, Any]:
        with self.database.session() as session:
            ids = tuple(
                session.scalars(
                    select(RuntimeArtifactRevisionRow.artifact_id)
                    .distinct()
                    .order_by(RuntimeArtifactRevisionRow.artifact_id)
                )
            )
        return {
            "items": [self._summary(item) for item in ids],
            "artifact_is_not_agent_identity": True,
            "execution_grant_issued": False,
            "release_authorization": False,
        }

    def record_candidate(
        self,
        *,
        document: Mapping[str, Any],
        expected_latest_revision_digest: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        normalized = _normalize(document)
        _validate_manifest(normalized)
        projection = _manifest_projection(normalized)
        _validate_reason(reason)
        _validate_actor(actor_ref)
        _validate_idempotency(idempotency_key)
        artifact_id = projection["artifact_id"]
        request = {
            "document": normalized,
            "expected_latest_revision_digest": expected_latest_revision_digest,
            "reason": reason,
        }
        replay = self._command(idempotency_key, "runtime_artifact_candidate", request)
        if replay is not None:
            return replay
        latest = self._latest(artifact_id)
        actual = "none" if latest is None else latest.revision_digest
        if expected_latest_revision_digest != actual:
            raise RuntimeArtifactError("runtime_artifact_expected_revision_drift")
        revision_digest = projection["revision_digest"]
        with self.database.session() as session:
            existing = session.scalar(
                select(RuntimeArtifactRevisionRow).where(
                    RuntimeArtifactRevisionRow.revision_digest == revision_digest
                )
            )
            appended = existing is None
            if existing is not None and existing.document != normalized:
                raise RuntimeArtifactError("runtime_artifact_revision_conflict")
            if appended:
                now = self._now()
                session.add(
                    RuntimeArtifactRevisionRow(
                        artifact_id=artifact_id,
                        revision_digest=revision_digest,
                        runtime_family=projection["runtime_family"],
                        runtime_source_digest=projection["runtime_source_digest"],
                        runtime_image_digest=projection["runtime_image_digest"],
                        isolation_profile_digest=projection["isolation_profile_digest"],
                        adapter_digest=projection["adapter_digest"],
                        target_platform=projection["target_platform"],
                        bundle_ref=projection["bundle_ref"],
                        bundle_digest=projection["bundle_digest"],
                        status="candidate",
                        document=normalized,
                        recorded_by_ref=actor_ref,
                        recorded_at=now,
                    )
                )
        response = {
            "artifact_id": artifact_id,
            "revision_digest": revision_digest,
            "runtime_source_digest": projection["runtime_source_digest"],
            "runtime_image_digest": projection["runtime_image_digest"],
            "isolation_profile_digest": projection["isolation_profile_digest"],
            "status": "candidate",
            "manifest_declared_status": projection["status"],
            "qualification_bindings": runtime_artifact_qualification_bindings(
                self._revision(artifact_id, revision_digest)
            ),
            "appended": appended,
            "contract_consumer": RUNTIME_ARTIFACT_CONSUMER_PROFILE,
            "production_authorized": False,
            "release_authorization": False,
        }
        self._record_command(
            idempotency_key=idempotency_key,
            command_kind="runtime_artifact_candidate",
            target_ref=f"runtime-artifact://{artifact_id}",
            request=request,
            response=response,
            actor_ref=actor_ref,
            event_type="runtime_artifact_candidate_recorded",
        )
        return response

    def revision(self, *, artifact_id: str, revision_digest: str) -> dict[str, Any]:
        row = self._revision(artifact_id, revision_digest)
        revoked = self._revocation(artifact_id, revision_digest) is not None
        qualified = self._is_qualified(row)
        return {
            "artifact_id": artifact_id,
            "revision_digest": revision_digest,
            "document": row.document,
            "status": (
                "revoked" if revoked else "qualified_d0" if qualified else "candidate"
            ),
            "revoked": revoked,
            "qualification_receipt_present": qualified,
            "production_authorized": False,
            "release_authorization": False,
            "contract_consumer": RUNTIME_ARTIFACT_CONSUMER_PROFILE,
        }

    def bundle_metadata(
        self, *, artifact_id: str, revision_digest: str
    ) -> dict[str, Any]:
        row = self._revision(artifact_id, revision_digest)
        return {
            "artifact_id": artifact_id,
            "revision_digest": revision_digest,
            "bundle_ref": row.bundle_ref,
            "bundle_digest": row.bundle_digest,
            "runtime_image_digest": row.runtime_image_digest,
            "selection_semantics": "explicit_revision_digest_only",
            "logical_metadata_only": True,
            "bundle_bytes_included": False,
            "release_authorization": False,
        }

    def qualify_d0(
        self,
        *,
        artifact_id: str,
        revision_digest: str,
        expected_bindings: Mapping[str, Any],
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        _validate_actor(actor_ref)
        _validate_reason(reason)
        _validate_idempotency(idempotency_key)
        normalized_bindings = _normalize(expected_bindings)
        row = self._revision(artifact_id, revision_digest)
        request = {
            "artifact_id": artifact_id,
            "revision_digest": revision_digest,
            "expected_bindings": normalized_bindings,
            "reason": reason,
        }
        replay = self._command(
            idempotency_key, "runtime_artifact_qualification_d0", request
        )
        if replay is not None:
            return replay
        if self._revocation(artifact_id, revision_digest) is not None:
            raise RuntimeArtifactError("runtime_artifact_qualification_revoked")
        actual_bindings = runtime_artifact_qualification_bindings(row)
        if normalized_bindings != actual_bindings:
            raise RuntimeArtifactError("runtime_artifact_qualification_binding_drift")
        subject_ref = runtime_artifact_subject_ref(artifact_id, revision_digest)
        with self.database.session() as session:
            existing = session.scalar(
                select(ReceiptRow).where(
                    ReceiptRow.receipt_type == "runtime_artifact_qualification_d0",
                    ReceiptRow.subject_ref == subject_ref,
                )
            )
            if existing is not None:
                raise RuntimeArtifactError("runtime_artifact_already_qualified")
            now = self._now()
            receipt_id = deterministic_id(
                "receipt_runtime_artifact_qualification",
                artifact_id,
                revision_digest,
            )
            receipt_document = {
                "kind": "RuntimeArtifactQualificationReceipt",
                "receipt_id": receipt_id,
                "subject_ref": subject_ref,
                "artifact_id": artifact_id,
                "revision_digest": revision_digest,
                "outcome": "pass",
                "evidence_status": "synthetic_d0",
                "bindings": actual_bindings,
                "qualified_by_human_ref": actor_ref,
                "reason": reason,
                "recorded_at": _time(now),
                "execution_grant_issued": False,
                "deployment_activated": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            receipt_digest = _digest(receipt_document)
            response = {
                "artifact_id": artifact_id,
                "revision_digest": revision_digest,
                "status": "qualified_d0",
                "qualification_recorded": True,
                "receipt_id": receipt_id,
                "receipt_digest": receipt_digest,
                "idempotent_replay": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            session.add(
                ReceiptRow(
                    receipt_id=receipt_id,
                    receipt_type="runtime_artifact_qualification_d0",
                    receipt_digest=receipt_digest,
                    subject_ref=subject_ref,
                    document=receipt_document,
                    recorded_at=now,
                )
            )
            session.add(
                ControlConsoleCommandRow(
                    idempotency_key=idempotency_key,
                    command_kind="runtime_artifact_qualification_d0",
                    target_ref=subject_ref,
                    request_digest=_digest(request),
                    response=response,
                    created_at=now,
                )
            )
            self._add_audit(
                session,
                correlation_id=artifact_id,
                event_type="runtime_artifact_qualified_d0",
                actor_ref=actor_ref,
                payload={
                    "revision_digest": revision_digest,
                    "receipt_id": receipt_id,
                    "receipt_digest": receipt_digest,
                    "release_authorization": False,
                },
                seed=idempotency_key,
                now=now,
            )
        return response

    def revoke(
        self,
        *,
        artifact_id: str,
        expected_revision_digest: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        _validate_actor(actor_ref)
        _validate_reason(reason)
        _validate_idempotency(idempotency_key)
        with self.database.session() as session:
            replay = session.scalar(
                select(RuntimeArtifactRevocationRow).where(
                    RuntimeArtifactRevocationRow.idempotency_key == idempotency_key
                )
            )
            if replay is not None:
                if replay.artifact_id != artifact_id or replay.revision_digest != expected_revision_digest or replay.reason != reason:
                    raise RuntimeArtifactError("runtime_artifact_idempotency_conflict")
                return self._revocation_response(replay, replayed=True)
        self._revision(artifact_id, expected_revision_digest)
        if self._latest(artifact_id).revision_digest != expected_revision_digest:
            raise RuntimeArtifactError("runtime_artifact_expected_revision_drift")
        if self._revocation(artifact_id, expected_revision_digest) is not None:
            raise RuntimeArtifactError("runtime_artifact_already_revoked")
        now = self._now()
        revocation_id = deterministic_id(
            "revocation", artifact_id, expected_revision_digest, idempotency_key
        )
        document = {
            "kind": "RuntimeArtifactRevocation",
            "revocation_id": revocation_id,
            "artifact_id": artifact_id,
            "revision_digest": expected_revision_digest,
            "reason": reason,
            "revoked_by_human_ref": actor_ref,
            "revoked_at": _time(now),
            "deny_new_lease_claims": True,
            "production_authorization": False,
            "release_authorization": False,
        }
        receipt_id = deterministic_id("receipt", revocation_id)
        receipt = {
            "kind": "RuntimeArtifactRevocationReceipt",
            "receipt_id": receipt_id,
            "subject_ref": f"runtime-artifact://{artifact_id}/{expected_revision_digest}",
            "revocation_digest": _digest(document),
            "recorded_at": _time(now),
            "execution_grant": False,
            "release_authorization": False,
        }
        receipt_digest = _digest(receipt)
        with self.database.session() as session:
            row = RuntimeArtifactRevocationRow(
                revocation_id=revocation_id,
                artifact_id=artifact_id,
                revision_digest=expected_revision_digest,
                idempotency_key=idempotency_key,
                reason=reason,
                revoked_by_ref=actor_ref,
                receipt_id=receipt_id,
                receipt_digest=receipt_digest,
                document=document,
                revoked_at=now,
            )
            session.add(row)
            session.add(
                ReceiptRow(
                    receipt_id=receipt_id,
                    receipt_type="runtime_artifact_revocation",
                    receipt_digest=receipt_digest,
                    subject_ref=receipt["subject_ref"],
                    document=receipt,
                    recorded_at=now,
                )
            )
            self._add_audit(
                session,
                correlation_id=artifact_id,
                event_type="runtime_artifact_revoked",
                actor_ref=actor_ref,
                payload={
                    "revision_digest": expected_revision_digest,
                    "receipt_id": receipt_id,
                    "release_authorization": False,
                },
                seed=revocation_id,
                now=now,
            )
        return self._revocation_response(row, replayed=False)

    # ---- node reports and import receipts -------------------------------

    def record_capability_report(
        self,
        *,
        node_id: str,
        document: Mapping[str, Any],
        idempotency_key: str,
        workload_identity: str,
    ) -> dict[str, Any]:
        normalized = _normalize(document)
        _validate_idempotency(idempotency_key)
        _validate_node_actor(node_id, workload_identity)
        if normalized.get("node_id") != node_id:
            raise RuntimeArtifactError("runtime_node_capability_binding_drift")
        reason_codes = _capability_reasons(
            normalized,
            workload_identity,
            authorized_scope=self.authorized_node_scopes.get(node_id),
        )
        status = "eligible_d0" if not reason_codes else "ineligible"
        report_digest = _digest(normalized)
        with self.database.session() as session:
            existing = session.scalar(
                select(RuntimeNodeCapabilityReportRow).where(
                    RuntimeNodeCapabilityReportRow.idempotency_key == idempotency_key
                )
            )
            if existing is not None:
                if existing.node_id != node_id or existing.report_digest != report_digest:
                    raise RuntimeArtifactError("runtime_node_capability_idempotency_conflict")
                return self._capability_public(existing, replayed=True)
            observed_at = _parse_time(normalized.get("observed_at"))
            now = self._now()
            if observed_at > now + timedelta(minutes=1) or observed_at < now - timedelta(hours=24):
                reason_codes.append("runtime_node_capability_observation_stale")
                status = "ineligible"
            row = RuntimeNodeCapabilityReportRow(
                node_id=node_id,
                report_digest=report_digest,
                idempotency_key=idempotency_key,
                status=status,
                reason_codes=sorted(set(reason_codes)),
                document=normalized,
                observed_at=observed_at,
                recorded_at=now,
            )
            session.add(row)
            receipt_id = deterministic_id(
                "receipt_runtime_node_capability", node_id, report_digest
            )
            receipt_document = {
                "kind": "RuntimeNodeCapabilityReceipt",
                "receipt_id": receipt_id,
                "node_id": node_id,
                "capability_report_digest": report_digest,
                "status": status,
                "reason_codes": sorted(set(reason_codes)),
                "recorded_at": _time(now),
                "execution_grant_issued": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            session.add(
                ReceiptRow(
                    receipt_id=receipt_id,
                    receipt_type="runtime_node_capability_report",
                    receipt_digest=_digest(receipt_document),
                    subject_ref=f"runtime-node://{node_id}",
                    document=receipt_document,
                    recorded_at=now,
                )
            )
            self._add_audit(
                session,
                correlation_id=node_id,
                event_type="runtime_node_capability_recorded",
                actor_ref=workload_identity,
                payload={
                    "capability_report_digest": report_digest,
                    "status": status,
                    "receipt_id": receipt_id,
                    "release_authorization": False,
                },
                seed=idempotency_key,
                now=now,
            )
        return self._capability_public(row, replayed=False)

    def record_import_receipt(
        self,
        *,
        node_id: str,
        document: Mapping[str, Any],
        idempotency_key: str,
        workload_identity: str,
    ) -> dict[str, Any]:
        normalized = _normalize(document)
        _validate_idempotency(idempotency_key)
        _validate_node_actor(node_id, workload_identity)
        projection = _validate_import_receipt(normalized, node_id=node_id)
        artifact = self._revision(
            projection["artifact_id"], projection["revision_digest"]
        )
        if (
            artifact.runtime_source_digest != projection["runtime_source_digest"]
            or artifact.runtime_image_digest != projection["runtime_image_digest"]
            or artifact.isolation_profile_digest
            != projection["isolation_profile_digest"]
            or artifact.bundle_digest != projection["artifact_set_manifest_digest"]
            or artifact.document["spec"]["artifact_bundle"]["signature_bundle_digest"]
            != projection["signature_bundle_digest"]
            or artifact.target_platform != projection["target_platform"]
            or self._revocation(artifact.artifact_id, artifact.revision_digest)
            is not None
        ):
            raise RuntimeArtifactError("runtime_artifact_import_binding_drift")
        capability = self._latest_capability(node_id)
        if projection["outcome"] == "imported" and (
            capability is None
            or capability.report_digest != projection["capability_report_digest"]
        ):
            raise RuntimeArtifactError("runtime_artifact_import_capability_drift")
        if projection["outcome"] == "imported" and (
            capability is None
            or capability.status != "eligible_d0"
            or capability.document["oci_platform"] != artifact.target_platform
        ):
            raise RuntimeArtifactError("runtime_artifact_import_preflight_blocked")
        if projection["outcome"] == "imported" and (
            artifact.revision_digest
            in capability.document["verified_runtime_artifact_digests"]
            or artifact.runtime_image_digest
            in capability.document["verified_image_digests"]
        ):
            raise RuntimeArtifactError(
                "runtime_artifact_import_preflight_report_not_clean"
            )
        receipt_digest = projection["receipt_digest"]
        with self.database.session() as session:
            existing = session.scalar(
                select(RuntimeArtifactImportReceiptRow).where(
                    RuntimeArtifactImportReceiptRow.idempotency_key == idempotency_key
                )
            )
            if existing is not None:
                if existing.receipt_digest != receipt_digest:
                    raise RuntimeArtifactError("runtime_artifact_import_idempotency_conflict")
                return self._import_public(existing, replayed=True)
            row = RuntimeArtifactImportReceiptRow(
                receipt_id=normalized["metadata"]["receipt_id"],
                idempotency_key=idempotency_key,
                node_id=node_id,
                artifact_id=artifact.artifact_id,
                revision_digest=artifact.revision_digest,
                runtime_image_digest=artifact.runtime_image_digest,
                capability_report_digest=projection["capability_report_digest"],
                outcome=projection["outcome"],
                receipt_digest=receipt_digest,
                document=normalized,
                recorded_at=_parse_time(normalized["metadata"]["recorded_at"]),
            )
            session.add(row)
            session.add(
                ReceiptRow(
                    receipt_id=row.receipt_id,
                    receipt_type="runtime_artifact_import",
                    receipt_digest=receipt_digest,
                    subject_ref=runtime_artifact_subject_ref(
                        artifact.artifact_id, artifact.revision_digest
                    ),
                    document=normalized,
                    recorded_at=row.recorded_at,
                )
            )
            self._add_audit(
                session,
                correlation_id=node_id,
                event_type="runtime_artifact_import_recorded",
                actor_ref=workload_identity,
                payload={
                    "artifact_id": artifact.artifact_id,
                    "revision_digest": artifact.revision_digest,
                    "receipt_id": row.receipt_id,
                    "outcome": row.outcome,
                    "release_authorization": False,
                },
                seed=idempotency_key,
                now=row.recorded_at,
            )
        return self._import_public(row, replayed=False)

    # ---- lease and append-only runtime evidence -------------------------

    def claim_lease(
        self,
        *,
        node_id: str,
        expected_capability_report_digest: str,
        idempotency_key: str,
        workload_identity: str,
    ) -> dict[str, Any]:
        _validate_node_actor(node_id, workload_identity)
        _validate_idempotency(idempotency_key)
        capability = self._latest_capability(node_id)
        if (
            capability is None
            or capability.status != "eligible_d0"
            or capability.report_digest != expected_capability_report_digest
            or _as_utc(capability.observed_at) < self._now() - timedelta(hours=24)
        ):
            raise RuntimeArtifactError("runtime_node_capability_not_eligible")
        with self.database.session() as session:
            replay = session.scalar(
                select(RuntimeNodeLeaseClaimRow).where(
                    RuntimeNodeLeaseClaimRow.idempotency_key == idempotency_key
                )
            )
            if replay is not None:
                if replay.node_id != node_id or replay.capability_report_digest != expected_capability_report_digest:
                    raise RuntimeArtifactError("runtime_node_lease_idempotency_conflict")
                return self._lease_public(replay, replayed=True)
            runs = tuple(
                session.scalars(
                    select(RuntimeRunRow)
                    .where(RuntimeRunRow.status == "queued")
                    .order_by(RuntimeRunRow.id)
                    .with_for_update(skip_locked=True)
                )
            )
            selected = next((row for row in runs if self._node_can_run(capability, row)), None)
            if selected is None:
                return {
                    "claimed": False,
                    "reason_code": "runtime_node_no_eligible_work",
                    "production_authorization": False,
                    "release_authorization": False,
                }
            if self.grant_revocations.is_revoked(
                grant_id=selected.grant_id, minimum_revision=0
            ):
                raise RuntimeArtifactError("runtime_node_lease_grant_revoked")
            now = self._now()
            expires_at = min(
                _as_utc(selected.expires_at), now + timedelta(minutes=5)
            )
            lease_id = deterministic_id("lease_node", node_id, selected.run_id)
            row = RuntimeNodeLeaseClaimRow(
                lease_id=lease_id,
                idempotency_key=idempotency_key,
                node_id=node_id,
                run_id=selected.run_id,
                invocation_digest=selected.invocation_digest,
                capability_report_digest=capability.report_digest,
                status="active",
                claimed_at=now,
                expires_at=expires_at,
                closed_at=None,
            )
            session.add(row)
            selected.status = "leased"
            selected.worker_identity = workload_identity
            selected.revision += 1
            receipt_id = deterministic_id("receipt_runtime_lease", lease_id)
            receipt_document = {
                "kind": "RuntimeNodeLeaseClaimReceipt",
                "receipt_id": receipt_id,
                "lease_id": lease_id,
                "node_id": node_id,
                "run_id": selected.run_id,
                "invocation_digest": selected.invocation_digest,
                "capability_report_digest": capability.report_digest,
                "claimed_at": _time(now),
                "expires_at": _time(expires_at),
                "execution_grant_issued": False,
                "production_authorization": False,
                "release_authorization": False,
            }
            session.add(
                ReceiptRow(
                    receipt_id=receipt_id,
                    receipt_type="runtime_node_lease_claim",
                    receipt_digest=_digest(receipt_document),
                    subject_ref=f"runtime-run://{selected.run_id}",
                    document=receipt_document,
                    recorded_at=now,
                )
            )
            self._add_audit(
                session,
                correlation_id=selected.run_id,
                event_type="runtime_node_lease_claimed",
                actor_ref=workload_identity,
                payload={
                    "lease_id": lease_id,
                    "node_id": node_id,
                    "receipt_id": receipt_id,
                    "release_authorization": False,
                },
                seed=idempotency_key,
                now=now,
            )
        return self._lease_public(row, replayed=False)

    def append_run_evidence(
        self,
        *,
        node_id: str,
        run_id: str,
        evidence_type: str,
        document: Mapping[str, Any],
        idempotency_key: str,
        workload_identity: str,
    ) -> dict[str, Any]:
        _validate_node_actor(node_id, workload_identity)
        _validate_idempotency(idempotency_key)
        if evidence_type not in {
            "container_event",
            "checkpoint_receipt",
            "cleanup_receipt",
            "result_package",
        }:
            raise RuntimeArtifactError("runtime_container_evidence_type_invalid")
        normalized = _normalize(document)
        _validate_runtime_evidence(evidence_type, normalized, self._now())
        digest = _digest(normalized)
        with self.database.session() as session:
            replay = session.scalar(
                select(RuntimeContainerEvidenceRow).where(
                    RuntimeContainerEvidenceRow.idempotency_key == idempotency_key
                )
            )
            if replay is not None:
                if (
                    replay.node_id != node_id
                    or replay.run_id != run_id
                    or replay.evidence_type != evidence_type
                    or replay.evidence_digest != digest
                ):
                    raise RuntimeArtifactError(
                        "runtime_container_evidence_idempotency_conflict"
                    )
                return self._evidence_public(replay, replayed=True)
            lease = session.scalar(
                select(RuntimeNodeLeaseClaimRow).where(
                    RuntimeNodeLeaseClaimRow.run_id == run_id,
                    RuntimeNodeLeaseClaimRow.node_id == node_id,
                )
            )
            if lease is None:
                raise RuntimeArtifactError("runtime_node_lease_not_found")
            now = self._now()
            run = session.scalar(
                select(RuntimeRunRow).where(RuntimeRunRow.run_id == run_id)
            )
            latest_event = session.scalar(
                select(RuntimeContainerEvidenceRow)
                .where(
                    RuntimeContainerEvidenceRow.run_id == run_id,
                    RuntimeContainerEvidenceRow.evidence_type == "container_event",
                )
                .order_by(RuntimeContainerEvidenceRow.sequence.desc())
                .limit(1)
            )
            if evidence_type == "result_package":
                prior_result = session.scalar(
                    select(RuntimeContainerEvidenceRow)
                    .where(
                        RuntimeContainerEvidenceRow.run_id == run_id,
                        RuntimeContainerEvidenceRow.evidence_type == "result_package",
                    )
                    .order_by(RuntimeContainerEvidenceRow.sequence.desc())
                    .limit(1)
                )
                if prior_result is not None:
                    if prior_result.evidence_digest != digest:
                        raise RuntimeArtifactError("runtime_result_conflict")
                    return self._evidence_public(prior_result, replayed=True)
                cleanup = session.scalar(
                    select(RuntimeContainerEvidenceRow.id).where(
                        RuntimeContainerEvidenceRow.run_id == run_id,
                        RuntimeContainerEvidenceRow.evidence_type == "cleanup_receipt",
                    ).limit(1)
                )
                if cleanup is not None:
                    raise RuntimeArtifactError("runtime_result_after_cleanup")
            _validate_runtime_evidence_transition(
                evidence_type=evidence_type,
                document=normalized,
                latest_event=latest_event,
                lease=lease,
                run=run,
                now=now,
            )
            if evidence_type == "checkpoint_receipt" and (
                run is None
                or run.runtime_image_digest is None
                or normalized["source_image_digest"] != run.runtime_image_digest
            ):
                raise RuntimeArtifactError(
                    "runtime_checkpoint_source_image_binding_drift"
                )
            maximum = session.scalar(
                select(func.max(RuntimeContainerEvidenceRow.sequence)).where(
                    RuntimeContainerEvidenceRow.run_id == run_id
                )
            )
            row = RuntimeContainerEvidenceRow(
                run_id=run_id,
                node_id=node_id,
                sequence=0 if maximum is None else int(maximum) + 1,
                evidence_type=evidence_type,
                idempotency_key=idempotency_key,
                evidence_digest=digest,
                document=normalized,
                recorded_at=now,
            )
            session.add(row)
            if evidence_type == "container_event":
                event = normalized["event_type"]
                if event == "started":
                    run.status = "running"
                    run.started_at = run.started_at or now
                    run.revision += 1
                elif event == "needs_input":
                    lease.status = "closed"
                    lease.closed_at = now
                    run.status = "paused"
                    run.worker_identity = None
                    run.revision += 1
                elif event in {"completed", "failed", "cancelled"}:
                    lease.status = "closed"
                    lease.closed_at = now
                    run.status = event
                    run.closed_at = now
                    run.revision += 1
            elif evidence_type == "cleanup_receipt" and lease.status == "active":
                lease.status = "closed"
                lease.closed_at = now
                if latest_event is None and run.status == "leased":
                    run.status = "cancelled"
                    run.worker_identity = None
                    run.cancel_reason_code = "runtime_cleanup_before_start"
                    run.closed_at = now
                    run.revision += 1
            elif evidence_type == "result_package":
                run.result_document = normalized
                run.result_digest = digest
                run.revision += 1
            receipt_id, receipt_document = _runtime_evidence_receipt(row)
            session.add(
                ReceiptRow(
                    receipt_id=receipt_id,
                    receipt_type=f"runtime_{evidence_type}",
                    receipt_digest=_digest(receipt_document),
                    subject_ref=f"runtime-run://{run_id}",
                    document=receipt_document,
                    recorded_at=now,
                )
            )
            self._add_audit(
                session,
                correlation_id=run_id,
                event_type=f"runtime_{evidence_type}_recorded",
                actor_ref=workload_identity,
                payload={
                    "evidence_digest": digest,
                    "receipt_id": receipt_id,
                    "lease_closed": lease.status == "closed",
                    "release_authorization": False,
                },
                seed=idempotency_key,
                now=now,
            )
        return self._evidence_public(row, replayed=False)

    # ---- deliberately disabled Model Gateway ---------------------------

    def exchange_model_token(
        self,
        *,
        node_id: str,
        document: Mapping[str, Any],
        idempotency_key: str,
        workload_identity: str,
    ) -> dict[str, Any]:
        _validate_node_actor(node_id, workload_identity)
        _validate_idempotency(idempotency_key)
        normalized = _normalize(document)
        expected = {
            "task_id",
            "grant_id",
            "run_id",
            "route_revision_digest",
            "data_classification",
            "production_authorization",
        }
        if (
            set(normalized) != expected
            or normalized["data_classification"] not in {"synthetic", "public"}
            or normalized["production_authorization"] is not False
            or not _digest_value(normalized["route_revision_digest"])
        ):
            raise RuntimeArtifactError("model_gateway_exchange_request_invalid")
        request_digest = _digest(normalized)
        with self.database.session() as session:
            replay = session.scalar(
                select(ModelGatewayTokenExchangeRow).where(
                    ModelGatewayTokenExchangeRow.idempotency_key == idempotency_key
                )
            )
            if replay is not None:
                if replay.request_digest != request_digest or replay.node_id != node_id:
                    raise RuntimeArtifactError("model_gateway_exchange_idempotency_conflict")
                return self._gateway_denial(replay, replayed=True)
            run = session.scalar(
                select(RuntimeRunRow).where(RuntimeRunRow.run_id == normalized["run_id"])
            )
            grant = session.scalar(
                select(SignedGrantRow).where(SignedGrantRow.grant_id == normalized["grant_id"])
            )
            reason_code = "model_gateway_provider_disabled_d0"
            if run is None or grant is None or run.task_id != normalized["task_id"] or run.grant_id != normalized["grant_id"]:
                reason_code = "model_gateway_exchange_binding_invalid"
            elif self.grant_revocations.is_revoked(grant_id=grant.grant_id, minimum_revision=0):
                reason_code = "model_gateway_exchange_grant_revoked"
            attempt_id = deterministic_id("gateway_attempt", node_id, idempotency_key)
            row = ModelGatewayTokenExchangeRow(
                attempt_id=attempt_id,
                idempotency_key=idempotency_key,
                node_id=node_id,
                task_id=normalized["task_id"],
                grant_id=normalized["grant_id"],
                run_id=normalized["run_id"],
                request_digest=request_digest,
                outcome="denied",
                reason_code=reason_code,
                token_issued=False,
                recorded_at=self._now(),
            )
            session.add(row)
        return self._gateway_denial(row, replayed=False)

    # ---- projections ----------------------------------------------------

    def _summary(self, artifact_id: str) -> dict[str, Any]:
        row = self._latest(artifact_id)
        revoked = self._revocation(artifact_id, row.revision_digest) is not None
        qualified = self._is_qualified(row)
        return {
            "artifact_id": artifact_id,
            "revision_digest": row.revision_digest,
            "runtime_family": row.runtime_family,
            "runtime_source_digest": row.runtime_source_digest,
            "runtime_image_digest": row.runtime_image_digest,
            "isolation_profile_digest": row.isolation_profile_digest,
            "target_platform": row.target_platform,
            "status": (
                "revoked" if revoked else "qualified_d0" if qualified else "candidate"
            ),
            "schedulable": not revoked and qualified,
            "production_authorized": False,
        }

    def _latest(self, artifact_id: str) -> RuntimeArtifactRevisionRow | None:
        with self.database.session() as session:
            return session.scalar(
                select(RuntimeArtifactRevisionRow)
                .where(RuntimeArtifactRevisionRow.artifact_id == artifact_id)
                .order_by(RuntimeArtifactRevisionRow.id.desc())
                .limit(1)
            )

    def _revision(self, artifact_id: str, digest: str) -> RuntimeArtifactRevisionRow:
        with self.database.session() as session:
            row = session.scalar(
                select(RuntimeArtifactRevisionRow).where(
                    RuntimeArtifactRevisionRow.artifact_id == artifact_id,
                    RuntimeArtifactRevisionRow.revision_digest == digest,
                )
            )
        if row is None:
            raise RuntimeArtifactError("runtime_artifact_revision_not_found")
        return row

    def _revocation(self, artifact_id: str, digest: str) -> RuntimeArtifactRevocationRow | None:
        with self.database.session() as session:
            return session.scalar(
                select(RuntimeArtifactRevocationRow).where(
                    RuntimeArtifactRevocationRow.artifact_id == artifact_id,
                    RuntimeArtifactRevocationRow.revision_digest == digest,
                )
            )

    def _is_qualified(self, row: RuntimeArtifactRevisionRow) -> bool:
        with self.database.session() as session:
            receipt = session.scalar(
                select(ReceiptRow).where(
                    ReceiptRow.receipt_type == "runtime_artifact_qualification_d0",
                    ReceiptRow.subject_ref
                    == runtime_artifact_subject_ref(
                        row.artifact_id, row.revision_digest
                    ),
                )
            )
        return runtime_artifact_qualification_receipt_matches(row, receipt)

    def _latest_capability(self, node_id: str) -> RuntimeNodeCapabilityReportRow | None:
        with self.database.session() as session:
            return session.scalar(
                select(RuntimeNodeCapabilityReportRow)
                .where(RuntimeNodeCapabilityReportRow.node_id == node_id)
                .order_by(RuntimeNodeCapabilityReportRow.id.desc())
                .limit(1)
            )

    def _node_can_run(
        self, capability: RuntimeNodeCapabilityReportRow, run: RuntimeRunRow
    ) -> bool:
        workload_scope = capability.document.get("workload_scope")
        department_id = run.invocation.get("department_id")
        agent_binding_ref = run.invocation.get("agent_binding_ref")
        agent_binding_digest = run.invocation.get("agent_binding_digest")
        if (
            run.runtime_artifact_digest is None
            or run.runtime_image_digest is None
            or run.isolation_profile_digest is None
            or run.invocation.get("production_authorization") is not False
            or run.invocation.get("data_classification") not in {"synthetic", "public"}
            or not isinstance(workload_scope, Mapping)
            or department_id not in workload_scope.get("department_ids", ())
            or not any(
                binding.get("id") == agent_binding_ref
                and binding.get("digest") == agent_binding_digest
                for binding in workload_scope.get("agent_bindings", ())
                if isinstance(binding, Mapping)
            )
        ):
            return False
        artifact = self._artifact_by_revision(run.runtime_artifact_digest)
        imported = self._successful_import(
            capability.node_id, run.runtime_artifact_digest
        )
        return (
            artifact is not None
            and self._is_qualified(artifact)
            and artifact.runtime_source_digest == run.runtime_source_digest
            and artifact.runtime_image_digest == run.runtime_image_digest
            and artifact.isolation_profile_digest == run.isolation_profile_digest
            and bool(run.input_snapshot_refs)
            and self._revocation(artifact.artifact_id, artifact.revision_digest) is None
            and imported is not None
            and imported.receipt_digest
            in capability.document["verified_import_receipt_digests"]
            and artifact.revision_digest
            in capability.document["verified_runtime_artifact_digests"]
            and artifact.runtime_image_digest
            in capability.document["verified_image_digests"]
        )

    def _successful_import(
        self, node_id: str, revision_digest: str
    ) -> RuntimeArtifactImportReceiptRow | None:
        with self.database.session() as session:
            return session.scalar(
                select(RuntimeArtifactImportReceiptRow)
                .where(
                    RuntimeArtifactImportReceiptRow.node_id == node_id,
                    RuntimeArtifactImportReceiptRow.revision_digest
                    == revision_digest,
                    RuntimeArtifactImportReceiptRow.outcome == "imported",
                )
                .order_by(RuntimeArtifactImportReceiptRow.id.desc())
                .limit(1)
            )

    def _artifact_by_revision(self, digest: str) -> RuntimeArtifactRevisionRow | None:
        with self.database.session() as session:
            return session.scalar(
                select(RuntimeArtifactRevisionRow).where(
                    RuntimeArtifactRevisionRow.revision_digest == digest
                )
            )

    def _command(
        self, idempotency_key: str, kind: str, request: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        with self.database.session() as session:
            row = session.scalar(
                select(ControlConsoleCommandRow).where(
                    ControlConsoleCommandRow.idempotency_key == idempotency_key
                )
            )
        if row is None:
            return None
        if row.command_kind != kind or row.request_digest != _digest(request):
            raise RuntimeArtifactError("runtime_artifact_idempotency_conflict")
        return {**row.response, "idempotent_replay": True}

    def _record_command(
        self,
        *,
        idempotency_key: str,
        command_kind: str,
        target_ref: str,
        request: Mapping[str, Any],
        response: Mapping[str, Any],
        actor_ref: str,
        event_type: str,
    ) -> None:
        now = self._now()
        with self.database.session() as session:
            session.add(
                ControlConsoleCommandRow(
                    idempotency_key=idempotency_key,
                    command_kind=command_kind,
                    target_ref=target_ref,
                    request_digest=_digest(request),
                    response=dict(response),
                    created_at=now,
                )
            )
            self._add_audit(
                session,
                correlation_id=target_ref.split("//", 1)[-1],
                event_type=event_type,
                actor_ref=actor_ref,
                payload={"response_digest": _digest(response), "release_authorization": False},
                seed=idempotency_key,
                now=now,
            )

    @staticmethod
    def _add_audit(session, *, correlation_id: str, event_type: str, actor_ref: str, payload: Mapping[str, Any], seed: str, now: datetime) -> None:
        session.add(
            AuditEventRow(
                audit_id=deterministic_id("audit", event_type, seed),
                correlation_id=correlation_id,
                event_type=event_type,
                actor_ref=actor_ref,
                payload=dict(payload),
                recorded_at=now,
            )
        )

    def _now(self) -> datetime:
        return self.now().astimezone(timezone.utc)

    @staticmethod
    def _revocation_response(row: RuntimeArtifactRevocationRow, *, replayed: bool) -> dict[str, Any]:
        return {
            "artifact_id": row.artifact_id,
            "revision_digest": row.revision_digest,
            "revocation_id": row.revocation_id,
            "receipt_id": row.receipt_id,
            "receipt_digest": row.receipt_digest,
            "schedulable": False,
            "idempotent_replay": replayed,
            "release_authorization": False,
        }

    @staticmethod
    def _capability_public(row: RuntimeNodeCapabilityReportRow, *, replayed: bool) -> dict[str, Any]:
        receipt_id = deterministic_id(
            "receipt_runtime_node_capability", row.node_id, row.report_digest
        )
        receipt_document = {
            "kind": "RuntimeNodeCapabilityReceipt",
            "receipt_id": receipt_id,
            "node_id": row.node_id,
            "capability_report_digest": row.report_digest,
            "status": row.status,
            "reason_codes": row.reason_codes,
            "recorded_at": _time(row.recorded_at),
            "execution_grant_issued": False,
            "production_authorization": False,
            "release_authorization": False,
        }
        return {
            "node_id": row.node_id,
            "report_digest": row.report_digest,
            "status": row.status,
            "reason_codes": row.reason_codes,
            "receipt_id": receipt_id,
            "receipt_digest": _digest(receipt_document),
            "idempotent_replay": replayed,
            "production_authorized": False,
            "release_authorization": False,
        }

    @staticmethod
    def _import_public(row: RuntimeArtifactImportReceiptRow, *, replayed: bool) -> dict[str, Any]:
        return {
            "receipt_id": row.receipt_id,
            "receipt_digest": row.receipt_digest,
            "node_id": row.node_id,
            "artifact_id": row.artifact_id,
            "revision_digest": row.revision_digest,
            "outcome": row.outcome,
            "idempotent_replay": replayed,
            "contract_consumer": RUNTIME_ARTIFACT_IMPORT_RECEIPT_CONSUMER_PROFILE,
            "release_authorization": False,
        }

    @staticmethod
    def _lease_public(row: RuntimeNodeLeaseClaimRow, *, replayed: bool) -> dict[str, Any]:
        receipt_id = deterministic_id("receipt_runtime_lease", row.lease_id)
        receipt_document = {
            "kind": "RuntimeNodeLeaseClaimReceipt",
            "receipt_id": receipt_id,
            "lease_id": row.lease_id,
            "node_id": row.node_id,
            "run_id": row.run_id,
            "invocation_digest": row.invocation_digest,
            "capability_report_digest": row.capability_report_digest,
            "claimed_at": _time(row.claimed_at),
            "expires_at": _time(row.expires_at),
            "execution_grant_issued": False,
            "production_authorization": False,
            "release_authorization": False,
        }
        return {
            "claimed": True,
            "lease_id": row.lease_id,
            "run_id": row.run_id,
            "invocation_digest": row.invocation_digest,
            "receipt_id": receipt_id,
            "receipt_digest": _digest(receipt_document),
            "expires_at": _time(row.expires_at),
            "idempotent_replay": replayed,
            "production_authorization": False,
            "release_authorization": False,
        }

    @staticmethod
    def _evidence_public(row: RuntimeContainerEvidenceRow, *, replayed: bool) -> dict[str, Any]:
        receipt_id, receipt_document = _runtime_evidence_receipt(row)
        return {
            "run_id": row.run_id,
            "sequence": row.sequence,
            "evidence_type": row.evidence_type,
            "evidence_digest": row.evidence_digest,
            "receipt_id": receipt_id,
            "receipt_digest": _digest(receipt_document),
            "idempotent_replay": replayed,
            "runtime_projection_authoritative": False,
            "release_authorization": False,
        }

    @staticmethod
    def _gateway_denial(row: ModelGatewayTokenExchangeRow, *, replayed: bool) -> dict[str, Any]:
        return {
            "attempt_id": row.attempt_id,
            "outcome": "denied",
            "reason_code": row.reason_code,
            "token_issued": False,
            "idempotent_replay": replayed,
            "provider_called": False,
            "secret_bytes_accessed": False,
            "production_authorization": False,
            "release_authorization": False,
        }


def runtime_artifact_subject_ref(artifact_id: str, revision_digest: str) -> str:
    del artifact_id
    return f"runtime-artifact://revision/{revision_digest}"


def runtime_artifact_qualification_bindings(
    row: RuntimeArtifactRevisionRow,
) -> dict[str, Any]:
    spec = row.document["spec"]
    evidence = spec["evidence"]
    return {
        "manifest_digest": row.revision_digest,
        "runtime_source_digest": row.runtime_source_digest,
        "runtime_realization_digest": spec["runtime_realization_digest"],
        "runtime_image_digest": row.runtime_image_digest,
        "isolation_profile_digest": row.isolation_profile_digest,
        "adapter_digest": row.adapter_digest,
        "bundle_digest": row.bundle_digest,
        "evidence_digests": {
            key: evidence[key]
            for key in (
                "sbom_digest",
                "build_provenance_digest",
                "vulnerability_report_digest",
                "license_report_digest",
            )
        },
    }


def runtime_artifact_qualification_receipt_matches(
    row: RuntimeArtifactRevisionRow,
    receipt: ReceiptRow | None,
) -> bool:
    if receipt is None:
        return False
    document = receipt.document
    return (
        receipt.receipt_type == "runtime_artifact_qualification_d0"
        and receipt.subject_ref
        == runtime_artifact_subject_ref(row.artifact_id, row.revision_digest)
        and receipt.receipt_digest == _digest(document)
        and document.get("kind") == "RuntimeArtifactQualificationReceipt"
        and document.get("receipt_id") == receipt.receipt_id
        and document.get("subject_ref") == receipt.subject_ref
        and document.get("artifact_id") == row.artifact_id
        and document.get("revision_digest") == row.revision_digest
        and document.get("outcome") == "pass"
        and document.get("evidence_status") == "synthetic_d0"
        and document.get("bindings")
        == runtime_artifact_qualification_bindings(row)
        and document.get("execution_grant_issued") is False
        and document.get("deployment_activated") is False
        and document.get("production_authorization") is False
        and document.get("release_authorization") is False
    )


def _validate_manifest(value: Mapping[str, Any]) -> None:
    if set(value) != _ARTIFACT_FIELDS:
        raise RuntimeArtifactError("runtime_artifact_manifest_invalid")
    metadata = value["metadata"]
    spec = value["spec"]
    boundary = value["authority_boundary"]
    if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping) or not isinstance(boundary, Mapping):
        raise RuntimeArtifactError("runtime_artifact_manifest_invalid")
    expected_metadata = {"artifact_id", "version", "revision", "evidence_status", "synthetic_only", "created_at"}
    expected_spec = {
        "runtime_family", "upstream_revision", "runtime_source_lock_ref",
        "runtime_source_digest", "runtime_realization_ref",
        "runtime_realization_digest", "oci_image", "runtime_adapter", "build_inputs",
        "evidence", "container_isolation_profile_ref",
        "container_isolation_profile_digest", "supported_scope",
        "minimum_runner_capabilities", "artifact_bundle", "lifecycle",
        "manifest_digest",
    }
    expected_boundary = {
        "agent_identity_created", "execution_grant_issued", "deployment_activated",
        "production_authorized", "release_authorization",
    }
    if set(metadata) != expected_metadata or set(spec) != expected_spec or set(boundary) != expected_boundary:
        raise RuntimeArtifactError("runtime_artifact_manifest_invalid")
    adapter = spec["runtime_adapter"]
    build = spec["build_inputs"]
    evidence = spec["evidence"]
    bundle = spec["artifact_bundle"]
    image = spec["oci_image"]
    scope = spec["supported_scope"]
    minimum = spec["minimum_runner_capabilities"]
    lifecycle = spec["lifecycle"]
    if (
        value["api_version"] != "company-ai-os/v1alpha3-draft"
        or value["kind"] != "RuntimeArtifactManifest"
        or not _id_value(metadata["artifact_id"])
        or not isinstance(metadata["version"], str) or not _VERSION.fullmatch(metadata["version"])
        or type(metadata["revision"]) is not int or metadata["revision"] < 1
        or metadata["evidence_status"] not in {"architecture_reference", "synthetic_d0"}
        or metadata["synthetic_only"] is not True
        or _parse_time(metadata["created_at"]) is None
        or spec["runtime_family"] not in {"hermes", "codex"}
        or not isinstance(spec["upstream_revision"], str) or not 7 <= len(spec["upstream_revision"]) <= 192
        or not _versioned_ref(spec["runtime_source_lock_ref"])
        or not _digest_value(spec["runtime_source_digest"])
        or not _versioned_ref(spec["runtime_realization_ref"])
        or not _digest_value(spec["runtime_realization_digest"])
        or spec["runtime_realization_ref"]["digest"]
        != spec["runtime_realization_digest"]
        or not _versioned_ref(spec["container_isolation_profile_ref"])
        or not _digest_value(spec["container_isolation_profile_digest"])
        or spec["container_isolation_profile_ref"]["digest"] != spec["container_isolation_profile_digest"]
        or not isinstance(adapter, Mapping)
        or set(adapter) != {"adapter_id", "version", "source_digest", "capability_report_ref", "capability_report_digest"}
        or not _id_value(adapter["adapter_id"])
        or not isinstance(adapter["version"], str)
        or not _VERSION.fullmatch(adapter["version"])
        or not _digest_value(adapter["source_digest"])
        or not _versioned_ref(adapter["capability_report_ref"])
        or adapter["capability_report_ref"]["digest"] != adapter["capability_report_digest"]
        or not isinstance(image, Mapping)
        or set(image) != {"layout_media_type", "manifest_digest", "config_digest", "target_platform", "archive_digest", "floating_tag_allowed"}
        or image["layout_media_type"] != "application/vnd.oci.layout.header.v1+json"
        or any(not _digest_value(image[item]) for item in ("manifest_digest", "config_digest", "archive_digest"))
        or image["target_platform"] not in {"linux/amd64", "linux/arm64"}
        or image["floating_tag_allowed"] is not False
        or spec["runtime_source_digest"] in {image["manifest_digest"], image["config_digest"], image["archive_digest"]}
        or not isinstance(build, Mapping)
        or set(build) != {"dockerfile_digest", "dependency_lock_digest", "base_image_digest", "build_arguments_contain_secrets"}
        or any(not _digest_value(build[item]) for item in ("dockerfile_digest", "dependency_lock_digest", "base_image_digest"))
        or build["build_arguments_contain_secrets"] is not False
        or not isinstance(evidence, Mapping)
        or set(evidence) != {"sbom_ref", "sbom_digest", "build_provenance_ref", "build_provenance_digest", "vulnerability_report_ref", "vulnerability_report_digest", "license_report_ref", "license_report_digest"}
        or any(not _logical_ref(evidence[item], schemes={"evidence", "artifact"}) for item in ("sbom_ref", "build_provenance_ref", "vulnerability_report_ref", "license_report_ref"))
        or any(not _digest_value(evidence[item]) for item in ("sbom_digest", "build_provenance_digest", "vulnerability_report_digest", "license_report_digest"))
        or not isinstance(scope, Mapping)
        or set(scope) != {"agent_release_refs", "model_protocols", "tool_operations", "data_classifications"}
        or not isinstance(scope["agent_release_refs"], list) or not scope["agent_release_refs"] or any(not _versioned_ref(item) for item in scope["agent_release_refs"])
        or not _string_list(scope["model_protocols"], minimum=1)
        or not set(scope["model_protocols"]).issubset({"openai_responses", "openai_chat_completions"})
        or not _string_list(scope["tool_operations"], minimum=0)
        or not _string_list(scope["data_classifications"], minimum=1)
        or not set(scope["data_classifications"]).issubset({"synthetic", "public"})
        or not isinstance(minimum, Mapping)
        or minimum != {"os_family": "linux", "wsl_distribution": "Ubuntu-22.04", "container_engine": "rootless-docker", "rootless_required": True, "systemd_required": True, "seccomp_required": True, "cgroup_resource_limits_required": True}
        or not isinstance(bundle, Mapping)
        or set(bundle) != {"bundle_ref", "artifact_set_manifest_digest", "signature_bundle_digest", "verification_key_ref"}
        or not _logical_ref(bundle["bundle_ref"], schemes={"bundle", "artifact"})
        or not _digest_value(bundle["artifact_set_manifest_digest"])
        or not _digest_value(bundle["signature_bundle_digest"])
        or not _logical_ref(bundle["verification_key_ref"], schemes={"key"})
        or not isinstance(lifecycle, Mapping)
        or set(lifecycle) != {"status", "revoked_at", "superseding_artifact_ref"}
        or lifecycle["status"] not in {"candidate", "qualified_d0", "revoked", "superseded"}
        or lifecycle["revoked_at"] is not None
        or lifecycle["superseding_artifact_ref"] is not None
        or any(item is not False for item in boundary.values())
        or not _digest_value(spec["manifest_digest"])
        or spec["manifest_digest"] != _embedded_digest(value, "manifest_digest")
    ):
        raise RuntimeArtifactError("runtime_artifact_manifest_invalid")
    _validate_safe_json(value)


def _manifest_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    spec = value["spec"]
    return {
        "artifact_id": value["metadata"]["artifact_id"],
        "revision_digest": spec["manifest_digest"],
        "runtime_family": spec["runtime_family"],
        "runtime_source_digest": spec["runtime_source_digest"],
        "runtime_image_digest": spec["oci_image"]["manifest_digest"],
        "isolation_profile_digest": spec["container_isolation_profile_digest"],
        "adapter_digest": spec["runtime_adapter"]["source_digest"],
        "target_platform": spec["oci_image"]["target_platform"],
        "bundle_ref": spec["artifact_bundle"]["bundle_ref"],
        "bundle_digest": spec["artifact_bundle"]["artifact_set_manifest_digest"],
        "status": spec["lifecycle"]["status"],
    }


def _capability_reasons(
    value: Mapping[str, Any],
    workload_identity: str,
    *,
    authorized_scope: Mapping[str, Any] | None,
) -> list[str]:
    expected = {
        "report_version", "node_id", "deployment_instance_ref", "workload_identity",
        "observed_at", "platform", "oci_platform", "systemd", "engine", "controls",
        "verified_runtime_artifact_digests", "verified_image_digests",
        "verified_import_receipt_digests",
        "workload_scope",
        "synthetic_only", "production_authorization",
    }
    if set(value) != expected:
        raise RuntimeArtifactError("runtime_node_capability_report_invalid")
    reasons: list[str] = []
    if value["report_version"] != "orbit.runtime-node-capability-report/0.1-draft": reasons.append("runtime_node_capability_version_invalid")
    if value["workload_identity"] != workload_identity: reasons.append("runtime_node_workload_identity_drift")
    if not _logical_ref(value["deployment_instance_ref"], schemes={"artifact", "task"}): reasons.append("runtime_node_deployment_instance_ref_invalid")
    platform = value["platform"]
    if not isinstance(platform, Mapping) or platform != {"os": "linux", "distribution": "ubuntu", "version": "22.04", "wsl_version": 2}: reasons.append("runtime_node_wsl_baseline_invalid")
    if value["oci_platform"] not in {"linux/amd64", "linux/arm64"}: reasons.append("runtime_node_oci_platform_invalid")
    if value["systemd"] is not True: reasons.append("runtime_node_systemd_unavailable")
    engine = value["engine"]
    if not isinstance(engine, Mapping) or set(engine) != {"engine_id", "version", "rootless", "user_namespace"} or engine.get("engine_id") != "rootless-docker" or engine.get("rootless") is not True or engine.get("user_namespace") is not True: reasons.append("runtime_node_rootless_engine_invalid")
    controls = value["controls"]
    if not isinstance(controls, Mapping) or set(controls) != {"cgroup_v2", "seccomp", "resource_limits", "task_relay_network"} or any(item is not True for item in controls.values()): reasons.append("runtime_node_isolation_controls_missing")
    for key in (
        "verified_runtime_artifact_digests",
        "verified_image_digests",
        "verified_import_receipt_digests",
    ):
        if not isinstance(value[key], list) or any(not _digest_value(item) for item in value[key]) or len(value[key]) != len(set(value[key])): reasons.append("runtime_node_verified_digests_invalid")
    workload_scope = value["workload_scope"]
    if not _valid_workload_scope(workload_scope):
        reasons.append("runtime_node_workload_scope_invalid")
    if authorized_scope is None:
        reasons.append("runtime_node_not_registered")
    elif (
        value["workload_identity"] != authorized_scope["workload_identity"]
        or value["deployment_instance_ref"]
        != authorized_scope["deployment_instance_ref"]
        or workload_scope != authorized_scope["workload_scope"]
    ):
        reasons.append("runtime_node_authorized_scope_drift")
    if value["synthetic_only"] is not True or value["production_authorization"] is not False: reasons.append("runtime_node_authority_invalid")
    _validate_safe_json(value)
    return reasons


def _authorized_node_scopes(
    value: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    normalized = _normalize(value)
    for node_id, scope in normalized.items():
        if (
            not isinstance(node_id, str)
            or not node_id.startswith("node_")
            or not _id_value(node_id)
            or not isinstance(scope, Mapping)
            or set(scope)
            != {"workload_identity", "deployment_instance_ref", "workload_scope"}
            or not isinstance(scope.get("workload_identity"), str)
            or not str(scope["workload_identity"]).startswith("workload_")
            or not _id_value(scope["workload_identity"])
            or not _logical_ref(
                scope.get("deployment_instance_ref"), schemes={"artifact", "task"}
            )
            or not _valid_workload_scope(scope.get("workload_scope"))
        ):
            raise RuntimeArtifactError("runtime_node_authorized_scope_invalid")
    return normalized


def _valid_workload_scope(value: Any) -> bool:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"department_ids", "agent_bindings"}
        or not isinstance(value.get("department_ids"), list)
        or not value.get("department_ids")
        or any(not _id_value(item) for item in value.get("department_ids", ()))
        or len(value.get("department_ids", ()))
        != len(set(value.get("department_ids", ())))
        or not isinstance(value.get("agent_bindings"), list)
        or not value.get("agent_bindings")
    ):
        return False
    bindings = value["agent_bindings"]
    if any(
        not isinstance(item, Mapping)
        or set(item) != {"id", "digest"}
        or not _id_value(item.get("id"))
        or not str(item.get("id", "")).startswith("agent_binding_")
        or not _digest_value(item.get("digest"))
        for item in bindings
    ):
        return False
    return len(bindings) == len(
        {(item["id"], item["digest"]) for item in bindings}
    )


def _validate_import_receipt(
    value: Mapping[str, Any], *, node_id: str
) -> dict[str, Any]:
    if (
        set(value) != _ARTIFACT_FIELDS
        or value.get("api_version") != "company-ai-os/v1alpha3-draft"
        or value.get("kind") != "RuntimeArtifactImportReceipt"
    ):
        raise RuntimeArtifactError("runtime_artifact_import_receipt_invalid")
    metadata = value["metadata"]
    spec = value["spec"]
    boundary = value["authority_boundary"]
    if not all(isinstance(item, Mapping) for item in (metadata, spec, boundary)):
        raise RuntimeArtifactError("runtime_artifact_import_receipt_invalid")
    expected_metadata = {
        "receipt_id",
        "revision",
        "status",
        "evidence_status",
        "synthetic_only",
        "recorded_at",
    }
    expected_spec = {
        "runtime_node_ref",
        "deployment_instance_ref",
        "runtime_artifact_manifest_ref",
        "runtime_artifact_manifest_digest",
        "runtime_source_digest",
        "runtime_image_manifest_digest",
        "container_isolation_profile_digest",
        "artifact_set_manifest_digest",
        "signature_bundle_digest",
        "engine_observation",
        "verification",
        "capability_report_ref",
        "capability_report_digest",
        "failure_reasons",
        "audit_refs",
        "receipt_digest",
    }
    expected_boundary = {
        "execution_grant_issued",
        "runtime_started",
        "agent_activated",
        "deployment_activated",
        "production_authorized",
        "release_authorization",
    }
    if (
        set(metadata) != expected_metadata
        or set(spec) != expected_spec
        or set(boundary) != expected_boundary
    ):
        raise RuntimeArtifactError("runtime_artifact_import_receipt_invalid")
    verification = spec["verification"]
    engine = spec["engine_observation"]
    verification_fields = {
        "signature_valid",
        "artifact_set_valid",
        "manifest_digest_valid",
        "source_digest_valid",
        "image_digest_valid",
        "platform_compatible",
        "isolation_compatible",
        "artifact_not_revoked",
        "probe_passed",
    }
    engine_fields = {
        "engine",
        "rootless",
        "platform",
        "wsl_distribution",
        "systemd",
        "seccomp",
        "cgroup_resource_limits",
    }
    imported = metadata.get("status") == "imported"
    failure_reasons = spec["failure_reasons"]
    capability_ref = spec["capability_report_ref"]
    capability_digest = spec["capability_report_digest"]
    if (
        not _id_value(metadata.get("receipt_id"))
        or type(metadata.get("revision")) is not int
        or metadata["revision"] < 1
        or metadata.get("status") not in {"imported", "rejected"}
        or metadata.get("evidence_status")
        not in {"architecture_reference", "synthetic_d0"}
        or metadata.get("synthetic_only") is not True
        or _parse_time(metadata.get("recorded_at")) is None
        or not _versioned_ref(spec["runtime_node_ref"])
        or spec["runtime_node_ref"]["id"] != node_id
        or not _versioned_ref(spec["deployment_instance_ref"])
        or not _versioned_ref(spec["runtime_artifact_manifest_ref"])
        or spec["runtime_artifact_manifest_ref"]["digest"]
        != spec["runtime_artifact_manifest_digest"]
        or any(
            not _digest_value(spec[item])
            for item in (
                "runtime_artifact_manifest_digest",
                "runtime_source_digest",
                "runtime_image_manifest_digest",
                "container_isolation_profile_digest",
                "artifact_set_manifest_digest",
                "signature_bundle_digest",
                "receipt_digest",
            )
        )
        or not isinstance(engine, Mapping)
        or set(engine) != engine_fields
        or engine.get("engine") != "rootless-docker"
        or type(engine.get("rootless")) is not bool
        or engine.get("platform") not in {"linux/amd64", "linux/arm64"}
        or engine.get("wsl_distribution") != "Ubuntu-22.04"
        or any(
            type(engine.get(item)) is not bool
            for item in ("systemd", "seccomp", "cgroup_resource_limits")
        )
        or not isinstance(verification, Mapping)
        or set(verification) != verification_fields
        or any(type(item) is not bool for item in verification.values())
        or not isinstance(failure_reasons, list)
        or len(failure_reasons) != len(set(failure_reasons))
        or any(not isinstance(item, str) or not _REASON.fullmatch(item) for item in failure_reasons)
        or not isinstance(spec["audit_refs"], list)
        or not spec["audit_refs"]
        or len(spec["audit_refs"]) != len(set(spec["audit_refs"]))
        or any(
            not _logical_ref(item, schemes={"audit"})
            for item in spec["audit_refs"]
        )
        or any(item is not False for item in boundary.values())
        or spec["receipt_digest"] != _embedded_digest(value, "receipt_digest")
    ):
        raise RuntimeArtifactError("runtime_artifact_import_receipt_invalid")
    all_verified = all(verification.values())
    if imported:
        if (
            not all_verified
            or failure_reasons
            or not _versioned_ref(capability_ref)
            or capability_ref["digest"] != capability_digest
            or any(
                engine[item] is not True
                for item in (
                    "rootless",
                    "systemd",
                    "seccomp",
                    "cgroup_resource_limits",
                )
            )
        ):
            raise RuntimeArtifactError("runtime_artifact_import_receipt_invalid")
    elif (
        all_verified
        or not failure_reasons
        or capability_ref is not None
        or capability_digest is not None
    ):
        raise RuntimeArtifactError("runtime_artifact_import_receipt_invalid")
    _validate_safe_json(value)
    return {
        "artifact_id": spec["runtime_artifact_manifest_ref"]["id"],
        "revision_digest": spec["runtime_artifact_manifest_digest"],
        "runtime_source_digest": spec["runtime_source_digest"],
        "runtime_image_digest": spec["runtime_image_manifest_digest"],
        "isolation_profile_digest": spec["container_isolation_profile_digest"],
        "artifact_set_manifest_digest": spec["artifact_set_manifest_digest"],
        "signature_bundle_digest": spec["signature_bundle_digest"],
        "target_platform": engine["platform"],
        "capability_report_digest": capability_digest,
        "outcome": metadata["status"],
        "receipt_digest": spec["receipt_digest"],
    }


def _validate_runtime_evidence_transition(
    *,
    evidence_type: str,
    document: Mapping[str, Any],
    latest_event: RuntimeContainerEvidenceRow | None,
    lease: RuntimeNodeLeaseClaimRow,
    run: RuntimeRunRow | None,
    now: datetime,
) -> None:
    if run is None:
        raise RuntimeArtifactError("runtime_run_not_found")
    previous = None if latest_event is None else latest_event.document["event_type"]
    active = lease.status == "active" and _as_utc(lease.expires_at) > now
    if evidence_type == "container_event":
        event = document["event_type"]
        if event == "resumed":
            raise RuntimeArtifactError("runtime_container_resume_requires_new_grant")
        if not active:
            raise RuntimeArtifactError("runtime_node_lease_not_active")
        allowed = {
            None: {"created"},
            "created": {"started"},
            "started": {"needs_input", "completed", "failed", "cancelled"},
        }
        if event not in allowed.get(previous, set()):
            raise RuntimeArtifactError("runtime_container_event_order_invalid")
        return
    if evidence_type == "checkpoint_receipt":
        if previous == "needs_input":
            retain_until = _parse_time(latest_event.document["retain_until"])
            if now > retain_until:
                raise RuntimeArtifactError("runtime_checkpoint_retention_expired")
            return
        if not active or previous != "started":
            raise RuntimeArtifactError("runtime_checkpoint_order_invalid")
        return
    if evidence_type == "result_package":
        if (
            previous != "completed"
            or run.status != "completed"
            or lease.status != "closed"
            or document["task_id"] != run.task_id
            or document["execution_grant_ref"]["id"] != run.grant_id
            or document["execution_grant_ref"]["digest"] != run.grant_digest
            or document.get("runtime_run_ref") != f"runtime-run://{run.run_id}"
        ):
            raise RuntimeArtifactError("runtime_result_binding_invalid")
        return
    if (
        previous is None
        and active
        and run.status == "leased"
        and document["outcome"] == "cancelled"
    ):
        return
    if previous not in {"needs_input", "completed", "failed", "cancelled"}:
        raise RuntimeArtifactError("runtime_cleanup_order_invalid")


def _runtime_evidence_receipt(
    row: RuntimeContainerEvidenceRow,
) -> tuple[str, dict[str, Any]]:
    receipt_id = deterministic_id(
        "receipt_runtime_evidence",
        row.run_id,
        row.evidence_type,
        row.evidence_digest,
    )
    closes_runtime_access = (
        row.evidence_type == "cleanup_receipt"
        or row.evidence_type == "container_event"
        and row.document["event_type"]
        in {"needs_input", "completed", "failed", "cancelled"}
    )
    document = {
        "kind": "RuntimeEvidenceReceipt",
        "receipt_id": receipt_id,
        "run_id": row.run_id,
        "node_id": row.node_id,
        "sequence": row.sequence,
        "evidence_type": row.evidence_type,
        "evidence_digest": row.evidence_digest,
        "relay_closed": closes_runtime_access,
        "model_token_revoked": closes_runtime_access,
        "recorded_at": _time(row.recorded_at),
        "runtime_projection_authoritative": False,
        "production_authorization": False,
        "release_authorization": False,
    }
    return receipt_id, document


def _validate_runtime_evidence(evidence_type: str, value: Mapping[str, Any], now: datetime) -> None:
    if evidence_type != "result_package" and (
        value.get("production_authorization") is not False
        or value.get("release_authorization") is not False
    ):
        raise RuntimeArtifactError("runtime_container_evidence_invalid")
    if evidence_type == "container_event":
        if set(value) != {"event_type", "container_ref", "recorded_at", "retain_until", "production_authorization", "release_authorization"} or value["event_type"] not in {"created", "started", "needs_input", "resumed", "completed", "failed", "cancelled"} or not _logical_ref(value["container_ref"], schemes={"task"}):
            raise RuntimeArtifactError("runtime_container_event_invalid")
        retain = value["retain_until"]
        if value["event_type"] == "needs_input":
            parsed = _parse_time(retain)
            if parsed <= now or parsed > now + timedelta(minutes=10): raise RuntimeArtifactError("runtime_container_retention_invalid")
        elif retain is not None:
            raise RuntimeArtifactError("runtime_container_retention_invalid")
    elif evidence_type == "checkpoint_receipt":
        if set(value) != {"checkpoint_refs", "source_image_digest", "created_at", "production_authorization", "release_authorization"} or not _digest_value(value["source_image_digest"]) or not isinstance(value["checkpoint_refs"], list) or not value["checkpoint_refs"] or any(not _logical_ref(item, schemes={"artifact", "task"}) for item in value["checkpoint_refs"]):
            raise RuntimeArtifactError("runtime_checkpoint_receipt_invalid")
    elif evidence_type == "cleanup_receipt":
        if set(value) != {"outcome", "container_removed", "network_removed", "workspace_removed", "removed_at", "production_authorization", "release_authorization"} or value["outcome"] not in {"completed", "failed", "cancelled"} or any(value[item] is not True for item in ("container_removed", "network_removed", "workspace_removed")):
            raise RuntimeArtifactError("runtime_cleanup_receipt_invalid")
    else:
        required = {
            "schema_version", "result_id", "task_id", "agent_id", "agent_version",
            "agent_definition_ref", "agent_binding_ref", "execution_grant_ref",
            "invocation_ref", "hierarchy_snapshot_ref", "runtime_run_ref", "status",
            "summary", "artifacts", "evidence", "limitations", "risk_flags",
            "tool_usage", "data_usage_receipt_refs", "used_dependency_refs",
            "business_outcome", "evaluation", "human_disposition", "audit_event_refs",
            "produced_at",
        }
        optional = {"model_usage_refs"}
        grant = value.get("execution_grant_ref")
        if (
            not required.issubset(value)
            or not set(value).issubset(required | optional)
            or value.get("schema_version") != "0.3"
            or not isinstance(value.get("result_id"), str)
            or not value["result_id"].startswith("res_")
            or not isinstance(value.get("task_id"), str)
            or not value["task_id"].startswith(("tsk_", "task_"))
            or value.get("status") not in {"succeeded", "partial", "failed", "cancelled", "rejected"}
            or not isinstance(grant, Mapping)
            or set(grant) != {"id", "version", "digest"}
            or not isinstance(grant.get("id"), str)
            or not grant["id"].startswith("grant_")
            or not _digest_value(grant.get("digest"))
            or not isinstance(value.get("artifacts"), list)
            or not isinstance(value.get("evidence"), list)
            or not isinstance(value.get("audit_event_refs"), list)
            or not value["audit_event_refs"]
        ):
            raise RuntimeArtifactError("runtime_result_package_invalid")
    _validate_safe_json(value)


def _validate_safe_json(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in {"secret", "api_key", "password", "endpoint", "physical_path", "docker_socket"}:
                raise RuntimeArtifactError("runtime_artifact_secret_or_path_forbidden")
            _validate_safe_json(item)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value: _validate_safe_json(item)
    elif isinstance(value, str):
        if _SECRET.search(value) or _PHYSICAL.match(value): raise RuntimeArtifactError("runtime_artifact_secret_or_path_forbidden")
    elif value is None or type(value) in {int, bool}:
        return
    else:
        raise RuntimeArtifactError("runtime_artifact_json_invalid")


def _normalize(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        result = json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError) as error:
        raise RuntimeArtifactError("runtime_artifact_json_invalid") from error
    if not isinstance(result, dict): raise RuntimeArtifactError("runtime_artifact_json_invalid")
    return result


def _digest(value: Mapping[str, Any]) -> str:
    source = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return "sha256:" + hashlib.sha256(source).hexdigest()


def _embedded_digest(value: Mapping[str, Any], field: str) -> str:
    normalized = _normalize(value)
    spec = normalized.get("spec")
    if not isinstance(spec, dict) or field not in spec:
        raise RuntimeArtifactError("runtime_artifact_manifest_invalid")
    del spec[field]
    return _digest(normalized)


def _digest_mapping(value: Any, expected: set[str]) -> bool:
    return isinstance(value, Mapping) and set(value) == expected and all(_digest_value(item) for item in value.values())


def _versioned_ref(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == {"id", "version", "digest"}
        and _id_value(value["id"])
        and isinstance(value["version"], str)
        and _VERSION.fullmatch(value["version"]) is not None
        and _digest_value(value["digest"])
    )


def _digest_value(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _id_value(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _string_list(value: Any, *, minimum: int) -> bool:
    return isinstance(value, list) and len(value) >= minimum and len(value) == len(set(value)) and all(isinstance(item, str) and 1 <= len(item) <= 240 for item in value)


def _logical_ref(value: Any, *, schemes: set[str]) -> bool:
    if not isinstance(value, str) or len(value) > 512 or _PHYSICAL.match(value): return False
    parsed = urlsplit(value)
    return parsed.scheme in schemes and bool(parsed.netloc) and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and ".." not in parsed.path.split("/")


def _validate_reason(reason: Any) -> None:
    cleaned = " ".join(reason.split()) if isinstance(reason, str) else ""
    if not 8 <= len(cleaned) <= 500 or "\x00" in cleaned: raise RuntimeArtifactError("runtime_artifact_reason_invalid")


def _validate_actor(actor_ref: Any) -> None:
    if not isinstance(actor_ref, str) or not actor_ref.startswith("human_") or not _id_value(actor_ref): raise RuntimeArtifactError("runtime_artifact_actor_invalid")


def _validate_idempotency(value: Any) -> None:
    if not isinstance(value, str) or not _IDEMPOTENCY.fullmatch(value): raise RuntimeArtifactError("runtime_artifact_idempotency_invalid")


def _validate_node_actor(node_id: Any, workload_identity: Any) -> None:
    if not isinstance(node_id, str) or not node_id.startswith("node_") or not _id_value(node_id) or not isinstance(workload_identity, str) or not workload_identity.startswith("workload_") or not _id_value(workload_identity): raise RuntimeArtifactError("runtime_node_identity_invalid")


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"): raise RuntimeArtifactError("runtime_artifact_time_invalid")
    try: parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error: raise RuntimeArtifactError("runtime_artifact_time_invalid") from error
    return parsed.astimezone(timezone.utc)


def _time(value: datetime) -> str:
    return _as_utc(value).isoformat().replace("+00:00", "Z")


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

