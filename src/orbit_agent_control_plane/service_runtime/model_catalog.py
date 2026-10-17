"""Company model catalog and department Agent proposal workflow.

The catalog is selectable input for a proposal, not a ModelRoute approval or
task permission.  A ModelRoute revision is generated only when the owning
department submits an immutable Agent proposal package.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from ..ids import deterministic_id
from ..qualification.automation import canonical_digest
from .control_console_models import ModelRouteDecisionRow
from .database import Database
from .model_catalog_compatibility import proposal_profile
from .model_catalog_exchange import exchange_context, export_proposal
from .model_catalog_models import (
    DepartmentAgentProposalDecisionRow,
    DepartmentAgentProposalRow,
    ModelCatalogCredentialBindingRow,
    ModelCatalogEntryRow,
    ModelCatalogLifecycleReceiptRow,
    ProviderModelDiscoveryRow,
    ProviderOnboardingProposalRow,
    ProviderOnboardingReviewRow,
)
from .model_catalog_transactions import CatalogTransactionScope, catalog_write
from .model_key_validation import KeyTestError, ModelKeyTestStore
from .model_route import ModelRouteError, ModelRouteReconciler
from .model_route import _route_document as stored_route_document
from .models import AuditEventRow, ModelRouteRevisionRow

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{8,192}$")
_SAFE_TEXT = re.compile(r"^[^\x00-\x1f\x7f]{2,500}$")
_DEPARTMENTS = {"product_center", "technology_center", "market_center"}
_CAPABILITIES = {
    "text",
    "structured_output",
    "reasoning",
    "streaming",
    "tool_calling",
    "vision",
}
_DATA_CLASSES = {"synthetic", "public"}
_PROVIDER_PROTOCOLS = {
    "openai_chat_completions",
    "openai_responses",
    "anthropic_messages",
}
_REGION_ID = re.compile(r"^[a-z][a-z0-9_]{2,95}$")


class ModelCatalogError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _time(value: datetime) -> str:
    normalized = (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )
    return normalized.isoformat().replace("+00:00", "Z")


def _utc(value: datetime) -> datetime:
    return (
        value.replace(tzinfo=timezone.utc)
        if value.tzinfo is None
        else value.astimezone(timezone.utc)
    )


def _preset_document(value: Mapping[str, Any]) -> dict[str, Any]:
    public = {
        "provider_preset_id": value["provider_preset_id"],
        "display_name": value["display_name"],
        "regions": [
            {
                "region_id": item["region_id"],
                "display_name": item["display_name"],
                "connection_aliases": item["connection_aliases"],
            }
            for item in value["regions"]
        ],
        "protocols": list(value["protocols"]),
        "authentication_modes": list(value["authentication_modes"]),
        "discovery_mode": value["discovery_mode"],
        "authority_claim": "none",
    }
    public["revision_digest"] = canonical_digest(
        {"format": "orbit.provider-preset-internal/1", "preset": dict(value)}
    )
    return public


_PRESETS: tuple[dict[str, Any], ...] = (
    {
        "provider_preset_id": "provider_preset_minimax_cn",
        "provider_key": "minimax",
        "display_name": "MiniMax 中国",
        "protocols": ["openai_chat_completions"],
        "authentication_modes": ["api_key_ref"],
        "discovery_mode": "fixed_allowlist",
        "regions": [
            {
                "region_id": "cn_mainland",
                "display_name": "中国大陆",
                "connection_aliases": ["MiniMax 中国连接"],
                "endpoint": "https://api.minimax.chat/v1/text/chatcompletion_v2",
            }
        ],
        "models": [
            {
                "model_key": "minimax_text_d0",
                "provider_model_id": "MiniMax-Text-01",
                "display_name": "MiniMax 文本模型",
                "version_label": "受控清单候选",
                "capabilities": ["text", "structured_output", "reasoning", "streaming"],
                "data_classifications": ["synthetic", "public"],
            }
        ],
    },
    {
        "provider_preset_id": "provider_preset_openai_codex",
        "provider_key": "openai",
        "display_name": "OpenAI Codex",
        "protocols": ["openai_responses"],
        "authentication_modes": ["oauth_ref", "api_key_ref"],
        "discovery_mode": "fixed_allowlist",
        "regions": [
            {
                "region_id": "global_service",
                "display_name": "公司批准服务区域",
                "connection_aliases": ["Codex 公司连接"],
                "endpoint": "https://api.openai.com/v1/responses",
            }
        ],
        "models": [
            {
                "model_key": "codex_cli_read_only_d0",
                "provider_model_id": "codex-cli",
                "display_name": "Codex CLI 只读模型路线",
                "version_label": "0.153.0 适配候选",
                "capabilities": [
                    "text",
                    "structured_output",
                    "reasoning",
                    "tool_calling",
                ],
                "data_classifications": ["synthetic", "public"],
            }
        ],
    },
    {
        "provider_preset_id": "provider_preset_fixture",
        "provider_key": "fixture",
        "display_name": "WeMeta",
        "protocols": ["openai_chat_completions"],
        "authentication_modes": ["api_key_ref"],
        "discovery_mode": "fixed_allowlist",
        "regions": [
            {
                "region_id": "company_controlled",
                "display_name": "公司受控区域",
                "connection_aliases": ["WeMeta 公司连接"],
                "endpoint": "https://models.paper-orbit.invalid/v1/chat/completions",
            }
        ],
        "models": [
            {
                "model_key": "fixture_gpt56sol_d0",
                "provider_model_id": "fixture-structured-v1",
                "display_name": "GPT-5.6 Sol（WeMeta）",
                "version_label": "既有合成观察候选",
                "capabilities": [
                    "text",
                    "structured_output",
                    "reasoning",
                    "tool_calling",
                    "streaming",
                ],
                "data_classifications": ["synthetic", "public"],
            }
        ],
    },
)


# Source provenance is a frozen D0 implementation candidate, not a vendor claim.
# Capacity limits below are explicit synthetic fixtures for proposal validation.
_PRESETS = tuple(
    {
        **preset,
        "source_lock": {
            "source_commit": "4fdcfbdf1b13d7e861ebf89d45aa6b10e5c1b1ba",
            "source_sha256": "sha256:98e158113d49b7038956811bd6e4763cfb790122584b17e5f9629e3b6dd643bf",
            "derived_facts_are_synthetic": True,
        },
        "models": [
            {
                **model,
                "model_limits": {"max_input_tokens": 20000, "max_output_tokens": 4000},
                "evidence_status": "synthetic_d0",
            }
            for model in preset["models"]
        ],
    }
    for preset in _PRESETS
)


class ModelCatalogService(CatalogTransactionScope):
    def __init__(
        self,
        *,
        database: Database,
        model_routes: ModelRouteReconciler,
        key_tests: ModelKeyTestStore | None = None,
        require_live_key_test: bool = False,
        now: Any | None = None,
    ) -> None:
        self._init_transaction_scope()
        if model_routes.store.database is not database:
            raise ModelCatalogError("model_catalog_database_mismatch")
        self.database = database
        self.model_routes = model_routes
        self.key_tests = key_tests
        self.require_live_key_test = require_live_key_test
        self.now = now or _now

    def list_provider_presets(self) -> dict[str, Any]:
        return {
            "items": [_preset_document(item) for item in _PRESETS],
            "raw_endpoints_visible": False,
            "release_authorization": False,
        }

    @catalog_write
    def discover_provider_models(
        self,
        *,
        provider_preset_id: str,
        provider_preset_revision_digest: str,
        region_id: str,
        connection_alias: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        request = {
            "provider_preset_id": provider_preset_id,
            "provider_preset_revision_digest": provider_preset_revision_digest,
            "region_id": region_id,
            "connection_alias": connection_alias,
        }
        request_digest = canonical_digest(request)
        replay = self._discovery_by_key(idempotency_key)
        if replay is not None:
            if (
                replay.actor_ref != actor_ref
                or replay.document["request_digest"] != request_digest
            ):
                raise ModelCatalogError("provider_model_discovery_idempotency_conflict")
            return {**replay.document["response"], "idempotent_replay": True}
        self._validate_idempotency(idempotency_key)
        preset = self._preset(provider_preset_id)
        if (
            _preset_document(preset)["revision_digest"]
            != provider_preset_revision_digest
        ):
            raise ModelCatalogError("provider_preset_revision_drift")
        region = self._region(preset, region_id)
        if connection_alias not in region["connection_aliases"]:
            raise ModelCatalogError("provider_connection_alias_not_allowed")
        models = [
            {
                "provider_model_key": item["model_key"],
                "display_name": item["display_name"],
                "version_label": item["version_label"],
                "capabilities": list(item["capabilities"]),
                "model_limits": dict(item["model_limits"]),
                "data_classifications": list(item["data_classifications"]),
                "selectable_for_catalog_candidate": True,
            }
            for item in preset["models"]
        ]
        observed_at = self.now().astimezone(timezone.utc)
        public = {
            "provider_preset_id": provider_preset_id,
            "provider_preset_revision_digest": provider_preset_revision_digest,
            "region_id": region_id,
            "region_display_name": region["display_name"],
            "connection_alias": connection_alias,
            "models": models,
            "observed_at": _time(observed_at),
            "expires_at": _time(observed_at + timedelta(hours=24)),
            "automatically_published": False,
            "raw_endpoints_visible": False,
            "release_authorization": False,
        }
        discovery_digest = canonical_digest(public)
        discovery_id = deterministic_id("provider_discovery", discovery_digest)
        response = {
            **public,
            "discovery_id": discovery_id,
            "discovery_digest": discovery_digest,
        }
        internal = {
            "request_digest": request_digest,
            "response": response,
            "provider_key": preset["provider_key"],
            "endpoint": region["endpoint"],
            "models": preset["models"],
            "protocols": preset["protocols"],
            "authentication_modes": preset["authentication_modes"],
        }
        with self._session() as session:
            session.add(
                ProviderModelDiscoveryRow(
                    discovery_id=discovery_id,
                    discovery_digest=discovery_digest,
                    idempotency_key=idempotency_key,
                    provider_preset_id=provider_preset_id,
                    provider_preset_revision_digest=provider_preset_revision_digest,
                    region_id=region_id,
                    connection_alias=connection_alias,
                    document=internal,
                    actor_ref=actor_ref,
                    recorded_at=observed_at,
                )
            )
            session.add(
                self._audit(
                    "provider_model_discovery_recorded",
                    discovery_id,
                    actor_ref,
                    {
                        "provider_preset_id": provider_preset_id,
                        "discovery_digest": discovery_digest,
                        "automatically_published": False,
                    },
                )
            )
        return response

    @catalog_write
    def submit_provider_onboarding(
        self,
        *,
        display_name: str,
        requested_regions: list[str],
        required_protocols: list[str],
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        request = {
            "display_name": display_name,
            "requested_regions": requested_regions,
            "required_protocols": required_protocols,
            "reason": reason,
        }
        digest = canonical_digest(request)
        with self._session() as session:
            existing = session.scalar(
                select(ProviderOnboardingProposalRow).where(
                    ProviderOnboardingProposalRow.idempotency_key == idempotency_key
                )
            )
        if existing is not None:
            if existing.actor_ref != actor_ref or existing.request_digest != digest:
                raise ModelCatalogError("provider_onboarding_idempotency_conflict")
            return {
                "proposal_id": existing.proposal_id,
                "proposal_digest": existing.request_digest,
                "status": "candidate",
                "provider_preset_created": False,
                "idempotent_replay": True,
                "release_authorization": False,
            }
        self._validate_idempotency(idempotency_key)
        if (
            not _SAFE_TEXT.fullmatch(display_name)
            or len(display_name) > 160
            or not _SAFE_TEXT.fullmatch(reason)
            or len(reason.strip()) < 8
            or not 1 <= len(requested_regions) <= 8
            or any(not _REGION_ID.fullmatch(item) for item in requested_regions)
            or len(set(requested_regions)) != len(requested_regions)
            or not 1 <= len(required_protocols) <= 8
            or not set(required_protocols).issubset(_PROVIDER_PROTOCOLS)
            or len(set(required_protocols)) != len(required_protocols)
        ):
            raise ModelCatalogError("provider_onboarding_proposal_invalid")
        proposal_id = deterministic_id("provider_onboarding", digest)
        response = {
            "proposal_id": proposal_id,
            "proposal_digest": digest,
            "status": "candidate",
            "provider_preset_created": False,
            "release_authorization": False,
        }
        with self._session() as session:
            session.add(
                ProviderOnboardingProposalRow(
                    proposal_id=proposal_id,
                    idempotency_key=idempotency_key,
                    request_digest=digest,
                    document={
                        "schema_version": "orbit.provider-onboarding-proposal/0.1-draft",
                        **request,
                        "raw_endpoint_included": False,
                    },
                    actor_ref=actor_ref,
                    recorded_at=self.now(),
                )
            )
        return response

    def list_provider_onboarding(self) -> dict[str, Any]:
        with self._session() as session:
            proposals = tuple(
                session.scalars(
                    select(ProviderOnboardingProposalRow).order_by(
                        ProviderOnboardingProposalRow.id.desc()
                    )
                )
            )
            reviews = tuple(
                session.scalars(
                    select(ProviderOnboardingReviewRow).order_by(
                        ProviderOnboardingReviewRow.id
                    )
                )
            )
        items = []
        for proposal in proposals:
            history = [
                row.document
                for row in reviews
                if row.proposal_id == proposal.proposal_id
            ]
            latest = history[-1] if history else None
            items.append(
                {
                    "proposal_id": proposal.proposal_id,
                    "proposal_digest": proposal.request_digest,
                    **proposal.document,
                    "status": latest["status"] if latest else "candidate",
                    "latest_review": latest,
                    "review_history": history,
                    "provider_preset_created": False,
                }
            )
        return {"items": items, "release_authorization": False}

    @catalog_write
    def review_provider_onboarding(
        self,
        *,
        proposal_id: str,
        expected_proposal_digest: str,
        expected_review_digest: str | None,
        status: str,
        reason: str,
        provider_preset_id: str | None,
        provider_preset_revision_digest: str | None,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        if (
            status not in {"revision_required", "rejected", "linked_to_preset"}
            or not _SAFE_TEXT.fullmatch(reason)
            or len(reason.strip()) < 8
        ):
            raise ModelCatalogError("provider_onboarding_review_invalid")
        with self._session() as session:
            proposal = session.scalar(
                select(ProviderOnboardingProposalRow).where(
                    ProviderOnboardingProposalRow.proposal_id == proposal_id
                )
            )
            latest = session.scalar(
                select(ProviderOnboardingReviewRow)
                .where(ProviderOnboardingReviewRow.proposal_id == proposal_id)
                .order_by(ProviderOnboardingReviewRow.revision.desc())
            )
        if proposal is None or proposal.request_digest != expected_proposal_digest:
            raise ModelCatalogError("provider_onboarding_proposal_drift")
        if (None if latest is None else latest.review_digest) != expected_review_digest:
            raise ModelCatalogError("provider_onboarding_review_drift")
        if latest is not None and latest.document["status"] in {
            "rejected",
            "linked_to_preset",
        }:
            raise ModelCatalogError("provider_onboarding_already_closed")
        if status == "linked_to_preset":
            preset = self._preset(provider_preset_id)
            if (
                _preset_document(preset)["revision_digest"]
                != provider_preset_revision_digest
                or not set(proposal.document["requested_regions"])
                <= {r["region_id"] for r in preset["regions"]}
                or not set(proposal.document["required_protocols"])
                <= set(preset["protocols"])
            ):
                raise ModelCatalogError("provider_onboarding_preset_mismatch")
        elif (
            provider_preset_id is not None
            or provider_preset_revision_digest is not None
        ):
            raise ModelCatalogError("provider_onboarding_preset_not_allowed")
        revision = 1 if latest is None else latest.revision + 1
        document = {
            "proposal_id": proposal_id,
            "proposal_digest": expected_proposal_digest,
            "revision": revision,
            "previous_review_digest": expected_review_digest,
            "status": status,
            "reason": reason,
            "provider_preset_id": provider_preset_id,
            "provider_preset_revision_digest": provider_preset_revision_digest,
            "actor_ref": actor_ref,
            "recorded_at": _time(self.now()),
            "provider_preset_created": False,
            "live_provider_health_checked": False,
            "release_authorization": False,
        }
        digest = canonical_digest(document)
        document["review_digest"] = digest
        with self._session() as session:
            session.add(
                ProviderOnboardingReviewRow(
                    proposal_id=proposal_id,
                    revision=revision,
                    review_digest=digest,
                    document=document,
                )
            )
            session.add(
                self._audit(
                    "provider_onboarding_reviewed",
                    proposal_id,
                    actor_ref,
                    {"review_digest": digest, "status": status},
                )
            )
        return document

    def list_catalog_entries(self) -> dict[str, Any]:
        with self._session() as session:
            rows = tuple(
                session.scalars(
                    select(ModelCatalogEntryRow).order_by(ModelCatalogEntryRow.id)
                )
            )
        latest: dict[str, ModelCatalogEntryRow] = {}
        for row in rows:
            latest[row.entry_id] = row
        return {
            "items": [self._entry_public(row) for row in latest.values()],
            "catalog_entry_is_not_model_route": True,
            "release_authorization": False,
        }

    @catalog_write
    def create_catalog_entry(
        self,
        *,
        discovery_digest: str,
        provider_model_key: str,
        idempotency_key: str,
        actor_ref: str,
        expected_entry_revision_digest: str | None = None,
    ) -> dict[str, Any]:
        discovery = self._discovery(discovery_digest)
        model = next(
            (
                item
                for item in discovery.document["models"]
                if item["model_key"] == provider_model_key
            ),
            None,
        )
        if model is None:
            raise ModelCatalogError("provider_model_discovery_model_not_found")
        entry_id = deterministic_id(
            "model_catalog_entry",
            discovery.provider_preset_id,
            discovery.region_id,
            provider_model_key,
        )
        with self._session() as session:
            latest = session.scalar(
                select(ModelCatalogEntryRow)
                .where(ModelCatalogEntryRow.entry_id == entry_id)
                .order_by(ModelCatalogEntryRow.revision.desc())
            )
        if latest is not None:
            if latest.lifecycle_state == "retired":
                raise ModelCatalogError("model_catalog_entry_retired")
            if expected_entry_revision_digest != latest.entry_revision_digest:
                raise ModelCatalogError("model_catalog_entry_revision_required")
            if latest.discovery_digest == discovery_digest:
                raise ModelCatalogError("model_catalog_new_discovery_required")
        elif expected_entry_revision_digest is not None:
            raise ModelCatalogError("model_catalog_entry_revision_drift")
        revision = 1 if latest is None else latest.revision + 1
        request_digest = canonical_digest(
            {
                "discovery_digest": discovery_digest,
                "provider_model_key": provider_model_key,
                "expected_entry_revision_digest": expected_entry_revision_digest,
            }
        )
        public_subject = {
            "schema_version": "orbit.model-catalog-entry/0.1-draft",
            "entry_id": entry_id,
            "revision": revision,
            "provider_preset_id": discovery.provider_preset_id,
            "provider_preset_revision_digest": discovery.provider_preset_revision_digest,
            "discovery_digest": discovery_digest,
            "region_id": discovery.region_id,
            "connection_alias": discovery.connection_alias,
            "provider_model_key": provider_model_key,
            "model_display_name": model["display_name"],
            "model_version_label": model["version_label"],
            "capabilities": list(model["capabilities"]),
            "model_limits": dict(model["model_limits"]),
            "data_classifications": list(model["data_classifications"]),
            "protocols": discovery.document["protocols"],
            "authentication_modes": discovery.document["authentication_modes"],
            "lifecycle_state": "candidate",
            "credential_health": "not_bound",
            "qualification_status": "not_observed",
            "authority_claim": "none",
            "supersedes_entry_revision_digest": expected_entry_revision_digest,
        }
        entry_digest = canonical_digest(public_subject)
        internal = {
            **public_subject,
            "entry_revision_digest": entry_digest,
            "request_digest": request_digest,
            "provider_key": discovery.document["provider_key"],
            "provider_model_id": model["provider_model_id"],
            "endpoint": discovery.document["endpoint"],
        }
        row = ModelCatalogEntryRow(
            entry_id=entry_id,
            revision=revision,
            entry_revision_digest=entry_digest,
            provider_preset_id=discovery.provider_preset_id,
            discovery_digest=discovery_digest,
            lifecycle_state="candidate",
            document=internal,
            created_by_ref=actor_ref,
            created_at=self.now(),
        )
        with self._session() as session:
            session.add(row)
            session.add(
                self._audit(
                    "model_catalog_candidate_created",
                    entry_id,
                    actor_ref,
                    {
                        "entry_revision_digest": entry_digest,
                        "previous_revision_digest": expected_entry_revision_digest,
                        "model_route_created": False,
                    },
                )
            )
        return self._entry_public(row)

    @catalog_write
    def qualify_catalog_api_key(
        self,
        *,
        entry_id: str,
        expected_entry_revision_digest: str,
        expected_binding_version: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        logical_ref = f"secret://company/model-catalog/{entry_id}/current"
        health = self.model_routes.secret_provider.health(logical_ref)
        fingerprint = str(health.get("secret_fingerprint", ""))
        if (
            not health.get("healthy")
            or health.get("binding_version") != expected_binding_version
            or not _DIGEST.fullmatch(fingerprint)
        ):
            raise ModelCatalogError("model_catalog_secret_binding_version_mismatch")
        entry = self._expect_entry(entry_id, expected_entry_revision_digest)
        test_receipt = self._key_test(entry, logical_ref, expected_binding_version, fingerprint)
        evidence = [fingerprint]
        expires = self.now() + timedelta(hours=24)
        if test_receipt is not None:
            evidence.append(test_receipt["receipt_digest"])
            expires = min(expires, datetime.fromisoformat(test_receipt["expires_at"]))
        return self.bind_catalog_credential(
            entry_id=entry_id,
            expected_entry_revision_digest=expected_entry_revision_digest,
            authentication_mode="api_key_ref",
            credential_binding_ref=logical_ref,
            qualification_evidence_refs=evidence,
            evidence_expires_at=expires,
            binding_version=expected_binding_version,
            idempotency_key=idempotency_key,
            actor_ref=actor_ref,
        )

    @catalog_write
    def bind_catalog_credential(
        self,
        *,
        entry_id: str,
        expected_entry_revision_digest: str,
        authentication_mode: str,
        credential_binding_ref: str,
        qualification_evidence_refs: list[str],
        evidence_expires_at: datetime,
        idempotency_key: str,
        actor_ref: str,
        binding_version: str | None = None,
    ) -> dict[str, Any]:
        self._validate_idempotency(idempotency_key)
        request = {
            "entry_id": entry_id,
            "expected_entry_revision_digest": expected_entry_revision_digest,
            "authentication_mode": authentication_mode,
            "credential_binding_ref": credential_binding_ref,
            "qualification_evidence_refs": qualification_evidence_refs,
            "evidence_expires_at": _time(evidence_expires_at),
        }
        request_digest = canonical_digest(request)
        with self._session() as session:
            existing = session.scalar(
                select(ModelCatalogCredentialBindingRow).where(
                    ModelCatalogCredentialBindingRow.idempotency_key == idempotency_key
                )
            )
        if existing is not None:
            if (
                getattr(
                    existing, "actor_ref", getattr(existing, "submitted_by_ref", None)
                )
                != actor_ref
                or existing.request_digest != request_digest
            ):
                raise ModelCatalogError("model_catalog_credential_idempotency_conflict")
            return self._credential_public(existing, replay=True)
        entry = self._expect_entry(entry_id, expected_entry_revision_digest)
        if entry.lifecycle_state == "retired":
            raise ModelCatalogError("model_catalog_entry_retired")
        if authentication_mode not in {"api_key_ref", "oauth_ref"}:
            raise ModelCatalogError("model_catalog_authentication_mode_invalid")
        if authentication_mode not in entry.document.get("authentication_modes", []):
            raise ModelCatalogError("model_catalog_authentication_mode_not_supported")
        prefix = "secret://" if authentication_mode == "api_key_ref" else "oauth://"
        if (
            not credential_binding_ref.startswith(prefix)
            or len(credential_binding_ref) > 240
            or not qualification_evidence_refs
            or any(not _DIGEST.fullmatch(item) for item in qualification_evidence_refs)
            or evidence_expires_at <= self.now()
        ):
            raise ModelCatalogError("model_catalog_credential_binding_invalid")
        if self.require_live_key_test and authentication_mode == "api_key_ref":
            if not binding_version:
                raise ModelCatalogError("model_catalog_api_key_test_required")
            health = self.model_routes.secret_provider.health(credential_binding_ref)
            test_receipt = self._key_test(entry, credential_binding_ref, binding_version, str(health.get("secret_fingerprint", "")))
            if test_receipt["receipt_digest"] not in qualification_evidence_refs:
                raise ModelCatalogError("model_catalog_api_key_test_required")
        binding_id = deterministic_id(
            "catalog_credential_binding",
            entry_id,
            expected_entry_revision_digest,
            authentication_mode,
            credential_binding_ref,
            idempotency_key,
        )
        row = ModelCatalogCredentialBindingRow(
            binding_version=binding_version,
            binding_id=binding_id,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            entry_id=entry_id,
            entry_revision_digest=expected_entry_revision_digest,
            authentication_mode=authentication_mode,
            credential_binding_ref=credential_binding_ref,
            qualification_evidence_refs=list(qualification_evidence_refs),
            status="healthy",
            expires_at=evidence_expires_at,
            actor_ref=actor_ref,
            recorded_at=self.now(),
        )
        with self._session() as session:
            session.add(row)
        return self._credential_public(row)

    @catalog_write
    def publish_catalog_entry(
        self,
        *,
        entry_id: str,
        expected_entry_revision_digest: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        return self._transition(
            entry_id=entry_id,
            expected_entry_revision_digest=expected_entry_revision_digest,
            expected_state="candidate",
            target_state="available_for_proposal",
            transition="publish_for_department_proposal",
            reason=reason,
            idempotency_key=idempotency_key,
            actor_ref=actor_ref,
            require_healthy_credential=True,
        )

    @catalog_write
    def retire_catalog_entry(
        self,
        *,
        entry_id: str,
        expected_entry_revision_digest: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        replay = self._lifecycle_replay(
            entry_id,
            expected_entry_revision_digest,
            "retire_catalog_entry",
            reason,
            idempotency_key,
            actor_ref,
        )
        if replay is not None:
            return replay
        entry = self._expect_entry(entry_id, expected_entry_revision_digest)
        if entry.lifecycle_state not in {"candidate", "available_for_proposal"}:
            raise ModelCatalogError("model_catalog_entry_already_retired")
        return self._transition(
            entry_id=entry_id,
            expected_entry_revision_digest=expected_entry_revision_digest,
            expected_state=entry.lifecycle_state,
            target_state="retired",
            transition="retire_catalog_entry",
            reason=reason,
            idempotency_key=idempotency_key,
            actor_ref=actor_ref,
            require_healthy_credential=False,
        )

    def proposal_catalog(
        self,
        *,
        department_id: str,
        model_requirements: Mapping[str, Any] | None = None,
        agent_kind: str = "professional",
        runtime_kind: str | None = None,
    ) -> dict[str, Any]:
        self._validate_department(department_id)
        requirements = self._requirements(
            model_requirements
            or {
                "capabilities": ["text", "structured_output"],
                "data_classifications": ["synthetic", "public"],
            }
        )
        runtime_kind = runtime_kind or (
            "langgraph"
            if agent_kind == "department_planning"
            else "codex"
            if department_id == "technology_center"
            else "hermes"
        )
        try:
            profile = proposal_profile(department_id, agent_kind, runtime_kind)
        except ValueError as error:
            raise ModelCatalogError(str(error)) from error
        minimum = set(profile["adapter"]["minimum_capabilities"])
        requirements["capabilities"] = sorted(
            minimum | set(requirements["capabilities"])
        )
        allowed = set(requirements["capabilities"]) <= set(
            profile["adapter"]["allowed_capabilities"]
        )
        entries = self.list_catalog_entries()["items"]
        items = []
        for item in entries:
            missing = sorted(
                set(requirements["capabilities"]) - set(item["capabilities"])
            )
            data_ok = set(requirements["data_classifications"]) <= set(
                item["data_classifications"]
            )
            protocol_ok = bool(
                set(item.get("protocols", [])) & set(profile["adapter"]["protocols"])
            )
            limits = item.get("model_limits", {})
            budget_ok = all(
                isinstance(limits.get(key), int)
                and limits[key] >= profile["policy"][key]
                for key in ["max_input_tokens", "max_output_tokens"]
            )
            selectable = (
                item["can_be_used_for_new_proposals"]
                and not missing
                and data_ok
                and protocol_ok
                and allowed
                and budget_ok
            )
            reasons = []
            if item["lifecycle_state"] != "available_for_proposal":
                reasons.append("该模型当前未向部门开放新申报")
            if not budget_ok:
                reasons.append("缺少满足受控预算上限的模型容量证据")
            if not protocol_ok:
                reasons.append("运行适配器协议不兼容或缺少锁定证据")
            if not allowed:
                reasons.append("能力要求超出受控绑定允许集")
            if missing:
                reasons.append("缺少能力：" + "、".join(missing))
            if not data_ok:
                reasons.append("数据分类边界不兼容")
            if item["credential_health"] != "healthy":
                reasons.append("公司凭据或健康证据当前不可用")
            if item["provider_health_status"] == "expired":
                reasons.append("公司目录观察已过期，需重新核验")
            if selectable:
                reasons.append("满足当前 Agent 的能力、数据与公司目录边界")
            items.append(
                {
                    **item,
                    "compatible": selectable,
                    "selectable": selectable,
                    "reason_summaries": reasons,
                    "recommendation_status": "comparable"
                    if selectable
                    else "insufficient_evidence",
                }
            )
        return {
            "department_id": department_id,
            "model_requirements": requirements,
            "compatibility_profile": profile,
            "items": items,
            "route_ids_visible": False,
            "provider_endpoints_visible": False,
            "release_authorization": False,
        }

    @catalog_write
    def submit_agent_proposal(
        self,
        *,
        department_id: str,
        agent_name: str,
        identity: str,
        task_scope: str,
        typical_inputs: list[str],
        expected_outputs: list[str],
        prohibited_actions: list[str],
        model_requirements: Mapping[str, Any],
        selected_catalog_entry_id: str,
        selected_catalog_entry_revision_digest: str,
        agent_kind: str,
        runtime_kind: str,
        supersedes_package_digest: str | None,
        idempotency_key: str,
        actor_ref: str,
        proposer_account_ref: str | None = None,
        department_owner_ref: str | None = None,
    ) -> dict[str, Any]:
        self._validate_department(department_id)
        self._validate_idempotency(idempotency_key)
        requirements = self._requirements(model_requirements)
        text_lists = (typical_inputs, expected_outputs, prohibited_actions)
        if (
            agent_kind not in {"department_planning", "professional"}
            or runtime_kind not in {"langgraph", "hermes", "codex"}
            or agent_kind == "department_planning"
            and runtime_kind != "langgraph"
            or agent_kind == "professional"
            and runtime_kind
            != ("codex" if department_id == "technology_center" else "hermes")
            or any(
                not _SAFE_TEXT.fullmatch(value)
                for value in [agent_name, identity, task_scope]
            )
            or any(
                not values
                or len(values) > 12
                or any(
                    not isinstance(value, str) or not _SAFE_TEXT.fullmatch(value)
                    for value in values
                )
                for values in text_lists
            )
        ):
            raise ModelCatalogError("department_agent_proposal_invalid")
        request = {
            "department_id": department_id,
            "agent_name": agent_name,
            "identity": identity,
            "task_scope": task_scope,
            "typical_inputs": typical_inputs,
            "expected_outputs": expected_outputs,
            "prohibited_actions": prohibited_actions,
            "model_requirements": requirements,
            "selected_catalog_entry_id": selected_catalog_entry_id,
            "selected_catalog_entry_revision_digest": selected_catalog_entry_revision_digest,
            "agent_kind": agent_kind,
            "runtime_kind": runtime_kind,
            "supersedes_package_digest": supersedes_package_digest,
        }
        request_digest = canonical_digest(request)
        with self._session() as session:
            existing = session.scalar(
                select(DepartmentAgentProposalRow).where(
                    DepartmentAgentProposalRow.idempotency_key == idempotency_key
                )
            )
        if existing is not None:
            if (
                getattr(
                    existing, "actor_ref", getattr(existing, "submitted_by_ref", None)
                )
                != actor_ref
                or existing.request_digest != request_digest
            ):
                raise ModelCatalogError(
                    "department_agent_proposal_idempotency_conflict"
                )
            return self._proposal_public(existing, replay=True)
        entry = self._expect_entry(
            selected_catalog_entry_id, selected_catalog_entry_revision_digest
        )
        compatibility = self.proposal_catalog(
            department_id=department_id,
            model_requirements=requirements,
            agent_kind=agent_kind,
            runtime_kind=runtime_kind,
        )
        selected = next(
            (
                item
                for item in compatibility["items"]
                if item["entry_id"] == selected_catalog_entry_id
                and item["entry_revision_digest"]
                == selected_catalog_entry_revision_digest
            ),
            None,
        )
        if selected is None or not selected["selectable"]:
            raise ModelCatalogError("model_catalog_entry_not_selectable")
        requirements = compatibility["model_requirements"]
        predecessor = None
        revision = 1
        if supersedes_package_digest is not None:
            if not _DIGEST.fullmatch(supersedes_package_digest):
                raise ModelCatalogError("department_agent_proposal_supersedes_invalid")
            predecessor = self._proposal_by_digest(supersedes_package_digest)
            if predecessor is None or predecessor.department_id != department_id:
                raise ModelCatalogError(
                    "department_agent_proposal_supersedes_not_found"
                )
            with self._session() as session:
                latest = session.scalar(
                    select(DepartmentAgentProposalRow)
                    .where(
                        DepartmentAgentProposalRow.proposal_id
                        == predecessor.proposal_id
                    )
                    .order_by(DepartmentAgentProposalRow.revision.desc())
                )
                activation = session.scalar(
                    select(DepartmentAgentProposalDecisionRow).where(
                        DepartmentAgentProposalDecisionRow.package_digest
                        == predecessor.package_digest
                    )
                )
                rejection = session.scalar(
                    select(ModelRouteDecisionRow).where(
                        ModelRouteDecisionRow.route_id == predecessor.model_route_id,
                        ModelRouteDecisionRow.route_revision_digest
                        == predecessor.model_route_revision_digest,
                        ModelRouteDecisionRow.action == "rejected",
                    )
                )
            if latest.package_digest != predecessor.package_digest:
                raise ModelCatalogError("department_agent_proposal_predecessor_stale")
            if (
                not (
                    activation
                    and activation.action in {"revision_required", "rejected"}
                )
                and rejection is None
            ):
                raise ModelCatalogError(
                    "department_agent_proposal_revision_not_requested"
                )
            revision = predecessor.revision + 1
        proposal_id = (
            predecessor.proposal_id
            if predecessor is not None
            else deterministic_id(
                "department_agent_proposal", department_id, agent_name
            )
        )
        if predecessor is None:
            with self._session() as session:
                existing_subject = session.scalar(
                    select(DepartmentAgentProposalRow).where(
                        DepartmentAgentProposalRow.proposal_id == proposal_id
                    )
                )
            if existing_subject is not None:
                raise ModelCatalogError(
                    "department_agent_proposal_predecessor_required"
                )
        agent_id = deterministic_id("agent_candidate", department_id, proposal_id)
        definition = {
            "kind": "AgentDefinition",
            "agent_id": agent_id,
            "name": agent_name,
            "identity": identity,
            "task_scope": task_scope,
            "typical_inputs": typical_inputs,
            "expected_outputs": expected_outputs,
            "prohibited_actions": prohibited_actions,
            "model_requirements": requirements,
            "department_id": department_id,
            "candidate_only": True,
            "activation_status": "not_reviewed",
            "version": f"0.1.0-synthetic.{revision}",
            "agent_kind": agent_kind,
            "runtime_kind": runtime_kind,
        }
        definition_digest = canonical_digest(definition)
        credential = self._healthy_credential(entry)
        route = self._route_document(
            department_id=department_id,
            proposal_id=proposal_id,
            revision=revision,
            definition_digest=definition_digest,
            entry=entry,
            credential=credential,
            requirements=requirements,
            runtime_kind=runtime_kind,
        )
        route_digest, _ = self.model_routes.store.record_route(
            route, session=self._active_session.get()
        )
        binding = {
            "kind": "AgentBinding",
            "binding_id": deterministic_id(
                "agent_binding_candidate", agent_id, route_digest
            ),
            "agent_definition_ref": agent_id,
            "agent_definition_digest": definition_digest,
            "model_route_refs": [
                {"route_id": route["route_id"], "revision_digest": route_digest}
            ],
            "runtime_binding": route["runtime_binding"],
            "policy_binding": route["policy_binding"],
            "department_id": department_id,
            "candidate_only": True,
            "effective_grant": False,
        }
        binding_digest = canonical_digest(binding)
        now = self.now()
        context = exchange_context(
            proposer_account_ref=proposer_account_ref,
            department_owner_ref=department_owner_ref,
            definition=definition,
            binding=binding,
            route_digest=route_digest,
            entry_digest=entry.entry_revision_digest,
            profile=compatibility["compatibility_profile"],
        )
        package = {
            "exchange_context_digest": canonical_digest(context),
            "submitted_at": _time(now),
            "schema_version": "orbit.department-agent-proposal-package/0.1-draft",
            "proposal_id": proposal_id,
            "revision": revision,
            "department_id": department_id,
            "submitted_by_ref": actor_ref,
            "agent_definition": {"ref": agent_id, "digest": definition_digest},
            "agent_binding": {"ref": binding["binding_id"], "digest": binding_digest},
            "selected_model_catalog_entry": {
                "entry_id": entry.entry_id,
                "revision_digest": entry.entry_revision_digest,
            },
            "generated_model_route": {
                "route_id": route["route_id"],
                "revision_digest": route_digest,
            },
            "supersedes_package_digest": supersedes_package_digest,
            "authority_claim": "none",
            "model_route_approval_status": "not_reviewed",
            "agent_activation_status": "not_reviewed",
            "execution_grant_issued": False,
            "release_authorization": False,
        }
        package_digest = canonical_digest(package)
        document = {
            "package": package,
            "agent_definition": definition,
            "agent_binding": binding,
            "compatibility_profile": compatibility["compatibility_profile"],
            "exchange_context": context,
            "model_route_public": {
                "route_id": route["route_id"],
                "revision_digest": route_digest,
                "provider_display_name": selected["provider_display_name"],
                "model_display_name": selected["model_display_name"],
                "model_version_label": selected["model_version_label"],
                "data_classification": route["data_classification"],
                "authentication_mode": credential.authentication_mode,
                "raw_endpoint_included": False,
                "provider_model_id_included": False,
                "credential_ref_included": False,
            },
        }
        row = DepartmentAgentProposalRow(
            proposal_id=proposal_id,
            revision=revision,
            package_digest=package_digest,
            supersedes_package_digest=supersedes_package_digest,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            department_id=department_id,
            selected_catalog_entry_id=entry.entry_id,
            selected_catalog_entry_revision_digest=entry.entry_revision_digest,
            agent_definition_digest=definition_digest,
            agent_binding_digest=binding_digest,
            model_route_id=route["route_id"],
            model_route_revision_digest=route_digest,
            document=document,
            submitted_by_ref=actor_ref,
            submitted_at=now,
        )
        with self._session() as session:
            session.add(row)
            session.add(
                self._audit(
                    "department_agent_proposal_submitted",
                    proposal_id,
                    actor_ref,
                    {
                        "department_id": department_id,
                        "proposal_id": proposal_id,
                        "package_digest": package_digest,
                        "agent_definition_ref": agent_id,
                        "agent_definition_digest": definition_digest,
                        "agent_binding_ref": binding["binding_id"],
                        "agent_binding_digest": binding_digest,
                        "model_route_id": route["route_id"],
                        "model_route_revision_digest": route_digest,
                        "agent_activation_status": "not_reviewed",
                        "execution_grant_issued": False,
                    },
                )
            )
        return self._proposal_public(row)

    def list_agent_route_reviews(
        self, *, department_id: str | None = None
    ) -> dict[str, Any]:
        with self._session() as session:
            query = select(DepartmentAgentProposalRow)
            if department_id is not None:
                self._validate_department(department_id)
                query = query.where(
                    DepartmentAgentProposalRow.department_id == department_id
                )
            rows = tuple(
                session.scalars(query.order_by(DepartmentAgentProposalRow.id.desc()))
            )
            decisions = tuple(
                session.scalars(
                    select(ModelRouteDecisionRow).order_by(ModelRouteDecisionRow.id)
                )
            )
            activations = tuple(
                session.scalars(
                    select(DepartmentAgentProposalDecisionRow).order_by(
                        DepartmentAgentProposalDecisionRow.id
                    )
                )
            )
        latest = {}
        for row in rows:
            latest.setdefault(row.proposal_id, row.package_digest)
        return {
            "items": [
                self._proposal_public(
                    row,
                    decisions=decisions,
                    activations=activations,
                    is_latest=latest[row.proposal_id] == row.package_digest,
                )
                for row in rows
            ],
            "company_may_change_department_model_selection": False,
            "model_route_approval_and_agent_activation_are_independent": True,
            "release_authorization": False,
        }

    def export_agent_proposal(
        self, *, department_id: str, package_digest: str
    ) -> dict[str, Any]:
        self._validate_department(department_id)
        chain, seen = [], set()
        digest = package_digest
        with self._session() as session:
            while digest is not None:
                if digest in seen or len(seen) >= 100:
                    raise ModelCatalogError(
                        "proposal_exchange_predecessor_chain_invalid"
                    )
                seen.add(digest)
                row = session.scalar(
                    select(DepartmentAgentProposalRow).where(
                        DepartmentAgentProposalRow.package_digest == digest,
                        DepartmentAgentProposalRow.department_id == department_id,
                    )
                )
                if row is None:
                    raise ModelCatalogError("department_agent_proposal_not_found")
                route = session.scalar(
                    select(ModelRouteRevisionRow).where(
                        ModelRouteRevisionRow.revision_digest
                        == row.model_route_revision_digest
                    )
                )
                entry = session.scalar(
                    select(ModelCatalogEntryRow).where(
                        ModelCatalogEntryRow.entry_revision_digest
                        == row.selected_catalog_entry_revision_digest
                    )
                )
                if route is None or entry is None:
                    raise ModelCatalogError("proposal_exchange_reference_missing")
                chain.append((row, stored_route_document(route), entry))
                digest = row.supersedes_package_digest
        result = None
        try:
            for row, route, entry in reversed(chain):
                result = export_proposal(
                    row, route=route, entry=entry, predecessor_export=result
                )
        except (ValueError, KeyError) as error:
            raise ModelCatalogError(
                str(error)
                if isinstance(error, ValueError)
                else "proposal_exchange_mapping_incomplete"
            ) from error
        return {
            "document": result,
            "source_package_digest": package_digest,
            "contract_release": False,
            "release_authorization": False,
        }

    def route_display_projection(
        self, *, route_id: str, revision_digest: str
    ) -> dict[str, str] | None:
        """Return business labels for a proposal-generated route without exposing provider internals."""
        with self._session() as session:
            row = session.scalar(
                select(DepartmentAgentProposalRow).where(
                    DepartmentAgentProposalRow.model_route_id == route_id,
                    DepartmentAgentProposalRow.model_route_revision_digest
                    == revision_digest,
                )
            )
        if row is None:
            return None
        public = row.document["model_route_public"]
        return {
            "provider_display_name": public["provider_display_name"],
            "model_display_name": public["model_display_name"],
            "model_version_label": public["model_version_label"],
        }

    @catalog_write
    def decide_agent_activation(
        self,
        *,
        proposal_id: str,
        expected_package_digest: str,
        expected_agent_definition_digest: str,
        decision: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
    ) -> dict[str, Any]:
        self._validate_idempotency(idempotency_key)
        if decision not in {
            "approved",
            "rejected",
            "revision_required",
        } or not _SAFE_TEXT.fullmatch(reason):
            raise ModelCatalogError("agent_activation_decision_invalid")
        with self._session() as session:
            proposal = session.scalar(
                select(DepartmentAgentProposalRow).where(
                    DepartmentAgentProposalRow.proposal_id == proposal_id,
                    DepartmentAgentProposalRow.package_digest
                    == expected_package_digest,
                )
            )
            replay = session.scalar(
                select(DepartmentAgentProposalDecisionRow).where(
                    DepartmentAgentProposalDecisionRow.idempotency_key
                    == idempotency_key
                )
            )
        request = {
            "proposal_id": proposal_id,
            "expected_package_digest": expected_package_digest,
            "expected_agent_definition_digest": expected_agent_definition_digest,
            "decision_scope": "agent_activation",
            "decision": decision,
            "reason": reason,
        }
        request_digest = canonical_digest(request)
        if replay is not None:
            if replay.actor_ref != actor_ref or replay.request_digest != request_digest:
                raise ModelCatalogError(
                    "agent_activation_decision_idempotency_conflict"
                )
            return self._activation_public(replay, replayed=True)
        if proposal is None:
            raise ModelCatalogError("department_agent_proposal_not_found")
        with self._session() as session:
            latest = session.scalar(
                select(DepartmentAgentProposalRow)
                .where(DepartmentAgentProposalRow.proposal_id == proposal_id)
                .order_by(DepartmentAgentProposalRow.revision.desc())
            )
        if latest.package_digest != expected_package_digest:
            raise ModelCatalogError("department_agent_proposal_predecessor_stale")
        if proposal.agent_definition_digest != expected_agent_definition_digest:
            raise ModelCatalogError("agent_activation_subject_digest_drift")
        with self._session() as session:
            existing = session.scalar(
                select(DepartmentAgentProposalDecisionRow).where(
                    DepartmentAgentProposalDecisionRow.package_digest
                    == expected_package_digest
                )
            )
        if existing is not None:
            raise ModelCatalogError("agent_activation_already_decided")
        now = self.now()
        decision_id = deterministic_id(
            "approval", "agent_activation", expected_package_digest, idempotency_key
        )
        document = {
            "kind": "ApprovalDecision",
            "decision_scope": "agent_activation",
            "decision_id": decision_id,
            "proposal_id": proposal_id,
            "package_digest": expected_package_digest,
            "agent_definition_digest": expected_agent_definition_digest,
            "decision": decision,
            "reason": reason,
            "decided_by_human_ref": actor_ref,
            "recorded_at": _time(now),
            "model_route_approval_unchanged": True,
            "execution_grant_issued": False,
            "release_authorization": False,
        }
        decision_digest = canonical_digest(document)
        row = DepartmentAgentProposalDecisionRow(
            decision_id=decision_id,
            decision_digest=decision_digest,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            proposal_id=proposal_id,
            package_digest=expected_package_digest,
            agent_definition_digest=expected_agent_definition_digest,
            decision_scope="agent_activation",
            action=decision,
            reason=reason,
            document=document,
            actor_ref=actor_ref,
            recorded_at=now,
        )
        with self._session() as session:
            session.add(row)
            session.add(
                self._audit(
                    "agent_activation_decided",
                    proposal_id,
                    actor_ref,
                    {
                        "department_id": proposal.department_id,
                        "proposal_id": proposal.proposal_id,
                        "package_digest": expected_package_digest,
                        "agent_definition_ref": proposal.document["package"]["agent_definition"]["ref"],
                        "agent_definition_digest": proposal.agent_definition_digest,
                        "agent_binding_ref": proposal.document["package"]["agent_binding"]["ref"],
                        "agent_binding_digest": proposal.agent_binding_digest,
                        "model_route_id": proposal.model_route_id,
                        "model_route_revision_digest": proposal.model_route_revision_digest,
                        "decision": decision,
                        "decision_digest": decision_digest,
                        "model_route_approval_unchanged": True,
                        "execution_grant_issued": False,
                    },
                )
            )
        return self._activation_public(row)

    def _transition(
        self,
        *,
        entry_id: str,
        expected_entry_revision_digest: str,
        expected_state: str,
        target_state: str,
        transition: str,
        reason: str,
        idempotency_key: str,
        actor_ref: str,
        require_healthy_credential: bool,
    ) -> dict[str, Any]:
        self._validate_idempotency(idempotency_key)
        if not _SAFE_TEXT.fullmatch(reason):
            raise ModelCatalogError("model_catalog_lifecycle_reason_invalid")
        request = {
            "entry_id": entry_id,
            "expected_entry_revision_digest": expected_entry_revision_digest,
            "transition": transition,
            "reason": reason,
        }
        request_digest = canonical_digest(request)
        replay = self._lifecycle_replay(
            entry_id,
            expected_entry_revision_digest,
            transition,
            reason,
            idempotency_key,
            actor_ref,
        )
        if replay is not None:
            return replay
        entry = self._expect_entry(entry_id, expected_entry_revision_digest)
        if entry.lifecycle_state != expected_state:
            raise ModelCatalogError("model_catalog_lifecycle_state_drift")
        if require_healthy_credential:
            self._discovery(entry.discovery_digest)
            self._healthy_credential(entry)
        now = self.now()
        next_public = {
            key: value
            for key, value in entry.document.items()
            if key
            not in {
                "entry_revision_digest",
                "request_digest",
                "provider_key",
                "provider_model_id",
                "endpoint",
            }
        }
        next_public.update(
            {
                "revision": entry.revision + 1,
                "lifecycle_state": target_state,
                "credential_health": "healthy"
                if require_healthy_credential
                else entry.document.get("credential_health", "not_bound"),
                "qualification_status": "current"
                if require_healthy_credential
                else entry.document.get("qualification_status", "not_observed"),
            }
        )
        if require_healthy_credential:
            next_public["credential_binding_source_digest"] = (
                entry.entry_revision_digest
            )
        next_digest = canonical_digest(next_public)
        next_document = {
            **entry.document,
            **next_public,
            "entry_revision_digest": next_digest,
            "request_digest": request_digest,
        }
        receipt_id = deterministic_id(
            "model_catalog_receipt",
            entry_id,
            expected_entry_revision_digest,
            transition,
            idempotency_key,
        )
        receipt_document = {
            "schema_version": "orbit.model-catalog-lifecycle-receipt/0.1-draft",
            "receipt_id": receipt_id,
            "entry_id": entry_id,
            "previous_revision_digest": expected_entry_revision_digest,
            "entry_revision_digest": next_digest,
            "transition": transition,
            "from_state": expected_state,
            "to_state": target_state,
            "actor_ref": actor_ref,
            "reason": reason,
            "recorded_at": _time(now),
            "evidence_status": "synthetic_d0",
            "live_provider_health_checked": False,
            "approval_scope_created": False,
            "model_route_created": False,
            "execution_grant_issued": False,
            "production_authorization": False,
            "release_authorization": False,
        }
        receipt_digest = canonical_digest(receipt_document)
        row = ModelCatalogLifecycleReceiptRow(
            receipt_id=receipt_id,
            receipt_digest=receipt_digest,
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            entry_id=entry_id,
            entry_revision_digest=next_digest,
            transition=transition,
            from_state=expected_state,
            to_state=target_state,
            reason=reason,
            document=receipt_document,
            actor_ref=actor_ref,
            recorded_at=now,
        )
        with self._session() as session:
            session.add(
                ModelCatalogEntryRow(
                    entry_id=entry_id,
                    revision=entry.revision + 1,
                    entry_revision_digest=next_digest,
                    provider_preset_id=entry.provider_preset_id,
                    discovery_digest=entry.discovery_digest,
                    lifecycle_state=target_state,
                    document=next_document,
                    created_by_ref=actor_ref,
                    created_at=now,
                )
            )
            session.add(row)
            session.add(
                self._audit(
                    "model_catalog_lifecycle_changed",
                    entry_id,
                    actor_ref,
                    {
                        "entry_revision_digest": next_digest,
                        "transition": transition,
                        "receipt_digest": receipt_digest,
                        "execution_grant_issued": False,
                    },
                )
            )
        return self._lifecycle_public(row)

    def _lifecycle_replay(
        self,
        entry_id: str,
        digest: str,
        transition: str,
        reason: str,
        key: str,
        actor_ref: str,
    ) -> dict[str, Any] | None:
        self._validate_idempotency(key)
        with self._session() as session:
            replay = session.scalar(
                select(ModelCatalogLifecycleReceiptRow).where(
                    ModelCatalogLifecycleReceiptRow.idempotency_key == key
                )
            )
        if replay is None:
            return None
        request = {
            "entry_id": entry_id,
            "expected_entry_revision_digest": digest,
            "transition": transition,
            "reason": reason,
        }
        if replay.actor_ref != actor_ref or replay.request_digest != canonical_digest(
            request
        ):
            raise ModelCatalogError("model_catalog_lifecycle_idempotency_conflict")
        return self._lifecycle_public(replay, replayed=True)

    def _route_document(
        self,
        *,
        department_id: str,
        proposal_id: str,
        revision: int,
        definition_digest: str,
        entry: ModelCatalogEntryRow,
        credential: ModelCatalogCredentialBindingRow,
        requirements: Mapping[str, Any],
        runtime_kind: str,
    ) -> dict[str, Any]:
        internal = entry.document
        route_id = deterministic_id("model_route", department_id, proposal_id)
        profile = proposal_profile(
            department_id,
            "department_planning" if runtime_kind == "langgraph" else "professional",
            runtime_kind,
        )
        runtime_ref = f"runtime-binding://{department_id}/{runtime_kind}-proposal"
        runtime_binding = {
            "ref": runtime_ref,
            "digest": canonical_digest(
                {
                    "adapter_digest": profile["adapter_digest"],
                    "agent_definition_digest": definition_digest,
                }
            ),
        }
        policy_ref = f"policy://department-agent-proposal/{department_id}/d0"
        policy_binding = {"ref": policy_ref, "digest": profile["policy_digest"]}
        auth = {
            "mode": credential.authentication_mode,
            "credential_binding_ref": credential.credential_binding_ref,
        }
        usage_only = credential.authentication_mode == "oauth_ref"
        budget = {
            "max_input_tokens": 20000,
            "max_output_tokens": 4000,
            "max_turns": 6,
            "max_duration_seconds": 900,
            "max_concurrency": 1,
        }
        if not usage_only:
            budget.update(
                {"max_cost_usd": "0.14", "max_cost_cny": "1.00", "cny_per_usd": "7.14"}
            )
        data_classification = (
            "synthetic"
            if "synthetic" in requirements["data_classifications"]
            else "public"
        )
        return {
            "route_version": "orbit.model-route-revision/2",
            "route_id": route_id,
            "provider": internal["provider_key"],
            "endpoint": internal["endpoint"],
            "requested_model": internal["provider_model_id"],
            "parameters": {
                "temperature": 0,
                "timeout_seconds": 30,
                "max_retries": 1,
                "max_model_calls": 6,
                "max_concurrency": 1,
                "fallback": False,
                "permissions": ["model.invoke"],
            },
            "data_classification": data_classification,
            "budget_policy": budget,
            "resolution_mode": "pinned",
            "authentication": auth,
            "credential_scope": "company",
            "authorized_node_refs": ["node_technology_001"]
            if runtime_kind == "codex"
            else [],
            "qualification_evidence_refs": list(credential.qualification_evidence_refs),
            "budget_control_mode": "usage_limits"
            if usage_only
            else "currency_and_usage",
            "approved_scope": {
                "provider": internal["provider_key"],
                "endpoint": internal["endpoint"],
                "model_family": internal["provider_model_id"],
                "resolved_model_ids": [internal["provider_model_id"]],
                "data_classification": data_classification,
                "permissions": ["model.invoke"],
            },
            "runtime_binding": runtime_binding,
            "policy_binding": policy_binding,
            "status": "proposed",
        }

    def _entry_public(self, row: ModelCatalogEntryRow) -> dict[str, Any]:
        try:
            binding = self._healthy_credential(row)
        except ModelCatalogError:
            binding = None
        try:
            self._discovery(row.discovery_digest)
            discovery_current = True
        except ModelCatalogError:
            discovery_current = False
        preset = self._preset(row.provider_preset_id)
        value = {
            key: row.document[key]
            for key in (
                "schema_version",
                "entry_id",
                "revision",
                "provider_preset_id",
                "provider_preset_revision_digest",
                "discovery_digest",
                "region_id",
                "connection_alias",
                "provider_model_key",
                "model_display_name",
                "model_version_label",
                "capabilities",
                "data_classifications",
                "lifecycle_state",
                "authority_claim",
            )
        }
        value.update(
            {
                "model_limits": row.document.get("model_limits", {}),
                "protocols": row.document.get("protocols", []),
                "supersedes_entry_revision_digest": row.document.get(
                    "supersedes_entry_revision_digest"
                ),
                "entry_revision_digest": row.entry_revision_digest,
                "provider_display_name": preset["display_name"],
                "credential_health": "healthy" if binding is not None else "not_bound",
                "qualification_status": "current"
                if binding is not None and discovery_current
                else "not_observed",
                "provider_health_status": "synthetic_observed"
                if discovery_current
                else "expired",
                "evidence_status": "synthetic_d0",
                "live_provider_health_checked": binding is not None and self.require_live_key_test
                and binding.authentication_mode == "api_key_ref",
                "api_key_test_required": self.require_live_key_test,
                "api_key_test": self._key_test_status(row),
                "can_be_used_for_new_proposals": row.lifecycle_state
                == "available_for_proposal"
                and binding is not None
                and discovery_current,
                "raw_endpoint_visible": False,
                "provider_model_id_visible": False,
                "credential_ref_visible": False,
                "production_authorization": False,
            }
        )
        return value

    def _proposal_public(
        self,
        row: DepartmentAgentProposalRow,
        *,
        replay: bool = False,
        decisions: tuple[ModelRouteDecisionRow, ...] = (),
        activations: tuple[DepartmentAgentProposalDecisionRow, ...] = (),
        is_latest: bool = True,
    ) -> dict[str, Any]:
        actions = [
            item.action
            for item in decisions
            if item.route_id == row.model_route_id
            and item.route_revision_digest == row.model_route_revision_digest
        ]
        route_status = (
            "revoked"
            if "revoked" in actions
            else "approved"
            if "approved" in actions
            else "rejected"
            if "rejected" in actions
            else "not_reviewed"
        )
        activation = next(
            (
                item
                for item in reversed(activations)
                if item.package_digest == row.package_digest
            ),
            None,
        )
        activation_status = "not_reviewed" if activation is None else activation.action
        agent_reason = None if activation is None else activation.reason
        route_reason = next(
            (
                item.reason
                for item in reversed(decisions)
                if item.route_id == row.model_route_id
                and item.route_revision_digest == row.model_route_revision_digest
                and item.action == route_status
            ),
            None,
        )
        # Preserve the legacy summary without hiding the decision that actually
        # asks the department to revise its package.
        reason = (
            agent_reason if activation_status in {"revision_required", "rejected"}
            else route_reason if route_status in {"rejected", "revoked"}
            else agent_reason or route_reason
        )
        return {
            "is_latest": is_latest,
            "can_revise": is_latest
            and (
                activation_status in {"revision_required", "rejected"}
                or route_status == "rejected"
            ),
            "review_reason": reason,
            "agent_review_reason": agent_reason,
            "model_route_review_reason": route_reason,
            "selected_catalog_entry_id": row.selected_catalog_entry_id,
            "selected_catalog_entry_revision_digest": row.selected_catalog_entry_revision_digest,
            "proposal_id": row.proposal_id,
            "revision": row.revision,
            "package_digest": row.package_digest,
            "supersedes_package_digest": row.supersedes_package_digest,
            "department_id": row.department_id,
            "submitted_by_ref": row.submitted_by_ref,
            "submitted_at": _time(row.submitted_at),
            "agent_definition": row.document["agent_definition"],
            "agent_binding": row.document["agent_binding"],
            "model_route": row.document["model_route_public"],
            "model_route_approval_status": route_status,
            "agent_activation_status": activation_status,
            "agent_activation_decision_digest": None
            if activation is None
            else activation.decision_digest,
            "agent_and_route_eligible": route_status == "approved"
            and activation_status == "approved",
            "execution_grant_issued": False,
            "company_may_change_selected_model": False,
            "idempotent_replay": replay,
            "release_authorization": False,
        }

    @staticmethod
    def _activation_public(
        row: DepartmentAgentProposalDecisionRow, replayed: bool = False
    ) -> dict[str, Any]:
        return {
            "decision_id": row.decision_id,
            "decision_digest": row.decision_digest,
            "decision_scope": row.decision_scope,
            "proposal_id": row.proposal_id,
            "package_digest": row.package_digest,
            "agent_definition_digest": row.agent_definition_digest,
            "decision": row.action,
            "model_route_approval_unchanged": True,
            "execution_grant_issued": False,
            "idempotent_replay": replayed,
            "release_authorization": False,
        }

    def _credential_public(
        self, row: ModelCatalogCredentialBindingRow, replay: bool = False
    ) -> dict[str, Any]:
        return {
            "binding_id": row.binding_id,
            "entry_id": row.entry_id,
            "entry_revision_digest": row.entry_revision_digest,
            "authentication_mode": row.authentication_mode,
            "binding_version": row.binding_version,
            "status": row.status,
            "qualification_evidence_refs": list(row.qualification_evidence_refs),
            "expires_at": _time(row.expires_at),
            "credential_ref_visible": False,
            "idempotent_replay": replay,
            "release_authorization": False,
        }

    @staticmethod
    def _lifecycle_public(
        row: ModelCatalogLifecycleReceiptRow, replayed: bool = False
    ) -> dict[str, Any]:
        return {
            "receipt_id": row.receipt_id,
            "receipt_digest": row.receipt_digest,
            "entry_id": row.entry_id,
            "entry_revision_digest": row.entry_revision_digest,
            "transition": row.transition,
            "from_state": row.from_state,
            "to_state": row.to_state,
            "model_route_created": False,
            "execution_grant_issued": False,
            "idempotent_replay": replayed,
            "release_authorization": False,
        }

    def _preset(self, preset_id: str) -> dict[str, Any]:
        preset = next(
            (item for item in _PRESETS if item["provider_preset_id"] == preset_id), None
        )
        if preset is None:
            raise ModelCatalogError("model_provider_preset_not_found")
        return preset

    @staticmethod
    def _region(preset: Mapping[str, Any], region_id: str) -> dict[str, Any]:
        region = next(
            (item for item in preset["regions"] if item["region_id"] == region_id), None
        )
        if region is None:
            raise ModelCatalogError("model_provider_region_not_found")
        return region

    def _discovery(self, digest: str) -> ProviderModelDiscoveryRow:
        with self._session() as session:
            row = session.scalar(
                select(ProviderModelDiscoveryRow).where(
                    ProviderModelDiscoveryRow.discovery_digest == digest
                )
            )
        if row is None:
            raise ModelCatalogError("provider_model_discovery_not_found")
        if (
            row.provider_preset_revision_digest
            != _preset_document(self._preset(row.provider_preset_id))["revision_digest"]
        ):
            raise ModelCatalogError("provider_preset_revision_drift")
        if (
            datetime.fromisoformat(
                row.document["response"]["expires_at"].replace("Z", "+00:00")
            )
            <= self.now()
        ):
            raise ModelCatalogError("provider_model_discovery_expired")
        return row

    def _discovery_by_key(self, key: str) -> ProviderModelDiscoveryRow | None:
        with self._session() as session:
            return session.scalar(
                select(ProviderModelDiscoveryRow).where(
                    ProviderModelDiscoveryRow.idempotency_key == key
                )
            )

    def _entry(self, entry_id: str) -> ModelCatalogEntryRow:
        with self._session() as session:
            row = session.scalar(
                select(ModelCatalogEntryRow)
                .where(ModelCatalogEntryRow.entry_id == entry_id)
                .order_by(ModelCatalogEntryRow.id.desc())
            )
        if row is None:
            raise ModelCatalogError("model_catalog_entry_not_found")
        return row

    def _expect_entry(self, entry_id: str, digest: str) -> ModelCatalogEntryRow:
        row = self._entry(entry_id)
        if row.entry_revision_digest != digest:
            raise ModelCatalogError("model_catalog_entry_revision_drift")
        return row

    def _latest_credential(
        self, entry_id: str, digest: str
    ) -> ModelCatalogCredentialBindingRow | None:
        with self._session() as session:
            rows = tuple(
                session.scalars(
                    select(ModelCatalogCredentialBindingRow)
                    .where(
                        ModelCatalogCredentialBindingRow.entry_id == entry_id,
                        ModelCatalogCredentialBindingRow.entry_revision_digest
                        == digest,
                    )
                    .order_by(ModelCatalogCredentialBindingRow.id.desc())
                )
            )
        return next(
            (
                row
                for row in rows
                if row.status == "healthy" and _utc(row.expires_at) > _utc(self.now())
            ),
            None,
        )

    def _healthy_credential(
        self, entry: ModelCatalogEntryRow
    ) -> ModelCatalogCredentialBindingRow:
        row = self._latest_credential(entry.entry_id, entry.entry_revision_digest)
        source_digest = entry.document.get("credential_binding_source_digest")
        if row is None and source_digest is not None:
            row = self._latest_credential(entry.entry_id, source_digest)
        if row is None:
            raise ModelCatalogError("model_catalog_credential_not_healthy")
        if row.binding_version is not None:
            try:
                health = self.model_routes.secret_provider.health(row.credential_binding_ref)
            except ModelRouteError:
                raise ModelCatalogError("model_catalog_credential_version_drift") from None
            if (
                not health.get("healthy")
                or health.get("binding_version") != row.binding_version
                or health.get("secret_fingerprint")
                not in row.qualification_evidence_refs
            ):
                raise ModelCatalogError("model_catalog_credential_version_drift")
        if self.require_live_key_test and row.authentication_mode == "api_key_ref":
            self._key_test(
                entry, row.credential_binding_ref, row.binding_version,
                str(health.get("secret_fingerprint", "")) if row.binding_version else "",
                source_revision_digest=row.entry_revision_digest,
            )
        return row

    def _key_test(self, entry, logical_ref, version, fingerprint, *, source_revision_digest=None):
        if not self.require_live_key_test:
            return None
        if self.key_tests is None:
            raise ModelCatalogError("model_catalog_api_key_test_required")
        try:
            return self.key_tests.qualified_health(
                logical_ref=logical_ref, version=version, fingerprint=fingerprint,
                entry_revision_digest=source_revision_digest or entry.entry_revision_digest,
                endpoint=entry.document["endpoint"], model=entry.document["provider_model_id"],
            )
        except (KeyTestError, OSError, ValueError):
            raise ModelCatalogError("model_catalog_api_key_test_required") from None

    def _key_test_status(self, entry):
        if not self.require_live_key_test:
            return {"status": "synthetic_only"}
        if self.key_tests is None:
            return {"status": "required"}
        try:
            # Publication changes the catalog digest without changing the model
            # or credential. Follow only its authoritative binding source; new
            # configuration revisions do not carry this publication-only link.
            source = entry.document.get("credential_binding_source_digest")
            return self.key_tests.latest_status(source or entry.entry_revision_digest)
        except (KeyTestError, OSError, ValueError):
            return {"status": "required"}

    def _proposal_by_digest(self, digest: str) -> DepartmentAgentProposalRow | None:
        with self._session() as session:
            return session.scalar(
                select(DepartmentAgentProposalRow).where(
                    DepartmentAgentProposalRow.package_digest == digest
                )
            )

    @staticmethod
    def _requirements(value: Mapping[str, Any]) -> dict[str, list[str]]:
        if set(value) != {"capabilities", "data_classifications"}:
            raise ModelCatalogError("agent_model_requirements_invalid")
        capabilities = value.get("capabilities")
        data_classes = value.get("data_classifications")
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or not set(capabilities) <= _CAPABILITIES
            or len(capabilities) != len(set(capabilities))
            or not isinstance(data_classes, list)
            or not data_classes
            or not set(data_classes) <= _DATA_CLASSES
            or len(data_classes) != len(set(data_classes))
        ):
            raise ModelCatalogError("agent_model_requirements_invalid")
        return {
            "capabilities": sorted(capabilities),
            "data_classifications": sorted(data_classes),
        }

    @staticmethod
    def _validate_department(value: str) -> None:
        if value not in _DEPARTMENTS:
            raise ModelCatalogError("department_not_found")

    @staticmethod
    def _validate_idempotency(value: str) -> None:
        if not _IDEMPOTENCY.fullmatch(value):
            raise ModelCatalogError("model_catalog_idempotency_key_invalid")

    @staticmethod
    def _audit(
        event_type: str, correlation_id: str, actor_ref: str, payload: Mapping[str, Any]
    ) -> AuditEventRow:
        document = {
            "event_type": event_type,
            "correlation_id": correlation_id,
            "actor_ref": actor_ref,
            "payload": dict(payload),
        }
        return AuditEventRow(
            audit_id=deterministic_id("audit", canonical_digest(document)),
            correlation_id=correlation_id,
            event_type=event_type,
            actor_ref=actor_ref,
            payload=dict(payload),
            recorded_at=_now(),
        )

