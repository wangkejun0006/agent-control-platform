from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import ValidationError
from sqlalchemy import select

from orbit_agent_control_plane.service_runtime.control_console_api import (
    ModelRouteCredentialBindingRequest,
)
from orbit_agent_control_plane.service_runtime.control_console_models import (
    ModelRouteCredentialBindingRow,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.model_route import (
    ModelRouteReconciler,
    ModelRouteStore,
    OwnerOnlyFileSecretProvider,
)
from orbit_agent_control_plane.service_runtime.model_route_credentials import (
    ModelRouteCredentialService,
)
from orbit_agent_control_plane.service_runtime.models import Base


class ModelRouteCredentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        os.chmod(root, 0o700)
        self.database = Database(f"sqlite+pysqlite:///{root / 'control.db'}")
        Base.metadata.create_all(self.database.engine)
        self.now = datetime(2026, 9, 3, 8, 0, tzinfo=timezone.utc)
        self.secret_provider = OwnerOnlyFileSecretProvider(root / "bindings.json")
        self.credentials = ModelRouteCredentialService(
            database=self.database,
            secret_provider=self.secret_provider,
            now=lambda: self.now,
        )
        self.store = ModelRouteStore(self.database)
        self.reconciler = ModelRouteReconciler(
            store=self.store,
            secret_provider=self.secret_provider,
            credential_health_provider=self.credentials,
            now=lambda: self.now,
        )

    def tearDown(self) -> None:
        self.database.dispose()
        self.temp.cleanup()

    def test_company_account_route_is_qualified_but_never_issues_a_grant(self) -> None:
        route = account_route()
        digest, _ = self.store.record_route(route)
        report = adapter_report(self.now)
        capability = self.credentials.record_adapter_capability_report(
            node_id="node_technology_001",
            document=report,
            authentication_modes=["oauth_ref"],
            expires_at=(self.now + timedelta(hours=2)).isoformat(),
            idempotency_key="adapter-report-account-001",
        )
        receipt = self.credentials.record_account_login_receipt(
            node_id="node_technology_001",
            document={
                "receipt_version": "orbit.codex-account-login-receipt/1",
                "route_id": route["route_id"],
                "route_revision_digest": digest,
                "credential_binding_ref": route["authentication"]["credential_binding_ref"],
                "node_id": "node_technology_001",
                "codex_cli_revision": "codex-cli/1.2.3",
                "login_status": "qualified",
                "verified_at": self.now.isoformat(),
                "expires_at": (self.now + timedelta(hours=1)).isoformat(),
                "runtime_started": False,
                "model_called": False,
                "production_authorization": False,
                "release_authorization": False,
            },
            idempotency_key="account-login-receipt-001",
            workload_identity="spiffe://orbit.local/workload/node_technology_001",
        )
        self.store.record_observation(observation(self.now, provider=route["provider"]))
        snapshot = self.reconciler.reconcile(route["route_id"])

        self.assertEqual("ready", snapshot["status"])
        self.assertEqual("qualified", receipt["status"])
        self.assertFalse(receipt["execution_grant_issued"])
        self.assertFalse(receipt["runtime_started"])
        self.assertFalse(receipt["model_called"])
        self.assertEqual([capability["capability_digest"]], self._binding().qualification_evidence_refs)

    def test_preprovisioned_api_key_is_qualified_without_browser_secret(self) -> None:
        route = api_route()
        digest, _ = self.store.record_route(route)
        secret = "synthetic-company-credential-never-store-in-database"
        binding_version = "credential-local-20260903"
        self.secret_provider.bind(
            route["authentication"]["credential_binding_ref"],
            secret.encode(),
            version=binding_version,
        )
        response = self.credentials.qualify_api_key_binding(
            route_id=route["route_id"],
            expected_revision_digest=digest,
            expected_binding_version=binding_version,
            reason="bind company API key for the synthetic route",
            idempotency_key="api-key-binding-001",
            actor_ref="human_control_plane_admin_syn",
        )
        self.assertFalse(response["secret_value_returned"])
        self.assertNotIn(secret, json.dumps(response))
        binding = self._binding()
        self.assertNotIn(secret, json.dumps({
            "fingerprint": binding.secret_fingerprint,
            "version": binding.secret_version,
            "status": binding.status,
        }))
        self.assertEqual(secret.encode(), self.secret_provider.read(
            route["authentication"]["credential_binding_ref"]
        ))

    def test_binding_version_mismatch_fails_closed(self) -> None:
        route = api_route()
        digest, _ = self.store.record_route(route)
        self.secret_provider.bind(
            route["authentication"]["credential_binding_ref"],
            b"synthetic-company-credential-never-store-in-database",
            version="credential-local-20260903",
        )
        with self.assertRaisesRegex(
            Exception, "model_route_secret_binding_version_mismatch"
        ):
            self.credentials.qualify_api_key_binding(
                route_id=route["route_id"],
                expected_revision_digest=digest,
                expected_binding_version="credential-stale-20260902",
                reason="reject a stale browser binding expectation",
                idempotency_key="api-key-binding-stale-001",
                actor_ref="human_control_plane_admin_syn",
            )

    def test_browser_binding_contract_rejects_secret_value(self) -> None:
        with self.assertRaises(ValidationError):
            ModelRouteCredentialBindingRequest.model_validate(
                {
                    "route_id": "model_route_technology_fixture_d0",
                    "expected_revision_digest": "sha256:" + "1" * 64,
                    "authentication_mode": "api_key_ref",
                    "expected_binding_version": "fixture-2026-09-03-v1",
                    "secret_value": "synthetic-secret-must-never-enter-browser-api",
                    "reason": "verify browser secret rejection",
                    "idempotency_key": "browser-secret-rejection-001",
                }
            )

    def test_adapter_capability_report_rejects_credential_material(self) -> None:
        report = adapter_report(self.now)
        report["spec"]["evidence_refs"] = [
            "Bearer synthetic-forbidden-credential-material"
        ]
        with self.assertRaisesRegex(
            ValueError, "runtime_adapter_capability_report_sensitive"
        ):
            self.credentials.record_adapter_capability_report(
                node_id="node_technology_001",
                document=report,
                authentication_modes=["oauth_ref"],
                expires_at=(self.now + timedelta(hours=2)).isoformat(),
                idempotency_key="adapter-report-sensitive-001",
            )

    def _binding(self) -> ModelRouteCredentialBindingRow:
        with self.database.session() as session:
            row = session.scalar(select(ModelRouteCredentialBindingRow))
        assert row is not None
        return row


def account_route() -> dict:
    return route("oauth_ref", "oauth://company/codex/technology", "usage_limits")


def api_route() -> dict:
    return route(
        "api_key_ref", "secret://company/model-routes/technology/current",
        "currency_and_usage",
    )


def route(mode: str, binding_ref: str, budget_mode: str) -> dict:
    budget = {
        "max_input_tokens": 20000,
        "max_output_tokens": 4000,
        "max_turns": 6,
        "max_duration_seconds": 900,
        "max_concurrency": 1,
    }
    if budget_mode == "currency_and_usage":
        budget.update({"max_cost_usd": "0.14", "max_cost_cny": "1.00", "cny_per_usd": "7.14"})
    provider = "openai_codex_account" if mode == "oauth_ref" else "openai"
    endpoint = "https://chatgpt.com/" if mode == "oauth_ref" else "https://api.openai.com/v1/responses"
    return {
        "route_version": "orbit.model-route-revision/2",
        "route_id": f"model_route_technology_{mode}",
        "provider": provider,
        "endpoint": endpoint,
        "requested_model": "gpt-5.6-luna",
        "parameters": {"permissions": ["model.invoke"], "max_concurrency": 1},
        "data_classification": "synthetic",
        "budget_policy": budget,
        "budget_control_mode": budget_mode,
        "resolution_mode": "pinned",
        "authentication": {"mode": mode, "credential_binding_ref": binding_ref},
        "credential_scope": "company",
        "authorized_node_refs": ["node_technology_001"] if mode == "oauth_ref" else [],
        "qualification_evidence_refs": [],
        "approved_scope": {
            "provider": provider,
            "endpoint": endpoint,
            "model_family": "gpt-5.6-luna",
            "resolved_model_ids": ["gpt-5.6-luna"],
            "data_classification": "synthetic",
            "permissions": ["model.invoke"],
        },
        "runtime_binding": {"ref": "runtime-binding://technology/codex-read-only-d0", "digest": f"sha256:{'1' * 64}"},
        "policy_binding": {"ref": "policy://stage1-lan/d0-synthetic-only", "digest": f"sha256:{'2' * 64}"},
        "status": "proposed",
    }


def observation(now: datetime, *, provider: str) -> dict:
    return {
        "observation_version": "orbit.provider-observation/1",
        "provider": provider,
        "requested_model": "gpt-5.6-luna",
        "resolved_model_id": "gpt-5.6-luna",
        "input_usd_per_million_tokens": "0",
        "output_usd_per_million_tokens": "0",
        "cached_input_usd_per_million_tokens": "0",
        "source": "codex-account-runtime-qualification",
        "source_kind": "deterministic_fixture",
        "regression_status": "pass",
        "observed_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=30)).isoformat(),
    }


def adapter_report(now: datetime) -> dict:
    versioned = lambda identity, digit: {"id": identity, "version": "0.1.0", "digest": f"sha256:{digit * 64}"}
    return {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "AdapterCapabilityReport",
        "metadata": {
            "report_id": "report_codex_account_adapter_syn",
            "version": "0.1.0",
            "status": "verified",
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "observed_at": now.isoformat(),
        },
        "spec": {
            "runtime_adapter_ref": versioned("adapter_codex_account", "3"),
            "runtime_revision_ref": versioned("runtime_codex_linux", "4"),
            "conformance_profile_ref": versioned("profile_codex_read_only", "5"),
            "capabilities": [{"capability": "authentication", "support": "supported", "evidence_kind": "synthetic_test", "evidence_ref": "evidence://codex/account-login"}],
            "unsupported_capabilities": ["production_execution"],
            "evidence_refs": ["evidence://codex/account-login"],
            "limitations": ["synthetic D0 only"],
        },
    }


if __name__ == "__main__":
    unittest.main()

