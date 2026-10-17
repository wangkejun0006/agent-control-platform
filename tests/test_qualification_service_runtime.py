from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

from fastapi.testclient import TestClient

from orbit_agent_control_plane.qualification import (
    QualificationCandidate,
    QualificationController,
    build_policy_activation_receipt,
)
from orbit_agent_control_plane.service_runtime.api import (
    create_app,
    load_service_runtime,
)
from orbit_agent_control_plane.service_runtime.config import (
    ServiceConfigurationError,
    ServiceSettings,
)
from orbit_agent_control_plane.service_runtime.managed_components import (
    GOVERNED_RELEASE_PIPELINE_COMPONENT_ID,
)
from orbit_agent_control_plane.service_runtime.model_route import ModelRouteStore
from orbit_agent_control_plane.service_runtime.models import Base
from orbit_agent_control_plane.service_runtime.repositories import (
    ServiceRepositoryError,
    SqlOutboxPublisher,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_ROOT = ROOT / "evidence/disease-agent-r2/2026-08-27-automation-policy-alpha2"
POLICY_PATH = POLICY_ROOT / "automation-policy.disease-r2.synthetic.json"
REVIEW_PATH = POLICY_ROOT / "automation-policy-review-package.json"
PROFILE_PATH = ROOT / "references/qualification-service-profile.candidate.json"


def approval(policy: dict, policy_digest: str) -> dict:
    return {
        "api_version": "company-ai-os/v1alpha1",
        "kind": "ApprovalDecision",
        "metadata": {
            "decision_id": "decision_service_policy_activation_test_syn",
            "approval_id": "approval_service_policy_activation_test_syn",
            "task_id": "task_service_policy_activation_test_syn",
            "status": "immutable",
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "decided_at": "2026-08-28T01:00:00Z",
        },
        "spec": {
            "decision": "approve",
            "decided_by_human_ref": "human_service_test_owner",
            "decided_by_role_ref": "role_orbit_platform_owner",
            "scope_ref": f"policy://{policy['metadata']['policy_id']}/0.1.0",
            "scope_digest": policy_digest,
            "reason": "approve exact service synthetic qualification policy",
            "expires_at": policy["metadata"]["expires_at"],
            "separation_of_duties_check_ref": "audit://service-policy/sod",
            "audit_event_refs": ["audit_service_policy_activation_test_syn"],
        },
    }


class QualificationServiceRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = ServiceSettings(
            mode="local_synthetic",
            database_url="sqlite+pysqlite:///:memory:",
            policy_path=POLICY_PATH,
            review_package_path=REVIEW_PATH,
            profile_path=PROFILE_PATH,
            adapter_evidence_path=None,
            oidc_issuer=None,
            oidc_audience=None,
            oidc_required_key_id=None,
            oidc_allowed_roles=(),
            oidc_admin_subject_digests=(),
            oidc_public_key_ref=None,
            workload_ca_ref=None,
            workload_allowed_identities=(),
            grant_signing_key_ref=None,
            grant_signing_key_id=None,
            secret_bindings_path=None,
            workload_trust_domain=None,
            mutations_enabled=False,
            host="127.0.0.1",
            port=8431,
        )
        self.runtime = load_service_runtime(
            settings=self.settings,
            repository_root=ROOT,
        )
        Base.metadata.create_all(self.runtime.database.engine)

    def tearDown(self) -> None:
        self.runtime.database.dispose()

    def test_health_is_live_but_formal_readiness_fails_closed(self) -> None:
        with TestClient(create_app(self.runtime)) as client:
            live = client.get("/health/live")
            self.assertEqual(200, live.status_code)
            self.assertFalse(live.json()["release_authorization"])
            ready = client.get("/health/ready")
            self.assertEqual(503, ready.status_code)
            self.assertEqual("not_ready", ready.json()["detail"]["status"])
            security = client.get("/v1/security/status")
            self.assertEqual(200, security.status_code)
            self.assertEqual("disabled", security.json()["identity_mode"])
            self.assertIsNone(security.json()["grant_signer"])
            policy = client.get("/v1/policies/pol_orbit_disease_r2_qualification_syn")
            self.assertEqual(200, policy.status_code)
            self.assertIsNone(policy.json()["activation"])
            adapter = client.get(
                "/v1/runtime-adapters/runtime_adapter_framework_neutral_disease_r2_syn"
            )
            self.assertEqual(200, adapter.status_code)
            self.assertFalse(adapter.json()["effective"])
            self.assertEqual("not_configured", adapter.json()["transport"]["status"])
            component = client.get(
                f"/v1/managed-components/{GOVERNED_RELEASE_PIPELINE_COMPONENT_ID}"
            )
            self.assertEqual(200, component.status_code)
            self.assertEqual("registered", component.json()["status"])
            self.assertEqual("none", component.json()["authority_claim"])
            self.assertFalse(component.json()["creates_human_checkpoint"])
            missing_component = client.get("/v1/managed-components/component_missing")
            self.assertEqual(404, missing_component.status_code)
            supervision = client.get(
                "/v1/automation-supervision",
                params={"scope_ref": "pilot://full-chain/not-started"},
            )
            self.assertEqual(200, supervision.status_code)
            self.assertEqual("not_started", supervision.json()["status"])
            self.assertEqual("none", supervision.json()["authority_claim"])
            mutation = client.post(
                "/v1/policies/pol_orbit_disease_r2_qualification_syn/activations",
                json={
                    "policy_digest": self.runtime.policy_digest,
                    "review_package_raw_digest": "sha256:" + ("0" * 64),
                    "activated_at": "2026-08-28T01:00:01Z",
                    "approval_decision": {},
                },
            )
            self.assertEqual(503, mutation.status_code)

    def test_model_route_status_api_is_read_only_and_redacted(self) -> None:
        route = json.loads(
            (
                ROOT
                / "references/model-route-revisions/"
                "disease-r2-fixture-fixture-structured-v1.public.json"
            ).read_text(encoding="utf-8")
        )
        observation = json.loads(
            (
                ROOT
                / "evidence/model-route/2026-08-28/"
                "fixture-fixture-structured-v1-observation.public.json"
            ).read_text(encoding="utf-8")
        )
        store = ModelRouteStore(self.runtime.database)
        route_digest, _ = store.record_route(route)
        observation_digest, _ = store.record_observation(observation)
        with TestClient(create_app(self.runtime)) as client:
            response = client.get(f"/v1/model-routes/{route['route_id']}")
            missing = client.get("/v1/model-routes/model_route_missing")
        self.assertEqual(200, response.status_code)
        self.assertEqual(route_digest, response.json()["route_revision_digest"])
        self.assertEqual(observation_digest, response.json()["observation_digest"])
        self.assertFalse(response.json()["secret_healthy"])
        self.assertNotIn("secret_ref", response.json())
        self.assertEqual(404, missing.status_code)

    def test_pipeline_uses_resident_supervisor_and_model_route_reconciler(
        self,
    ) -> None:
        self.assertIs(
            self.runtime.automation_supervisor,
            self.runtime.governed_release_pipeline.automation_supervisor,
        )
        self.assertIs(
            self.runtime.model_route_reconciler,
            self.runtime.governed_release_pipeline.model_route_reconciler,
        )

    def test_activation_repository_outbox_revocation_and_lease_close(self) -> None:
        policy = self.runtime.policy
        decision = approval(policy, self.runtime.policy_digest)
        receipt = build_policy_activation_receipt(
            policy=policy,
            policy_digest=self.runtime.policy_digest,
            approval_decision=decision,
            activated_at="2026-08-28T01:00:01Z",
        )
        self.assertTrue(
            self.runtime.policy_activations.record(
                policy=policy,
                policy_digest=self.runtime.policy_digest,
                approval_decision=decision,
                receipt=receipt,
            )
        )
        self.assertFalse(
            self.runtime.policy_activations.record(
                policy=policy,
                policy_digest=self.runtime.policy_digest,
                approval_decision=decision,
                receipt=receipt,
            )
        )
        self.assertEqual(
            receipt.digest,
            self.runtime.policy_activations.get_by_policy_digest(
                self.runtime.policy_digest
            )["receipt_digest"],
        )
        published = []
        self.assertEqual(
            1,
            SqlOutboxPublisher(self.runtime.database, published.append).publish_pending(
                limit=10
            ),
        )
        self.assertEqual(receipt.digest, published[0]["payload"]["receipt_digest"])
        revision = self.runtime.grant_revocations.revoke(
            grant_id="grant_service_runtime_test_syn",
            reason_code="human_cancelled",
            revoked_by_ref="human_service_test_owner",
        )
        self.assertTrue(
            self.runtime.grant_revocations.is_revoked(
                grant_id="grant_service_runtime_test_syn",
                minimum_revision=revision,
            )
        )
        lease_id = self.runtime.worker_leases.claim(
            run_id="run_service_runtime_test_syn",
            worker_identity="workload_service_test_worker",
            ttl_seconds=30,
        )
        self.runtime.worker_leases.heartbeat(
            lease_id=lease_id,
            worker_identity="workload_service_test_worker",
        )
        self.runtime.worker_leases.close(
            lease_id=lease_id,
            worker_identity="workload_service_test_worker",
            outcome="completed",
        )
        self.assertEqual(
            "closed", self.runtime.worker_leases.status(lease_id)["status"]
        )
        with self.assertRaises(ServiceRepositoryError):
            self.runtime.worker_leases.heartbeat(
                lease_id=lease_id,
                worker_identity="workload_service_test_worker",
            )

    def test_sql_qualification_store_replays_exact_controller_registration(
        self,
    ) -> None:
        policy = self.runtime.policy
        policy_digest = self.runtime.policy_digest
        decision = approval(policy, policy_digest)
        activation = build_policy_activation_receipt(
            policy=policy,
            policy_digest=policy_digest,
            approval_decision=decision,
            activated_at="2026-08-28T01:00:01Z",
        )
        candidate = QualificationCandidate.from_mapping(
            json.loads(
                (
                    POLICY_ROOT / "qualification-candidate.attempt-004.synthetic.json"
                ).read_text(encoding="utf-8")
            )
        )
        review = json.loads(REVIEW_PATH.read_text(encoding="utf-8"))
        bindings = review["handler_bindings"]
        by_id = {item["id"]: item for item in bindings}
        default = by_id["component_qualification_policy_engine"]
        execution = by_id["component_disease_r2_execution_worker"]
        domain = by_id["component_disease_r2_stage_hooks"]
        company = by_id["component_qualification_service_gate"]
        stage_plan = tuple(policy["spec"]["stage_plan"])
        stage_handlers = {
            stage: (
                domain
                if stage == "domain_evaluation"
                else company
                if stage == "company_evaluation"
                else execution
                if stage in {"isolation_e4", "model_literature_r2"}
                else default
            )
            for stage in stage_plan
        }
        controller = QualificationController(self.runtime.qualification_store)
        appended = controller.register_run(
            run_id="run_service_qualification_test_syn",
            policy=policy,
            policy_digest=policy_digest,
            policy_activation=activation,
            policy_approval_decision=decision,
            candidate=candidate,
            stage_plan=stage_plan,
            stage_handlers=stage_handlers,
            registered_at="2026-08-28T01:00:02Z",
            idempotency_key="service:qualification:register:test",
        )
        replay = self.runtime.qualification_store.replay()
        self.assertTrue(appended.appended)
        self.assertEqual(1, replay.records_checked)
        self.assertEqual(
            "candidate_build",
            replay.run("run_service_qualification_test_syn").current_stage,
        )
        duplicate = controller.register_run(
            run_id="run_service_qualification_test_syn",
            policy=policy,
            policy_digest=policy_digest,
            policy_activation=activation,
            policy_approval_decision=decision,
            candidate=candidate,
            stage_plan=stage_plan,
            stage_handlers=stage_handlers,
            registered_at="2026-08-28T01:00:02Z",
            idempotency_key="service:qualification:register:test",
        )
        self.assertFalse(duplicate.appended)
        with TestClient(create_app(self.runtime)) as client:
            pilot = client.get("/v1/pilots/run_service_qualification_test_syn")
            self.assertEqual(200, pilot.status_code)
            self.assertEqual("candidate_build", pilot.json()["stage"])
            self.assertEqual(3, pilot.json()["attempts_ceiling"])
            self.assertEqual([], pilot.json()["runtime_runs"])
            self.assertFalse(pilot.json()["release_authorization"])
        allowed, reason = self.runtime.governed_release_pipeline.remediation_allowed(
            predecessor=candidate,
            successor=replace(
                candidate,
                attempt_id="attempt_disease_r2_public_successor",
                attempt_number=candidate.attempt_number + 1,
                runtime_source_digest="sha256:" + "1" * 64,
                composition_digest="sha256:" + "2" * 64,
            ),
            failure_class="engineering_compatibility",
            attempts_consumed=1,
            verified_source_change=True,
        )
        self.assertTrue(allowed)
        self.assertEqual("same_runtime_family_remediation_allowed", reason)
        unverified, unverified_reason = (
            self.runtime.governed_release_pipeline.remediation_allowed(
                predecessor=candidate,
                successor=replace(
                    candidate,
                    attempt_id="attempt_disease_r2_unverified_successor",
                    attempt_number=candidate.attempt_number + 1,
                    runtime_source_digest="sha256:" + "6" * 64,
                    composition_digest="sha256:" + "7" * 64,
                ),
                failure_class="engineering_compatibility",
                attempts_consumed=1,
            )
        )
        self.assertFalse(unverified)
        self.assertEqual("pilot_verified_source_change_missing", unverified_reason)
        denied, checkpoint = (
            self.runtime.governed_release_pipeline.remediation_allowed(
                predecessor=candidate,
                successor=replace(
                    candidate,
                    attempt_id="attempt_disease_r2_scope_drift",
                    attempt_number=candidate.attempt_number + 1,
                    runtime_source_digest="sha256:" + "3" * 64,
                    composition_digest="sha256:" + "4" * 64,
                    boundary_digests={
                        **candidate.boundary_digests,
                        "model_route": "sha256:" + "5" * 64,
                    },
                ),
                failure_class="engineering_compatibility",
                attempts_consumed=1,
            )
        )
        self.assertFalse(denied)
        self.assertEqual("pilot_scope_change_requires_human_checkpoint", checkpoint)

    def test_environment_requires_postgres_and_complete_mutation_identity(self) -> None:
        base = {
            "ORBIT_SERVICE_MODE": "local_synthetic",
            "ORBIT_SERVICE_DATABASE_URL": "sqlite:///:memory:",
            "ORBIT_SERVICE_POLICY_PATH": str(POLICY_PATH),
            "ORBIT_SERVICE_REVIEW_PACKAGE_PATH": str(REVIEW_PATH),
            "ORBIT_SERVICE_PROFILE_PATH": str(PROFILE_PATH),
        }
        with self.assertRaisesRegex(
            ServiceConfigurationError, "service_database_url_invalid"
        ):
            ServiceSettings.from_environment(base)
        base["ORBIT_SERVICE_DATABASE_URL"] = (
            "postgresql+psycopg://synthetic@127.0.0.1/orbit"
        )
        base["ORBIT_SERVICE_MUTATIONS_ENABLED"] = "true"
        with self.assertRaisesRegex(
            ServiceConfigurationError, "service_mutation_identity_incomplete"
        ):
            ServiceSettings.from_environment(base)
        base.update(
            {
                "ORBIT_SERVICE_OIDC_ISSUER": "https://identity.orbit.example",
                "ORBIT_SERVICE_OIDC_AUDIENCE": "orbit_control_plane",
                "ORBIT_SERVICE_OIDC_REQUIRED_KEY_ID": "oidc_admin_2026_08",
                "ORBIT_SERVICE_OIDC_ALLOWED_ROLES": "control_plane_admin",
                "ORBIT_SERVICE_OIDC_ADMIN_SUBJECT_DIGESTS": "sha256:"
                + ("a" * 64),
                "ORBIT_SERVICE_OIDC_PUBLIC_KEY_REF": "secret://control-plane/oidc-public-key",
                "ORBIT_SERVICE_WORKLOAD_CA_REF": "secret://control-plane/workload-ca",
                "ORBIT_SERVICE_WORKLOAD_ALLOWED_IDENTITIES": "qualification_reconciler,r2_evaluation_runner",
                "ORBIT_SERVICE_GRANT_SIGNING_KEY_REF": "secret://control-plane/grant-signing-key",
                "ORBIT_SERVICE_GRANT_SIGNING_KEY_ID": "grant_signer_2026_08",
                "ORBIT_SERVICE_SECRET_BINDINGS_PATH": "/run/secrets/bindings.json",
                "ORBIT_SERVICE_WORKLOAD_TRUST_DOMAIN": "orbit.control-plane.internal",
            }
        )
        settings = ServiceSettings.from_environment(base)
        self.assertEqual("orbit_control_plane", settings.oidc_audience)
        self.assertEqual(
            ("qualification_reconciler", "r2_evaluation_runner"),
            settings.workload_allowed_identities,
        )

    def test_local_mode_allows_only_exact_persistent_loopback_socket(self) -> None:
        base = {
            "ORBIT_SERVICE_MODE": "local_synthetic",
            "ORBIT_SERVICE_DATABASE_URL": (
                "postgresql+psycopg://synthetic@/orbit?"
                "host=/Users/Shared/OrbitControlPlane/sockets"
            ),
            "ORBIT_SERVICE_POLICY_PATH": str(POLICY_PATH),
            "ORBIT_SERVICE_REVIEW_PACKAGE_PATH": str(REVIEW_PATH),
            "ORBIT_SERVICE_PROFILE_PATH": str(PROFILE_PATH),
        }
        settings = ServiceSettings.from_environment(base)
        self.assertIn("/Users/Shared/OrbitControlPlane/sockets", settings.database_url)
        base["ORBIT_SERVICE_DATABASE_URL"] = (
            "postgresql+psycopg://synthetic@/orbit?"
            "host=/Users/Shared/OrbitControlPlane-other/sockets"
        )
        with self.assertRaisesRegex(
            ServiceConfigurationError, "service_database_url_invalid"
        ):
            ServiceSettings.from_environment(base)


if __name__ == "__main__":
    unittest.main()

