from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from candidate_support.disease_r2_execution_worker import digest as worker_digest
from orbit_agent_control_plane.qualification.automation import (
    QualificationCandidate,
    canonical_digest,
)
from orbit_agent_control_plane.service_runtime.database import Database
from orbit_agent_control_plane.service_runtime.local_pilot_main import (
    create_pilot_enablement_receipt,
)
from orbit_agent_control_plane.service_runtime.models import Base
from orbit_agent_control_plane.service_runtime.public_pilot_execution import (
    run_public_pilot,
)
from orbit_agent_control_plane.service_runtime.repositories import (
    SqlAuditExporter,
    SqlGrantRevocationRegistry,
    SqlWorkerLeaseCoordinator,
)
from orbit_agent_control_plane.service_runtime.runner_queue import (
    DurableRunnerWorker,
    SqlSignedGrantRegistry,
)
from orbit_agent_control_plane.service_runtime.security import (
    Ed25519EvaluationGrantVerifier,
)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/disease-agent-r2/2026-08-28-public-pilot-enablement"
TOOL_RELEASE = "sha256:775e2996c5302a28e24d2b8b7b104788e0a782688ba847ae63c8a8b729b48f0d"


class PublicPilotExecutionTests(unittest.TestCase):
    def test_owner_only_enablement_receipt_binds_review_and_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "pilot-enablement-receipt.public.json"
            receipt = create_pilot_enablement_receipt(
                receipt_path=receipt_path,
                review_package_path=(
                    EVIDENCE / "pilot-enablement-review-package.json"
                ),
                approval_prompt_path=EVIDENCE / "approval-prompt.zh-CN.md",
                approved_by_human_ref="human_local_os_owner_uid_501",
            )
            second = create_pilot_enablement_receipt(
                receipt_path=receipt_path,
                review_package_path=(
                    EVIDENCE / "pilot-enablement-review-package.json"
                ),
                approval_prompt_path=EVIDENCE / "approval-prompt.zh-CN.md",
                approved_by_human_ref="human_local_os_owner_uid_501",
            )
            self.assertEqual(0o600, receipt_path.stat().st_mode & 0o777)
        self.assertEqual(receipt["receipt_digest"], second["receipt_digest"])
        self.assertFalse(receipt["release_authorization"])

    def test_exact_policy_auto_repairs_mapping_and_closes_provider_run(self) -> None:
        policy = _read(EVIDENCE / "automation-policy.disease-r2.public.json")
        review = _read(EVIDENCE / "pilot-enablement-review-package.json")
        first = _read(EVIDENCE / "qualification-candidate.attempt-001.public.json")
        candidates = _successors(first, policy)
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "control-plane.sqlite3"
            database_url = f"sqlite+pysqlite:///{database_path}"
            database = Database(database_url)
            Base.metadata.create_all(database.engine)
            grants = SqlSignedGrantRegistry(
                database,
                verifier=Ed25519EvaluationGrantVerifier(
                    public_key_pem=public_pem,
                    key_id="local_pilot_grant_signer",
                ),
                revocations=SqlGrantRevocationRegistry(database),
            )
            worker = DurableRunnerWorker(
                database,
                grants=grants,
                leases=SqlWorkerLeaseCoordinator(database),
                audit=SqlAuditExporter(database),
                handlers={
                    "run_public_r2_fixture": _fixture_result,
                    "run_public_r2_provider_attempt": _provider_result,
                },
            )
            receipt = _enablement_receipt(review)
            output = run_public_pilot(
                database_url=database_url,
                policy=policy,
                review=review,
                enablement_receipt=receipt,
                candidates=candidates,
                private_key_pem=private_pem,
                public_key_pem=public_pem,
                runtime_adapter_digest=canonical_digest("runtime_adapter_source"),
                drive_runner_once=worker.run_once,
            )
            database.dispose()
        self.assertEqual("R2 provider-backed public-corpus pass", output["status"])
        self.assertEqual("completed", output["qualification_status"])
        self.assertEqual(1, output["provider_attempts"])
        self.assertEqual(1, len(output["remediation_history"]))
        self.assertEqual(2, len(output["runtime_runs"]))
        self.assertIsNone(output["next_human_checkpoint"])
        self.assertFalse(output["release_authorization"])
        self.assertEqual(
            "attempt_orbit_disease_r2_public_pilot_002",
            output["current_attempt"],
        )


def _successors(first: dict, policy: dict) -> tuple[QualificationCandidate, ...]:
    values = [QualificationCandidate.from_mapping(first)]
    allowed = sorted(
        item["digest"]
        for item in policy["spec"]["execution_envelope"][
            "input_artifact_allowlist"
        ]
    )
    for number in range(2, 5):
        value = copy.deepcopy(first)
        value.update(
            {
                "attempt_id": f"attempt_orbit_disease_r2_public_pilot_{number:03d}",
                "attempt_number": number,
                "runtime_source_digest": canonical_digest(
                    {"runtime_family": "disease_r2_v4", "attempt": number}
                ),
                "composition_ref": (
                    f"composition://orbit_disease_r2/public_pilot_attempt_{number:03d}"
                ),
                "composition_digest": canonical_digest(
                    {"composition": "public_r2", "attempt": number}
                ),
                "task_ref": (
                    f"task://orbit_disease_r2/public_pilot_attempt_{number:03d}"
                ),
                "task_digest": canonical_digest(
                    {"task": "public_r2", "attempt": number}
                ),
                "grant_candidate_ref": (
                    "grant://orbit_disease_r2/"
                    f"public_pilot_attempt_{number:03d}_candidate"
                ),
                "grant_candidate_digest": canonical_digest(
                    {"grant": "public_r2", "attempt": number}
                ),
                "tool_operations": [
                    f"{TOOL_RELEASE}#fetch_public_record",
                    f"{TOOL_RELEASE}#search_public_corpus",
                ],
                "input_artifact_digests": allowed,
            }
        )
        values.append(QualificationCandidate.from_mapping(value))
    return tuple(values)


def _enablement_receipt(review: dict) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "receipt_version": "orbit.local-public-pilot-enablement-receipt/1",
        "status": "active",
        "scope": "public_r2_pilot_enablement",
        "review_package_raw_digest": "sha256:" + "a" * 64,
        "review_package_digest": review["review_package_digest"],
        "automation_policy_digest": review["automation_policy_digest"],
        "approved_by_human_ref": "human_local_os_owner_uid_501",
        "approval_text_digest": "sha256:" + "b" * 64,
        "activated_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=15))
        .isoformat()
        .replace("+00:00", "Z"),
        "single_pilot": True,
        "max_provider_attempts": 3,
        "max_cost_usd": "0.60",
        "max_cost_cny": "4.50",
        "production_authorization": False,
        "release_authorization": False,
        "receipt_digest": "sha256:" + "c" * 64,
    }


def _fixture_result(_: dict) -> dict:
    return {
        "artifact_ref": "artifact://disease-r2/public-pilot/isolation-e4",
        "evidence_status": "public",
        "model_requests": 0,
        "network_calls": 0,
        "production_authorization": False,
        "release_authorization": False,
    }


def _provider_result(invocation: dict) -> dict:
    citations = [
        "artifact://public/pubmed/10000001",
        "artifact://public/pubmed/10000002",
    ]
    claims = [
        {
            "claim_id": "claim_001",
            "text": "The fixed corpus supports a cautious research synthesis.",
            "evidence_refs": citations,
            "certainty": "limited",
        }
    ]
    result = {
        "result_version": "orbit.disease-r2-execution-result/1",
        "status": "R2 provider-backed public-corpus pass",
        "evidence_status": "public",
        "task_id": invocation["task_id"],
        "corpus_ref": "dataset://public/disease-r2/fictional-stationery-literature/0.1.0",
        "corpus_revision": "sha256:bb796b5aa76f930566e78c599eb197282595b26f2523f7b062374b7c261d6b30",
        "claims": claims,
        "synthesis": {
            "summary": "Cautious synthesis of the fixed public corpus.",
            "uncertainty": ["The corpus is small and heterogeneous."],
            "clinical_boundary": "Refuse diagnosis or treatment advice.",
            "claim_ids": ["claim_001"],
        },
        "citation_refs": citations,
        "model_usage": {
            "calls": 4,
            "request_attempts": 4,
            "input_tokens": 1000,
            "output_tokens": 200,
        },
        "authority_boundary": {
            "agent_network_access": False,
            "agent_model_credentials": False,
            "host_filesystem_access": False,
            "nas_access": False,
            "fulltext_access": False,
            "personal_medical_data": False,
            "a2a_access": False,
            "release_authorization": False,
        },
        "release_authorization": False,
        "preproduction_authorized": False,
        "production_authorized": False,
    }
    result["result_digest"] = worker_digest(result)
    return {
        "status": "R2 provider-backed public-corpus pass",
        "result": result,
        "usage": {
            "model_calls": 4,
            "request_attempts": 4,
            "input_tokens": 1000,
            "output_tokens": 200,
            "cost_usd": "0.011000",
            "cost_cny": "0.082500",
        },
        "provider_response_set_digest": canonical_digest("provider-responses"),
        "production_authorization": False,
        "release_authorization": False,
    }


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

