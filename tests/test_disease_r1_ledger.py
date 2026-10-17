from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path

from orbit_agent_control_plane.disease_r1 import (
    evaluate_worker_response,
    grant_from_mapping,
    plan_disease_r1,
)
from orbit_agent_control_plane.disease_r1_review import verify_disease_r1_review
from orbit_agent_control_plane.ids import deterministic_id
from orbit_agent_control_plane.ledger import SyntheticTaskLedger


ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_ROOT = ROOT.parent / "orbit-health-system" / "scientific-research-platform"
REVIEW = (
    ROOT
    / "evidence/disease-agent-r1/2026-08-26/retry-004/execution-review-request.json"
)
TASK_INPUT = (
    SCIENTIFIC_ROOT
    / "contracts"
    / "disease-research"
    / "fixtures"
    / "synthetic"
    / "fictional-stationery.task-input.synthetic.json"
)
sys.path.insert(0, str(SCIENTIFIC_ROOT / "src"))
_ipc = importlib.import_module(
    "orbit_scientific_research_platform.disease_research.ipc"
)
_worker = importlib.import_module(
    "orbit_scientific_research_platform.disease_research.r1_worker"
)


class DiseaseR1LedgerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.review = verify_disease_r1_review(ROOT, REVIEW)
        grant = grant_from_mapping(self.review.synthetic_grant)
        self.plan = plan_disease_r1(
            grant,
            checked_at="2026-08-26T00:05:00Z",
            lifecycle_status="active",
            lifecycle_release_digest=grant.agent_release_digest,
        )

    def outcome(self, status: str, domain=None, company=None) -> dict:
        return {
            "outcome_version": "orbit.synthetic-disease-r1-outcome/1",
            "attempt_id": deterministic_id(
                "attempt", self.plan.task.task_id, self.review.review_request_digest
            ),
            "task_id": self.plan.task.task_id,
            "status": status,
            "review_request_digest": self.review.review_request_digest,
            "agent_release_digest": self.plan.grant.agent_release_digest,
            "package_digest": self.plan.grant.package.digest,
            "runtime_source_digest": self.plan.grant.runtime_source_digest,
            "control_source_digest": self.review.control_source_digest,
            "grant_digest": self.plan.grant_digest,
            "evidence_ref": "evidence://synthetic/disease-r1/sha256/" + ("d" * 64),
            "evidence_digest": "sha256:" + ("d" * 64),
            "domain_evaluation": None if domain is None else asdict(domain),
            "company_evaluation": None if company is None else asdict(company),
            "reason_codes": [
                "disease_r1_fixed_suite_pass" if status == "pass" else "failed_closed"
            ],
            "evidence_status": "synthetic",
            "synthetic_only": True,
            "release_authorization": False,
        }

    def start(self, path: Path) -> SyntheticTaskLedger:
        ledger = SyntheticTaskLedger(path)
        ledger.register_task(
            self.plan.task, idempotency_key=f"register:{self.plan.task.task_id}"
        )
        ledger.start_worker_lease(
            self.plan.worker_lease,
            idempotency_key=f"lease-start:{self.plan.worker_lease.lease_id}",
        )
        return ledger

    def evaluated(self):
        task_input = json.loads(TASK_INPUT.read_text(encoding="utf-8"))
        task_input["parent_task_ref"] = (
            f"company-task://synthetic/{self.plan.task.task_id}"
        )
        task_input["agent_binding_ref"] = (
            "agent-binding://synthetic/"
            "bind_orbit_disease_research_task_d0_syn/0.1.0/sha256/"
            "a9edd1b1648650631cfeade592430e494e624a220b22fc528748adcb3cdd1334"
        )
        task_input["execution_grant_ref"] = self.plan.grant.grant_id
        task_input["route_decision_ref"] = self.plan.route.decision_id
        event = _ipc.build_task_event(
            task_input,
            event_id="drevent_orbit_disease_r1_ledger_syn",
            company_task_id=self.plan.task.task_id,
            invocation_id="inv_orbit_disease_r1_ledger_syn",
            runtime_adapter_ref={
                "id": "runtime_adapter_orbit_disease_r1_syn",
                "version": "0.1.0",
                "digest": self.plan.grant.runtime_source_digest,
            },
        )
        request = _ipc.build_ipc_request(event, request_id=self.plan.request_id)
        response = _worker._process(
            json.dumps(request, separators=(",", ":")).encode("utf-8"),
            enforce_process_boundary=False,
        )
        return evaluate_worker_response(self.plan, response)

    def test_passing_outcome_precedes_completed_lease(self) -> None:
        path = Path(self.temporary.name) / "pass.jsonl"
        ledger = self.start(path)
        evaluated = self.evaluated()
        outcome = self.outcome(
            "pass",
            evaluated.domain_evaluation,
            evaluated.company_outcome.evaluation,
        )
        ledger.record_disease_r1_outcome(
            outcome,
            idempotency_key=f"disease-r1-outcome:{self.plan.task.task_id}",
        )
        completed = replace(
            self.plan.worker_lease,
            status="completed",
            revision=1,
            last_event_ref="audit_orbit_disease_r1_completed_syn",
        )
        ledger.close_worker_lease(
            completed,
            idempotency_key=f"lease-close:{completed.lease_id}",
        )
        replay = SyntheticTaskLedger(path).replay().task(self.plan.task.task_id)
        self.assertEqual("pass", replay.disease_r1_outcome["status"])
        self.assertEqual("completed", replay.worker_lease.status)

    def test_failed_outcome_allows_failed_lease_without_pass_claim(self) -> None:
        path = Path(self.temporary.name) / "fail.jsonl"
        ledger = self.start(path)
        outcome = self.outcome("fail")
        ledger.record_disease_r1_outcome(
            outcome,
            idempotency_key=f"disease-r1-outcome:{self.plan.task.task_id}",
        )
        failed = replace(
            self.plan.worker_lease,
            status="failed",
            revision=1,
            last_event_ref="audit_orbit_disease_r1_failed_syn",
        )
        ledger.close_worker_lease(
            failed,
            idempotency_key=f"lease-close:{failed.lease_id}",
        )
        replay = SyntheticTaskLedger(path).replay().task(self.plan.task.task_id)
        self.assertEqual("fail", replay.disease_r1_outcome["status"])
        self.assertEqual("failed", replay.worker_lease.status)


if __name__ == "__main__":
    unittest.main()

