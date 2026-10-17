from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from candidate_support import disease_r2_v4_preflight as preflight
from orbit_agent_control_plane.registration import (
    DEFAULT_COMPANY_LOCK,
    DEFAULT_CONTRACT_BUNDLE,
    _load_verified_company_schemas,
    _SchemaValidator,
)
from tests.disease_r2_fixture import SCOPE_LEDGER

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = (
    ROOT
    / "evidence/disease-agent-r2/2026-08-27-execution-remediation-v4-attempt-002"
)
REVIEW = EVIDENCE / "execution-review-package.json"


def load(name: str) -> dict:
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


class DiseaseR2V4ReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.review = load("execution-review-package.json")
        cls.task = load("task-candidate.synthetic.json")
        cls.grant = load("execution-grant-candidate.synthetic.json")
        cls.scopes = load("approval-scope-bindings.synthetic.json")
        cls.schemas, _, _ = _load_verified_company_schemas(
            DEFAULT_COMPANY_LOCK,
            DEFAULT_CONTRACT_BUNDLE,
            {
                "urn:company-ai-os:schema:agent-common:0.1",
                "urn:company-ai-os:schema:task:0.3",
                "urn:company-ai-os:schema:execution-grant:0.1",
            },
        )
        cls.validator = _SchemaValidator(cls.schemas)

    def test_static_preflight_closes_graph_and_keeps_execution_pending(self) -> None:
        result = preflight.verify_candidate(
            REVIEW,
            runtime_root=EVIDENCE,
            scope_ledger_path=SCOPE_LEDGER,
        )
        self.assertEqual("PASS", result["status"])
        self.assertEqual("pending", result["execution_scope_status"])
        self.assertFalse(result["effective"])
        self.assertFalse(result["runtime_started"])
        self.assertFalse(result["release_authorization"])

    def test_company_task_and_grant_projections_validate_without_schema_change(self) -> None:
        self.validator.validate(
            self.task["company_contract_projection"],
            "urn:company-ai-os:schema:task:0.3",
        )
        self.validator.validate(
            self.grant["company_contract_projection"],
            "urn:company-ai-os:schema:execution-grant:0.1",
        )
        self.assertTrue(self.grant["company_contract_gap"])
        self.assertFalse(self.grant["effective"])

    def test_subjects_are_distinct_from_decision_and_status_receipts(self) -> None:
        for item in self.scopes["scopes"][:3]:
            with self.subTest(scope=item["scope_kind"]):
                self.assertNotEqual(
                    item["subject_digest"], item["decision_receipt_digest"]
                )
                self.assertNotEqual(
                    item["subject_digest"], item["status_receipt_digest"]
                )
        execution = self.scopes["scopes"][3]
        self.assertEqual("pending", execution["current_status"])
        self.assertIsNone(execution["decision_receipt_digest"])
        self.assertEqual("pending_approval", execution["consumption_status"])

    def test_execution_cannot_proceed_without_new_exact_owner_only_approval(self) -> None:
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_execution_approval_missing",
        ):
            preflight.verify_candidate(
                REVIEW,
                runtime_root=EVIDENCE,
                scope_ledger_path=SCOPE_LEDGER,
                require_execution_approval=True,
            )

    def test_exact_v4_approval_receipt_passes_and_digest_drift_fails(self) -> None:
        intent = load("execution-intent.synthetic.json")
        source = load("runtime-source-lock.json")
        realization = load("runtime-realization-candidate.synthetic.json")
        composition = load("runtime-composition-candidate.synthetic.json")
        approval = {
            "approval_version": "orbit.synthetic-disease-r2-execution-approval/4",
            "decision_id": "approval_orbit_disease_r2_v4_002_syn",
            "scope": "r2_execution",
            "subject_digest": intent["execution_intent_digest"],
            "review_package_digest": self.review["review_package_digest"],
            "runtime_source_lock_digest": source["runtime_source_lock_digest"],
            "runtime_realization_digest": realization["runtime_realization_digest"],
            "task_candidate_digest": self.task["task_candidate_digest"],
            "grant_candidate_digest": self.review["grant_candidate_digest"],
            "grant_canonical_digest": self.grant["grant_canonical_digest"],
            "composition_digest": composition["composition_digest"],
            "image_id": preflight.EXPECTED_IMAGE_ID,
            "decided_by_human_ref": "hum_orbit_platform_owner_syn",
            "decision": "approve",
            "synthetic_only": True,
            "single_use": True,
            "release_authorization": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            path.write_text(json.dumps(approval), encoding="utf-8")
            os.chmod(path, 0o600)
            result = preflight.verify_candidate(
                REVIEW,
                runtime_root=EVIDENCE,
                scope_ledger_path=SCOPE_LEDGER,
                execution_approval_path=path,
                require_execution_approval=True,
            )
            self.assertEqual("approved_unconsumed", result["execution_scope_status"])
            approval["subject_digest"] = "sha256:" + ("0" * 64)
            path.write_text(json.dumps(approval), encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(
                preflight.DiseaseR2V4PreflightError,
                "r2_v4_execution_approval_invalid",
            ):
                preflight.verify_candidate(
                    REVIEW,
                    runtime_root=EVIDENCE,
                    scope_ledger_path=SCOPE_LEDGER,
                    execution_approval_path=path,
                    require_execution_approval=True,
                )

    def test_budget_endpoint_permission_and_receipt_mutations_fail_closed(self) -> None:
        values = {
            role: load(entry["path"])
            for role, entry in self.review["artifacts"].items()
        }
        bad = copy.deepcopy(values)
        bad["composition"]["model_route"]["endpoint"] = (
            "https://models.paper-orbit.invalid/v1/responses"
        )
        canonical = copy.deepcopy(bad["composition"])
        canonical.pop("composition_digest")
        bad["composition"]["composition_digest"] = preflight.digest(canonical)
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_model_route_mismatch",
        ):
            preflight._verify_direct_graph(self.review, bad)
        bad = copy.deepcopy(values)
        bad["grant"]["implementation_extension"]["budget"]["hard_cap_usd"] = (
            "unbounded"
        )
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_grant_budget_mismatch",
        ):
            preflight._verify_direct_graph(self.review, bad)
        bad_scopes = copy.deepcopy(self.scopes)
        bad_scopes["scopes"][0]["decision_receipt_digest"] = bad_scopes[
            "scopes"
        ][0]["subject_digest"]
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_scope_receipt_mismatch",
        ):
            preflight._verify_scope_bindings(bad_scopes, None)
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_authority_widening",
        ):
            preflight._reject_authority_or_secret({"effective": True})
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_physical_path_forbidden",
        ):
            preflight._reject_authority_or_secret({"storage_ref": "/Volumes/nas/a"})

    def test_price_window_revocation_corpus_and_receipt_drift_fail_closed(self) -> None:
        values = {
            role: load(entry["path"])
            for role, entry in self.review["artifacts"].items()
        }
        bad = copy.deepcopy(values)
        bad["price_observation"]["input_usd_per_million_tokens"] = "6.00"
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_price_observation_mismatch",
        ):
            preflight._verify_direct_graph(self.review, bad)
        bad = copy.deepcopy(values)
        bad["grant"]["implementation_extension"]["candidate_expires_at"] = (
            "2026-08-27T08:31:00Z"
        )
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_grant_candidate_window_mismatch",
        ):
            preflight._verify_direct_graph(self.review, bad)
        bad = copy.deepcopy(values)
        bad["grant"]["implementation_extension"]["revocation"][
            "budget_exhaustion"
        ] = "continue"
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_candidate_state_or_revocation_invalid",
        ):
            preflight._verify_direct_graph(self.review, bad)
        bad = copy.deepcopy(values)
        bad["corpus_binding"]["revision"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_corpus_binding_mismatch",
        ):
            preflight._verify_direct_graph(self.review, bad)
        bad = copy.deepcopy(values)
        bad["composition"]["approval_receipt_refs"] = []
        canonical = copy.deepcopy(bad["composition"])
        canonical.pop("composition_digest")
        bad["composition"]["composition_digest"] = preflight.digest(canonical)
        with self.assertRaisesRegex(
            preflight.DiseaseR2V4PreflightError,
            "r2_v4_direct_approval_receipt_binding_mismatch",
        ):
            preflight._verify_direct_graph(self.review, bad)

    def test_v3_and_published_dataset_r1_bytes_are_still_exact(self) -> None:
        predecessor = load("predecessor-lock.json")
        v3 = ROOT / "evidence/disease-agent-r2/2026-08-27-execution-remediation-v3"
        for name, expected in predecessor["v3_raw_file_digests"].items():
            with self.subTest(name=name):
                self.assertEqual(expected, preflight.file_digest(v3 / name))
        v4_attempt_001 = (
            ROOT
            / "evidence/disease-agent-r2/2026-08-27-execution-remediation-v4"
        )
        self.assertEqual(
            predecessor["v4_attempt_001"]["review_file_digest"],
            preflight.file_digest(v4_attempt_001 / "execution-review-package.json"),
        )
        baseline = json.loads(
            (
                ROOT
                / "evidence/publication-baseline/2026-08-26/publication-baseline.synthetic.json"
            ).read_text(encoding="utf-8")
        )
        for entry in baseline["artifacts"]:
            with self.subTest(role=entry["role"]):
                self.assertEqual(
                    entry["sha256"], preflight.file_digest(ROOT / entry["path"])
                )

    def test_runtime_is_framework_neutral_and_snapshot_is_immutable(self) -> None:
        realization = load("runtime-realization-candidate.synthetic.json")
        self.assertEqual(
            "framework-neutral-python-state-machine", realization["framework"]
        )
        self.assertNotIn("langgraph", json.dumps(realization).lower())
        self.assertNotIn("codex", realization["framework"].lower())
        self.assertTrue(REVIEW.is_file())
        self.assertFalse(REVIEW.is_symlink())
        self.assertTrue(EVIDENCE.is_dir())
        self.assertFalse(EVIDENCE.is_symlink())
        self.assertEqual(
            "sha256:7a7f938d3329e34f3acbac021fedb10265037b80d57b97dd097046e136c59c60",
            preflight.file_digest(REVIEW),
        )


if __name__ == "__main__":
    unittest.main()

