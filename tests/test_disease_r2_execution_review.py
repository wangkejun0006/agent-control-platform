from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from candidate_support.disease_r2_execution_ledger import (
    SyntheticDiseaseR2ExecutionLedger,
)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/disease-agent-r2/2026-08-27-execution-remediation-v3"
RUNNER_PATH = ROOT / "scripts/run_disease_r2_docker.py"
SPEC = importlib.util.spec_from_file_location("run_disease_r2_docker", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("R2 runner unavailable")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def digest(value) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
    ).hexdigest()


class DiseaseR2ExecutionReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(
            (EVIDENCE / "execution-review-package.json").read_text(encoding="utf-8")
        )

    def test_manifest_artifacts_runtime_source_and_self_digest_close(self) -> None:
        canonical = copy.deepcopy(self.manifest)
        supplied = canonical.pop("review_package_digest")
        self.assertEqual(supplied, digest(canonical))
        for name, expected in self.manifest["artifacts"].items():
            actual = "sha256:" + hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest()
            self.assertEqual(expected, actual)
        source = {
            "runtime_source_version": "orbit.disease-r2-runtime-source/3",
            "entries": self.manifest["runtime_sources"],
        }
        self.assertEqual(self.manifest["runtime_source_digest"], digest(source))
        # v3 is an immutable predecessor, not a live source selection.  Later
        # remediation intentionally changed runtime bytes, so its old source
        # lock must not be treated as executable against the current checkout.
        self.assertTrue(self.manifest["runtime_sources"])
        self.assertFalse(self.manifest["authority_boundary"]["external_model_called"])
        self.assertFalse(self.manifest["authority_boundary"]["release_authorization"])

    def test_owner_only_replacement_approval_must_bind_every_digest(self) -> None:
        review = runner._verify_review(EVIDENCE / "execution-review-package.json")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "approval.json"
            value = {
                "approval_version": "orbit.synthetic-disease-r2-execution-approval/3",
                "decision_id": "approval_disease_r2_execution_v3_syn",
                "scope": "r2_execution",
                "review_package_digest": review["review_package_digest"],
                "runtime_source_digest": review["runtime_source_digest"],
                "task_candidate_digest": review["task_candidate_digest"],
                "grant_candidate_digest": review["grant_candidate_digest"],
                "composition_candidate_digest": review["composition_candidate_digest"],
                "image_id": review["image_id"],
                "decided_by_human_ref": "hum_orbit_platform_owner_syn",
                "decision": "approve",
                "reason": "replacement one-time local synthetic R2 execution only",
                "synthetic_only": True,
                "release_authorization": False,
            }
            path.write_text(json.dumps(value), encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertEqual(value, runner._load_approval(path, review))
            value["runtime_source_digest"] = "sha256:" + ("0" * 64)
            path.write_text(json.dumps(value), encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaises(runner.DiseaseR2RunError) as caught:
                runner._load_approval(path, review)
            self.assertEqual("r2_execution_approval_invalid", caught.exception.reason_code)

    def test_docker_command_is_networkless_nonroot_and_read_only(self) -> None:
        command = runner._docker_command(
            bundle=Path("/private/tmp/orbit-r2-bundle"),
            image_id=runner.IMAGE_ID,
            name="orbit-disease-r2-test",
        )
        text = " ".join(command)
        for expected in (
            "--network none",
            "--read-only",
            "--user 65532:65532",
            "--cap-drop ALL",
            "--security-opt no-new-privileges",
            "--pids-limit 64",
            "--pull never",
        ):
            self.assertIn(expected, text)
        self.assertNotIn(".env", text)
        self.assertNotIn("/Users/", text)

    def test_runner_writes_evidence_and_closes_lease_with_review_digest(self) -> None:
        review = runner._verify_review(EVIDENCE / "execution-review-package.json")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            approval = root / "approval.json"
            approval.write_text(
                json.dumps(
                    {
                        "approval_version": "orbit.synthetic-disease-r2-execution-approval/3",
                        "decision_id": "approval_disease_r2_execution_v3_syn",
                        "scope": "r2_execution",
                        "review_package_digest": review["review_package_digest"],
                        "runtime_source_digest": review["runtime_source_digest"],
                        "task_candidate_digest": review["task_candidate_digest"],
                        "grant_candidate_digest": review["grant_candidate_digest"],
                        "composition_candidate_digest": review[
                            "composition_candidate_digest"
                        ],
                        "image_id": review["image_id"],
                        "decided_by_human_ref": "hum_orbit_platform_owner_syn",
                        "decision": "approve",
                        "reason": "one exact local synthetic R2 execution only",
                        "synthetic_only": True,
                        "release_authorization": False,
                    }
                ),
                encoding="utf-8",
            )
            price = root / "price.json"
            price.write_text(
                json.dumps(
                    {
                        "observation_version": "orbit.fixture-price-observation/1",
                        "source": "https://models.paper-orbit.invalid/pricing",
                        "provider_id": "fixture",
                        "model_id": "fixture-structured-v1",
                        "input_usd_per_million_tokens": "5.00",
                        "output_usd_per_million_tokens": "30.00",
                        "cached_input_usd_per_million_tokens": "0.50",
                        "hard_cap_usd": "0.20",
                        "cny_per_usd": "7.50",
                        "hard_cap_cny": "1.50",
                        "verified_for_single_execution": True,
                    }
                ),
                encoding="utf-8",
            )
            provider = root / "provider.env"
            provider.write_text(
                """ORBIT_MODEL_PROVIDER_ID=fixture
ORBIT_MODEL_BASE_URL=https://models.paper-orbit.invalid
ORBIT_MODEL_ID=fixture-structured-v1
ORBIT_MODEL_ALLOWED_RETURNED_IDS=fixture-structured-v1
ORBIT_MODEL_CNY_PER_USD=7.50
ORBIT_MODEL_SECRET_REF=env:ORBIT_MODEL_API_KEY
ORBIT_MODEL_API_KEY=synthetic-secret-value
""",
                encoding="utf-8",
            )
            for path in (approval, price, provider):
                os.chmod(path, 0o600)

            stages = (
                "question_decomposition",
                "query_generation",
                "evidence_mapping",
                "synthesis",
            )
            calls = tuple(
                SimpleNamespace(
                    stage=stage,
                    input_tokens=100,
                    output_tokens=20,
                    attempts=1,
                    cost_usd="0.001100",
                    cost_cny="0.008250",
                )
                for stage in stages
            )
            gateway = SimpleNamespace(calls=calls)
            result = {
                "status": "R2 synthetic pass",
                "corpus_revision": runner.CORPUS_REVISION,
                "model_usage": {"calls": 4},
                "claims": [{"claim_id": "claim_1"}],
                "citation_refs": ["artifact://public/pubmed/1"],
                "synthesis": {
                    "uncertainty": ["synthetic fixture"],
                    "clinical_boundary": "refuse clinical advice",
                },
                "result_digest": "sha256:" + ("a" * 64),
                "release_authorization": False,
            }
            model_calls = [
                {
                    "stage": stage,
                    "request_digest": "sha256:" + ("b" * 64),
                    "response_digest": "sha256:" + ("c" * 64),
                    "returned_model_id": "fixture-structured-v1",
                    "usage": {"input_tokens": 100, "output_tokens": 20},
                    "attempts": 1,
                }
                for stage in stages
            ]

            class ScopeLedger:
                def __init__(self, _path):
                    pass

                def record_status(self, _status, *, idempotency_key):
                    self.idempotency_key = idempotency_key

            output = root / "result.json"
            ledger_path = root / "execution.jsonl"
            with (
                mock.patch.object(runner, "_verify_lifecycle"),
                mock.patch.object(runner, "_verify_runtime_sources"),
                mock.patch.object(runner, "_image_id", return_value=review["image_id"]),
                mock.patch.object(
                    runner, "FrozenPublicLiteraturePort", return_value=object()
                ),
                mock.patch.object(
                    runner, "DiseaseR2ModelGateway", return_value=gateway
                ),
                mock.patch.object(runner, "SyntheticR2ScopeLedger", ScopeLedger),
                mock.patch.object(
                    runner,
                    "run_r2_ports",
                    return_value={
                        "result": result,
                        "model_calls": model_calls,
                        "cost": {"usd": "0.004400", "cny": "0.033000"},
                    },
                ),
            ):
                status = runner.run(
                    scientific=ROOT,
                    review_package=EVIDENCE / "execution-review-package.json",
                    approval=approval,
                    provider_env=provider,
                    price_observation=price,
                    scope_ledger_path=root / "scope.jsonl",
                    execution_ledger_path=ledger_path,
                    output=output,
                    image=runner.DEFAULT_IMAGE,
                )

            self.assertEqual(0, status)
            self.assertGreater(output.stat().st_size, 0)
            replay = SyntheticDiseaseR2ExecutionLedger(ledger_path).replay()
            self.assertEqual(4, replay.records_checked)
            self.assertEqual("completed", replay.state.lease["status"])
            self.assertEqual("completed", replay.state.terminal["task"]["status"])
            self.assertEqual("consumed", replay.state.terminal["grant"]["status"])
            self.assertEqual(
                "sha256:" + hashlib.sha256(approval.read_bytes()).hexdigest(),
                replay.state.started["execution_approval_digest"],
            )


if __name__ == "__main__":
    unittest.main()

