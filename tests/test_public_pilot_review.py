from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from orbit_agent_control_plane.qualification.automation import (
    QualificationCandidate,
    canonical_digest,
    validate_automation_policy,
)

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/disease-agent-r2/2026-08-28-public-pilot-enablement"
EXECUTION = ROOT / "evidence/disease-agent-r2/2026-08-28-public-pilot-execution"


class PublicPilotReviewTests(unittest.TestCase):
    def test_review_policy_candidate_and_runtime_sources_close_exactly(self) -> None:
        review_path = EVIDENCE / "pilot-enablement-review-package.json"
        review = _read(review_path)
        policy = _read(EVIDENCE / "automation-policy.disease-r2.public.json")
        candidate = _read(
            EVIDENCE / "qualification-candidate.attempt-001.public.json"
        )
        source_lock = _read(EVIDENCE / "runtime-source-lock.public.json")
        validate_automation_policy(policy)
        QualificationCandidate.from_mapping(candidate)
        self.assertEqual(
            review["automation_policy_digest"], canonical_digest(policy)
        )
        self.assertEqual(
            review["execution_candidates"]["qualification_candidate_digest"],
            canonical_digest(candidate),
        )
        content = {
            key: value
            for key, value in review.items()
            if key != "review_package_digest"
        }
        self.assertEqual(review["review_package_digest"], canonical_digest(content))
        self.assertEqual(3, review["pilot_budget"]["max_provider_attempts"])
        self.assertFalse(review["model_called"])
        self.assertFalse(review["runtime_started"])
        self.assertFalse(review["release_authorization"])
        entries = source_lock["entries"]
        self.assertEqual(source_lock["source_set_digest"], canonical_digest(entries))
        for entry in entries:
            self.assertEqual("orbit-agent-control-plane", entry["repository"])
            self.assertRegex(entry["sha256"], r"^sha256:[0-9a-f]{64}$")
        current_source_lock = _read(
            EXECUTION / "runtime-source-lock.attempt-004.public.json"
        )
        current_source_content = {
            key: value
            for key, value in current_source_lock.items()
            if key != "source_set_digest"
        }
        self.assertEqual(
            current_source_lock["source_set_digest"],
            canonical_digest(current_source_content),
        )
        for entry in current_source_lock["entries"]:
            self.assertEqual("orbit-agent-control-plane", entry["repository"])
            # Historical attempt locks remain immutable after a successor Runtime
            # Source is prepared. Current-source closure belongs to that new lock.
            self.assertRegex(entry["sha256"], r"^sha256:[0-9a-f]{64}$")
        prompt = (EVIDENCE / "approval-prompt.zh-CN.md").read_text(encoding="utf-8")
        self.assertIn(_raw_digest(review_path), prompt)
        self.assertIn(review["review_package_digest"], prompt)


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _raw_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()

