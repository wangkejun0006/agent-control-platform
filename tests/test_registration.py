from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane import registration
from orbit_agent_control_plane.registration import (
    RegistrationError,
    SyntheticAgentRegistrationLedger,
    verify_registration_handoff,
)

ROOT = Path(__file__).resolve().parents[1]
SCIENTIFIC_ROOT = ROOT.parent / "orbit-health-system" / "scientific-research-platform"
HANDOFF_RELATIVE = Path(
    "contracts/agents/disease-research-task-agent/registration/0.1.0/registration-handoff-manifest.json"
)
CANDIDATE_MANIFEST_RELATIVE = Path(
    "contracts/agents/disease-research-task-agent/candidates/0.1.0/candidate-review-manifest.json"
)
REGISTRATION_ROOT_RELATIVE = HANDOFF_RELATIVE.parent
CANDIDATE_ROOT_RELATIVE = CANDIDATE_MANIFEST_RELATIVE.parent
HISTORICAL_ALPHA1_ARGS = {
    "company_lock_path": registration.HISTORICAL_ALPHA1_COMPANY_LOCK,
    "contract_bundle_root": registration.HISTORICAL_ALPHA1_CONTRACT_BUNDLE,
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_digest(document: dict, path: tuple[str, ...]) -> str:
    value = copy.deepcopy(document)
    parent = value
    for key in path[:-1]:
        parent = parent[key]
    del parent[path[-1]]
    source = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(source).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


class AgentRegistrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture_root = Path(self.temporary.name) / "scientific-research-platform"
        self.approval_lock = Path(self.temporary.name) / "approved-inputs.json"
        self.ledger_path = Path(self.temporary.name) / "ledger" / "registration.synthetic.jsonl"
        self._reset_fixture()

    def _reset_fixture(self) -> None:
        if self.fixture_root.exists():
            shutil.rmtree(self.fixture_root)
        shutil.copytree(SCIENTIFIC_ROOT / "contracts", self.fixture_root / "contracts")
        shutil.copyfile(registration.DEFAULT_APPROVAL_LOCK, self.approval_lock)
        self._approve_current_handoff()

    def assert_reason(self, reason: str, callback) -> None:
        with self.assertRaises(RegistrationError) as raised:
            callback()
        self.assertEqual(reason, raised.exception.reason_code)

    def verify(self, root: Path | None = None):
        return verify_registration_handoff(
            root or self.fixture_root,
            HANDOFF_RELATIVE,
            approval_lock_path=self.approval_lock,
            **HISTORICAL_ALPHA1_ARGS,
        )

    def _approve_current_handoff(self) -> None:
        handoff_path = self.fixture_root / HANDOFF_RELATIVE
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        lock = json.loads(registration.DEFAULT_APPROVAL_LOCK.read_text(encoding="utf-8"))
        entries = lock["approved_handoffs"] or lock["review_requests"]
        approved = copy.deepcopy(entries[0])
        approved["handoff_id"] = handoff["handoff_id"]
        approved["manifest_sha256"] = f"sha256:{_sha256(handoff_path)}"
        approved["candidate_digest"] = handoff["candidate_set_ref"]["digest"]
        approved["handoff_digest"] = f"sha256:{handoff['handoff_digest']['value']}"
        approved["registration_intake_profile"] = (
            registration.REGISTRATION_INTAKE_PROFILE
        )
        approved["approval_semantics"] = (
            registration.REGISTRATION_APPROVAL_SEMANTICS
        )
        lock["status"] = "local-synthetic-registration-only"
        lock["review_requests"] = []
        lock["approved_handoffs"] = [approved]
        _write_json(self.approval_lock, lock)

    def _resign_fixture(self) -> None:
        candidate_path = self.fixture_root / CANDIDATE_MANIFEST_RELATIVE
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        for entry in candidate["artifacts"]:
            entry["sha256"] = _sha256(self.fixture_root / entry["path"])
        for entry in candidate["supporting_contracts"]:
            entry["sha256"] = _sha256(self.fixture_root / entry["path"])
        candidate["review_guide"]["sha256"] = _sha256(
            self.fixture_root / candidate["review_guide"]["path"]
        )
        candidate["company_contract"]["lock_sha256"] = _sha256(
            self.fixture_root / candidate["company_contract"]["lock_path"]
        )
        candidate["candidate_set_digest"]["value"] = _canonical_digest(
            candidate, ("candidate_set_digest", "value")
        )
        _write_json(candidate_path, candidate)
        candidate_digest = f"sha256:{candidate['candidate_set_digest']['value']}"

        handoff_path = self.fixture_root / HANDOFF_RELATIVE
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        handoff["candidate_set_ref"]["digest"] = candidate_digest
        by_kind = {entry["kind"]: entry for entry in candidate["artifacts"]}
        for name, kind in (
            ("definition", "AgentDefinition"),
            ("binding", "AgentBinding"),
            ("template", "AgentTemplate"),
        ):
            handoff["candidate_artifact_refs"][name]["digest"] = (
                f"sha256:{by_kind[kind]['sha256']}"
            )
        for entry in handoff["registration_artifacts"]:
            entry["sha256"] = _sha256(self.fixture_root / entry["path"])
        deferred = handoff["deferred_activation_test_ref"]
        deferred["sha256"] = _sha256(self.fixture_root / deferred["path"])
        handoff["handoff_digest"]["value"] = _canonical_digest(
            handoff, ("handoff_digest", "value")
        )
        _write_json(handoff_path, handoff)
        self._approve_current_handoff()

    def _write_legacy_registration_record(self) -> None:
        current = self.verify().ledger_payload()
        legacy = {
            key: current[key]
            for key in registration._LEGACY_LEDGER_PAYLOAD_KEYS
        }
        legacy["handoff_digest"] = "sha256:" + ("7" * 64)
        legacy["handoff_manifest_sha256"] = "sha256:" + ("5" * 64)
        idempotency_key = f"registration:{legacy['handoff_id']}"
        payload_digest = registration._digest(
            registration._canonical_json(legacy).encode("utf-8")
        )
        content = {
            "ledger_version": registration.LEGACY_REGISTRATION_LEDGER_VERSION,
            "sequence": 0,
            "record_id": registration.deterministic_id(
                "registration", idempotency_key, payload_digest
            ),
            "record_type": "synthetic_registration_evidence",
            "idempotency_key": idempotency_key,
            "previous_record_hash": registration.REGISTRATION_GENESIS_HASH,
            "payload": legacy,
        }
        content["record_hash"] = registration._digest(
            registration._canonical_json(content).encode("utf-8")
        )
        self.ledger_path.parent.mkdir(mode=0o700)
        self.ledger_path.write_text(
            registration._canonical_json(content) + "\n", encoding="utf-8"
        )
        self.ledger_path.chmod(0o600)

    def test_exact_handoff_verifies_and_ledger_apply_is_idempotent(self) -> None:
        verified = self.verify()
        self.assertEqual(
            "sha256:1eb5524baa23191f2beae80a1962785c4847c93eb42fa98ed4eb5133b67aaefe",
            verified.candidate_digest,
        )
        payload = verified.ledger_payload()
        ledger = SyntheticAgentRegistrationLedger(self.ledger_path)
        first = ledger.append_registration(payload, idempotency_key="registration:exact")
        retry = ledger.append_registration(payload, idempotency_key="registration:exact")
        self.assertTrue(first.appended)
        self.assertFalse(retry.appended)
        self.assertEqual(first.record_hash, retry.record_hash)
        self.assertEqual(1, ledger.replay().records_checked)
        self.assertEqual(0o700, stat_mode(self.ledger_path.parent))
        self.assertEqual(0o600, stat_mode(self.ledger_path))

    def test_historical_alpha1_handoff_matches_exact_approved_input(self) -> None:
        verified = verify_registration_handoff(
            SCIENTIFIC_ROOT,
            HANDOFF_RELATIVE,
            **HISTORICAL_ALPHA1_ARGS,
        )
        self.assertEqual(
            "sha256:ca0bfb071806ae13d7c20275989f9bed87ff4aff024840e41de704d5efe8f095",
            verified.handoff_digest,
        )

    def test_pending_handoff_waits_for_exact_human_approval(self) -> None:
        lock = json.loads(self.approval_lock.read_text(encoding="utf-8"))
        lock["status"] = "awaiting-human-review"
        lock["review_requests"] = lock["approved_handoffs"]
        lock["approved_handoffs"] = []
        _write_json(self.approval_lock, lock)
        self.assert_reason(
            "registration_input_not_approved",
            lambda: verify_registration_handoff(
                SCIENTIFIC_ROOT,
                HANDOFF_RELATIVE,
                approval_lock_path=self.approval_lock,
                **HISTORICAL_ALPHA1_ARGS,
            ),
        )

    def test_same_idempotency_key_with_different_content_fails(self) -> None:
        payload = self.verify().ledger_payload()
        ledger = SyntheticAgentRegistrationLedger(self.ledger_path)
        ledger.append_registration(payload, idempotency_key="registration:conflict")
        changed = {**payload, "registry_record_ref": "registry_other_candidate_syn"}
        self.assert_reason(
            "idempotency_conflict",
            lambda: ledger.append_registration(
                changed, idempotency_key="registration:conflict"
            ),
        )

    def test_legacy_ledger_replays_and_new_handoff_appends_as_v2(self) -> None:
        self._write_legacy_registration_record()
        ledger = SyntheticAgentRegistrationLedger(self.ledger_path)
        legacy_replay = ledger.replay()
        self.assertEqual(1, legacy_replay.records_checked)

        _, first = registration.apply_registration_handoff(
            self.fixture_root,
            HANDOFF_RELATIVE,
            self.ledger_path,
            approval_lock_path=self.approval_lock,
            **HISTORICAL_ALPHA1_ARGS,
        )
        _, retry = registration.apply_registration_handoff(
            self.fixture_root,
            HANDOFF_RELATIVE,
            self.ledger_path,
            approval_lock_path=self.approval_lock,
            **HISTORICAL_ALPHA1_ARGS,
        )
        replay = ledger.replay()
        self.assertTrue(first.appended)
        self.assertFalse(retry.appended)
        self.assertEqual(2, replay.records_checked)
        documents = [json.loads(line) for line in self.ledger_path.read_text().splitlines()]
        self.assertEqual(
            registration.LEGACY_REGISTRATION_LEDGER_VERSION,
            documents[0]["ledger_version"],
        )
        self.assertEqual(
            registration.REGISTRATION_LEDGER_VERSION,
            documents[1]["ledger_version"],
        )

    def test_handoff_and_candidate_digest_tamper_fail(self) -> None:
        handoff_path = self.fixture_root / HANDOFF_RELATIVE
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        handoff["handoff_digest"]["value"] = "0" * 64
        _write_json(handoff_path, handoff)
        self.assert_reason("handoff_digest_mismatch", self.verify)

        shutil.rmtree(self.fixture_root)
        shutil.copytree(SCIENTIFIC_ROOT / "contracts", self.fixture_root / "contracts")
        candidate_path = self.fixture_root / CANDIDATE_MANIFEST_RELATIVE
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        candidate["candidate_set_digest"]["value"] = "0" * 64
        _write_json(candidate_path, candidate)
        self.assert_reason("candidate_digest_mismatch", self.verify)

    def test_candidate_and_registration_raw_byte_tamper_fail(self) -> None:
        relative_paths = (
            CANDIDATE_ROOT_RELATIVE / "agent-definition.synthetic.yaml",
            CANDIDATE_ROOT_RELATIVE / "agent-binding.synthetic.yaml",
            CANDIDATE_ROOT_RELATIVE / "agent-template.synthetic.yaml",
            REGISTRATION_ROOT_RELATIVE / "agent-registry-record.synthetic.yaml",
            REGISTRATION_ROOT_RELATIVE / "registration-approval-decision.synthetic.yaml",
            REGISTRATION_ROOT_RELATIVE / "registration-audit-event.synthetic.yaml",
        )
        for index, relative in enumerate(relative_paths):
            with self.subTest(path=relative.name):
                root = Path(self.temporary.name) / f"tamper-{index}"
                shutil.copytree(SCIENTIFIC_ROOT / "contracts", root / "contracts")
                target = root / relative
                target.write_bytes(target.read_bytes() + b"\n")
                self.assert_reason(
                    "artifact_bytes_mismatch",
                    lambda root=root: verify_registration_handoff(
                        root,
                        HANDOFF_RELATIVE,
                        approval_lock_path=self.approval_lock,
                        **HISTORICAL_ALPHA1_ARGS,
                    ),
                )

    def test_registry_approval_and_audit_reference_drift_fail(self) -> None:
        registry_path = self.fixture_root / REGISTRATION_ROOT_RELATIVE / "agent-registry-record.synthetic.yaml"
        registry_path.write_text(
            registry_path.read_text(encoding="utf-8").replace(
                "id: agt_orbit_disease_research_task_syn",
                "id: agt_orbit_disease_research_other_syn",
                1,
            ),
            encoding="utf-8",
        )
        self._resign_fixture()
        self.assert_reason("registry_candidate_reference_mismatch", self.verify)

        self._reset_fixture()
        approval_path = self.fixture_root / REGISTRATION_ROOT_RELATIVE / "registration-approval-decision.synthetic.yaml"
        approval_path.write_text(
            approval_path.read_text(encoding="utf-8").replace(
                "scope_digest: sha256:1eb5524baa23191f2beae80a1962785c4847c93eb42fa98ed4eb5133b67aaefe",
                "scope_digest: sha256:" + ("1" * 64),
            ),
            encoding="utf-8",
        )
        self._resign_fixture()
        self.assert_reason("approval_scope_digest_mismatch", self.verify)

        self._reset_fixture()
        approval_path = self.fixture_root / REGISTRATION_ROOT_RELATIVE / "registration-approval-decision.synthetic.yaml"
        approval_path.write_text(
            approval_path.read_text(encoding="utf-8").replace(
                "audit_orbit_disease_agent_registration_approval_syn",
                "audit_orbit_disease_agent_registration_other_syn",
            ),
            encoding="utf-8",
        )
        self._resign_fixture()
        self.assert_reason("registration_audit_reference_mismatch", self.verify)

    def test_audit_integrity_digest_drift_fails(self) -> None:
        audit_path = self.fixture_root / REGISTRATION_ROOT_RELATIVE / "registration-audit-event.synthetic.yaml"
        audit_path.write_text(
            audit_path.read_text(encoding="utf-8").replace(
                "event_digest: sha256:ba577cae9507e3f2627dbe05f96612e80e21211678bfc5b26f658cbc5216e5b6",
                "event_digest: sha256:" + ("2" * 64),
            ),
            encoding="utf-8",
        )
        self._resign_fixture()
        self.assert_reason("audit_integrity_digest_mismatch", self.verify)

    def test_company_tag_commit_and_schema_hash_drift_fail(self) -> None:
        lock_path = self.fixture_root / REGISTRATION_ROOT_RELATIVE / "company-registration-contract.lock.json"
        for index, (field, replacement, reason) in enumerate(
            (
                ("git_tag", "contract-v0.1.0-alpha.other", "company_contract_identity_mismatch"),
                ("git_commit", "1" * 40, "company_contract_identity_mismatch"),
            )
        ):
            with self.subTest(field=field):
                if index:
                    self._reset_fixture()
                    lock_path = self.fixture_root / REGISTRATION_ROOT_RELATIVE / "company-registration-contract.lock.json"
                lock = json.loads(lock_path.read_text(encoding="utf-8"))
                lock["authority"][field] = replacement
                _write_json(lock_path, lock)
                self._resign_fixture()
                self.assert_reason(reason, self.verify)

        self._reset_fixture()
        lock_path = self.fixture_root / REGISTRATION_ROOT_RELATIVE / "company-registration-contract.lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["schemas"][0]["sha256"] = "sha256:" + ("3" * 64)
        _write_json(lock_path, lock)
        self._resign_fixture()
        self.assert_reason("company_schema_digest_mismatch", self.verify)

    def test_control_plane_compatibility_profile_drift_fails(self) -> None:
        lock_path = (
            self.fixture_root
            / REGISTRATION_ROOT_RELATIVE
            / "company-registration-contract.lock.json"
        )
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["target_control_plane"]["compatibility_profile"] = (
            "orbit.synthetic-agent-registration-intake/other"
        )
        _write_json(lock_path, lock)
        self._resign_fixture()
        self.assert_reason("source_authority_boundary_invalid", self.verify)

    def test_duplicate_json_and_yaml_keys_fail(self) -> None:
        handoff_path = self.fixture_root / HANDOFF_RELATIVE
        source = handoff_path.read_text(encoding="utf-8").replace(
            '"handoff_id":', '"handoff_id": "duplicate_syn",\n  "handoff_id":', 1
        )
        handoff_path.write_text(source, encoding="utf-8")
        self.assert_reason("duplicate_json_key", self.verify)

        self._reset_fixture()
        registry_path = self.fixture_root / REGISTRATION_ROOT_RELATIVE / "agent-registry-record.synthetic.yaml"
        registry_path.write_text(
            registry_path.read_text(encoding="utf-8").replace(
                "kind: AgentRegistryRecord",
                "kind: AgentRegistryRecord\nkind: AgentRegistryRecord",
            ),
            encoding="utf-8",
        )
        self._resign_fixture()
        self.assert_reason("duplicate_yaml_key", self.verify)

    def test_unknown_manifest_version_and_nonstandard_json_constant_fail(self) -> None:
        handoff_path = self.fixture_root / HANDOFF_RELATIVE
        handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        handoff["schema_version"] = "orbit.agent-registration-handoff-manifest/2.0"
        handoff["handoff_digest"]["value"] = _canonical_digest(
            handoff, ("handoff_digest", "value")
        )
        _write_json(handoff_path, handoff)
        self._approve_current_handoff()
        self.assert_reason("handoff_boundary_invalid", self.verify)

        self._reset_fixture()
        handoff_path = self.fixture_root / HANDOFF_RELATIVE
        source = handoff_path.read_text(encoding="utf-8").replace(
            '"synthetic_only": true', '"synthetic_only": NaN', 1
        )
        handoff_path.write_text(source, encoding="utf-8")
        self.assert_reason("invalid_json_constant", self.verify)

    def test_yaml_anchor_alias_tag_and_merge_key_fail(self) -> None:
        replacements = (
            ("kind: AgentRegistryRecord", "kind: &kind AgentRegistryRecord"),
            ("kind: AgentRegistryRecord", "kind: *kind"),
            ("kind: AgentRegistryRecord", "kind: !candidate AgentRegistryRecord"),
            ("metadata:", "metadata:\n  <<: {}"),
        )
        for index, (before, after) in enumerate(replacements):
            with self.subTest(feature=index):
                if index:
                    self._reset_fixture()
                path = self.fixture_root / REGISTRATION_ROOT_RELATIVE / "agent-registry-record.synthetic.yaml"
                path.write_text(
                    path.read_text(encoding="utf-8").replace(before, after, 1),
                    encoding="utf-8",
                )
                self._resign_fixture()
                expected = (
                    "yaml_merge_key_forbidden" if index == 3 else "yaml_advanced_feature_forbidden"
                )
                self.assert_reason(expected, self.verify)

    def test_path_traversal_absolute_path_and_symlink_fail(self) -> None:
        handoff_path = self.fixture_root / HANDOFF_RELATIVE
        for index, unsafe in enumerate(("../escape.json", "/absolute/escape.json")):
            with self.subTest(path=unsafe):
                if index:
                    self._reset_fixture()
                    handoff_path = self.fixture_root / HANDOFF_RELATIVE
                handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
                handoff["registration_artifacts"][0]["path"] = unsafe
                handoff["handoff_digest"]["value"] = _canonical_digest(
                    handoff, ("handoff_digest", "value")
                )
                _write_json(handoff_path, handoff)
                self._approve_current_handoff()
                self.assert_reason("unsafe_source_path", self.verify)

        self._reset_fixture()
        target = self.fixture_root / CANDIDATE_ROOT_RELATIVE / "agent-definition.synthetic.yaml"
        original = target.with_name("definition-target.yaml")
        target.rename(original)
        target.symlink_to(original.name)
        self.assert_reason("source_symlink_forbidden", self.verify)

    def test_path_storage_secret_and_endpoint_leaks_fail(self) -> None:
        leaks = ("/Users/example/source", "opaque://asset", "Secret Reference", "Endpoint")
        for index, leak in enumerate(leaks):
            with self.subTest(leak=leak):
                if index:
                    self._reset_fixture()
                registry_path = self.fixture_root / REGISTRATION_ROOT_RELATIVE / "agent-registry-record.synthetic.yaml"
                source = registry_path.read_text(encoding="utf-8")
                source = source.replace("本记录不授权", f"{leak}；本记录不授权", 1)
                registry_path.write_text(source, encoding="utf-8")
                self._resign_fixture()
                self.assert_reason("registration_evidence_leak_detected", self.verify)

    def test_activation_execution_or_active_true_fail(self) -> None:
        for index, field in enumerate(
            ("activation_authorized", "active", "task_execution_authorized")
        ):
            with self.subTest(field=field):
                if index:
                    self._reset_fixture()
                path = self.fixture_root / HANDOFF_RELATIVE
                handoff = json.loads(path.read_text(encoding="utf-8"))
                handoff["gate_state"][field] = True
                handoff["handoff_digest"]["value"] = _canonical_digest(
                    handoff, ("handoff_digest", "value")
                )
                _write_json(path, handoff)
                self._approve_current_handoff()
                self.assert_reason("activation_boundary_violated", self.verify)

    def test_ledger_permissions_truncation_hash_and_semantic_drift_fail(self) -> None:
        payload = self.verify().ledger_payload()
        ledger = SyntheticAgentRegistrationLedger(self.ledger_path)
        ledger.append_registration(payload, idempotency_key="registration:ledger")

        os.chmod(self.ledger_path, 0o644)
        self.assert_reason("ledger_permissions_too_broad", ledger.replay)
        os.chmod(self.ledger_path, 0o600)

        original = self.ledger_path.read_bytes()
        self.ledger_path.write_bytes(original[:-1])
        os.chmod(self.ledger_path, 0o600)
        self.assert_reason("truncated_record", ledger.replay)

        self.ledger_path.write_bytes(original.replace(b'"registration_status":"draft"', b'"registration_status":"other"'))
        os.chmod(self.ledger_path, 0o600)
        self.assert_reason("registration_semantic_drift", ledger.replay)

        self.ledger_path.write_bytes(original.replace(b'"handoff_id":', b'"handoff_id":"duplicate","handoff_id":', 1))
        os.chmod(self.ledger_path, 0o600)
        self.assert_reason("duplicate_json_key", ledger.replay)

        document = json.loads(original)
        current_hash = document["record_hash"]
        replacement = "0" if current_hash[-1] != "0" else "1"
        document["record_hash"] = current_hash[:-1] + replacement
        self.ledger_path.write_text(
            json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        os.chmod(self.ledger_path, 0o600)
        self.assert_reason("record_hash_mismatch", ledger.replay)

        target = Path(self.temporary.name) / "ledger-target.jsonl"
        target.write_bytes(original)
        os.chmod(target, 0o600)
        link = Path(self.temporary.name) / "ledger-link.jsonl"
        link.symlink_to(target)
        self.assert_reason(
            "ledger_symlink_forbidden",
            SyntheticAgentRegistrationLedger(link).replay,
        )


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


if __name__ == "__main__":
    unittest.main()

