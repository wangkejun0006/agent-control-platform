from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path, PurePosixPath

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".agents/skills/orbit-agent-lifecycle-review/scripts/verify_artifact_set.py"
)
SPEC = importlib.util.spec_from_file_location("orbit_lifecycle_review_verify", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFY_MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY_MODULE)


def _canonical_handoff_digest(manifest: dict[str, object]) -> str:
    canonical = copy.deepcopy(manifest)
    del canonical["handoff_digest"]["value"]  # type: ignore[index]
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class LifecycleReviewSkillTest(unittest.TestCase):
    def _fixture(self, root: Path) -> Path:
        artifact = root / "registration/record.synthetic.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b'{"synthetic_only":true}\n')
        manifest: dict[str, object] = {
            "schema_version": "orbit.agent-registration-handoff-manifest/1.0",
            "handoff_digest": {
                "algorithm": "sha256",
                "canonicalization": "orbit.canonical-json/1.0",
                "value": "",
            },
            "registration_artifacts": [
                {
                    "path": "registration/record.synthetic.json",
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }
            ],
            "release_authorization": False,
            "activation_authorized": False,
        }
        manifest["handoff_digest"]["value"] = _canonical_handoff_digest(  # type: ignore[index]
            manifest
        )
        path = root / "registration/handoff.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def _artifact_set_v2(self, root: Path) -> tuple[Path, dict[str, object]]:
        artifact = root / "runtime/source.synthetic.json"
        artifact.parent.mkdir(parents=True)
        artifact.write_text('{"effective":false}\n', encoding="utf-8")
        subject = "sha256:" + ("a" * 64)
        manifest: dict[str, object] = {
            "manifest_version": "orbit.lifecycle-review-artifact-set/2",
            "manifest_type": "runtime_execution_review",
            "algorithm": "sha256",
            "canonicalization": "orbit.canonical-json/1.0",
            "evidence_status": "synthetic",
            "artifacts": [
                {
                    "path": "runtime/source.synthetic.json",
                    "sha256": "sha256:"
                    + hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }
            ],
            "digest_bindings": {
                "subjects": [
                    {
                        "scope_kind": "agent_activation",
                        "subject_id": "agt_fixture_syn",
                        "subject_digest": subject,
                    },
                    {
                        "scope_kind": "r2_execution",
                        "subject_id": "review_fixture_syn",
                        "subject_digest": "sha256:" + ("c" * 64),
                    },
                    {
                        "scope_kind": "automation_policy_activation",
                        "subject_id": "policy_fixture_syn",
                        "subject_digest": "sha256:" + ("d" * 64),
                    },
                ],
                "approval_receipts": [
                    {
                        "scope_kind": "agent_activation",
                        "subject_digest": subject,
                        "approval_receipt_digest": "sha256:" + ("b" * 64),
                        "ledger_revision": 1,
                        "approval_action": "activate",
                        "current_status": "active",
                        "expires_at": None,
                        "consumption_status": "not_applicable",
                    }
                ],
                "pending_approval_scopes": [
                    "automation_policy_activation",
                    "r2_execution",
                ],
            },
            "release_authorization": False,
            "activation_authorized": False,
            "runtime_started": False,
            "effective": False,
        }
        path = root / "review/artifact-set.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path, manifest

    def _verify_v2(self, root: Path, path: Path) -> dict[str, object]:
        return VERIFY_MODULE.verify(
            root, PurePosixPath(path.relative_to(root).as_posix())
        )

    def _artifact_set_v3(self, root: Path) -> tuple[Path, dict[str, object]]:
        path, manifest = self._artifact_set_v2(root)
        profile_path = VERIFY_MODULE.CONCEPT_PROFILE_PATH
        profile_raw = profile_path.read_bytes()
        profile = json.loads(profile_raw)
        manifest["manifest_version"] = "orbit.lifecycle-review-artifact-set/3"
        manifest["concept_bindings"] = {
            "binding_version": "orbit.lifecycle-review-concept-bindings/1",
            "profile_version": profile["profile_version"],
            "profile_sha256": "sha256:" + hashlib.sha256(profile_raw).hexdigest(),
            "architecture_commit": profile["source"]["commit"],
            "catalog_sha256": profile["source"]["catalog_sha256"],
            "concept_ids": sorted(profile["concept_ids"]),
        }
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path, manifest

    def test_registration_handoff_artifacts_and_digest_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            result = VERIFY_MODULE.verify(
                root, PurePosixPath(manifest.relative_to(root).as_posix())
            )
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["handoff_digest"].startswith("sha256:"))
            self.assertFalse(result["release_authorization"])
            self.assertFalse(result["activation_authorized"])

    def test_registration_handoff_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self._fixture(root)
            (root / "registration/record.synthetic.json").write_text(
                '{"synthetic_only":false}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(
                VERIFY_MODULE.ReviewError, "artifact_digest_mismatch"
            ):
                VERIFY_MODULE.verify(
                    root, PurePosixPath(manifest.relative_to(root).as_posix())
                )

    def test_v2_artifact_set_strict_profile_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _ = self._artifact_set_v2(root)
            result = self._verify_v2(root, path)
            self.assertEqual("PASS", result["status"])
            self.assertEqual("lifecycle_artifact_set_v2", result["manifest_profile"])
            self.assertFalse(result["runtime_started"])
            self.assertFalse(result["effective"])

    def test_v3_artifact_set_binds_published_concept_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, manifest = self._artifact_set_v3(root)
            result = self._verify_v2(root, path)
            self.assertEqual("PASS", result["status"])
            self.assertEqual("lifecycle_artifact_set_v3", result["manifest_profile"])
            self.assertEqual(
                manifest["concept_bindings"]["architecture_commit"],  # type: ignore[index]
                result["concept_bindings"]["architecture_commit"],  # type: ignore[index]
            )
            self.assertIn(
                "orbit.concept/execution-grant",
                result["concept_bindings"]["concept_ids"],  # type: ignore[index]
            )

    def test_v3_concept_source_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, manifest = self._artifact_set_v3(root)
            manifest["concept_bindings"]["catalog_sha256"] = (  # type: ignore[index]
                "sha256:" + ("0" * 64)
            )
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY_MODULE.ReviewError, "concept_bindings_source_drift"
            ):
                self._verify_v2(root, path)

    def test_v3_missing_effective_authority_concept_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, manifest = self._artifact_set_v3(root)
            concepts = manifest["concept_bindings"]["concept_ids"]  # type: ignore[index]
            concepts.remove("orbit.concept/execution-grant")
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY_MODULE.ReviewError, "concept_bindings_required_id_missing"
            ):
                self._verify_v2(root, path)

    def test_v3_unknown_or_alias_concept_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, manifest = self._artifact_set_v3(root)
            concepts = manifest["concept_bindings"]["concept_ids"]  # type: ignore[index]
            concepts.append("orbit.concept/grant")
            concepts.sort()
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY_MODULE.ReviewError, "concept_bindings_unknown_id"
            ):
                self._verify_v2(root, path)

    def test_v2_wrong_algorithm_canonicalization_and_unknown_field_fail(self) -> None:
        mutations = (
            ("algorithm", "sha512", "artifact_set_algorithm_invalid"),
            (
                "canonicalization",
                "json-default",
                "artifact_set_canonicalization_invalid",
            ),
            ("unknown", True, "artifact_set_v2_fields_invalid"),
        )
        for field, value, reason in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, manifest = self._artifact_set_v2(root)
                manifest[field] = value
                path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(VERIFY_MODULE.ReviewError, reason):
                    self._verify_v2(root, path)

    def test_v2_authority_widening_is_rejected(self) -> None:
        for field in (
            "release_authorization",
            "activation_authorized",
            "runtime_started",
            "effective",
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, manifest = self._artifact_set_v2(root)
                manifest[field] = True
                path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(
                    VERIFY_MODULE.ReviewError, "authority_widening_forbidden"
                ):
                    self._verify_v2(root, path)

    def test_subject_digest_cannot_masquerade_as_approval_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, manifest = self._artifact_set_v2(root)
            bindings = manifest["digest_bindings"]  # type: ignore[index]
            receipt = bindings["approval_receipts"][0]  # type: ignore[index]
            receipt["approval_receipt_digest"] = receipt["subject_digest"]
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY_MODULE.ReviewError,
                "subject_digest_used_as_approval_receipt",
            ):
                self._verify_v2(root, path)

    def test_v2_path_traversal_duplicate_path_and_symlink_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, manifest = self._artifact_set_v2(root)
            manifest["artifacts"][0]["path"] = "../escape.json"  # type: ignore[index]
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY_MODULE.ReviewError, "artifact_path_unsafe"
            ):
                self._verify_v2(root, path)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, manifest = self._artifact_set_v2(root)
            manifest["artifacts"].append(copy.deepcopy(manifest["artifacts"][0]))  # type: ignore[index]
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY_MODULE.ReviewError, "artifact_path_duplicated"
            ):
                self._verify_v2(root, path)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, manifest = self._artifact_set_v2(root)
            target = root / "runtime/source.synthetic.json"
            link = root / "runtime/link.synthetic.json"
            link.symlink_to(target)
            manifest["artifacts"][0]["path"] = "runtime/link.synthetic.json"  # type: ignore[index]
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY_MODULE.ReviewError, "artifact_symlink_forbidden"
            ):
                self._verify_v2(root, path)

    def test_v2_duplicate_key_nan_and_artifact_unknown_field_fail(self) -> None:
        cases = (
            ('"effective": false, "effective": false', "duplicate_json_key"),
            ('"effective": NaN', "invalid_json_constant"),
        )
        for replacement, reason in cases:
            with (
                self.subTest(reason=reason),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                path, manifest = self._artifact_set_v2(root)
                source = json.dumps(manifest).replace('"effective": false', replacement)
                path.write_text(source, encoding="utf-8")
                with self.assertRaisesRegex(VERIFY_MODULE.ReviewError, reason):
                    self._verify_v2(root, path)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, manifest = self._artifact_set_v2(root)
            manifest["artifacts"][0]["role"] = "runtime"  # type: ignore[index]
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY_MODULE.ReviewError, "artifact_entry_fields_invalid"
            ):
                self._verify_v2(root, path)


if __name__ == "__main__":
    unittest.main()

