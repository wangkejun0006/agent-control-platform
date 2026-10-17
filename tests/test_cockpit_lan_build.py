"""LAN packaging rejects demo builds and mismatched build evidence."""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "deploy/lan-stage1/verify-cockpit-build.py"
SPEC = importlib.util.spec_from_file_location("cockpit_build_validator_test", PATH)
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class CockpitLanBuildTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        (self.root / "assets").mkdir()
        self.script = self.root / "assets/index-test.js"
        self.script.write_text('export const mode="bff";')
        (self.root / "index.html").write_text(
            '<script type="module" src="/assets/index-test.js"></script>'
        )
        self.manifest = {
            "schema_version": "orbit.cockpit-build-evidence/1",
            "data_mode": "bff",
            "entrypoints": ["assets/index-test.js"],
            "javascript": [
                {
                    "path": "assets/index-test.js",
                    "sha256": "sha256:"
                    + hashlib.sha256(self.script.read_bytes()).hexdigest(),
                }
            ],
        }
        self.write_manifest()
        self.addCleanup(self.directory.cleanup)

    def write_manifest(self):
        (self.root / "orbit-build-evidence.json").write_text(json.dumps(self.manifest))

    def test_accepts_bound_bff_and_rejects_demo(self):
        self.assertEqual("bff", validator.validate_build(self.root)["data_mode"])
        self.manifest["data_mode"] = "demo"
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "requires_bff"):
            validator.validate_build(self.root)

    def test_stale_sidecar_cannot_relabel_another_bundle(self):
        self.script.write_text('export const mode="demo";')
        with self.assertRaisesRegex(RuntimeError, "digest_mismatch"):
            validator.validate_build(self.root)

    def test_html_cannot_select_unbound_javascript(self):
        (self.root / "index.html").write_text(
            '<script src="/assets/old-demo.js"></script>'
        )
        with self.assertRaisesRegex(RuntimeError, "html_entrypoint_mismatch"):
            validator.validate_build(self.root)

    def test_rejects_missing_evidence_duplicate_keys_and_symlinks(self):
        evidence = self.root / "orbit-build-evidence.json"
        evidence.unlink()
        with self.assertRaisesRegex(RuntimeError, "file_missing"):
            validator.validate_build(self.root)
        evidence.write_text('{"data_mode":"demo","data_mode":"bff"}')
        with self.assertRaisesRegex(RuntimeError, "duplicate_json_key"):
            validator.validate_build(self.root)
        self.write_manifest()
        alternate = self.root / "alternate.js"
        self.script.rename(alternate)
        self.script.symlink_to(alternate)
        with self.assertRaisesRegex(RuntimeError, "symlink_rejected"):
            validator.validate_build(self.root)

