"""Public packaging boundaries and optional configuration, without credentials."""

import runpy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.export_release import ROOT, public_files
from showcase.live_budget import LiveError, load_secret, provider_proxy


class ReleaseCandidateTests(unittest.TestCase):
    def test_public_manifest_has_portable_case_and_excludes_private_material(self):
        paths = {p.relative_to(ROOT).as_posix() for p in public_files()}
        for name in (
            "LICENSE",
            "README.md",
            "examples/delivery-snapshot/local-delivery.zip",
            ".github/workflows/offline.yml",
            "scripts/run_qualification_service_postgres_harness.py",
            "examples/historical-workbench/delivery.zip",
        ):
            self.assertIn(name, paths)
        self.assertNotIn("scripts/prepare_showcase.py", paths)
        self.assertFalse(
            any(
                part.endswith((".egg-info", ".dist-info"))
                for name in paths
                for part in Path(name).parts
            )
        )
        self.assertFalse(
            any(
                p.startswith((".runtime/", ".agent/", ".venv/"))
                or p.endswith((".pem", ".sqlite3", ".pyc"))
                for p in paths
            )
        )

    def test_optional_native_harness_requires_installer_even_with_powershell(self):
        harness = ROOT / "tests/test_department_wsl_native_transport.py"
        for helper_present in (False, True):
            with (
                self.subTest(helper_present=helper_present),
                patch("shutil.which", return_value="/synthetic/pwsh"),
                patch("pathlib.Path.is_file", return_value=helper_present),
                patch("os.name", "posix"),
            ):
                loaded = runpy.run_path(str(harness))
                case = loaded["DepartmentWslNativeTransportTests"]
                self.assertEqual(
                    getattr(case, "__unittest_skip__", False), not helper_present
                )

    def test_configured_file_selection_uses_mock_bytes_not_existing_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "fake-only.env")
            with (
                patch.dict("os.environ", {"ORBIT_MODEL_CREDENTIAL_FILE": path}),
                patch(
                    "showcase.live_budget.private_read",
                    return_value=b"DEEPSEEK_API_KEY=offline-fixture-only-value",
                ) as read,
            ):
                self.assertEqual(load_secret(), "offline-fixture-only-value")
                read.assert_called_once_with(Path(path))
        with (
            patch.dict("os.environ", {"ORBIT_MODEL_CREDENTIAL_FILE": "relative.env"}),
            patch(
                "showcase.live_budget.private_read",
                side_effect=AssertionError("no_file_read"),
            ),
            self.assertRaisesRegex(LiveError, "absolute"),
        ):
            load_secret()

    def test_proxy_direct_local_and_no_auth_or_external_proxy(self):
        for value, expected in (
            ("direct", {}),
            ("http://localhost:12345", {"https": "http://localhost:12345"}),
        ):
            with patch.dict("os.environ", {"ORBIT_MODEL_PROXY": value}):
                self.assertEqual(provider_proxy(), expected)
        for value in (
            "https://proxy.invalid",
            "http://user:pass@localhost:123",
            "http://localhost:12/?token=secret",
        ):
            with (
                patch.dict("os.environ", {"ORBIT_MODEL_PROXY": value}),
                self.assertRaises(LiveError),
            ):
                provider_proxy()
