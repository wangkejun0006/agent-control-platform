from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from orbit_agent_control_plane.lifecycle_assurance import LifecycleAssuranceError
from orbit_agent_control_plane.provider_environment import (
    load_provider_environment_file,
)


VALID_ENVIRONMENT = """ORBIT_MODEL_PROVIDER_ID=synthetic-provider
ORBIT_MODEL_BASE_URL=https://provider.example.invalid
ORBIT_MODEL_ID=synthetic-model
ORBIT_MODEL_ALLOWED_RETURNED_IDS=synthetic-model
ORBIT_MODEL_SECRET_REF=env:ORBIT_TEST_API_KEY
ORBIT_MODEL_CNY_PER_USD=10
ORBIT_TEST_API_KEY=synthetic-secret-value
"""


class ProviderEnvironmentFileTest(unittest.TestCase):
    @staticmethod
    def write_file(root: str, content: str = VALID_ENVIRONMENT) -> Path:
        path = Path(root) / ".env"
        path.write_text(content, encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_owner_only_file_loads_exact_provider_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = load_provider_environment_file(
                self.write_file(temporary)
            )

        self.assertEqual("synthetic-provider", environment["ORBIT_MODEL_PROVIDER_ID"])
        self.assertEqual("synthetic-secret-value", environment["ORBIT_TEST_API_KEY"])
        self.assertEqual(7, len(environment))

    def test_symlink_and_broad_permissions_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = self.write_file(temporary)
            os.chmod(target, 0o644)
            with self.assertRaises(LifecycleAssuranceError) as caught:
                load_provider_environment_file(target)
            self.assertEqual(
                "provider_environment_file_insecure", caught.exception.reason_code
            )

            os.chmod(target, 0o600)
            hard_link = Path(temporary) / ".env.hard-link"
            os.link(target, hard_link)
            with self.assertRaises(LifecycleAssuranceError) as caught:
                load_provider_environment_file(target)
            self.assertEqual(
                "provider_environment_file_insecure", caught.exception.reason_code
            )
            hard_link.unlink()

            alias = Path(temporary) / ".env.alias"
            alias.symlink_to(target)
            with self.assertRaises(LifecycleAssuranceError) as caught:
                load_provider_environment_file(alias)
            self.assertEqual(
                "provider_environment_file_insecure", caught.exception.reason_code
            )

    def test_duplicate_shell_syntax_unknown_and_missing_secret_fail_closed(self) -> None:
        cases = (
            (
                VALID_ENVIRONMENT + "ORBIT_MODEL_ID=duplicate\n",
                "provider_environment_file_duplicate_key",
            ),
            (
                VALID_ENVIRONMENT.replace(
                    "ORBIT_MODEL_ID=synthetic-model",
                    "export ORBIT_MODEL_ID=synthetic-model",
                ),
                "provider_environment_file_invalid",
            ),
            (
                VALID_ENVIRONMENT.replace(
                    "ORBIT_MODEL_ID=synthetic-model",
                    'ORBIT_MODEL_ID="synthetic-model"',
                ),
                "provider_environment_file_invalid",
            ),
            (
                VALID_ENVIRONMENT.replace(
                    "ORBIT_MODEL_ID=synthetic-model",
                    "ORBIT_MODEL_ID=$(unsupported-command)",
                ),
                "provider_environment_file_invalid",
            ),
            (
                VALID_ENVIRONMENT + "UNRELATED_API_KEY=synthetic-other-secret\n",
                "provider_environment_unknown_key",
            ),
            (
                VALID_ENVIRONMENT.replace(
                    "ORBIT_TEST_API_KEY=synthetic-secret-value\n", ""
                ),
                "provider_environment_secret_missing",
            ),
        )
        for content, reason_code in cases:
            with self.subTest(reason_code=reason_code):
                with tempfile.TemporaryDirectory() as temporary:
                    path = self.write_file(temporary, content)
                    with self.assertRaises(LifecycleAssuranceError) as caught:
                        load_provider_environment_file(path)
                    self.assertEqual(reason_code, caught.exception.reason_code)


if __name__ == "__main__":
    unittest.main()

