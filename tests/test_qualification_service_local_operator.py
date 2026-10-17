from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from orbit_agent_control_plane.service_runtime.config import (
    ServiceConfigurationError,
    ServiceSettings,
)
from orbit_agent_control_plane.service_runtime.local_operator import (
    LocalOperatorError,
    LocalTrustedOperatorGuard,
)
from orbit_agent_control_plane.service_runtime.local_pilot_main import (
    run,
    validate_pilot_enablement,
)


class LocalTrustedOperatorTests(unittest.TestCase):
    def test_current_owner_and_owner_only_files_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            secret = root / "grant-signing-key.pem"
            secret.write_text("non-secret-test-key-material", encoding="utf-8")
            secret.chmod(0o600)
            principal = LocalTrustedOperatorGuard(
                owner_uid=os.geteuid(),
                state_root=root,
                protected_files=(secret,),
            ).verify_current_process()
            self.assertEqual("local_trusted_operator", principal.profile)
            self.assertFalse(principal.release_authorization)
            self.assertFalse(principal.production_authorization)

    def test_group_access_and_wrong_owner_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o750)
            with self.assertRaisesRegex(
                LocalOperatorError, "local_operator_state_root_invalid"
            ):
                LocalTrustedOperatorGuard(
                    owner_uid=os.geteuid(), state_root=root
                ).verify_current_process()
            root.chmod(0o700)
            with self.assertRaisesRegex(
                LocalOperatorError, "local_operator_uid_mismatch"
            ):
                LocalTrustedOperatorGuard(
                    owner_uid=os.geteuid() + 1, state_root=root
                ).verify_current_process()

    def test_local_operator_service_mode_is_loopback_and_api_read_only(self) -> None:
        base = {
            "ORBIT_SERVICE_MODE": "local_trusted_operator",
            "ORBIT_SERVICE_DATABASE_URL": (
                "postgresql+psycopg://pilot@127.0.0.1/orbit_control_plane"
            ),
            "ORBIT_SERVICE_POLICY_PATH": "/tmp/policy.json",
            "ORBIT_SERVICE_REVIEW_PACKAGE_PATH": "/tmp/review.json",
            "ORBIT_SERVICE_PROFILE_PATH": "/tmp/profile.json",
            "ORBIT_SERVICE_HOST": "127.0.0.1",
        }
        settings = ServiceSettings.from_environment(base)
        self.assertEqual("local_trusted_operator", settings.mode)
        self.assertFalse(settings.mutations_enabled)
        base["ORBIT_SERVICE_MUTATIONS_ENABLED"] = "true"
        with self.assertRaisesRegex(
            ServiceConfigurationError, "service_local_operator_api_read_only"
        ):
            ServiceSettings.from_environment(base)
        base["ORBIT_SERVICE_MUTATIONS_ENABLED"] = "false"
        base["ORBIT_SERVICE_HOST"] = "0.0.0.0"
        with self.assertRaisesRegex(ServiceConfigurationError, "service_local_bind_invalid"):
            ServiceSettings.from_environment(base)

    def test_supported_start_entry_validates_owner_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            for name in (
                "postgres-password",
                "database-url",
                "grant-signing-key.pem",
                "grant-signing-public.pem",
            ):
                path = root / name
                path.write_text("test-only", encoding="utf-8")
                path.chmod(0o600)
            output = StringIO()
            with patch(
                "sys.argv",
                ["orbit-agent-control-plane-local-pilot", "--state-root", str(root), "--validate-only"],
            ), redirect_stdout(output):
                run()
            self.assertIn('"profile": "local_trusted_operator"', output.getvalue())
            self.assertIn('"release_authorization": false', output.getvalue())

    def test_provider_start_requires_exact_live_enablement_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(timezone.utc).replace(microsecond=0)
            review = {
                "review_package_digest": "sha256:" + "a" * 64,
                "automation_policy_digest": "sha256:" + "b" * 64,
                "expires_at": (now + timedelta(minutes=10))
                .isoformat()
                .replace("+00:00", "Z"),
                "pilot_budget": {
                    "max_provider_attempts": 3,
                    "max_cost_usd": "0.60",
                    "max_cost_cny": "4.50",
                },
            }
            review_path = root / "review.json"
            review_path.write_text(json.dumps(review), encoding="utf-8")
            raw_digest = "sha256:" + hashlib.sha256(review_path.read_bytes()).hexdigest()
            content = {
                "receipt_version": "orbit.local-public-pilot-enablement-receipt/1",
                "status": "active",
                "scope": "public_r2_pilot_enablement",
                "review_package_raw_digest": raw_digest,
                "review_package_digest": review["review_package_digest"],
                "automation_policy_digest": review["automation_policy_digest"],
                "approved_by_human_ref": "human_local_os_owner",
                "approval_text_digest": "sha256:" + "c" * 64,
                "activated_at": (now - timedelta(seconds=1))
                .isoformat()
                .replace("+00:00", "Z"),
                "expires_at": (now + timedelta(minutes=5))
                .isoformat()
                .replace("+00:00", "Z"),
                "single_pilot": True,
                "max_provider_attempts": 3,
                "max_cost_usd": "0.60",
                "max_cost_cny": "4.50",
                "production_authorization": False,
                "release_authorization": False,
            }
            receipt = {
                **content,
                "receipt_digest": "sha256:"
                + hashlib.sha256(
                    json.dumps(
                        content,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest(),
            }
            receipt_path = root / "receipt.json"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            receipt_path.chmod(0o600)
            self.assertEqual(
                receipt["receipt_digest"],
                validate_pilot_enablement(
                    receipt_path=receipt_path,
                    review_package_path=review_path,
                )["receipt_digest"],
            )
            review_path.write_text(json.dumps({**review, "tampered": True}))
            with self.assertRaisesRegex(SystemExit, "local_pilot_enablement_invalid"):
                validate_pilot_enablement(
                    receipt_path=receipt_path,
                    review_package_path=review_path,
                )


if __name__ == "__main__":
    unittest.main()

