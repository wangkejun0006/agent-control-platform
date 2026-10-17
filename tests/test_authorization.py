import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from orbit_agent_control_plane.authorization import (
    AuthorizationError,
    SyntheticOperatorGrant,
    authorize_control,
    load_synthetic_operator_grant,
)


class SyntheticOperatorAuthorizationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.grant = SyntheticOperatorGrant(
            version="orbit.synthetic-operator-grant/1",
            grant_id="operator_grant_company_control_syn",
            operator_ref="human_operator_cli_syn",
            task_id="task_company_d0_probe_syn",
            allowed_actions=("pause", "revoke", "cancel", "takeover"),
            issued_at="2026-08-19T01:00:00Z",
            expires_at="2026-08-19T01:15:00Z",
            evidence_status="synthetic",
            synthetic_only=True,
        )

    def authorize(self, **overrides: object):
        arguments = {
            "operator_ref": "human_operator_cli_syn",
            "task_id": "task_company_d0_probe_syn",
            "action": "pause",
            "request_reason": "D0 synthetic pause verification",
            "checked_at": "2026-08-19T01:05:00Z",
            "confirmed_action": "pause",
        }
        arguments.update(overrides)
        return authorize_control(self.grant, **arguments)

    def test_exact_short_lived_grant_and_confirmation_allow_control(self) -> None:
        decision = self.authorize()

        self.assertTrue(decision.allowed)
        self.assertEqual(("synthetic_operator_authorized",), decision.reason_codes)
        self.assertEqual(self.grant, decision.grant_snapshot)
        self.assertEqual("pause", decision.confirmed_action)

    def test_identity_task_action_time_and_confirmation_fail_closed(self) -> None:
        cases = (
            ({"operator_ref": "human_operator_other_syn"}, "operator_identity_mismatch"),
            ({"task_id": "task_other_syn"}, "operator_grant_task_mismatch"),
            ({"action": "resume", "confirmed_action": "resume"}, "control_action_not_allowed"),
            ({"checked_at": "2026-08-19T00:59:59Z"}, "operator_grant_not_yet_valid"),
            ({"checked_at": "2026-08-19T01:15:00Z"}, "operator_grant_expired"),
            ({"confirmed_action": "cancel"}, "operator_confirmation_mismatch"),
            ({"request_reason": "short"}, "control_reason_invalid"),
        )
        for overrides, reason_code in cases:
            with self.subTest(reason_code=reason_code):
                decision = self.authorize(**overrides)
                self.assertFalse(decision.allowed)
                self.assertIn(reason_code, decision.reason_codes)

    def test_non_synthetic_wildcard_and_long_lived_grants_are_rejected(self) -> None:
        cases = (
            (replace(self.grant, synthetic_only=False), "operator_grant_not_synthetic"),
            (replace(self.grant, allowed_actions=("*",)), "operator_grant_action_invalid"),
            (
                replace(self.grant, expires_at="2026-08-19T01:15:01Z"),
                "operator_grant_not_short_lived",
            ),
        )
        for grant, reason_code in cases:
            with self.subTest(reason_code=reason_code):
                with self.assertRaises(AuthorizationError) as raised:
                    authorize_control(
                        grant,
                        operator_ref="human_operator_cli_syn",
                        task_id="task_company_d0_probe_syn",
                        action="pause",
                        request_reason="D0 synthetic pause verification",
                        checked_at="2026-08-19T01:05:00Z",
                        confirmed_action="pause",
                    )
                self.assertEqual(reason_code, raised.exception.reason_code)

    def test_grant_file_rejects_duplicate_keys_symlinks_and_broad_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / "operator-grant.synthetic.json"
            document = {
                "version": self.grant.version,
                "grant_id": self.grant.grant_id,
                "operator_ref": self.grant.operator_ref,
                "task_id": self.grant.task_id,
                "allowed_actions": list(self.grant.allowed_actions),
                "issued_at": self.grant.issued_at,
                "expires_at": self.grant.expires_at,
                "evidence_status": self.grant.evidence_status,
                "synthetic_only": self.grant.synthetic_only,
            }
            path.write_text(json.dumps(document), encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertEqual(self.grant, load_synthetic_operator_grant(path))

            duplicate = json.dumps(document).replace(
                '"grant_id":', '"grant_id": "operator_grant_duplicate_syn", "grant_id":', 1
            )
            path.write_text(duplicate, encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaises(AuthorizationError) as raised:
                load_synthetic_operator_grant(path)
            self.assertEqual("duplicate_json_key", raised.exception.reason_code)

            path.write_text(json.dumps(document), encoding="utf-8")
            os.chmod(path, 0o644)
            with self.assertRaises(AuthorizationError) as raised:
                load_synthetic_operator_grant(path)
            self.assertEqual("operator_grant_permissions_too_broad", raised.exception.reason_code)

            os.chmod(path, 0o600)
            link = directory / "operator-grant-link.synthetic.json"
            link.symlink_to(path)
            with self.assertRaises(AuthorizationError) as raised:
                load_synthetic_operator_grant(link)
            self.assertEqual("operator_grant_symlink_forbidden", raised.exception.reason_code)


if __name__ == "__main__":
    unittest.main()

