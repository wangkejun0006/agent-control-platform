"""Offline credential acceptance: fake keys and transport, never a provider call."""

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from orbit_agent_control_plane.service_runtime.model_key_validation import (
    KeyTestError,
    ModelKeyTestStore,
)
from orbit_agent_control_plane.service_runtime.model_route import (
    OwnerOnlyFileSecretProvider,
)

NOW = datetime(2026, 9, 4, 10, tzinfo=timezone.utc)
KEY = b"synthetic-only-credential-123456"
REF = "secret://company/model-catalog/catalog_test/current"
REV = "sha256:" + "a" * 64


def policy():
    return {
        "schema_version": "orbit.model-key-test-policy/1",
        "budget_id": "synthetic-test-budget-001",
        "max_cost_microusd": 300000,
        "reservation_microusd": 20480,
        "price_observed_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        "endpoint": "https://models.paper-orbit.invalid/v1/chat/completions",
        "model": "fixture-structured-v1",
        "allowed_returned_models": ["fixture-structured-v1"],
    }


class KeyValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="orbit-key-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.provider = OwnerOnlyFileSecretProvider(self.root / "bindings.json")
        self.store = ModelKeyTestStore(self.provider, now=lambda: NOW)
        self.calls = 0

    def good(self, raw, secret):
        self.calls += 1
        self.assertEqual(secret, KEY)
        self.assertFalse(self.provider.bindings_path.exists())
        state = json.loads(self.store.path.read_text())
        self.assertEqual(
            sum(attempt["status"] == "reserved_outcome_unknown" for attempt in state["attempts"].values()),
            1,
        )
        body = {
            "model": "fixture-structured-v1",
            "usage": {
                "prompt_tokens": 150,
                "completion_tokens": 30,
                "total_tokens": 180,
            },
            "choices": [
                {
                    "message": {"content": '{"status":"ok","sum":5}'},
                    "finish_reason": "stop",
                }
            ],
        }
        return 200, json.dumps(body).encode()

    def run_key(self, transport=None, **updates):
        args = {
            "logical_ref": REF,
            "version": "test-v1",
            "secret": KEY,
            "entry_revision_digest": REV,
            "policy": policy(),
            "transport": transport or self.good,
        }
        args.update(updates)
        return self.store.test_and_bind(**args)

    def test_failed_key_never_writes_secret_or_replaces_existing(self):
        self.provider.bind(REF, b"synthetic-old-working-key", version="old")
        result = self.run_key(lambda *_: (401, b"Bearer do-not-echo"))
        self.assertEqual(result["reason_code"], "model_key_test_authentication_failed")
        self.assertEqual(self.provider.health(REF)["binding_version"], "old")
        self.assertNotIn("do-not-echo", self.store.path.read_text())
        self.assertEqual(len(list((self.root / "values").iterdir())), 1)

    def test_success_saves_only_after_request_and_replays_without_charge(self):
        first = self.run_key()
        again = self.run_key()
        self.assertEqual(first["status"], "verified_and_saved")
        self.assertTrue(again["idempotent_replay"])
        self.assertEqual(self.calls, 1)
        self.assertEqual(self.provider.read(REF), KEY)
        self.assertNotIn(KEY.decode(), self.store.path.read_text())
        self.assertEqual(first["reserved_cost_microusd"], 20480)

    def test_timeout_reservation_survives_and_never_retries(self):
        def timeout(*_):
            self.calls += 1
            raise TimeoutError("secret-must-not-escape")

        first = self.run_key(timeout)
        again = self.run_key()
        self.assertEqual(first["reason_code"], "model_key_test_timeout")
        self.assertEqual(self.calls, 1)
        self.assertTrue(again["idempotent_replay"])
        self.assertFalse(self.provider.bindings_path.exists())
        self.assertNotIn("secret-must-not-escape", self.store.path.read_text())

    def test_crash_after_reservation_is_not_retried(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_key(lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        again = self.run_key()
        self.assertEqual(again["status"], "reserved_outcome_unknown")
        self.assertEqual(self.calls, 0)
        self.assertFalse(self.provider.bindings_path.exists())

    def test_budget_and_policy_drift_rejected_before_request(self):
        self.run_key(lambda *_: (401, b""))
        changed = {**policy(), "max_cost_microusd": 100000}
        with self.assertRaisesRegex(KeyTestError, "budget_policy_drift"):
            self.run_key(policy=changed)
        with self.assertRaisesRegex(KeyTestError, "budget_exceeded"):
            self.run_key(
                version="test-v2",
                policy={
                    **policy(),
                    "budget_id": "tiny-budget-001",
                    "max_cost_microusd": 100,
                },
            )
        self.assertEqual(self.calls, 0)

    def test_unconfigured_provider_expiry_and_non_ascii_key_send_nothing(self):
        for changed in (
            {"model": "another-model"},
            {"endpoint": "http://localhost/test"},
            {"expires_at": (NOW - timedelta(seconds=1)).isoformat()},
        ):
            with self.assertRaises(KeyTestError):
                self.run_key(policy={**policy(), **changed})
        with self.assertRaises(KeyTestError):
            self.run_key(secret="不是 key".encode())
        self.assertEqual(self.calls, 0)
        self.assertFalse(self.provider.bindings_path.exists())

    def test_bad_model_usage_output_or_tool_does_not_save(self):
        for index, change in enumerate(
            ({"model": "wrong-model"}, {"usage": {}}, {"choices": []}), start=1
        ):

            def bad(*_, change=change):
                _, raw = self.good(b"", KEY)
                return 200, json.dumps({**json.loads(raw), **change}).encode()

            # Distinct synthetic budgets; each failed attempt remains spent.
            result = self.run_key(bad, entry_revision_digest="sha256:" + str(index).zfill(64))
            self.assertEqual("test_failed", result["status"])
        self.assertFalse(self.provider.bindings_path.exists())

    def test_concurrent_identical_submissions_call_once(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.run_key(), range(2)))
        self.assertEqual(self.calls, 1)
        self.assertEqual(sum(r.get("idempotent_replay", False) for r in results), 1)

    def test_receipt_is_bound_to_key_version_catalog_model_and_expiry(self):
        self.run_key()
        args = {
            "logical_ref": REF,
            "version": "test-v1",
            "fingerprint": self.provider.health(REF)["secret_fingerprint"],
            "entry_revision_digest": REV,
            "endpoint": policy()["endpoint"],
            "model": policy()["model"],
        }
        self.assertEqual(
            self.store.qualified_health(**args)["status"], "verified_and_saved"
        )
        for changed in (
            {"version": "different"},
            {"entry_revision_digest": "sha256:" + "b" * 64},
            {"fingerprint": "sha256:" + "c" * 64},
            {"model": "different"},
        ):
            with self.assertRaisesRegex(KeyTestError, "required"):
                self.store.qualified_health(**{**args, **changed})
        later = ModelKeyTestStore(self.provider, now=lambda: NOW + timedelta(hours=2))
        with self.assertRaisesRegex(KeyTestError, "required"):
            later.qualified_health(**args)

    def test_save_failure_can_resume_without_another_request(self):
        with patch.object(
            self.provider, "bind", side_effect=OSError("synthetic write failure")
        ):
            first = self.run_key()
        self.assertEqual(first["status"], "verified_not_saved")
        second = self.run_key()
        self.assertEqual(second["status"], "verified_and_saved")
        self.assertEqual(self.calls, 1)

    def test_receipt_write_failure_preserves_reservation_and_no_retry(self):
        original = self.store._write

        def failing(state):
            if any(
                a["status"] != "reserved_outcome_unknown"
                for a in state["attempts"].values()
            ):
                raise OSError("synthetic disk error")
            original(state)

        with (
            patch.object(self.store, "_write", side_effect=failing),
            self.assertRaises(OSError),
        ):
            self.run_key()
        self.assertEqual(self.run_key()["status"], "reserved_outcome_unknown")
        self.assertEqual(self.calls, 1)
        self.assertFalse(self.provider.bindings_path.exists())


class CatalogAcceptanceGateTests(unittest.TestCase):
    def setUp(self):
        from tests.test_model_catalog import ModelCatalogTests

        ModelCatalogTests.setUp(self)
        self.addCleanup(lambda: ModelCatalogTests.tearDown(self))
        self.service.now = lambda: NOW
        with patch("tests.test_model_catalog.NOW", NOW):
            self.entry = ModelCatalogTests._available_entry(
                self, "provider_preset_fixture"
            )
        root = Path(self.temporary.name)
        root.chmod(0o700)
        self.provider = OwnerOnlyFileSecretProvider(root / "bindings.json")
        self.service.model_routes.secret_provider = self.provider
        self.store = ModelKeyTestStore(self.provider, now=lambda: NOW)
        self.service.key_tests = self.store
        self.service.require_live_key_test = True
        self.ref = (
            "secret://company/model-catalog/" + self.entry["entry_id"] + "/current"
        )

    def qualify(self, key="catalog:key:test:001"):
        return self.service.qualify_catalog_api_key(
            entry_id=self.entry["entry_id"],
            expected_entry_revision_digest=self.entry["entry_revision_digest"],
            expected_binding_version="test-v1",
            idempotency_key=key,
            actor_ref="human_admin_syn",
        )

    def test_file_presence_does_not_qualify_or_leave_catalog_selectable(self):
        self.provider.bind(self.ref, KEY, version="test-v1")
        with self.assertRaisesRegex(ValueError, "api_key_test_required"):
            self.qualify()
        item = self.service.list_catalog_entries()["items"][0]
        self.assertFalse(item["can_be_used_for_new_proposals"])
        self.assertFalse(item["live_provider_health_checked"])
        self.assertEqual(item["api_key_test"]["status"], "required")

    def test_verified_exact_key_allows_recording_and_projection_without_network_replay(
        self,
    ):
        def response(*_):
            return 200, json.dumps(
                {
                    "model": "fixture-structured-v1",
                    "choices": [
                        {
                            "message": {"content": '{"status":"ok","sum":5}'},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 86,
                        "completion_tokens": 18,
                        "total_tokens": 104,
                    },
                }
            ).encode()

        result = self.store.test_and_bind(
            logical_ref=self.ref,
            version="test-v1",
            secret=KEY,
            entry_revision_digest=self.entry["entry_revision_digest"],
            policy=policy(),
            transport=response,
        )
        self.assertEqual(result["status"], "verified_and_saved")
        first = self.qualify()
        replay = self.qualify()
        self.assertEqual(first["binding_id"], replay["binding_id"])
        self.assertTrue(replay["idempotent_replay"])
        item = self.service.list_catalog_entries()["items"][0]
        self.assertTrue(item["can_be_used_for_new_proposals"])
        self.assertTrue(item["live_provider_health_checked"])
        self.assertNotIn(KEY.decode(), json.dumps(item))
        self.provider.bind(
            self.ref, b"synthetic-rotated-without-test", version="untested-v2"
        )
        item = self.service.list_catalog_entries()["items"][0]
        self.assertFalse(item["can_be_used_for_new_proposals"])
        self.assertFalse(item["live_provider_health_checked"])

    def test_test_bind_publish_and_renew_preserve_only_verified_credential_source(self):
        def discover(offset):
            self.service.now = lambda: NOW + timedelta(seconds=offset)
            preset = next(
                item
                for item in self.service.list_provider_presets()["items"]
                if item["provider_preset_id"] == "provider_preset_fixture"
            )
            return self.service.discover_provider_models(
                provider_preset_id=preset["provider_preset_id"],
                provider_preset_revision_digest=preset["revision_digest"],
                region_id=preset["regions"][0]["region_id"],
                connection_alias=preset["regions"][0]["connection_aliases"][0],
                idempotency_key=f"catalog:tested:discover:{offset}",
                actor_ref="human_admin_syn",
            )

        self.entry = self.service.create_catalog_entry(
            discovery_digest=discover(10)["discovery_digest"],
            provider_model_key=self.entry["provider_model_key"],
            expected_entry_revision_digest=self.entry["entry_revision_digest"],
            idempotency_key="catalog:tested:successor",
            actor_ref="human_admin_syn",
        )
        tested_revision = self.entry["entry_revision_digest"]
        calls = []

        def response(*_):
            calls.append(1)
            return 200, json.dumps(
                {
                    "model": "fixture-structured-v1",
                    "choices": [
                        {
                            "message": {"content": '{"status":"ok","sum":5}'},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 86,
                        "completion_tokens": 18,
                        "total_tokens": 104,
                    },
                }
            ).encode()

        self.store.test_and_bind(
            logical_ref=self.ref,
            version="test-v1",
            secret=KEY,
            entry_revision_digest=tested_revision,
            policy=policy(),
            transport=response,
        )
        self.qualify()
        self.service.publish_catalog_entry(
            entry_id=self.entry["entry_id"],
            expected_entry_revision_digest=tested_revision,
            reason="synthetic verified key publication",
            idempotency_key="catalog:tested:publish",
            actor_ref="human_admin_syn",
        )
        published = self.service.list_catalog_entries()["items"][0]
        self.assertNotEqual(tested_revision, published["entry_revision_digest"])
        self.assertTrue(published["live_provider_health_checked"])
        self.assertTrue(published["can_be_used_for_new_proposals"])
        self.assertEqual("verified_and_saved", published["api_key_test"]["status"])
        self.assertEqual(1, len(calls))
        # A new catalog configuration does not inherit the publication-only source.
        renewed = self.service.create_catalog_entry(
            discovery_digest=discover(20)["discovery_digest"],
            provider_model_key=published["provider_model_key"],
            expected_entry_revision_digest=published["entry_revision_digest"],
            idempotency_key="catalog:tested:renew",
            actor_ref="human_admin_syn",
        )
        self.assertFalse(renewed["live_provider_health_checked"])
        self.assertFalse(renewed["can_be_used_for_new_proposals"])
        self.assertEqual("required", renewed["api_key_test"]["status"])
        self.assertEqual(1, len(calls))


class KeyImportCliTests(unittest.TestCase):
    def test_legacy_bind_refuses_catalog_before_reading_key(self):
        from orbit_agent_control_plane.service_runtime.model_route_cli import (
            build_parser,
            run,
        )

        args = build_parser().parse_args(
            [
                "bind-secret",
                "--secret-bindings",
                "/synthetic/bindings.json",
                "--secret-family-ref",
                REF,
                "--secret-version",
                "test-v1",
            ]
        )
        with (
            patch("getpass.getpass", side_effect=AssertionError("must not read key")),
            self.assertRaisesRegex(ValueError, "catalog_key_test_required"),
        ):
            run(args)

    def test_paid_entry_requires_visible_terminal_and_explicit_policy(self):
        from orbit_agent_control_plane.service_runtime.model_route_cli import (
            build_parser,
            run,
        )

        args = build_parser().parse_args(
            [
                "test-bind-secret",
                "--secret-bindings",
                "/synthetic/bindings.json",
                "--secret-family-ref",
                REF,
                "--secret-version",
                "test-v1",
            ]
        )
        with (
            patch("getpass.getpass", side_effect=AssertionError("must not read key")),
            self.assertRaisesRegex(ValueError, "interactive_policy_required"),
        ):
            run(args)

