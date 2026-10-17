"""Offline safety and native integration checks. Never reads credentials."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from showcase.live_budget import (
    RESERVATION,
    Campaign,
    LiveError,
    atomic_private,
    encoded,
    strict_json,
)
from showcase.live_flow import (
    ControlledTools,
    _workflow_questions,
    _workflow_required_sections,
    run_campaign,
    source_snapshot,
)

GOLDEN = {"low_stock": ["PO-102"], "open_support": 2, "shipment_units": 8}
CANDIDATE = {
    "summary": "Fictional report: PO-102 needs stock review. Two open tickets and eight shipped units. No support/shipment join key; owner should inspect evidence before acting.",
    "citations": ["PO-102", "T-001", "T-004", "S-001", "S-002"],
    "metrics": GOLDEN,
}


def call(name, arguments=None, call_id="call_1"):
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments or {})},
    }


def response(message=None):
    return {
        "id": "offline_fake_response",
        "model": "deepseek-flash",
        "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        "choices": [
            {
                "finish_reason": "tool_calls"
                if message and message.get("tool_calls")
                else "stop",
                "message": message or {"role": "assistant", "content": "offline fake"},
            }
        ],
    }


class FakeProvider:
    def __init__(self):
        self.calls = 0

    def __call__(self, body):
        self.calls += 1
        payload = strict_json(body)
        if payload.get("response_format"):
            if "exact structure/IDs" in payload["messages"][0]["content"]:
                output = {
                    "result_kind": "questions",
                    "questions": _workflow_questions("product_center", 1, strict=True),
                }
            else:
                output = {
                    "result_kind": "task_package_candidate",
                    "candidate": {
                        "sections": [
                            {
                                "name": name,
                                "summary": "Query fixture, compute deterministic metrics, submit candidate, then scripted reviewer approves or requests changes.",
                            }
                            for name in _workflow_required_sections("product_center")
                        ],
                        "risk_summary": "No causal joins; only local fictional data; never publish.",
                    },
                }
            message = {
                "role": "assistant",
                "content": json.dumps(output, ensure_ascii=False),
            }
        elif "Untrusted fixture" in payload["messages"][0]["content"]:
            message = {
                "role": "assistant",
                "content": "Refused untrusted instructions.",
            }
        elif not any(m["role"] == "tool" for m in payload["messages"]):
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    call("query_fixture"),
                    call("compute_metrics", call_id="call_2"),
                ],
            }
        else:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [call("submit_candidate", CANDIDATE, "call_3")],
            }
        for index, tool_call in enumerate(message.get("tool_calls", [])):
            tool_call["index"] = index
        return 200, encoded(response(message))


class LiveCampaignTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "campaign"
        self.previous_umask = os.umask(0o077)

    def tearDown(self):
        os.umask(self.previous_umask)
        self.temporary.cleanup()

    def campaign(self, transport=None, **kwargs):
        return Campaign.authorize(
            self.root,
            authorization_ref="offline-test",
            transport=transport or FakeProvider(),
            **kwargs,
        )

    def chat(self, campaign, key="1"):
        return campaign.chat(
            key=key, phase="test", messages=[{"role": "user", "content": "test"}]
        )

    def test_shared_limit_restart_and_idempotency(self):
        provider = FakeProvider()
        campaign = self.campaign(provider, max_requests=1)
        self.chat(campaign)
        self.chat(Campaign(self.root, transport=provider))
        self.assertEqual(provider.calls, 1)
        with self.assertRaisesRegex(LiveError, "request_budget_exhausted"):
            self.chat(campaign, "2")
        campaign.close("done")
        with self.assertRaisesRegex(LiveError, "campaign_closed"):
            self.chat(campaign)

    def test_failure_counts_reserves_and_never_retries(self):
        campaign = self.campaign(
            lambda _: (429, b"never log provider secret/error"), max_requests=1
        )
        with self.assertRaisesRegex(LiveError, "provider_http_rejected"):
            self.chat(campaign)
        self.assertEqual(Campaign.charge(campaign.state()), RESERVATION)
        with self.assertRaisesRegex(LiveError, "previous_attempt_not_retryable"):
            self.chat(campaign)
        self.assertEqual(len(campaign.state()["attempts"]), 1)
        self.assertNotIn("secret/error", campaign.path.read_text())

    def test_unknown_usage_stops_campaign(self):
        campaign = self.campaign(
            lambda _: (200, encoded({"model": "unapproved-model"}))
        )
        with self.assertRaisesRegex(LiveError, "returned_model_not_allowed"):
            self.chat(campaign)
        self.assertTrue(campaign.state()["closed"])

    def test_cost_and_input_rejected_before_transport(self):
        provider = FakeProvider()
        campaign = self.campaign(provider, max_cost_micros=1)
        with self.assertRaisesRegex(LiveError, "cost_budget_exhausted"):
            self.chat(campaign)
        with self.assertRaisesRegex(LiveError, "input_reservation_exceeded"):
            campaign.chat(
                key="big",
                phase="test",
                messages=[{"role": "user", "content": "x" * 9000}],
            )
        self.assertEqual(provider.calls, 0)

    def test_repair_preserves_attempts_reservations_and_caps(self):
        campaign = self.campaign(lambda _: (429, b""), max_requests=2)
        with self.assertRaises(LiveError):
            self.chat(campaign)
        campaign.close("recoverable_operator_check")
        campaign.resume_remaining_authorization()
        campaign.transport = FakeProvider()
        self.chat(campaign, "2")
        self.assertEqual(len(campaign.state()["attempts"]), 2)
        self.assertGreater(Campaign.charge(campaign.state()), RESERVATION)
        with self.assertRaisesRegex(LiveError, "request_budget_exhausted"):
            self.chat(campaign, "3")

    def test_unknown_usage_close_cannot_be_overwritten(self):
        campaign = self.campaign(lambda _: (200, encoded({"model": "unapproved"})))
        with self.assertRaises(LiveError):
            self.chat(campaign)
        campaign.close("less_specific_outer_failure")
        self.assertEqual(campaign.state()["close_reason"], "unverified_provider_usage")
        with self.assertRaisesRegex(LiveError, "campaign_not_resumable"):
            campaign.resume_remaining_authorization()

    def test_event_tampering_is_detected(self):
        campaign = self.campaign()
        campaign.event("check", {"passed": True})
        state = campaign.state()
        state["events"][0]["payload"]["passed"] = False
        atomic_private(campaign.path, state)
        with self.assertRaisesRegex(LiveError, "campaign_event_chain_invalid"):
            campaign.state()

    def test_source_drift_and_persistent_revocation(self):
        campaign = self.campaign()
        campaign.event("source_snapshot", source_snapshot())
        tools = ControlledTools(campaign, "sourcecheck", 1)
        with patch(
            "showcase.live_flow.source_snapshot", return_value={"drift": "changed"}
        ):
            self.assertEqual(
                tools.execute(call("query_fixture"))["error"],
                "tool_source_revision_drift",
            )
        campaign.event("grant_revoked", {"task_id": "sourcecheck", "revision": 1})
        restarted = ControlledTools(campaign, "sourcecheck", 1)
        self.assertEqual(
            restarted.execute(call("query_fixture"))["error"], "execution_grant_revoked"
        )

    def test_duplicate_json_and_candidate_gate(self):
        with self.assertRaisesRegex(LiveError, "duplicate_json_key"):
            strict_json('{"a":1,"a":2}')
        campaign = self.campaign()
        tools = ControlledTools(campaign, "gatecheck", 1)
        self.assertIn("error", tools.execute(call("submit_candidate", CANDIDATE)))
        self.assertIn(
            "error", tools.execute(call("query_fixture", {"path": "/etc/passwd"}))
        )
        self.assertIn("error", tools.execute(call("publish_now")))
        tools.revoked = True
        self.assertEqual(
            tools.execute(call("query_fixture"))["error"], "execution_grant_revoked"
        )

    def test_actual_process_receipts_idempotent_restart(self):
        campaign = self.campaign()
        first = ControlledTools(campaign, "actualprocess", 1).execute(
            call("query_fixture")
        )
        second = ControlledTools(campaign, "actualprocess", 1).execute(
            call("query_fixture", call_id="new_id")
        )
        self.assertEqual(first, second)
        self.assertFalse(first["credential_environment_present"])
        self.assertIsInstance(first["pid"], int)
        self.assertEqual(
            len([e for e in campaign.state()["events"] if e["kind"] == "tool_receipt"]),
            1,
        )

    def test_native_planning_tools_rework_review_full_offline(self):
        campaign = self.campaign()
        run_campaign(campaign)
        state = campaign.state()
        self.assertTrue(state["closed"])
        self.assertLessEqual(len(state["attempts"]), 24)
        reviews = [
            e["payload"] for e in state["events"] if e["kind"] == "scripted_review"
        ]
        self.assertEqual(
            [r["decision"] for r in reviews], ["request_changes", "approve", "approve"]
        )
        self.assertTrue(all(r["authenticated_human"] is False for r in reviews))
        self.assertEqual(
            len([e for e in state["events"] if e["kind"] == "native_plan_approval"]), 3
        )
        self.assertEqual(
            len([e for e in state["events"] if e["kind"] == "tool_receipt"]), 9
        )


if __name__ == "__main__":
    unittest.main()
