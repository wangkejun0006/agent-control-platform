"""Exact new campaign driver, offline transport; no secret resolution."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from showcase.live_budget import Campaign, LiveError, encoded
from showcase.workbench.sharing_validation import SharingValidation, run_campaign
from tests.test_workbench_live import fake_provider


def sharing_fixture(raw):
    request = json.loads(raw)
    user = json.loads(request["messages"][1]["content"])
    if "resource" not in user:
        return fake_provider(raw)
    resource = user["resource"]
    allowed = bool(
        resource["approved"] and "technology_center" in resource["shared_to"]
    )
    return 200, encoded(
        {
            "id": "offline-sharing-fixture",
            "model": request["model"],
            "usage": {"prompt_tokens": 100, "completion_tokens": 100},
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": json.dumps(
                            {
                                "decision": "allow" if allowed else "reject",
                                "readable_refs": ["approved-artifact@2"]
                                if allowed
                                else [],
                                "source_documents_allowed": False,
                                "reason": "按已批准、显式共享及绑定版本分别判断；来源资料未共享不可访问。",
                            },
                            ensure_ascii=False,
                        )
                    },
                }
            ],
        }
    )


class SharingCampaignTests(unittest.TestCase):
    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.guard = patch(
            "showcase.live_budget.load_secret",
            side_effect=AssertionError("no_keys_offline"),
        )
        self.guard.start()

    def tearDown(self):
        self.guard.stop()
        self.temp.cleanup()
        os.umask(self.previous_umask)

    def campaign(self, transport=sharing_fixture):
        return Campaign.authorize(
            self.root / "campaign",
            authorization_ref="offline-sharing-driver-test",
            input_price=3,
            output_price=12,
            transport=transport,
        )

    def test_exact_full_round_23_requests_handoffs_rework_and_immutable_history(self):
        campaign = self.campaign()
        report = run_campaign(
            campaign, self.root / "state", self.root / "report.json", offline=True
        )
        self.assertEqual(report["status"], "passed", report["events"])
        self.assertEqual(report["requests"], 23)
        self.assertTrue(report["closed"] and report["old_evidence_unchanged"])
        self.assertEqual(
            sum(c["category"] == "model_classification" for c in report["checks"]), 3
        )
        self.assertTrue(all(c["passed"] for c in report["checks"]))
        with self.assertRaises(LiveError):
            campaign.chat(key="after-close", phase="invalid", messages=[])
        self.assertEqual(len(campaign.state()["attempts"]), 23)
        before = (self.root / "report.json").read_bytes()
        with self.assertRaises(LiveError):
            run_campaign(
                campaign, self.root / "state", self.root / "report.json", offline=True
            )
        self.assertEqual((self.root / "report.json").read_bytes(), before)

    def test_provider_contract_failure_preserved_and_campaign_closed(self):
        def invalid(raw):
            status, response = sharing_fixture(raw)
            value = json.loads(response)
            value["choices"][0]["message"]["content"] = "{invalid"
            return status, encoded(value)

        campaign = self.campaign(invalid)
        report = run_campaign(
            campaign, self.root / "state", self.root / "failed.json", offline=True
        )
        self.assertEqual(report["status"], "stopped")
        self.assertEqual(report["requests"], 1)
        self.assertTrue(report["closed"])
        self.assertTrue((campaign.root / "response-01.json").is_file())
        self.assertEqual(report["events"][-1]["payload"]["reason"], "invalid_json")

    def test_reject_everything_is_not_success(self):
        def rejects(raw):
            request = json.loads(raw)
            status, response = sharing_fixture(raw)
            if "resource" in json.loads(request["messages"][1]["content"]):
                value = json.loads(response)
                body = json.loads(value["choices"][0]["message"]["content"])
                body.update(decision="reject", readable_refs=[])
                value["choices"][0]["message"]["content"] = json.dumps(body)
                return status, encoded(value)
            return status, response

        campaign = self.campaign(rejects)
        runner = SharingValidation(campaign, self.root / "state")
        runner.probes()
        self.assertEqual([c["passed"] for c in runner.checks], [True, True, False])
        self.assertEqual(len(campaign.state()["attempts"]), 3)
        campaign.close("offline_probe_test_completed")

    def test_malformed_package_is_preserved_without_approval_or_tools(self):
        count = 0

        def bad_package(raw):
            nonlocal count
            count += 1
            status, response = sharing_fixture(raw)
            if count == 5:
                value = json.loads(response)
                body = json.loads(value["choices"][0]["message"]["content"])
                body.pop("section_updates")
                body["type"] = "json_object"
                body["candidate"] = {
                    "sections": [
                        {
                            "name": "三态决策表",
                            "summary": "新增业务正文不得成为额外的任务包结构章节。",
                        }
                    ]
                }
                value["choices"][0]["message"]["content"] = json.dumps(body)
                return status, encoded(value)
            return status, response

        campaign = self.campaign(bad_package)
        report = run_campaign(
            campaign, self.root / "state", self.root / "bad-package.json", offline=True
        )
        self.assertEqual(report["status"], "stopped")
        self.assertEqual(report["requests"], 5)
        self.assertEqual(
            report["events"][-1]["payload"]["reason"],
            "validation_planning_package_unavailable",
        )
        self.assertFalse(
            any(a["phase"] == "workbench_tools" for a in report["attempts"])
        )
        self.assertTrue((campaign.root / "response-05.json").is_file())

    def test_single_question_contract_repair_keeps_failure_and_finishes_at_24(self):
        count = 0

        def one_bad_question(raw):
            nonlocal count
            count += 1
            status, response = sharing_fixture(raw)
            if count == 9:
                value = json.loads(response)
                body = json.loads(value["choices"][0]["message"]["content"])
                body["questions"][0]["options"][0].pop("recommended")
                value["choices"][0]["message"]["content"] = json.dumps(body)
                return status, encoded(value)
            return status, response

        campaign = self.campaign(one_bad_question)
        stopped_path = self.root / "stopped.json"
        stopped = run_campaign(
            campaign, self.root / "state", stopped_path, offline=True
        )
        self.assertEqual(stopped["requests"], 9)
        self.assertEqual(stopped["status"], "stopped")
        before = stopped_path.read_bytes()
        original = (campaign.root / "validation-report.json").read_bytes()
        pending = self.root / "state/worker-heartbeat.json.pending"
        if not pending.exists():
            pending.write_bytes(b'{"interrupted":')
            pending.chmod(0o600)
        heartbeat_evidence = pending.read_bytes()
        campaign.resume_remaining_authorization()
        resumed = run_campaign(
            campaign,
            self.root / "state",
            self.root / "continuation.json",
            offline=True,
            resume_from=stopped,
        )
        self.assertEqual(resumed["status"], "passed", resumed["events"][-3:])
        self.assertEqual(resumed["requests"], 24)
        self.assertEqual(stopped_path.read_bytes(), before)
        self.assertEqual(
            (campaign.root / "validation-report.json").read_bytes(), original
        )
        self.assertTrue(
            any(
                p.read_bytes() == heartbeat_evidence
                for p in (self.root / "state").glob(
                    "worker-heartbeat.interrupted-*.json"
                )
            )
        )
        self.assertTrue(
            any(
                e["kind"] == "workbench_plan_contract_failed" for e in resumed["events"]
            )
        )
        with self.assertRaises(LiveError):
            campaign.resume_remaining_authorization()
