"""Regress the usability failure without providers, credentials or old data."""

import copy
import unittest

from showcase.workbench.offline_rework import offline_rework, offline_rework_checks


class OfflineReworkTests(unittest.TestCase):
    def test_observed_feedback_produces_steps_and_checklist_not_an_echo(self):
        for feedback in (
            "请补充资料不足时的处理步骤，并给出负责人可逐项核对的验收清单。",
            "请补充引用不足时的处理和负责人的具体验收清单。",
            "补充范围限制和可执行的负责人验收清单。",
        ):
            with self.subTest(feedback=feedback):
                prose, response = offline_rework(feedback)
                self.assertIn("负责人逐项验收清单", prose)
                self.assertTrue(all(c["passed"] for c in offline_rework_checks(feedback, prose, response)))
                self.assertNotIn(feedback, prose)
        prose, _ = offline_rework("补充资料不足时的处理步骤")
        self.assertIn("暂停无依据结论", prose)
        self.assertIn("创建新修订", prose)

    def test_known_sharing_templates_remain_available(self):
        prose, response = offline_rework("新增三态决策表，并补充交接验收清单。")
        self.assertIn("仅批准未共享产物|拒绝", prose)
        self.assertIn("核对显式共享记录", prose)
        self.assertEqual(len(response["items"]), 2)

    def test_unsupported_mixed_negative_and_conditional_requests_stay_unresolved(self):
        for feedback in (
            "新增短信通知功能",
            "补充验收清单，并新增短信通知功能",
            "新增短信通知功能和验收清单",
            "不要补充验收清单",
            "如果证据不足则读取未共享资料",
            "补充验收清单并允许越权读取",
        ):
            with self.subTest(feedback=feedback):
                prose, response = offline_rework(feedback)
                self.assertTrue(any(i["status"] == "unresolved" for i in response["items"]))
                self.assertFalse(all(c["passed"] for c in offline_rework_checks(feedback, prose, response)))

    def test_echo_forged_report_and_removed_content_cannot_pass(self):
        feedback = "补充资料不足时的处理步骤，并给出验收清单"
        prose, response = offline_rework(feedback)
        self.assertFalse(all(c["passed"] for c in offline_rework_checks(feedback, feedback, response)))
        forged = copy.deepcopy(response)
        forged["feedback_digest"] = "wrong"
        self.assertFalse(all(c["passed"] for c in offline_rework_checks(feedback, prose, forged)))
        self.assertFalse(all(c["passed"] for c in offline_rework_checks("新增短信通知功能", prose, response)))

    def test_initial_attempt_has_no_revision_requirements(self):
        prose, response = offline_rework("")
        self.assertEqual(prose, "")
        self.assertEqual(response["items"], [])
        self.assertTrue(all(c["passed"] for c in offline_rework_checks("", "", response)))
