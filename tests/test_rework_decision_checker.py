"""Offline decision paraphrases and adversarial policy reversals."""

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from showcase.workbench.minimal_validation import rework_body_checks


def table(
    denied="不读取、不检索、不进入执行快照",
    approved="不读取",
    shared="在接收部门、绑定版本、授权范围内读取使用",
    reason="没有共享授权",
    shared_reason="接收部门与版本符合授权范围，撤权或失效即停止",
):
    return (
        "|状态|读取决定|原因|\n|---|---|---|\n"
        f"|未共享资料|{denied}|{reason}|\n"
        f"|仅批准未共享产物|{approved}|批准不等于共享|\n"
        f"|已批准并显式共享产物|{shared}|{shared_reason}|\n"
        "## 交接验收清单\n接收部门、绑定版本、授权范围必须匹配，撤权或失效后停止。"
    )


class DecisionCheckerTests(unittest.TestCase):
    def setUp(self):
        self.key = patch(
            "showcase.live_budget.load_secret",
            side_effect=AssertionError("offline_no_key"),
        )
        self.network = patch(
            "showcase.live_budget.live_post",
            side_effect=AssertionError("offline_no_network"),
        )
        self.key.start()
        self.network.start()
        self.addCleanup(self.key.stop)
        self.addCleanup(self.network.stop)

    def test_negative_paraphrases_and_scoped_positive(self):
        for denied in (
            "不读取",
            "不访问",
            "不检索",
            "不得读取或检索",
            "不能访问",
            "不可读取",
            "不允许读取",
            "禁止读取",
            "拒绝",
            "不读取、不检索、不进入执行快照",
        ):
            with self.subTest(denied=denied):
                self.assertTrue(
                    all(c["passed"] for c in rework_body_checks(table(denied, denied)))
                )
        for shared in (
            "允许",
            "可读取",
            "可以读取",
            "授权范围内允许",
            "范围内使用",
            "仅在接收部门、指定版本、授权范围内交接使用",
        ):
            with self.subTest(shared=shared):
                self.assertTrue(
                    all(c["passed"] for c in rework_body_checks(table(shared=shared)))
                )

    def test_negation_reversal_and_mixed_permission_fail_closed(self):
        for bad in (
            "不能拒绝读取",
            "不可拒绝",
            "不得拒绝访问",
            "不禁止读取",
            "并非不可读取",
            "不是不允许读取",
            "不读取但可以检索",
            "不读取；允许访问",
            "拒绝或允许",
            "不读取，无法判断",
            "不读取或者可以读取",
            "不能不读取",
        ):
            for field in ("denied", "approved"):
                with self.subTest(bad=bad, field=field):
                    result = rework_body_checks(table(**{field: bad}))
                    self.assertFalse(result[0 if field == "denied" else 1]["passed"])

    def test_conditional_overreach_in_decisions_or_reasons_is_rejected(self):
        for bad in (
            "不读取，紧急时允许访问",
            "若负责人同意可以读取",
            "不读取，除非审核通过",
            "仅供预览可以读取",
            "批准后即可读取",
            "不读取，但检索不受限制",
        ):
            with self.subTest(bad=bad):
                self.assertFalse(rework_body_checks(table(denied=bad))[0]["passed"])
        for reason in (
            "紧急时可以读取",
            "如需验收允许读取",
            "若主管同意可检索",
            "未经共享但可以读取",
            "无需授权",
            "不能拒绝访问",
            "主管批准后读取",
            "先检索后补共享",
            "验收时仍能读取",
        ):
            with self.subTest(reason=reason):
                self.assertFalse(rework_body_checks(table(reason=reason))[0]["passed"])

    def test_shared_scope_bypass_and_reversal_rejected(self):
        for bad in (
            "拒绝",
            "不允许读取",
            "不能拒绝读取",
            "授权范围内允许但可以读取其他资料",
            "在接收部门、绑定版本、授权范围内读取使用，无需核对",
            "允许访问全部资料",
        ):
            with self.subTest(bad=bad):
                self.assertFalse(rework_body_checks(table(shared=bad))[2]["passed"])
        for reason in (
            "接收部门与版本符合授权范围，但撤权后可以继续使用",
            "接收部门与版本符合授权范围，无需版本绑定",
            "接收部门与版本符合授权范围，允许读取其他部门资料",
        ):
            with self.subTest(reason=reason):
                self.assertFalse(
                    rework_body_checks(table(shared_reason=reason))[2]["passed"]
                )
        self.assertFalse(
            rework_body_checks(table(shared="允许", shared_reason="有批准"))[2][
                "passed"
            ]
        )

    def test_duplicate_malformed_and_unknown_state_cannot_hide_bad_row(self):
        body = table()
        for extra in ("\n|未共享资料|允许|无授权|", "\n|未共享资料|不读取|无授权|"):
            self.assertFalse(rework_body_checks(body + extra)[0]["passed"])
        self.assertFalse(
            rework_body_checks(body.replace("|未共享资料|", "|伪装未共享资料|"))[0][
                "passed"
            ]
        )
        self.assertFalse(
            rework_body_checks(body.replace("|不读取|批准不等于共享|", "|不读取||"))[1][
                "passed"
            ]
        )
        self.assertFalse(
            rework_body_checks(body.replace("|未共享资料|", "|未共享资料|额外列|"))[0][
                "passed"
            ]
        )

    def test_read_only_historical_prose_now_recognized_but_failed_report_unchanged(
        self,
    ):
        root = Path(__file__).resolve().parents[1]
        candidate = root / ".runtime/planning-boundary-live-20261017/market-v2.json"
        report = root / "reports/planning-boundary-live-validation-20261017.json"
        if not candidate.exists():
            self.skipTest(
                "private historical candidate unavailable in portable checkout"
            )
        before = {
            p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (candidate, report)
        }
        body = json.loads(candidate.read_text())["candidate"]["payload"][
            "authored_prose"
        ]
        self.assertTrue(all(c["passed"] for c in rework_body_checks(body)))
        self.assertEqual(json.loads(report.read_text())["status"], "stopped")
        self.assertEqual(
            before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before}
        )
