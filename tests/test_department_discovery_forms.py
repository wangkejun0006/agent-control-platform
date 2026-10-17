from __future__ import annotations

import json
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORMS_DIR = ROOT / "department-discovery" / "forms"
EXPECTED_FORMS = {
    "产品中心负责人-Department-Discovery-调查表.html": ("产品中心", False),
    "技术中心负责人-Department-Discovery-调查表.html": ("技术中心", False),
    "市场中心负责人-Department-Discovery-调查表.html": ("市场中心", True),
}
EXPECTED_PRESETS = {
    "产品中心": {"需求调研与优先级判断", "产品方案与体验设计协作", "开发跟进、Coding 协作与产品验收"},
    "技术中心": {"技术方案评估与任务拆解", "Coding、代码评审与联调", "测试、发布与故障处理"},
    "市场中心": {"市场调研与活动策划", "内容制作、审核与渠道投放", "线索复盘与客户反馈交接"},
}


class _FormAuditParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.external_assets: list[tuple[str, str]] = []
        self.form_actions: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.append(attributes["id"] or "")
        if tag == "script" and attributes.get("src"):
            self.external_assets.append((tag, attributes["src"] or ""))
        if tag == "link" and attributes.get("href"):
            self.external_assets.append((tag, attributes["href"] or ""))
        if tag == "form" and attributes.get("action"):
            self.form_actions.append(attributes["action"] or "")


class DepartmentDiscoveryFormsTest(unittest.TestCase):
    def test_expected_single_file_forms_exist(self) -> None:
        actual = {path.name for path in FORMS_DIR.glob("*.html")}
        self.assertEqual(actual, set(EXPECTED_FORMS))

    def test_forms_are_standalone_offline_and_department_specific(self) -> None:
        for filename, (department, market_feedback) in EXPECTED_FORMS.items():
            with self.subTest(filename=filename):
                content = (FORMS_DIR / filename).read_text(encoding="utf-8")
                parser = _FormAuditParser()
                parser.feed(content)

                self.assertTrue(content.lower().startswith("<!doctype html>"))
                self.assertEqual(parser.external_assets, [])
                self.assertEqual(parser.form_actions, [])
                self.assertEqual(len(parser.ids), len(set(parser.ids)))
                self.assertNotRegex(
                    content,
                    r"\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\s*\(",
                )
                self.assertNotRegex(content, r"https?://")
                self.assertIn('const SCHEMA_ID = "orbit.department-discovery-response/2";', content)
                self.assertIn('termRef: "orbit.term/department-discovery"', content)
                self.assertIn('termClassificationStatus: "release"', content)
                self.assertIn("保存填写版 HTML", content)
                self.assertIn("localStorage", content)
                self.assertIn("prefers-reduced-motion", content)

                match = re.search(
                    r'<script id="departmentConfig" type="application/json">\s*(.*?)\s*</script>',
                    content,
                    flags=re.DOTALL,
                )
                self.assertIsNotNone(match)
                config = json.loads(match.group(1))
                self.assertEqual(config["department"], department)
                self.assertEqual(config["marketFeedback"], market_feedback)
                self.assertEqual(len(config["workflowPresets"]), 3)
                self.assertEqual({item["name"] for item in config["workflowPresets"]}, EXPECTED_PRESETS[department])
                self.assertGreaterEqual(len(config["respondentRoles"]), 5)
                self.assertGreaterEqual(len(config["roleOptions"]), 9)

    def test_discovery_boundary_is_visible_and_embedded(self) -> None:
        for filename in EXPECTED_FORMS:
            with self.subTest(filename=filename):
                content = (FORMS_DIR / filename).read_text(encoding="utf-8")
                self.assertIn("不代表已经部署、接入系统、获得数据权限或允许自动执行", content)
                self.assertIn('productionAuthorization: false', content)
                self.assertIn("not a Contract instance, QualificationRun", content)

    def test_department_defaults_are_specific_and_require_explicit_review(self) -> None:
        for filename, (department, _) in EXPECTED_FORMS.items():
            with self.subTest(filename=filename):
                content = (FORMS_DIR / filename).read_text(encoding="utf-8")
                match = re.search(
                    r'<script id="departmentConfig" type="application/json">\s*(.*?)\s*</script>',
                    content,
                    flags=re.DOTALL,
                )
                config = json.loads(match.group(1))
                self.assertIn('<label for="respondentRole">本次填写身份', content)
                self.assertIn('<select id="respondentRole"', content)
                self.assertNotIn("你的职责", content)
                self.assertNotIn("例如：产品负责人、技术负责人", content)
                self.assertIn('<select id="accountableRole"', content)
                self.assertIn('id="reviewStatus"', content)
                self.assertIn('const requiredWorkflowFields = ["reviewStatus"]', content)
                self.assertIn('workflow.reviewStatus === "confirmed"', content)
                self.assertIn("department-discovery.v2", content)
                self.assertEqual(content.count('class="optional-section"'), 5)
                self.assertNotIn('aria-hidden="true">*</span>', content)
                for preset in config["workflowPresets"]:
                    for key in ("name", "accountableRole", "participants", "trigger", "outcome", "steps", "supportModes"):
                        self.assertTrue(preset.get(key), f"{department} preset {preset.get('presetId')} missing {key}")
                self.assertIn(department, content)

    def test_user_facing_page_hides_architecture_vocabulary(self) -> None:
        forbidden = ("权威 Concept", "orbit.concept/", "Agent System", "希望 Agent", "不构成 Agent")
        for filename in EXPECTED_FORMS:
            with self.subTest(filename=filename):
                content = (FORMS_DIR / filename).read_text(encoding="utf-8")
                visible_markup = content.split('<script id="departmentConfig"', 1)[0]
                for term in forbidden:
                    self.assertNotIn(term, visible_markup)

    def test_guided_choices_and_offline_ai_help_are_embedded(self) -> None:
        for filename in EXPECTED_FORMS:
            with self.subTest(filename=filename):
                content = (FORMS_DIR / filename).read_text(encoding="utf-8")
                self.assertGreaterEqual(content.count('class="quick-choice-button"'), 30)
                self.assertIn('data-quick-target="trigger"', content)
                self.assertIn('data-quick-target="neverAutomate"', content)
                self.assertIn('data-quick-target="negativeScenarios"', content)
                self.assertIn('id="aiGuideButton"', content)
                self.assertIn('id="aiGuideDialog"', content)
                self.assertIn('id="copyPromptButton"', content)
                self.assertIn("只根据我提供的材料判断，不补造", content)
                self.assertIn("不把建议写成已经批准、部署或授权", content)
                self.assertIn("不确定时不要上传", content)
                self.assertIn("navigator.clipboard.writeText", content)


if __name__ == "__main__":
    unittest.main()

