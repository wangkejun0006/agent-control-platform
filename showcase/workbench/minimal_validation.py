"""Fresh five-request market rework campaign; no historical budget access."""

import argparse
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

from showcase.live_budget import Campaign, LiveError, atomic_private, digest, require

from .api import create_workbench_app
from .live_validation import WorkbenchValidation
from .service import DEPARTMENTS, ROOT, source_revision
from .sharing_validation import REWORK

MINIMAL_REWORK = REWORK + (
    "决策表正文使用Markdown三列：状态、读取决定、原因；三行状态为未共享资料、仅批准未共享产物、"
    "已批准并显式共享产物。交接验收清单须包含接收部门、绑定版本、授权范围、撤权及失效后的停止规则。"
)

# Bounded decision grammar, not a language-understanding or authorization gate.
# Reject unknown/contradictory wording rather than matching a safe substring.
REWORK_CHECK_VERSION = "market-rework-decisions/2"
_ACTION = r"(?:读取|访问|检索|使用|进入执行快照)"
_DENIAL = (
    r"(?:拒绝|禁止|不得|不能|不可|不允许)"
    r"|(?:不|不得|不能|不可|不允许|禁止|拒绝)"
    + _ACTION
    + r"(?:(?:或|及|和)"
    + _ACTION
    + r")*"
)
_AMBIGUOUS = re.compile(
    r"除非|但是|不过|但|即使|如果|若|如需|紧急|可先|无须|无需|不必|"
    r"不受|不限|不绑定|忽略|绕过|并非|不是|不能拒绝|不可拒绝|不得拒绝|不禁止|不拒绝|"
    r"(?:批准|确认|同意|审核)(?:后|即可)|(?:仍|也)(?:能|可)|"
    r"先(?:读取|访问|检索)|后补(?:授权|批准|共享)"
)
_PERMISSION = re.compile(r"允许|可以|可(?:读取|访问|检索|使用|交接)|内(?:读取|使用)")


def _compact_cell(value):
    return re.sub(r"[\s*`]", "", value)


def _safe_decision(decision, reason, *, shared):
    if not reason or _AMBIGUOUS.search(decision + reason):
        return False
    if not shared:
        clauses = re.split(r"[、，,；;。]+", decision.rstrip("。"))
        # All clauses must deny; safe prefix plus a conditional exception fails.
        return all(re.fullmatch(_DENIAL, c) for c in clauses) and not (
            _PERMISSION.search(re.sub(_DENIAL, "", reason))
        )
    scope = decision + reason
    if not all(word in scope for word in ("接收部门", "版本", "授权范围")):
        return False
    return bool(
        re.fullmatch(
            r"(?:允许|可读取|可以读取|可交接使用|授权范围内允许|范围内使用)"
            r"|(?:仅在|在|仅限)?接收部门[、，,及和与]+(?:绑定|指定)?版本"
            r"[、，,及和与]+授权范围内(?:允许|读取|使用|读取使用|交接使用)",
            decision.rstrip("。"),
        )
    ) and not re.search(r"允许|可以|可(?:读取|访问|检索|使用|交接)", reason)


def rework_body_checks(body):
    rows = [
        [part.strip() for part in line.strip().strip("|").split("|")]
        for line in body.splitlines()
        if line.strip().startswith("|")
    ]

    def matching(labels, *, shared=False):
        matches = [row for row in rows if _compact_cell(row[0]) in labels]
        # Duplicate states cannot hide one unsafe row behind a valid row.
        return (
            len(matches) == 1
            and len(matches[0]) == 3
            and _safe_decision(
                _compact_cell(matches[0][1]),
                _compact_cell(matches[0][2]),
                shared=shared,
            )
        )

    checklist = body.partition("交接验收清单")[2]
    return [
        {
            "name": "unshared_row_denied",
            "passed": matching({"未共享资料", "未经共享资料"}),
        },
        {
            "name": "approval_only_row_denied",
            "passed": matching(
                {"仅批准未共享产物", "已批准但未共享产物", "批准未共享产物"}
            ),
        },
        {
            "name": "explicit_share_row_allowed",
            "passed": matching(
                {"已批准并显式共享产物", "已批准并明确共享产物"}, shared=True
            ),
        },
        {
            "name": "checklist_scope_and_expiry",
            "passed": bool(checklist)
            and all(
                word in checklist for word in ("接收部门", "版本", "授权范围", "撤权")
            )
            and any(word in checklist for word in ("失效", "过期")),
        },
    ]


class MinimalValidation(WorkbenchValidation):
    def __init__(self, campaign, root):
        self.campaign, self.root = campaign, Path(root)
        self.workflow = None
        self.checks = []
        self.headers = {
            "Origin": "http://testserver",
            "X-Orbit-Request": "department-cockpit",
        }
        self.phase = "not_started"

    def check(self, name, passed, **facts):
        self.checks.append({"name": name, "passed": bool(passed), **facts})
        require(passed, "minimal_validation_failed:" + name)

    def login(self, password, *, register=False):
        actions = ("register", "login") if register else ("login",)
        for action in actions:
            data = {"username": "minimal_reviewer", "password": password}
            if action == "register":
                data["display_name"] = "自动化最小验证审核账号"
            response = self.client.post(
                "/v1/auth/" + action, json=data, headers=self.headers
            )
            require(
                response.status_code in (200, 201), "minimal_validation_login_failed"
            )

    def offline_execute(self, department):
        prefix = f"/v1/workflows/{self.workflow}/departments/{department}"
        self.post(prefix + "/plan")
        questions = self.node(department)["planning"]["question_card"]["questions"]
        answers = {
            q["question_id"]: next(
                o["option_id"] for o in q["options"] if o["recommended"]
            )
            for q in questions
        }
        self.post(
            prefix + "/answers",
            {
                "answers": answers,
                "supplement": "离线前置合成产物，仅供隔离验证，不代表真实模型输出或真人审核。",
            },
        )
        subject = self.node(department)["planning"]["task_approval_subject"]
        self.post(
            prefix + "/approve-plan",
            {
                "package_digest": subject["package_digest"],
                "reason": "自动化测试账号确认离线前置计划；非真人或生产批准。",
            },
        )
        self.post(prefix + "/execute")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            worker = self.app.state.worker_process
            require(worker.poll() is None, "offline_precondition_worker_exited")
            self.app.state.delivery.reconcile()
            node = self.node(department)
            if node.get("candidate"):
                payload = node["candidate"]["payload"]
                self.check(
                    "offline_precondition_" + department,
                    node["candidate"]["checks_passed"]
                    and payload["model_requests"] == 0
                    and payload["model_mode"] == "offline_deterministic"
                    and len(payload["tool_receipts"]) == 5,
                )
                return node
            require(
                (node.get("runtime") or {}).get("status")
                not in {"failed", "cancelled"},
                "offline_precondition_execution_failed",
            )
            time.sleep(0.15)
        raise LiveError("offline_precondition_timeout")

    def prepare(self, password):
        self.phase = "offline_preconditions"
        self.app = create_workbench_app(state_root=self.root)
        self.client = TestClient(self.app)
        with self.client:
            self.login(password, register=True)
            for action in ("evaluate", "activate"):
                assets = self.client.get("/v1/workbench/assets").json()
                self.post(
                    "/v1/workbench/assets/batch/" + action,
                    {
                        "items": [
                            {
                                "kind": kind,
                                "id": asset["id"],
                                "release_digest": asset["release_digest"],
                            }
                            for kind in ("agents", "tools")
                            for asset in assets[kind]
                        ]
                    },
                )
            self.workflow = self.post(
                "/v1/workflows",
                {
                    "title": "虚构知识助手市场返工最小验证",
                    "goal": "以虚构团队知识助手为案例，核对部门权限、引用、撤权和验收。市场说明须区分本部门授权资料与上游显式交接产物，仅供本地预览，不扩大权限。",
                },
                expected=201,
            )["workflow_id"]
            self.post(f"/v1/workflows/{self.workflow}/import-fixtures")
            for index, department in enumerate(DEPARTMENTS):
                node = self.offline_execute(department)
                if index < 2:
                    self.review(
                        department,
                        node,
                        target=DEPARTMENTS[index + 1],
                        reason="自动化测试审核离线合成上游产物并显式交接；非真实模型或真人批准。",
                    )
                else:
                    self.old = node
                    self.review(
                        department,
                        node,
                        decision="request_changes",
                        reason=MINIMAL_REWORK,
                    )
            self.check(
                "zero_paid_preconditions", len(self.campaign.state()["attempts"]) == 0
            )
            self.old_record_digest = digest(
                self.app.state.delivery.store.get("candidate:" + self.old["attempt_id"])
            )
            atomic_private(
                self.campaign.root / "offline-preconditions.json",
                {
                    "workflow_id": self.workflow,
                    "input_mode": "fictional_current_fixtures",
                    "upstream_mode": "offline_deterministic_not_real_model",
                    "first_market_candidate": self.old["candidate"],
                    "first_market_revision": self.old["revision"],
                    "handoffs": self.client.get(
                        "/v1/workflows/" + self.workflow
                    ).json()["handoffs"],
                    "reviewer_mode": "automated_authenticated_local_test_account_not_human",
                },
            )

    def run(self):
        password = secrets.token_urlsafe(24)
        self.prepare(password)
        self.app = create_workbench_app(
            state_root=self.root, live_campaign=self.campaign
        )
        self.client = TestClient(self.app)
        with self.client:
            self.login(password)
            password = None
            prefix = f"/v1/workflows/{self.workflow}/departments/market_center"
            self.phase = "real_rework_planning_and_tools"
            self.post(
                prefix + "/revise",
                {
                    "reason": MINIMAL_REWORK,
                    "revision_kind": "business_rework",
                    "acknowledge_uncertain": True,
                },
            )
            revised = self.execute("market_center", start=False)
            # No paid work is permitted beyond this point, even if a later
            # model-free review/delivery check fails.
            self.campaign.close("request_budget_exhausted")
            self.phase = "model_free_review"
            atomic_private(self.campaign.root / "market-v2.json", revised)
            body = revised["candidate"]["payload"]["authored_prose"]
            for check in rework_body_checks(body):
                self.check(check["name"], check["passed"])
            self.check(
                "new_candidate_not_old_text",
                body != self.old["candidate"]["payload"]["authored_prose"],
            )
            service = self.app.state.delivery
            current = service.current_sharing_checks(revised["candidate"])
            self.check(
                "independent_host_content_and_provenance",
                all(c["passed"] for c in current),
            )
            source = next(
                h["artifact_ref"]
                for h in self.client.get("/v1/workflows/" + self.workflow).json()[
                    "handoffs"
                ]
                if h["target_department"] == "market_center"
            )
            self.check(
                "actual_shared_artifact_cited",
                source
                in {
                    c["artifact_ref"]
                    for c in revised["candidate"]["payload"]["citations"]
                },
            )
            self.post(
                prefix + "/review",
                {
                    "candidate_digest": self.old["candidate"]["candidate_digest"],
                    "revision": self.old["revision"],
                    "decision": "approve",
                    "reason": "自动化负向测试：旧版本不可作为新版批准。",
                },
                expected=409,
            )
            self.check("stale_approval_rejected", True)
            self.check(
                "old_candidate_preserved",
                digest(service.store.get("candidate:" + self.old["attempt_id"]))
                == self.old_record_digest,
            )
            self.review(
                "market_center",
                revised,
                reason="自动化测试账号核对三态表、交接清单、来源和回执，仅推进本地验证；非用户真人审核或生产批准。",
            )
            self.phase = "local_delivery"
            final = self.post(
                f"/v1/workflows/{self.workflow}/deliver",
                {
                    "reason": "自动化测试确认隔离案例完成返工审核，仅生成本地交付包，不发布。"
                },
            )
            self.check(
                "local_delivery",
                final["status"] == "delivered" and len(final["handoffs"]) == 2,
            )
            response = self.client.get(f"/v1/workflows/{self.workflow}/download")
            require(
                response.status_code == 200 and response.content[:2] == b"PK",
                "minimal_delivery_zip_missing",
            )
            with (self.campaign.root / "delivery.zip").open("xb") as stream:
                stream.write(response.content)
            atomic_private(self.campaign.root / "final-workflow.json", final)
            atomic_private(
                self.campaign.root / "rework-comparison.json",
                {
                    "before": self.old["candidate"],
                    "after": revised["candidate"],
                    "before_mode": "offline_deterministic",
                    "after_mode": "authorized_real_provider_or_explicit_offline_test_transport",
                    "reviewer_mode": "automated_authenticated_local_test_account_not_human",
                },
            )
            self.check(
                "exactly_five_requests", len(self.campaign.state()["attempts"]) == 5
            )


def run_campaign(campaign, state_root, report_path, *, offline=False):
    require(not report_path.exists(), "fresh_minimal_report_required")
    runner = MinimalValidation(campaign, state_root)
    revision = source_revision()
    reason = "stopped_failure_preserved"
    try:
        runner.run()
        require(source_revision() == revision, "source_changed_during_validation")
        reason = "completed_minimal_rework_validation"
    except Exception as error:  # noqa: BLE001 - no raw provider/internal payload logging
        campaign.event(
            "minimal_validation_stopped",
            {
                "phase": runner.phase,
                "reason": str(error)
                if isinstance(error, LiveError)
                else "minimal_validation_internal_error",
                "exception_type": type(error).__name__,
            },
        )
    finally:
        campaign.close(reason)
        state = campaign.state()
        report = {
            "schema": "orbit.minimal-market-rework/1",
            "rework_check_version": REWORK_CHECK_VERSION,
            "status": "passed" if reason.startswith("completed") else "stopped",
            "phase": runner.phase,
            "workflow_id": runner.workflow,
            "mode": "offline_fake_transport" if offline else "authorized_real_provider",
            "requests": len(state["attempts"]),
            "request_limit": 5,
            "cost_limit_cny": 0.30,
            "cost_cny_conservative_not_invoice": campaign.charge(state) / 1_000_000,
            "closed": state["closed"],
            "close_reason": state.get("close_reason"),
            "source_revision": revision,
            "checks": runner.checks,
            "attempts": [
                {k: v for k, v in a.items() if k not in {"key", "request_digest"}}
                for a in state["attempts"]
            ],
            "events": state["events"],
            "upstream_and_first_market_mode": "offline_deterministic",
            "reviewer_mode": "automated_authenticated_local_test_account_not_human",
            "historical_budgets_read_or_reopened": False,
            "production_authorized": False,
            "published": False,
            "limitations": "One fictional market rework. Upstream and v1 are explicit offline fixtures. Bounded Chinese checks do not certify arbitrary prose; human review still required.",
        }
        atomic_private(campaign.root / "validation-report.json", report)
        with report_path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorize-5-requests-030-cny", action="store_true")
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    require(
        args.authorize_5_requests_030_cny, "explicit_minimal_authorization_required"
    )
    for path in (args.campaign_root, args.state_root):
        require(
            path.is_absolute()
            and path.resolve().is_relative_to(ROOT / ".runtime")
            and not path.exists(),
            "fresh_minimal_private_directory_required",
        )
    require(
        args.report.resolve().parent == ROOT / "reports" and not args.report.exists(),
        "fresh_minimal_report_required",
    )
    os.umask(0o077)
    current_budget = (args.campaign_root / "budget.json").resolve()

    def budget_access_guard(event, values):
        if event == "open" and isinstance(values[0], (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(values[0]))
            if path.name == "budget.json" and path.resolve() != current_budget:
                raise LiveError("historical_budget_access_forbidden")

    sys.addaudithook(budget_access_guard)
    campaign = Campaign.authorize(
        args.campaign_root,
        authorization_ref="user-authorized-minimal-market-rework-20261017-5-requests-030-cny",
        max_requests=5,
        max_cost_micros=300_000,
        input_price=3,
        output_price=12,
    )
    report = run_campaign(campaign, args.state_root, args.report)
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "status",
                    "requests",
                    "closed",
                    "cost_cny_conservative_not_invoice",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
