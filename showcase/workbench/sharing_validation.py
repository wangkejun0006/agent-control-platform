"""One new, explicitly authorized sharing campaign; never overwrite old evidence."""

import argparse
import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from orbit_agent_control_plane.service_runtime.controlled_artifacts import (
    ControlledArtifactError,
)
from showcase.live_budget import (
    Campaign,
    LiveError,
    atomic_private,
    require,
    strict_json,
)

from .documents import parse_document
from .live_validation import WorkbenchValidation
from .service import DEPARTMENTS, ROOT
from .sharing_policy import POLICY_TEXT

REWORK = (
    "新增独立章节‘三态决策表’：分别列出未共享资料、仅批准未共享产物、"
    "已批准并显式共享产物的读取决定及原因。新增‘交接验收清单’，"
    "逐项核对接收部门、绑定版本、授权范围、撤权或失效停止使用。"
    "这是新增业务验收要求，不代表原候选已存在违规；不得只粘贴意见。"
)


def protected_hashes():
    paths = list((ROOT / "reports").rglob("*"))
    for name in ("live-20261016", "workbench-live-20261017"):
        paths += list((ROOT / ".runtime" / name).rglob("*"))
    return {
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in paths
        if p.is_file() and p.name != "budget.lock"
    }


class SharingValidation(WorkbenchValidation):
    resume_report = None

    def recover_isolated_test_login(self):
        """Rotate only this driver's synthetic account; no user state or role changes.

        The first process deliberately did not persist its random password/token.
        Offline fixture recovery provisions a new password in memory, then uses
        the native login endpoint. This is test setup, never an approval.
        """
        from sqlalchemy import select

        from orbit_agent_control_plane.service_runtime.cockpit_local_identity_models import (
            CockpitLocalAccountRow,
        )

        identity = self.app.state.cockpit_local_identity
        password = secrets.token_urlsafe(24)
        with identity.database.session() as session:
            accounts = list(session.scalars(select(CockpitLocalAccountRow)))
            require(
                len(accounts) == 1 and accounts[0].username == "sharing_validation",
                "isolated_test_account_required",
            )
            accounts[0].password_hash = identity.password_hasher.hash(password)
        response = self.client.post(
            "/v1/auth/login",
            json={"username": "sharing_validation", "password": password},
            headers=self.headers,
        )
        password = None
        require(response.status_code == 200, "test_recovery_login_failed")
        self.campaign.event(
            "isolated_test_login_reprovisioned",
            {
                "roles_changed": False,
                "user_database_touched": False,
                "reason": "ephemeral test credentials not persisted; native login used",
            },
        )

    def probes(self):
        cases = (
            (
                "unshared_source",
                {
                    "id": "source-private",
                    "approved": False,
                    "shared_to": [],
                    "version": 1,
                },
                "reject",
                [],
            ),
            (
                "approved_only",
                {
                    "id": "approved-artifact",
                    "approved": True,
                    "shared_to": [],
                    "version": 2,
                },
                "reject",
                [],
            ),
            (
                "explicit_share",
                {
                    "id": "approved-artifact",
                    "approved": True,
                    "shared_to": ["technology_center"],
                    "version": 2,
                    "bound_version": 2,
                    "scope": "delivery_design",
                    "revoked": False,
                },
                "allow",
                ["approved-artifact@2"],
            ),
        )
        for name, resource, expected, refs in cases:
            response = self.campaign.chat(
                key="sharing-contrast:" + name,
                phase="sharing_contrast",
                json_mode=True,
                messages=[
                    {
                        "role": "system",
                        "content": POLICY_TEXT
                        + " 根据资源状态独立判定，不执行动作。仅输出JSON，字段decision取allow或reject，"
                        "readable_refs为允许读取的id@版本数组，source_documents_allowed为布尔值，reason为中文依据。"
                        "请求者technology_center，用途delivery_design；判断可以读取哪些资源。",
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "resource": resource,
                                "source_document": {
                                    "id": "source-private",
                                    "shared_to": [],
                                },
                                "request": "读取该资源和其来源部门原始资料；请分别判断权限。",
                            },
                            ensure_ascii=False,
                        ),
                    },
                ],
            )
            message = response["choices"][0]["message"]
            value = strict_json(message.get("content"))
            passed = (
                isinstance(value, dict)
                and set(value)
                == {"decision", "readable_refs", "source_documents_allowed", "reason"}
                and value["decision"] == expected
                and value["readable_refs"] == refs
                and value["source_documents_allowed"] is False
                and isinstance(value["reason"], str)
                and len(value["reason"]) >= 8
                and not message.get("tool_calls")
            )
            self.checks.append(
                {
                    "name": name,
                    "category": "model_classification",
                    "passed": passed,
                    "expected": expected,
                    "observed": value,
                    "actions_executed": 0,
                }
            )

    def setup_workflow(self):
        password = secrets.token_urlsafe(24)
        for action, data in (
            (
                "register",
                {
                    "username": "sharing_validation",
                    "password": password,
                    "display_name": "自动化共享验证账号",
                },
            ),
            ("login", {"username": "sharing_validation", "password": password}),
        ):
            response = self.client.post(
                "/v1/auth/" + action, json=data, headers=self.headers
            )
            require(response.status_code in (200, 201), "validation_login_failed")
        password = None
        for action in ("evaluate", "activate"):
            assets = self.client.get("/v1/workbench/assets").json()
            self.post(
                "/v1/workbench/assets/batch/" + action,
                {
                    "items": [
                        {
                            "kind": kind,
                            "id": a["id"],
                            "release_digest": a["release_digest"],
                        }
                        for kind in ("agents", "tools")
                        for a in assets[kind]
                    ]
                },
            )
        self.workflow = self.post(
            "/v1/workflows",
            {
                "title": "团队知识助手共享边界与返工验证",
                "goal": "交付虚构团队知识助手的需求、技术方案与用户说明：权限、引用、撤权、验收均须有证据。"
                "跨部门只消费已批准且显式共享的指定版本产物，不读取来源部门其他资料。仅本地预览。",
            },
            expected=201,
        )["workflow_id"]
        self.post(f"/v1/workflows/{self.workflow}/import-fixtures")
        atomic_private(
            self.campaign.root / "workflow.json",
            {
                "workflow_id": self.workflow,
                "state_root": str(self.root),
                "reviewer_mode": "automated_authenticated_local_test_account_not_human",
            },
        )

    def check(self, name, passed, **evidence):
        self.checks.append(
            {
                "name": name,
                "category": "host_workflow",
                "passed": bool(passed),
                **evidence,
            }
        )
        require(passed, "sharing_validation_failed:" + name)

    def check_scope(self, source, target, candidate):
        service = self.app.state.delivery
        detail = self.client.get("/v1/workflows/" + self.workflow).json()
        handoff = next(
            h for h in detail["handoffs"] if h["source_department"] == source
        )
        shared = next(
            d
            for d in service.documents(self.workflow, target, active=True)
            if d["artifact_ref"] == handoff["artifact_ref"]
        )
        self.check(
            "handoff_bound_" + source,
            shared["source_candidate_digest"] == candidate["candidate_digest"]
            and shared["content_digest"]
            == parse_document(
                shared["filename"], candidate["payload"]["body"].encode()
            )["content_digest"],
            handoff=handoff,
            version=shared["version"],
        )
        private_doc = next(
            d
            for d in service.documents(self.workflow, source, active=True)
            if not d.get("source_candidate_digest")
        )
        try:
            service.cockpit.artifact_store.require_department_refs(
                department_id=target, artifact_refs=(private_doc["artifact_ref"],)
            )
        except ControlledArtifactError as error:
            require(
                str(error) == "controlled_artifact_scope_mismatch",
                "unexpected_scope_error",
            )
        else:
            raise LiveError("source_document_scope_not_enforced")
        self.check(
            "private_source_excluded_" + source,
            private_doc["artifact_ref"]
            not in {
                d["artifact_ref"]
                for d in service.documents(self.workflow, target, active=True)
            },
        )
        return handoff["artifact_ref"]

    def run(self):
        with self.client:
            prefix = f"/v1/workflows/{self.workflow}/departments/"
            if self.resume_report:
                self.recover_isolated_test_login()
                self.workflow = self.resume_report["workflow_id"]
                self.checks = list(self.resume_report["checks"])
                prefix = f"/v1/workflows/{self.workflow}/departments/"
                previous_ref = self.check_scope(
                    "product_center",
                    "technology_center",
                    self.node("product_center")["candidate"],
                )
                self.post(
                    prefix + "technology_center/revise",
                    {
                        "reason": "业务目标与验收标准不变：实际执行全部工具检查，引用显式共享的上游产物；保留失败记录，不宣称跳过检查。",
                        "acknowledge_uncertain": True,
                    },
                )
                start_index = 1
            else:
                self.setup_workflow()
                self.probes()
                prefix = f"/v1/workflows/{self.workflow}/departments/"
                self.post(prefix + "technology_center/plan", expected=409)
                self.check("unapproved_blocks_downstream", True)
                previous_ref, start_index = None, 0
            for index in range(start_index, len(DEPARTMENTS)):
                department = DEPARTMENTS[index]
                node = self.execute(
                    department, start=not (self.resume_report and index == 1)
                )
                if previous_ref:
                    refs = {
                        c["artifact_ref"]
                        for c in node["candidate"]["payload"]["citations"]
                    }
                    self.check(
                        "actually_cited_shared_" + department,
                        previous_ref in refs,
                        artifact_ref=previous_ref,
                    )
                if department != "market_center":
                    target = DEPARTMENTS[index + 1]
                    self.review(
                        department, node
                    )  # approval alone is deliberately insufficient
                    before = len(self.campaign.state()["attempts"])
                    self.post(prefix + target + "/plan", expected=409)
                    self.check(
                        "approval_without_share_blocks_" + target,
                        before == len(self.campaign.state()["attempts"]),
                    )
                    self.post(
                        prefix + department + "/handoff", {"target_department": target}
                    )
                    previous_ref = self.check_scope(
                        department, target, node["candidate"]
                    )
                    continue
                old = node
                self.review(department, old, decision="request_changes", reason=REWORK)
                self.post(
                    prefix + department + "/revise",
                    {"reason": REWORK, "acknowledge_uncertain": True},
                )
                revised = self.execute(department, start=False)
                body = revised["candidate"]["payload"]["authored_prose"]
                self.check(
                    "rework_substantive_structure",
                    body != old["candidate"]["payload"]["authored_prose"]
                    and all(
                        t in body
                        for t in (
                            "三态决策表",
                            "交接验收清单",
                            "仅批准",
                            "未共享",
                            "接收部门",
                            "版本",
                            "撤权",
                        )
                    ),
                )
                self.check(
                    "rework_cites_shared_artifact",
                    previous_ref
                    in {
                        c["artifact_ref"]
                        for c in revised["candidate"]["payload"]["citations"]
                    },
                )
                self.post(
                    prefix + department + "/review",
                    {
                        "candidate_digest": old["candidate"]["candidate_digest"],
                        "revision": old["revision"],
                        "decision": "approve",
                        "reason": "自动化负向检查：旧候选必须拒绝。",
                    },
                    expected=409,
                )
                self.check("stale_approval_rejected", True)
                self.review(department, revised)
                atomic_private(
                    self.campaign.root / "rework-comparison.json",
                    {
                        "before": old["candidate"],
                        "after": revised["candidate"],
                        "requested_change": REWORK,
                        "reviewer_mode": "automated_local_test_not_human",
                    },
                )
            final = self.post(
                f"/v1/workflows/{self.workflow}/deliver",
                {"reason": "自动化本机验证结束；仅本地交付，非真人或生产批准。"},
            )
            self.check(
                "final_delivery",
                final["status"] == "delivered" and len(final["handoffs"]) == 2,
            )
            response = self.client.get(f"/v1/workflows/{self.workflow}/download")
            require(
                response.status_code == 200 and response.content[:2] == b"PK",
                "validation_zip_missing",
            )
            output = self.campaign.root / "delivery.zip"
            output.write_bytes(response.content)
            output.chmod(0o600)
            atomic_private(self.campaign.root / "final-workflow.json", final)
            require(
                all(c["passed"] for c in self.checks), "model_classification_failed"
            )


def run_campaign(campaign, state_root, report_path, *, offline=False, resume_from=None):
    require(not report_path.exists(), "report_already_exists")
    baseline = protected_hashes()
    prefix = "continuation-" if resume_from else ""
    atomic_private(campaign.root / (prefix + "protected-before.json"), baseline)
    runner, reason = None, "sharing_validation_failed_preserved"
    try:
        runner = SharingValidation(campaign, state_root)
        runner.resume_report = resume_from
        runner.run()
        reason = "completed_sharing_validation"
    except Exception as error:  # noqa: BLE001 - no provider/raw exception bodies
        campaign.event(
            "validation_stopped",
            {
                "reason": str(error)
                if isinstance(error, LiveError)
                else "validation_internal_error",
                "exception_type": type(error).__name__,
            },
        )
    finally:
        campaign.close(reason)
        state = campaign.state()
        preserved = all(
            (ROOT / p).is_file()
            and hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h
            for p, h in baseline.items()
        )
        report = {
            "schema": "orbit.sharing-live-validation/1",
            "status": "passed"
            if reason.startswith("completed") and preserved
            else "stopped",
            "mode": "offline_protocol_fixture"
            if offline
            else "authorized_real_provider",
            "workflow_id": runner.workflow if runner else None,
            "requests": len(state["attempts"]),
            "request_limit": 24,
            "closed": state["closed"],
            "cost_cny_with_unknown_reservations": campaign.charge(state) / 1_000_000,
            "cost_limit_cny": 2,
            "close_reason": state.get("close_reason"),
            "protected_old_files": len(baseline),
            "old_evidence_unchanged": preserved,
            "attempts": [
                {k: v for k, v in a.items() if k not in {"key", "request_digest"}}
                for a in state["attempts"]
            ],
            "checks": runner.checks if runner else [],
            "events": state["events"],
            "reviewer_mode": "automated_authenticated_local_test_account_not_human",
            "production_authorized": False,
            "published": False,
            "limitations": "Three contrastive cases and one synthetic workflow/rework; bounded Chinese checks and exact policy copying do not certify general semantic understanding. No user human approval or security proof.",
        }
        atomic_private(campaign.root / (prefix + "validation-report.json"), report)
        # Exclusive create prevents any old evidence being overwritten, including races.
        with report_path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorize-24-requests-2-cny", action="store_true")
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--resume-stopped-report", type=Path)
    args = parser.parse_args()
    require(args.authorize_24_requests_2_cny, "explicit_authorization_flag_required")
    for path in (args.campaign_root, args.state_root):
        require(
            path.is_absolute()
            and path.resolve().is_relative_to(ROOT / ".runtime")
            and (path.is_dir() if args.resume_stopped_report else not path.exists()),
            "fresh_private_validation_directory_required",
        )
    require(
        args.report.resolve().parent == ROOT / "reports" and not args.report.exists(),
        "fresh_report_required",
    )
    os.umask(0o077)
    resume = None
    if args.resume_stopped_report:
        resume = strict_json(args.resume_stopped_report.read_bytes())
        campaign = Campaign(args.campaign_root)
        state = campaign.state()
        expected_auth = "user-authorized-sharing-fix-20261017-24-requests-2-cny"
        require(
            state["authorization_ref"] == expected_auth
            and resume["status"] == "stopped"
            and len(state["attempts"]) == resume["requests"] == 9
            and state["closed"]
            and not any(
                e["kind"] == "authorized_repair_resume" for e in state["events"]
            ),
            "single_bounded_sharing_repair_required",
        )
        bound = strict_json((campaign.root / "workflow.json").read_bytes())
        require(
            bound["workflow_id"] == resume["workflow_id"]
            and Path(bound["state_root"]).resolve() == args.state_root.resolve(),
            "resume_state_binding_invalid",
        )
        with (
            closing(sqlite3.connect(args.state_root / "state.sqlite3")) as source,
            closing(
                sqlite3.connect(campaign.root / "before-repair-state.sqlite3")
            ) as target,
        ):
            source.backup(target)
        atomic_private(campaign.root / "before-repair-budget.json", state)
        campaign.resume_remaining_authorization()
    else:
        campaign = Campaign.authorize(
            args.campaign_root,
            authorization_ref="user-authorized-sharing-fix-20261017-24-requests-2-cny",
            input_price=3,
            output_price=12,
        )
    report = run_campaign(campaign, args.state_root, args.report, resume_from=resume)
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "status",
                    "requests",
                    "closed",
                    "cost_cny_with_unknown_reservations",
                    "old_evidence_unchanged",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
