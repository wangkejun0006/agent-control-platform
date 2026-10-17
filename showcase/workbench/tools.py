"""Fixed professional tools actually run inside the original isolated Runner.

No generated Python/shell, arbitrary file path, provider, or publication tool.
"""

import os
import time

from showcase.live_budget import digest, require

from .content_contract import VERSION as CONTENT_VERSION
from .content_contract import content_checks, enforce_content, source_manifest
from .documents import retrieve
from .model_gateway import OfflineProfessionalDecisionPort
from .sharing_policy import POLICY_TEXT, VERSION, sharing_checks

OPERATIONS = (
    "query_documents",
    "retrieve_evidence",
    "validate_requirements",
    "run_acceptance",
    "submit_candidate",
)


def execute_tool(name, arguments, snapshot):
    require(name in OPERATIONS, "tool_operation_not_allowed")
    require(
        set(arguments) <= {"query"} and (name == "retrieve_evidence" or not arguments),
        "tool_arguments_invalid",
    )
    docs = snapshot["documents"]
    if name == "query_documents":
        return {
            "documents": [
                {
                    k: d[k]
                    for k in ("artifact_ref", "filename", "version", "content_digest")
                }
                for d in docs
            ]
        }
    if name == "retrieve_evidence":
        query = arguments.get("query", "权限 引用 撤权 验收 用户")
        require(isinstance(query, str) and 0 < len(query) < 200, "query_invalid")
        # Put actual, version-bound handoff evidence before local material so
        # the model's bounded evidence window can consume approved upstream work.
        shared = [d for d in docs if d.get("source_candidate_digest")]
        hits = retrieve(shared, query) + retrieve(docs, query)
        unique = {}
        for hit in hits:
            unique.setdefault((hit["artifact_ref"], hit["line"]), hit)
        return {"citations": list(unique.values())[:8]}
    if name == "validate_requirements":
        text = "\n".join(c["text"] for d in docs for c in d["chunks"])
        checks = [
            {"name": "需求包含" + word, "passed": word in text}
            for word in ("权限", "引用", "撤权", "验收")
        ]
        versions = {}
        for d in docs:
            key = (d["document_id"], d["version"])
            versions.setdefault(key, set()).add(d["content_digest"])
        checks.append(
            {
                "name": "同一文档版本没有内容冲突",
                "passed": all(len(v) == 1 for v in versions.values()),
            }
        )
        checks.append(
            {
                "name": "无未解决的旧版需求冲突",
                "passed": snapshot["scenario"] != "scope_conflict",
            }
        )
        return {"checks": checks, "passed": all(c["passed"] for c in checks)}
    if name == "run_acceptance":
        # Exercise the actual department filter and citation locator, not hardcoded PASS.
        cases = []
        for actor in ("product_center", "technology_center", "market_center"):
            scoped = [d for d in docs if actor in d["shared_with"]]
            hits = retrieve(scoped, "权限 引用", limit=6)
            cases.append(
                {
                    "name": actor + "检索结果不越部门",
                    "passed": all(
                        actor
                        in next(
                            d for d in docs if d["artifact_ref"] == h["artifact_ref"]
                        )["shared_with"]
                        for h in hits
                    ),
                }
            )
        refs = {d["artifact_ref"]: d for d in docs}
        hits = retrieve(docs, "权限 引用", limit=6)
        cases.append(
            {
                "name": "引用可以定位到原文版本和行",
                "passed": bool(hits)
                and all(
                    any(
                        c["line"] == h["line"] and c["text"] == h["text"]
                        for c in refs[h["artifact_ref"]]["chunks"]
                    )
                    for h in hits
                ),
            }
        )
        cases.append(
            {
                "name": "未共享资料不可进入执行快照",
                "passed": all(
                    snapshot["department_id"] in d["shared_with"] for d in docs
                ),
            }
        )
        cases.append(
            {
                "name": "角色权限验收",
                "passed": snapshot["scenario"] != "permission_failure",
            }
        )
        return {"checks": cases, "passed": all(c["passed"] for c in cases)}
    return {"status": "local_candidate", "external_publication": False}


def run_professional(snapshot, *, decision_port=None):
    if snapshot["scenario"] in {"slow", "timeout"}:
        time.sleep(5 if snapshot["scenario"] == "slow" else 130)
    receipts = []
    results = {}
    decision_port = decision_port or OfflineProfessionalDecisionPort()
    for _ in range(len(OPERATIONS) + 1):
        decision = decision_port.next_action(
            completed=tuple(results),
            operations=OPERATIONS,
            context={
                "goal": snapshot["goal"],
                "department_id": snapshot["department_id"],
            },
            tool_results=results,
        )
        if decision.get("kind") == "finish":
            require(
                set(results) == set(OPERATIONS),
                "professional_finished_without_required_tools",
            )
            break
        require(
            set(decision) == {"kind", "operation", "arguments"}
            and decision["kind"] == "tool_call",
            "professional_action_contract_invalid",
        )
        name, arguments = decision["operation"], decision["arguments"]
        require(
            name in OPERATIONS and name not in results and isinstance(arguments, dict),
            "professional_tool_not_allowed_or_repeated",
        )
        result = execute_tool(name, arguments, snapshot)
        results[name] = result
        receipts.append(
            {
                "operation": name,
                "arguments_digest": digest(arguments),
                "output_digest": digest(result),
                "pid": os.getpid(),
                "actual_execution": True,
            }
        )
    require(set(results) == set(OPERATIONS), "professional_tool_budget_exhausted")
    citations = results["retrieve_evidence"]["citations"]
    if snapshot["scenario"] == "missing_evidence":
        citations = []
    sections = {
        "product_center": (
            "需求说明",
            "目标：团队知识助手支持按部门权限检索资料，返回可核验引用。范围：仅本地虚构资料；不自动发布或承诺全部回答正确。验收：权限过滤、引用定位、撤权后停止、人工审核。",
        ),
        "technology_center": (
            "技术方案与检查报告",
            "方案：部门隔离的资料索引、确定性检索、版本化引用、受控工具和独立检查。接口遵循任务包授权，工具不能批准自身结果。实现边界：离线规划、本机单Worker，不代表生产RAG或OS沙箱。",
        ),
        "market_center": (
            "用户说明与能力承诺审查",
            "用户说明：这是使用虚构资料的本机知识助手演示。仅可检索获共享的资料；回答依据可追溯到文档版本和行。资料不足时需补充证据，不能宣称零幻觉、生产可用或自动合规。",
        ),
    }
    title, description = sections[snapshot["department_id"]]
    description += "\n\n## 资料访问与交接边界\n" + POLICY_TEXT
    description += "\n本部门原始资料按部门授权使用；上游交接产物须额外具备批准及显式共享记录。撤权后停止后续使用，历史审核证据保留供核查。"
    feedback = snapshot.get("review_feedback", "")
    if feedback:
        description += "\n已根据业务意见重新形成候选，并实际重新检索、校验和验收；待负责人核查修订。"
        if "三态决策表" in feedback:
            description += "\n## 三态决策表\n|状态|决定|依据|\n|未共享资料|拒绝|没有共享授权|\n|仅批准未共享产物|拒绝|批准不等于共享|\n|已批准且显式共享产物|在范围内使用|接收部门与绑定版本均匹配|"
        if "交接验收清单" in feedback:
            description += "\n## 交接验收清单\n- 核对接收部门。\n- 核对绑定版本及授权范围。\n- 撤权或失效后停止后续使用，保留历史审核证据。"
    live_draft = getattr(decision_port, "draft", None)
    if live_draft:
        require(
            snapshot.get("model_mode") == "live_authorized_campaign",
            "live_draft_not_authorized",
        )
        description = live_draft["body"]
        citations = [
            {**citations[i], "evidence_index": i}
            for i in live_draft["citation_indices"]
        ]
        enforce_content(
            description,
            documents=snapshot["documents"],
            department=snapshot["department_id"],
            citations=citations,
            receipts=receipts,
        )
    text = f"# {title}\n\n## 交付目标（用户输入，不构成权限授权）\n{snapshot['goal']}\n\n## 部门交付说明\n{description}\n\n## 依据\n"
    for index, citation in enumerate(citations):
        index = citation.get("evidence_index", index)
        text += f"- [{index}] {citation['filename']} v{citation['version']} 第{citation['line']}行：{citation['text']}\n"
    manifest = source_manifest(snapshot["documents"], snapshot["department_id"])
    text += "\n## 来源与授权依据（宿主生成）\n"
    for source in manifest:
        text += f"- {source['filename']} v{source['version']}：{source['source_kind']} / {source['access_basis']} / 来源部门 {source['source_department']}\n"
    text += "\n## 检查与风险\n"
    checks = (
        results["validate_requirements"]["checks"]
        + results["run_acceptance"]["checks"]
        + sharing_checks(description)
        + content_checks(
            description,
            documents=snapshot["documents"],
            department=snapshot["department_id"],
            citations=citations,
            receipts=receipts,
        )
    )
    text += "\n".join(
        f"- {'通过' if c['passed'] else '失败'}：{c['name']}" for c in checks
    )
    if snapshot.get("review_feedback") and not live_draft:
        text += (
            "\n\n## 本轮返工意见\n"
            + snapshot["review_feedback"]
            + "\n已重新执行资料检索与检查；请审阅证据和修订内容。"
        )
    return {
        "artifact_ref": f"artifact://synthetic/{snapshot['task_id']}/candidate",
        "body": text,
        "authored_prose": description,
        "sharing_policy_version": VERSION,
        "content_contract_version": CONTENT_VERSION,
        "source_manifest": manifest,
        "citations": citations,
        "checks": checks,
        "tool_receipts": receipts,
        "snapshot_digest": digest(snapshot),
        "input_refs": [d["artifact_ref"] for d in snapshot["documents"]],
        "model_mode": "live_authorized_campaign"
        if live_draft
        else "offline_deterministic",
        "model_requests": getattr(decision_port, "model_requests", 0),
        "cost_cny_micros": getattr(decision_port, "cost", 0),
        "release_authorization": False,
        "production_authorization": False,
    }
