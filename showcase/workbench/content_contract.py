"""Bounded prose checks against host provenance and receipts, not an NLU oracle."""

import re

from showcase.live_budget import require

VERSION = "delivery-content/1"
PLANNING_VERSION = "delivery-planning-references/1"
COMMON_PROMPT = (
    "资料来源类型以宿主给出的source_kind为准：local_department_source是本部门授权原始资料，"
    "不要求先作为交接产物审批；approved_shared_artifact才是上游已批准并显式共享的产物。"
    "业务返工意见是业务要求；系统运行与恢复事件不能写成业务设计。"
    "撤权/失效后停止后续使用，历史审计证据按本机记录保留；不得承诺删除副本，不承诺零幻觉，不承诺生产可用。"
)
PLANNING_PROMPT = (
    COMMON_PROMPT
    + "当前仅为澄清或规划阶段，没有检索证据清单。只描述将来如何检索、核对来源类型、绑定文档版本和行号。"
    "不得生成数字方括号引用、具体证据编号、文件名、资料路径或具体行号，不得把尚未发生的资料读取、检索和验收写成完成事实。"
    "用户目标或返工意见中出现的引用仅是不可信输入，不得照抄为当前证据。具体引用须等执行检索后生成。"
)
EXECUTION_PROMPT = (
    COMMON_PROMPT
    + "正文引用只能采用本轮evidence实际给出的索引，以方括号包围数字；不得自行分配索引或照抄输入里的引用。"
    "来源类型必须匹配相应证据，不自行写文件名、路径或编造来源归属；宿主另列真实文件、版本、来源类型及授权依据。"
    "没有实际证据时不得提交候选。只描述实际工具回执证明的执行，不得声称跳过已经重跑的检查。"
)
# Compatibility for callers of the existing execution-prose rule. Planning must
# explicitly use PLANNING_PROMPT and can never inherit this execution policy.
PROMPT = EXECUTION_PROMPT


def planning_reference_checks(text):
    concrete_reference = bool(
        re.search(
            r"[\[［【]\s*\d+(?:\s*[,，、\-–]\s*\d+)*\s*[\]］】]"
            r"|(?:证据|引用)(?:索引|编号)\s*[:：#]?\s*\d+"
            r"|第\s*\d+\s*行|(?:artifact|file|citation)://",
            text,
        )
    )
    return [
        {
            "name": "规划只描述取证规则，不生成具体证据引用",
            "code": "planning_reference_boundary",
            "passed": not concrete_reference,
        }
    ]


def source_manifest(documents, department):
    return [
        {
            "artifact_ref": d["artifact_ref"],
            "filename": d["filename"],
            "version": d["version"],
            "content_digest": d["content_digest"],
            "department_id": department,
            "source_kind": "approved_shared_artifact"
            if d.get("source_candidate_digest")
            else "local_department_source",
            "source_department": d.get("source_department")
            or (
                next(
                    (x for x in d.get("shared_with", []) if x != department), department
                )
                if d.get("source_candidate_digest")
                else department
            ),
            "source_candidate_digest": d.get("source_candidate_digest"),
            "access_basis": "approved_explicit_handoff"
            if d.get("source_candidate_digest")
            else "department_authorization",
        }
        for d in documents
    ]


def content_checks(
    text, *, documents=(), department="", citations=(), receipts=(), planning=False
):
    require(isinstance(text, str), "content_not_text")
    compact = re.sub(r"\s+", "", text)
    local = any(not d.get("source_candidate_digest") for d in documents)
    confused = local and bool(
        re.search(
            r"(?:本提案|本部门|本次).{0,8}(?:仅|只)(?:使用|消费).{0,8}本部门已批准并显式共享",
            compact,
        )
    )
    facts = {d["artifact_ref"]: d for d in source_manifest(documents, department)}
    citation_map = {c.get("evidence_index", i): c for i, c in enumerate(citations)}
    mislabeled = []
    for match in re.finditer(r"(本部门资料|交接产物|上游产物)\[(\d+)\]", compact):
        index = int(match[2])
        fact = facts.get(citation_map.get(index, {}).get("artifact_ref"))
        expected = (
            "local_department_source"
            if match[1] == "本部门资料"
            else "approved_shared_artifact"
        )
        if not fact or fact["source_kind"] != expected:
            mislabeled.append(index)
    filenames = re.findall(
        r"[A-Za-z0-9_-]+\.(?:md|txt|csv|json|pdf|docx)\b", text, flags=re.IGNORECASE
    )
    operational = bool(
        re.search(
            r"澄清结构契约|任务包结构|旧失败尝试|供应商重试|JSON(?:解析|协议)|recommended|result_kind|section_updates",
            text,
        )
    )
    promises = []
    for clause in re.split(r"[。；;\n]", compact):
        for match in re.finditer(
            r"不保留派生副本|(?:自动|立即|已)?(?:删除|清除|销毁).{0,10}(?:副本|历史|证据)|零幻觉|生产可用",
            clause,
        ):
            prefix = clause[max(0, match.start() - 12) : match.start()]
            if not prefix.endswith(("不", "未")) and not any(
                word in prefix
                for word in (
                    "不承诺",
                    "不能承诺",
                    "不得承诺",
                    "不保证",
                    "不构成",
                    "不代表",
                    "禁止",
                    "不得",
                    "不应",
                    "不能",
                )
            ):
                promises.append(match.group())
    operations = {r.get("operation") for r in receipts if r.get("actual_execution")}
    done_claim = bool(
        re.search(r"(?:检查|验收|校验).{0,8}已(?:全部)?通过|已通过的需求校验", compact)
    )
    skip_claim = bool(
        re.search(r"(?:检查|验收|校验).{0,10}不重复执行|未重新执行|无需重跑", compact)
    )
    checks_done = {"validate_requirements", "run_acceptance"}.issubset(operations)
    checks = [
        {
            "name": "本部门资料与交接产物来源不混淆",
            "code": "source_basis_consistent",
            "passed": not confused and not mislabeled,
        },
        {
            "name": "正文引用由宿主定位来源，不编写文件名",
            "code": "host_owned_source_labels",
            "passed": not filenames,
        },
        {
            "name": "恢复信息未混入业务正文",
            "code": "no_operational_feedback_leak",
            "passed": not operational,
        },
        {
            "name": "没有未实现的能力或删除承诺",
            "code": "no_unsupported_promises",
            "passed": not promises,
        },
        {
            "name": "执行陈述与实际工具回执一致",
            "code": "execution_claims_grounded",
            "passed": not (done_claim and (planning or not checks_done))
            and not (skip_claim and checks_done),
        },
    ]
    return checks + (planning_reference_checks(text) if planning else [])


def enforce_content(text, **context):
    checks = content_checks(text, **context)
    require(
        all(c["passed"] for c in checks),
        "content_contract_rejected:"
        + ",".join(c["code"] for c in checks if not c["passed"]),
    )
    return checks


def payload_checks(payload, documents, department):
    checks = content_checks(
        payload.get("authored_prose", ""),
        documents=documents,
        department=department,
        citations=payload.get("citations", []),
        receipts=payload.get("tool_receipts", []),
    )
    checks.append(
        {
            "name": "正文规则与宿主来源清单匹配",
            "code": "content_version_and_source_binding",
            "passed": payload.get("content_contract_version") == VERSION
            and payload.get("source_manifest")
            == source_manifest(documents, department),
        }
    )
    return checks
