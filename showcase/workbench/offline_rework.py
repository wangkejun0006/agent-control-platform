"""Bounded offline revisions: explicit templates, never free-form NLU approval."""

import re

from showcase.live_budget import digest

VERSION = "offline-rework/1"

TEMPLATES = {
    "missing_evidence": (
        "缺少依据时的处理步骤",
        "1. 记录缺失的结论、文档版本和引用定位，不用其他部门未共享资料补齐。\n"
        "2. 暂停无依据结论和后续交付，向负责人提出补充资料请求。\n"
        "3. 负责人按原权限导入新资料或提供获批准且显式共享的指定产物。\n"
        "4. 创建新修订，重新检索与核对引用；仍缺少依据则保持阻断，不自动通过。",
    ),
    "acceptance": (
        "负责人逐项验收清单",
        "- 核对当前部门和资料授权；未共享资料拒绝访问。\n"
        "- 核对引用对应文档版本、原文行及实际检索结果。\n"
        "- 核对交接产物已批准且显式共享给接收部门，绑定版本及授权范围。\n"
        "- 核对撤权或版本失效后停止后续使用，固定工具回执与当前候选一致。\n"
        "- 核对本轮修改回应审核意见；未解决项保持阻断。\n"
        "- 核对当前候选版本和摘要后人工决定；最终审核只生成本地交付包。",
    ),
    "scope": (
        "范围限制与证据边界",
        "仅使用本机虚构资料、固定工具和单Worker。引用必须可定位，资料不足时停止无依据结论。"
        "不承诺零幻觉、生产可用、自动合规或自动发布；检查通过仍须负责人审核。",
    ),
    "sharing": (
        "三态决策表",
        "|状态|决定|依据|\n|未共享资料|拒绝|没有共享授权|\n"
        "|仅批准未共享产物|拒绝|批准不等于共享|\n"
        "|已批准且显式共享产物|在范围内使用|接收部门、绑定版本及授权范围均匹配|",
    ),
    "handoff": (
        "交接验收清单",
        "- 核对来源候选当前版本及摘要和批准记录。\n"
        "- 核对显式共享记录的接收部门、版本和授权范围。\n"
        "- 接收部门仅使用指定产物，不据此读取来源部门其他资料。\n"
        "- 撤权或版本失效后停止后续使用，保留历史审核证据供核查。",
    ),
}
# Deliberately closed vocabulary. Unknown instructions remain unresolved rather
# than being deemed satisfied because they happen to contain a known keyword.
INTENTS = (
    ("sharing", r"三态决策表"),
    ("handoff", r"交接验收清单|交接清单"),
    ("missing_evidence", r"(?:资料|引用|证据)(?:不足|缺失)(?:时)?(?:的)?(?:处理步骤|处理流程|处理)"),
    ("acceptance", r"验收清单|验收结果|权限(?:和|与|及)验收结果"),
    ("scope", r"范围限制|证据边界|权限边界"),
)
FILLER = re.compile(
    r"请|本轮|需要|要求|明确|补充|新增|给出|保留|核对|逐项|"
    r"可执行的|具体的|具体|负责人|可以|可|的|并且|以及|和|与|及|、|\s+"
)


def offline_rework(feedback):
    items, sections = [], {}
    clauses = [s.strip() for s in re.split(r"[。；;，\n]+|并且|并", feedback) if s.strip()]
    for index, request in enumerate(clauses):
        remainder, selected = request, []
        for key, pattern in INTENTS:
            if re.search(pattern, remainder):
                selected.append(key)
                remainder = re.sub(pattern, "", remainder)
        supported = bool(selected) and not FILLER.sub("", remainder)
        for key in selected if supported else ():
            title, body = TEMPLATES[key]
            sections[key] = f"## {title}\n{body}"
        items.append({
            "id": f"feedback-{index + 1}",
            "request": request,
            "status": "addressed_by_template" if supported else "unresolved",
            "sections": selected if supported else [],
            "reason": "" if supported else "超出离线模板支持范围，需要负责人细化要求；未自动完成。",
        })
    report = {"version": VERSION, "feedback_digest": digest(feedback), "items": items}
    text = "\n\n".join(sections.values())
    if any(i["status"] == "unresolved" for i in items):
        text += "\n\n## 未解决的返工要求\n存在超出离线模板支持范围的意见；当前候选不能批准或交付，请负责人细化要求。"
    return text, report


def offline_rework_checks(feedback, prose, response):
    expected_text, expected = offline_rework(feedback)
    sections = {key for item in expected["items"] for key in item["sections"]}
    content_present = all(
        f"## {TEMPLATES[key][0]}\n{TEMPLATES[key][1]}" in prose for key in sections
    )
    # No feedback is a normal first attempt, not a revision.
    return [
        {"code": "offline_rework_binding", "name": "离线返工处理绑定本轮审核意见",
         "passed": response == expected},
        {"code": "offline_rework_changes", "name": "离线返工要求对应实际新增内容",
         "passed": content_present and (not feedback.strip() or bool(expected_text))},
        {"code": "offline_rework_resolved", "name": "离线返工没有未解决意见",
         "passed": all(i["status"] == "addressed_by_template" for i in expected["items"])},
    ]
