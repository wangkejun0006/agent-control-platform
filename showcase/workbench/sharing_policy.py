"""Versioned, bounded Chinese sharing checks; never full semantic certification.

Evaluate authored policy prose, not quoted source passages or reviewer feedback.
Runtime authorization still depends on native approved-version handoff records.
"""

import re

from showcase.live_budget import require

VERSION = "delivery-sharing/1"
POLICY_TEXT = (
    "未经共享的资料不能访问、读取或检索。"
    "已批准并显式共享的产物可以交接使用，仅限接收部门、绑定版本和授权范围。"
    "仅批准不等于共享，交接不授予访问来源部门其他资料的权限；撤权或版本失效后停止使用。"
)
PROMPT_RULE = (
    "正文必须准确表达以下访问边界："
    + POLICY_TEXT
    + " 不得写成‘跨部门资料一律不得进入结果’或‘批准后即可访问全部资料’。"
    "允许交接的是获批准且明确共享给接收部门的指定产物版本，不是来源部门全部资料。"
    "不能在正文先写绝对禁止，再在文末补例外来掩盖矛盾。"
    "为使权限表述可稳定核查，请在计划risk_summary或候选正文中逐字保留上述三句规范，"
    "并另行解释本部门如何应用；仅复制规范不构成场景理解或授权证明。"
)


def sharing_checks(text):
    require(isinstance(text, str), "sharing_prose_not_text")
    compact = re.sub(r"\s+", "", text)
    clauses = re.split(r"[。！？；;\n，,]", text)
    denied = bool(
        re.search(
            r"(?:未经共享|未共享|未获共享|未经授权共享|未获授权共享|未授权共享)(?:的)?(?:资料|材料|数据).{0,12}(?:不能|不得|不可|禁止|不允许).{0,10}(?:访问|读取|检索)",
            compact,
        )
    )
    approved = r"(?:已|已经|经审核|经|获得)?批准.{0,8}(?:并|且).{0,5}(?:显式|明确)共享.{0,8}(?:产物|成果)"
    allowed = bool(
        re.search(approved + r"(?:可以|可|允许).{0,16}(?:交接|使用|消费)", compact)
    )
    bounded = all(word in compact for word in ("接收部门", "授权范围")) and bool(
        re.search(r"(?:绑定|指定|获批|当前|批准)(?:的)?版本", compact)
    )
    approval_not_share = bool(
        re.search(
            r"(?:仅批准|批准本身|批准不)(?:不等于|等于|代表|意味着|不代表).{0,5}共享",
            compact,
        )
    )
    # A broad denial remains contradictory even if correct keywords are appended
    # elsewhere. Explicit exceptions must qualify the *same* rule.
    conflicts = []
    for clause in clauses:
        clean = re.sub(r"\s+", "", clause)
        blanket = re.search(
            r"跨部门(?:的)?(?:资料|材料|数据).{0,12}(?:不得|不能|不可|禁止|不允许).{0,12}(?:访问|读取|检索|进入|使用)|(?:不得|不能|不可|禁止|不允许).{0,8}(?:访问|读取|检索|使用).{0,8}跨部门(?:的)?(?:资料|材料|数据)",
            clean,
        )
        exception = any(
            word in clean
            for word in ("未经", "未共享", "未获", "未授权", "除", "但", "例外")
        )
        approved_denial = re.search(
            approved + r".{0,8}(?:不得|不能|不可|禁止|不允许).{0,8}(?:交接|使用|消费)",
            clean,
        )
        blanket_allow = re.search(
            r"(?:批准|交接|共享).{0,12}(?:即可|就可|可以|可直接|允许).{0,10}(?:访问|读取|检索).{0,8}(?:全部|所有|任意)(?:资料|材料|数据)",
            clean,
        )
        negated_allow = any(
            word in clean for word in ("不代表", "并非", "不等于", "不能据此")
        )
        if (
            (blanket and not exception)
            or approved_denial
            or (blanket_allow and not negated_allow)
        ):
            conflicts.append(clean[:180])
    return [
        {
            "name": "未共享资料明确拒绝访问",
            "code": "unshared_access_denied",
            "passed": denied,
        },
        {
            "name": "批准且显式共享的产物允许交接",
            "code": "approved_shared_artifact_allowed",
            "passed": allowed,
        },
        {
            "name": "交接限定接收部门、版本和授权范围",
            "code": "handoff_scope_bounded",
            "passed": bounded,
        },
        {
            "name": "批准不自动等于共享",
            "code": "approval_is_not_sharing",
            "passed": approval_not_share,
        },
        {
            "name": "无绝对隔离或全面开放的矛盾表述",
            "code": "no_conflicting_blanket_claim",
            "passed": not conflicts,
            "evidence": conflicts,
        },
    ]


def enforce_sharing_prose(text):
    checks = sharing_checks(text)
    require(
        all(c["passed"] for c in checks),
        "sharing_semantics_rejected:"
        + ",".join(c["code"] for c in checks if not c["passed"]),
    )
    return checks
