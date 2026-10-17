"""Read-only loopback view of an already delivered, immutable evidence snapshot.

No database, identity service, model gateway, Campaign or Worker is initialized.
Only the completed snapshot's JSON and exact ZIP are loaded.
"""

import argparse
import hashlib
import html
import io
import json
import re
import zipfile
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / "examples/delivery-snapshot"
NAMES = {
    "product_center": "产品部门",
    "technology_center": "技术部门",
    "market_center": "市场部门",
}
CSS = """
:root{color-scheme:light;font-family:system-ui,'Microsoft YaHei',sans-serif;color:#17283b;background:#f3f6fa}
*{box-sizing:border-box}body{margin:0}a{color:#1751ac;text-decoration:none}a:hover{text-decoration:underline}
.shell{max-width:1460px;margin:auto;padding:32px}header{display:flex;justify-content:space-between;gap:28px;align-items:center}
.eyebrow{font-size:13px;color:#5e7085;letter-spacing:2px}h1{font-size:30px;margin:8px 0}h2{font-size:23px}h3{font-size:18px}
.muted{color:#5e7085;font-size:14px;line-height:1.7}.pill{display:inline-block;background:#def4e9;color:#176346;padding:6px 12px;border-radius:24px;font-size:13px}
.button{display:inline-block;padding:12px 18px;background:#2258c4;color:white;border-radius:9px;font-weight:600}.button:hover{background:#1747a7;text-decoration:none}
.notice{border-left:4px solid #dfb256;background:#fff8e9;padding:13px 18px;margin:22px 0;line-height:1.8;font-size:14px}
nav{display:flex;gap:8px;padding:14px 0;position:sticky;top:0;background:#f3f6faf5;z-index:2}nav a{padding:10px 18px;border:1px solid #d9e2ee;border-radius:8px;background:white}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:12px 0 28px}.stat,.card{background:white;border:1px solid #dde5ef;border-radius:12px;padding:22px;box-shadow:0 2px 6px #182b4505}
.stat strong{display:block;font-size:24px;margin-bottom:6px}.stat span{font-size:13px;color:#5e7085}.compare{display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start}
section{scroll-margin-top:80px;margin-bottom:30px}.card h2{margin-top:0}.version{display:flex;justify-content:space-between;gap:12px;align-items:center;border-bottom:1px solid #e4eaf1;padding-bottom:15px;margin-bottom:15px}
.version strong{font-size:19px}.version .pill.old{background:#fff0e0;color:#955710}.prose{line-height:1.85;font-size:14px;overflow-wrap:anywhere}.prose h1{font-size:22px}.prose h2{font-size:18px;margin-top:24px}.prose h3{font-size:16px}
.prose p{white-space:pre-wrap}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #dce4ee;text-align:left;vertical-align:top;padding:10px;line-height:1.65}th{background:#f1f5fa}
details{margin-top:16px;border-top:1px solid #e4eaf1;padding-top:12px}summary{cursor:pointer;color:#1751ac;font-size:14px}code{font-size:12px;overflow-wrap:anywhere}
.review{border-left:3px solid #8da9cf;padding:0 0 12px 20px;margin-bottom:22px}.review p{line-height:1.8;margin:8px 0}.review .meta{font-size:13px;color:#5e7085}
.review.returned{border-color:#dcaa58}.files{display:grid;grid-template-columns:1fr 1fr;gap:20px}.file{border-bottom:1px solid #e4eaf1;padding:10px 0;font-size:14px}.footer{font-size:13px;color:#617288;line-height:1.8;margin-top:28px}
@media(max-width:900px){.compare,.files{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}.shell{padding:18px}header{align-items:flex-start;flex-direction:column}nav{overflow:auto;white-space:nowrap}}
"""


def escape(value):
    return html.escape(str(value), quote=True)


def prose(text):
    """Escape first; render only headings, paragraphs and simple Markdown tables."""
    result, paragraph, rows = [], [], []

    def flush():
        if paragraph:
            result.append("<p>" + escape("\n".join(paragraph)) + "</p>")
            paragraph.clear()
        if rows:
            result.append('<div class="table-wrap"><table>')
            for i, row in enumerate(rows):
                tag = "th" if i == 0 else "td"
                result.append(
                    "<tr>"
                    + "".join(f"<{tag}>{escape(c)}</{tag}>" for c in row)
                    + "</tr>"
                )
            result.append("</table></div>")
            rows.clear()

    for line in text.splitlines():
        if line.strip().startswith("|"):
            if paragraph:
                flush()
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not all(re.fullmatch(r":?-+:?", c) for c in cells):
                rows.append(cells)
        else:
            if rows:
                flush()
            heading = re.match(r"^(#{1,3})\s+(.+)$", line)
            if heading or not line.strip():
                flush()
                if heading:
                    n = len(heading[1])
                    result.append(f"<h{n}>{escape(heading[2])}</h{n}>")
            else:
                paragraph.append(line)
    flush()
    return "".join(result)


def load_snapshot(root):
    root = Path(root)
    if root.is_symlink():
        raise ValueError("snapshot_symlink_not_allowed")
    root = root.resolve(strict=True)

    def read(name):
        p = root / name
        if p.is_symlink() or p.resolve().parent != root:
            raise ValueError("snapshot_file_not_regular")
        return p.read_bytes()

    report_raw = read("validation-report.json")
    report, workflow = json.loads(report_raw), json.loads(read("final-workflow.json"))
    archive = read("local-delivery.zip")
    if not (
        report["status"] == "passed"
        and report["new_model_requests"] == 0
        and report["local_delivery_completed"]
        and workflow["status"] == "delivered"
        and hashlib.sha256(archive).hexdigest() == report["zip_sha256"]
    ):
        raise ValueError("completed_snapshot_integrity_required")
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        if zipped.testzip() is not None:
            raise ValueError("snapshot_zip_invalid")
        reviews = json.loads(zipped.read("review-records.json"))
        node = next(
            n for n in workflow["nodes"] if n["department_id"] == "market_center"
        )
        if (
            json.loads(zipped.read("market_center-evidence.json"))
            != node["candidate"]["payload"]
        ):
            raise ValueError("market_candidate_zip_mismatch")
        files = zipped.namelist()
    return report, workflow, reviews, files, archive, report_raw


def render_page(report, workflow, reviews, files):
    node = next(n for n in workflow["nodes"] if n["department_id"] == "market_center")
    before = next(h["candidate"] for h in node["history"] if h["revision"] == 1)
    after = node["candidate"]

    def version(candidate, old=False):
        return f"""<article class="card"><div class="version"><strong>市场 v{candidate["revision"]}</strong>
<span class="pill {"old" if old else ""}">{"已退回 · 离线初稿" if old else "已批准 · 既有真实模型候选"}</span></div>
<div class="prose">{prose(candidate["payload"]["authored_prose"])}</div>
<details><summary>查看候选摘要、来源与工具证据</summary><p class="muted">候选摘要：<code>{escape(candidate["candidate_digest"])}</code></p>
<p class="muted">版本：{candidate["revision"]} · 工具回执：{len(candidate["payload"]["tool_receipts"])}</p>
<div class="prose">{prose(candidate["payload"]["body"].partition("## 依据")[2])}</div></details></article>"""

    cards = []
    for review in reviews:
        returned = review["decision"] == "request_changes"
        cards.append(f"""<article class="review {"returned" if returned else ""}"><strong>{escape(NAMES.get(review["department_id"], review["department_id"]))} · v{review["revision"]} · {"退回修改" if returned else "批准"}</strong>
<p>{escape(review["reason"])}</p><div class="meta">{escape(review["recorded_at"])} · 合成本机测试账号（自动化）</div>
<details><summary>核对审核身份与绑定摘要</summary><p class="muted">身份：<code>{escape(review["actor"])}</code><br>候选：<code>{escape(review["candidate_digest"])}</code></p></details></article>""")
    labels = {
        "product_center.md": "产品需求说明",
        "technology_center.md": "技术方案与检查报告",
        "market_center.md": "市场说明（v2）",
        "review-records.json": "完整审核记录",
        "delivery.json": "本地交付记录",
    }
    file_rows = "".join(
        f'<div class="file">{escape(labels.get(n, NAMES.get(n.split("-evidence")[0], n) + " · 引用与工具证据"))}<br><span class="muted">{escape(n)}</span></div>'
        for n in files
    )
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>市场返工与交付 · 隔离案例</title><link rel="stylesheet" href="/style.css"></head><body><main class="shell">
<header><div><div class="eyebrow">AGENT 协作工作台 / 隔离案例</div><h1>团队知识助手 · 市场返工与交付</h1><p class="muted">已完成的案例快照 · 独立本机只读入口</p></div><a class="button" href="/download">下载本地交付包 ↓</a></header>
<div class="notice">本页只读，不创建任务、不调用模型。市场 v2 来自上轮真实模型；产品、技术和市场 v1 为虚构离线前置。审核由合成测试账号自动完成，不代表真人或生产批准。旧失败活动仍保留停止状态。</div>
<nav aria-label="案例导航"><a href="#market">返工前后</a><a href="#reviews">审核记录</a><a href="#delivery">交付文件</a></nav>
<div class="stats"><div class="stat"><strong>已本地交付</strong><span>新隔离副本 · 未发布</span></div><div class="stat"><strong>v1 → v2</strong><span>市场退回、修订与批准</span></div><div class="stat"><strong>5 个</strong><span>市场 v2 原实际工具回执</span></div><div class="stat"><strong>0 次 / 0 元</strong><span>本次审核与页面新增模型调用</span></div></div>
<section id="market"><h2>市场返工前后</h2><p class="muted">v1 保留原文。v2 补充三态决策表和交接验收清单，可对照下方退回意见核查。</p><div class="compare">{version(before, True)}{version(after)}</div></section>
<section id="reviews" class="card"><h2>审核与退回记录</h2>{"".join(cards)}</section>
<section id="delivery" class="card"><h2>本地交付文件</h2><div class="files"><div>{file_rows}</div><div><p class="muted">下载的是原下载接口生成的交付包，字节保持一致。包含三个部门正文、引用与实际工具回执、退回和批准记录。</p><a class="button" href="/download">下载 ZIP 交付包</a><p><a href="/report" download>下载本次零模型审核验证报告</a></p><details><summary>核对交付包 SHA256 与案例编号</summary><p class="muted"><code>{escape(report["zip_sha256"])}</code><br>案例：<code>{escape(workflow["workflow_id"])}</code></p></details></div></div></section>
<p class="footer">独立证据查看页 · 未连接任何模型或任务执行器 · 现有工作台数据不切换、不迁移<br>页面中的批准与交付仅对应新隔离副本；不追溯改写旧失败报告。</p></main></body></html>"""


def create_snapshot_view(root=DEFAULT):
    report, workflow, reviews, files, archive, report_raw = load_snapshot(root)
    page = render_page(report, workflow, reviews, files)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def local_read_only(request: Request, call_next):
        if request.url.hostname not in {"127.0.0.1", "localhost", "testserver"}:
            return JSONResponse({"detail": "loopback_host_required"}, status_code=403)
        if request.method not in {"GET", "HEAD"}:
            return JSONResponse({"detail": "snapshot_is_read_only"}, status_code=405)
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
                "Referrer-Policy": "no-referrer",
            }
        )
        return response

    @app.get("/", response_class=HTMLResponse)
    def home():
        return page

    @app.get("/style.css")
    def style():
        return Response(CSS, media_type="text/css")

    @app.get("/download")
    def download():
        return Response(
            archive,
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="local-delivery.zip"'
            },
        )

    @app.get("/report")
    def validation_report():
        return Response(
            report_raw,
            media_type="application/json",
            headers={
                "Content-Disposition": 'attachment; filename="snapshot-validation.json"'
            },
        )

    @app.get("/health/ready")
    def health():
        return {
            "status": "snapshot_ready",
            "read_only": True,
            "live_model_enabled": False,
            "database_opened": False,
        }

    return app


def main():
    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8433)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("local port must be between 1024 and 65535")
    uvicorn.run(
        create_snapshot_view(), host="127.0.0.1", port=args.port, access_log=False
    )


if __name__ == "__main__":
    main()
