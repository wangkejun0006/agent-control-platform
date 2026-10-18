import { setupState, departmentTab, uniqueChecks, proseDiff } from "./workbench-usability.js";
import { finalReviewRoute, nextTaskRoute, reviewItems } from "./workbench-review.js";
import { useCallback, useEffect, useRef, useState } from "react";
import Governance from "./App.jsx";
import OfflineDemo from "./OfflineDemo.jsx";
import { request, post, authPost, departments, statuses, operations } from "./workbench-api.js";
import "./workbench.css";
import "./sharing.css";

const nav = [["tasks", "任务工作台", "01"], ["reviews", "审核待办", "02"], ["assets", "Agent 与工具", "03"],
  ["runtime", "运行与预算", "04"], ["governance", "治理与审计", "05"], ["examples", "示例与验证", "06"]];
const tabs = [["overview", "概览"], ["documents", "资料"], ["planning", "规划"], ["execution", "执行"], ["review", "产物与审核"], ["events", "事件"]];
const reasons = { runtime_interrupted_unknown: "执行器中断，结果不确定；请核查后创建新尝试", runtime_handler_timeout: "执行超时，进程已停止",
  runtime_cancelled: "已按请求终止实际执行", local_operator_revoked: "负责人已撤销执行授权" };
const eventNames = { workflow_created: "创建交付任务", document_parsed: "资料已解析", fixture_share_authorized: "授权导入虚构资料",
  planning_started: "启动部门规划", clarification_answered: "提交澄清回答", plan_approved: "负责人确认计划", execution_queued: "任务进入受控队列",
  candidate_evaluated: "独立检查完成", candidate_reviewed: "提交产物审核决定", handoff_authorized: "授权跨部门交接", downstream_invalidated: "修订使下游旧版本失效",
  execution_cancel_requested: "请求取消实际执行", execution_revoked: "撤销执行授权", local_delivery_approved: "批准本地交付" };
const go = (path) => { window.location.hash = `#/${path}`; };
const badge = (value) => <span className={`wb-status wb-status-${value}`}>{statuses[value] || value}</span>;

function Text({ text = "" }) {
  return <div className="wb-prose">{text.split("\n").map((line, index) => line.startsWith("# ") ? <h3 key={index}>{line.slice(2)}</h3>
    : line.startsWith("## ") ? <h4 key={index}>{line.slice(3)}</h4> : <p key={index}>{line || "\u00a0"}</p>)}</div>;
}

function SharingBoundary({ compact = false }) {
  const body = <><div className="wb-sharing-grid"><div className="wb-sharing-deny"><small>01 / 默认拒绝</small><h3>未经共享的资料，不能访问</h3><p>不能访问、读取或检索未获授权共享的资料。任务存在、计划确认或产物批准，都不自动开放其他部门资料。</p></div><div className="wb-sharing-allow"><small>02 / 有条件交接</small><h3>已批准并显式共享的产物，可以使用</h3><p>仅限指定接收部门、绑定版本与授权范围。不能据此读取来源部门其他资料；撤权或版本失效后停止使用。</p></div></div><p className="wb-sharing-foot"><span>产物批准</span><i>→</i><span>明确共享对象与版本</span><i>→</i><span>接收部门使用</span><small>批准 ≠ 共享 · 检查通过 ≠ 人工批准</small></p></>;
  return compact ? <details className="wb-sharing-panel wb-sharing-compact"><summary>资料访问与交接规则 <span>未共享不可访问 · 批准且显式共享可交接</span></summary>{body}</details> : <section className="wb-sharing-panel" aria-label="资料访问与交接规则">{body}</section>;
}

function WorkbenchLiveEvidence() {
  const [report, setReport] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => { request("/v1/showcase/workbench-live-report").then(setReport).catch(e => { if (e.status !== 404) setError(e.message); }); }, []);
  if (!report) return error ? <p className="wb-error">{error}</p> : null;
  return <section className="wb-panel"><div className="wb-section-head"><div><h3>跨部门工作台 · 真实模型验证</h3><p>{report.date} · {report.closed ? "活动已关闭，不会继续消费" : "活动状态待核查"}</p></div><strong>{report.requests}/{report.request_limit} 次</strong></div>
    <p>流程契约{report.workflow_contract_status === "passed" ? "通过" : "待核查"} · 保守估算 ¥{report.cost_cny_with_unknown_reservations.toFixed(6)} / ¥{report.cost_limit_cny}。{report.actual_tool_receipts}个实际工具回执，三部门交接与市场返工。</p>
    <div className="wb-note">审核人为自动化本机测试账号，不能当作用户亲自审核。正文仍需人工复核；独立检查不认证全部语义。</div>
    {report.offline_sharing_fix?.semantic_regression_passed && <div className="wb-sharing-fix"><strong>当前规则已完成离线修复</strong><span>提示词与独立语义门禁已更新 · 新增模型请求0次 · 下方保留历史原文</span></div>}
    <SharingBoundary compact />
    {(report.quality_findings || []).map(f => <p className="wb-sharing-history" key={f.id}><strong>历史正文待改进：</strong>旧响应没有明确保留共享例外。原文和旧交付包保留，不把离线修复当作重新通过真实模型验证。</p>)}
    <div className="wb-actions"><button aria-expanded={Boolean(comparison)} onClick={async () => { if (comparison) { setComparison(null); return; } try { setComparison(await request("/v1/showcase/workbench-live-comparison")); } catch (e) { setError(e.message); } }}>{comparison ? "收起历史原文" : "查看返工前后原文"}</button><a className="wb-download" href="/v1/showcase/workbench-live-delivery">下载历史验证交付包</a></div>
    {error && <p role="alert">{error}</p>}
    {comparison && <div className="wb-two-col wb-sharing-comparison"><article><h4>市场 v1 · 已退回</h4><Text text={comparison.before.payload.body} /></article><article><h4>市场 v2 · 测试审核通过，正文仍待人工复核</h4><Text text={comparison.after.payload.body} /></article></div>}
  </section>;
}

function Login({ onLogin }) {
  const [status, setStatus] = useState(null);
  const [register, setRegister] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { request("/v1/auth/status").then(s => { setStatus(s); setRegister(s.bootstrap_required); }).catch(e => setError(e.message)); }, []);
  const submit = async (event) => {
    event.preventDefault(); setBusy(true); setError("");
    const fields = new window.FormData(event.currentTarget);
    const data = { username: String(fields.get("username")), password: String(fields.get("password")) };
    try {
      if (register) {
        await authPost("register", { ...data, display_name: String(fields.get("display_name")), department_id: fields.get("department_id") || null });
        if (!status?.bootstrap_required) { setRegister(false); setError("申请已提交，请管理员或部门负责人批准后登录。"); return; }
      }
      await authPost("login", data); await onLogin();
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  return <div className="wb-login"><div className="wb-login-intro"><span className="wb-kicker">ORBIT / LOCAL WORKBENCH</span>
    <h1>让每一次交付<br />有计划、有证据、有人负责。</h1>
    <p>产品澄清 → 技术验收 → 用户说明审查 → 负责人交付</p><div className="wb-flow-preview"><span>产品</span><i>→</i><span>技术</span><i>→</i><span>市场</span></div>
    <div className="wb-login-boundary"><strong>资料默认隔离，产物受控交接。</strong><p>未经共享不可访问；批准并显式共享后，按接收部门与版本使用。</p></div>
    <small>虚构资料 · 受控模型入口 · 实际工具执行 · 本机账号审核</small></div>
    <form className="wb-login-form" onSubmit={submit}><span className="wb-kicker">LOCAL SESSION</span>
      <h2>{status?.bootstrap_required ? "初始化本机工作台" : register ? "申请部门账号" : "登录工作台"}</h2>
      <p>{status?.bootstrap_required ? "第一个账号成为本机管理员。账号与口令仅存本机，不是企业身份认证。" : "使用本机账号。首次申请的部门账号需要审批。"}</p>
      <label>用户名<input name="username" autoComplete="username" required minLength={3} maxLength={32} /></label>
      {register && <label>显示名称<input name="display_name" required minLength={2} maxLength={40} /></label>}
      {register && !status?.bootstrap_required && <label>所属部门<select name="department_id">{Object.entries(departments).map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></label>}
      <label>口令（至少12位）<input name="password" type="password" autoComplete={register ? "new-password" : "current-password"} required minLength={12} maxLength={128} /></label>
      {error && <div className="wb-error" role="alert">{error}</div>}
      <button className="wb-primary" disabled={busy}>{busy ? "正在验证…" : status?.bootstrap_required ? "创建管理员并进入" : register ? "提交账号申请" : "登录"}</button>
      {!status?.bootstrap_required && <button type="button" className="wb-link" onClick={() => { setRegister(!register); setError(""); }}>{register ? "返回登录" : "申请本机部门账号"}</button>}
      <small>本轮不读取模型密钥，也不产生付费模型请求。</small>
    </form></div>;
}

function NewTask({ busy, act }) {
  const [open, setOpen] = useState(false);
  if (!open) return <button className="wb-primary" onClick={() => setOpen(true)}>＋ 创建交付任务</button>;
  return <form className="wb-panel wb-new-task" onSubmit={event => {
    event.preventDefault(); const form = new window.FormData(event.currentTarget);
    act(async () => { const result = await post("/v1/workflows", { title: String(form.get("title")), goal: String(form.get("goal")), scenario: String(form.get("scenario")) }); setOpen(false); go(`tasks/${result.workflow_id}/overview/product_center`); });
  }}><h3>创建 AI 功能交付评审</h3><label>任务标题<input name="title" defaultValue="团队知识助手 · 功能交付评审" required minLength={2} maxLength={100} /></label>
    <label>交付目标<textarea name="goal" defaultValue="为虚构团队知识助手明确用户需求、部门权限、资料引用、撤权和验收边界，形成可审核的本地交付包。" required minLength={8} maxLength={1500} /></label>
    <label>场景<select name="scenario"><option value="normal">正常交付</option><option value="missing_evidence">引用缺失门禁</option><option value="scope_conflict">需求版本冲突门禁</option><option value="permission_failure">权限检查失败</option><option value="slow">慢任务（用于执行中取消）</option><option value="timeout">执行超时（用于恢复验收）</option></select></label>
    <div className="wb-actions"><button className="wb-primary" disabled={busy}>创建任务</button><button type="button" onClick={() => setOpen(false)}>取消</button></div></form>;
}

function Preparation({ catalog, isAdmin, busy, returnTo = "tasks" }) {
  const state = setupState(catalog);
  return <section className="wb-panel" aria-label="首次使用准备清单"><h3>首次使用准备清单</h3><p>先评价并明确批准三个专业 Agent 和五个固定工具，再提交执行；不会自动激活或调用模型。</p>
    {state.loading ? <p>正在读取准备状态，尚不能确认执行条件。</p> : <ul className="wb-checklist"><li>专业 Agent：已激活 {state.agents}/{catalog.agents.length}</li><li>固定工具：已激活 {state.tools}/{catalog.tools.length}</li><li>{state.ready ? "执行资源已就绪，仍需逐任务确认计划和审核产物。" : "执行资源未就绪，请先完成评价和批准激活。"}</li></ul>}
    {isAdmin ? <button disabled={busy || state.loading} onClick={() => go(`assets?returnTo=${encodeURIComponent(returnTo)}`)}>{state.ready ? "检查Agent与工具" : "前往配置Agent与工具"}</button> : <p>资源激活需要管理员；请联系本机管理员处理。你仍可在授权部门查看资料和规划。</p>}
  </section>;
}

function Tasks({ workflows, busy, act, catalog, isAdmin }) {
  return <><div className="wb-page-head"><div><h1>任务工作台</h1><p>围绕一次交付，协作完成规划、执行、证据核查与审核。</p></div><NewTask busy={busy} act={act} /></div>
    <div className="wb-stats"><div><strong>{workflows.length}</strong><span>全部任务</span></div><div><strong>{workflows.filter(w => w.status === "delivered").length}</strong><span>已交付</span></div><div><strong>{workflows.filter(w => ["awaiting_review", "awaiting_final_review", "awaiting_approval"].includes(w.status)).length}</strong><span>等待人工决定</span></div><div><strong>{workflows[0]?.model_requests || 0}</strong><span>当前活动模型请求（含失败）</span></div></div>
    <Preparation catalog={catalog} isAdmin={isAdmin} busy={busy} />
    <SharingBoundary />
    {!workflows.length ? <div className="wb-empty"><h2>从一份可核验的交付开始</h2><p>创建任务后，可显式导入13份虚构需求、接口、权限与验收资料。三个部门依次执行，所有批准均由你操作。</p></div> :
      <div className="wb-task-grid">{workflows.map(w => <button className="wb-task-card" key={w.workflow_id} onClick={() => go(`tasks/${w.workflow_id}/overview/${w.current_department || "product_center"}`)}>
        <div>{badge(w.status)}<small>{new Date(w.created_at).toLocaleDateString("zh-CN")}</small></div><h2>{w.title}</h2><p>{w.goal}</p>
        <div className="wb-mini-flow">{w.nodes.map(n => <span key={n.department_id} className={n.status === "approved" ? "complete" : ""}>{n.name}<small>{statuses[n.status] || n.status}</small></span>)}</div>
        <footer>{w.current_department ? `${departments[w.current_department]} · ${w.nodes.find(n => n.department_id === w.current_department)?.next_action}` : "三个部门已批准 · 最终交付"}<span>打开任务 →</span></footer>
      </button>)}</div>}
  </>;
}

function Documents({ workflow, department, act, busy, isAdmin }) {
  const docs = workflow.documents.filter(d => d.department_id === department);
  const [selected, setSelected] = useState(null);
  useEffect(() => { setSelected(null); }, [department, workflow.workflow_id]);
  return <div className="wb-two-col"><section className="wb-panel"><div className="wb-section-head"><h3>本部门受控资料</h3>{isAdmin && <button disabled={busy || docs.length > 0} onClick={() => act(() => post(`/v1/workflows/${workflow.workflow_id}/import-fixtures`))}>导入13份虚构资料并授权三部门使用</button>}</div>
    <p className="wb-muted">只解析UTF-8的txt、md、csv、json，单份不超过256KiB。未完成恶意内容扫描；PDF/DOCX暂不解析。已启动规划的资料快照不可原地覆盖。</p>
    <form className="wb-upload" onSubmit={event => {
      event.preventDefault(); const form = new window.FormData(event.currentTarget); const file = form.get("file");
      act(async () => { const bytes = new window.Uint8Array(await file.arrayBuffer()); let raw = ""; for (let i = 0; i < bytes.length; i += 8192) raw += String.fromCharCode(...bytes.slice(i, i + 8192));
        await post(`/v1/workflows/${workflow.workflow_id}/artifacts`, { department_id: department, filename: file.name,
          document_id: String(form.get("document_id")) || file.name.replace(/\.[^.]+$/, "").replace(/[^A-Za-z0-9_-]/g, "_"), version: Number(form.get("version")), content_base64: window.btoa(raw) });
      });
    }}><label>上传资料<input type="file" name="file" accept=".txt,.md,.csv,.json" required /></label><label>逻辑资料ID<input name="document_id" placeholder="同一资料使用相同ID" pattern="[A-Za-z0-9_-]{1,80}" /></label><label>版本<input name="version" type="number" min="1" max="1000" defaultValue="1" /></label><button disabled={busy}>上传并解析</button></form>
    <div className="wb-doc-list">{docs.map(d => <button key={d.record_id} onClick={() => setSelected(d)}><span>{d.filename}<small>{d.document_id} · v{d.version} · {d.is_current ? "当前版本" : "历史版本，不进入新快照"} · 已解析{d.warnings.length ? " · 不可信指令警示" : ""}</small></span><span>查看原文 →</span></button>)}</div>
    {!docs.length && <p>尚无资料。请先导入虚构资料或上传本部门文档。</p>}</section>
    <section className="wb-panel"><h3>原文与引用定位</h3>{selected ? <><h4>{selected.filename} · v{selected.version}</h4>{selected.warnings.map(w => <p className="wb-warning" key={w}>{w}</p>)}<div className="wb-source-lines">{selected.chunks.map(c => <p key={c.line}><span>{c.line}</span>{c.text}</p>)}</div><details><summary>查看资料引用与摘要</summary><code>{selected.artifact_ref}<br />{selected.content_digest}</code></details></> : <p className="wb-muted">选择一份资料，查看可追溯的原文行号。相同资料ID采用最新版本；同版本内容冲突会阻断验收。</p>}</section></div>;
}

function Planning({ workflow, node, act, busy, canReview, ready }) {
  const [answers, setAnswers] = useState({}); const [supplement, setSupplement] = useState(""); const [reason, setReason] = useState("");
  useEffect(() => { setAnswers({}); setSupplement(""); setReason(""); }, [node.attempt_id]);
  const prefix = `/v1/workflows/${workflow.workflow_id}/departments/${node.department_id}`;
  const planning = node.planning;
  if (!planning || node.status === "stale") return <div className="wb-panel"><h3>规划从目标与资料开始</h3>{node.upstream_ready === false && <p className="wb-warning">等待上游产物批准并显式交接，当前不能启动本部门规划。</p>}{!node.has_documents && <p className="wb-warning">本部门尚无资料，请先到“资料”导入或上传。</p>}<p>规划将生成澄清问题，回答后形成版本化任务包。{workflow.live_model_enabled ? "当前使用独立授权的真实模型活动，失败也计入额度。" : "当前使用离线规划端口，不调用模型。"}</p><button className="wb-primary" disabled={busy || workflow.campaign_closed || node.upstream_ready === false || !node.has_documents} onClick={() => act(() => post(prefix + "/plan"))}>开始部门规划</button></div>;
  return <div className="wb-panel">{node.attempt?.review_feedback && <section className="wb-note" aria-label="返工上下文"><h4>本轮返工意见</h4><p>{node.attempt.review_feedback}</p><p>生成修订后，请对照每项意见和新增正文，不把重新执行等同于修改完成。</p></section>}<div className="wb-section-head"><h3>部门规划</h3>{badge(node.status)}</div>
    {planning.question_card && <form onSubmit={event => { event.preventDefault(); const values = {}; for (const q of planning.question_card.questions) values[q.question_id] = answers[q.question_id] || q.options.find(o => o.recommended)?.option_id;
      act(() => post(prefix + "/answers", { answers: values, supplement })); }}>
      <p>请确认需求，不完整的回答不会进入执行。澄清结果会保存在原生规划会话和checkpoint中。</p>
      {planning.question_card.questions.map(q => <fieldset className="wb-question" key={q.question_id}><legend>{q.label}</legend>{q.options.map(o => <label key={o.option_id}>
        <input type="radio" name={q.question_id} value={o.option_id} checked={(answers[q.question_id] || q.options.find(x => x.recommended)?.option_id) === o.option_id}
          onChange={() => setAnswers(a => ({ ...a, [q.question_id]: o.option_id }))} /><span>{o.label}<small>{o.description}</small></span></label>)}</fieldset>)}
      <label>补充约束<textarea value={supplement} onChange={e => setSupplement(e.target.value)} maxLength={1000} placeholder="例如：不跨部门检索、不承诺生产能力、所有结论须有引用。" /></label><button className="wb-primary" disabled={busy}>提交回答并生成计划</button></form>}
    {planning.task_package && <><h4>待确认的任务包</h4><p>{planning.task_package.spec.goal}</p><ul className="wb-checklist">{planning.task_package.spec.success_criteria.map((c, i) => <li key={i}>{c}</li>)}</ul>
      <div className="wb-note">工具范围：查询、检索、需求校验、固定验收、本地候选。计划确认不会自动启动执行，也不代表产物已经批准。</div>
      {node.status !== "plan_approved" && !node.attempt?.run_id && <><label>计划审核说明（至少8字）<textarea value={reason} onChange={e => setReason(e.target.value)} /></label>
        <button className="wb-primary" disabled={busy || !canReview || reason.trim().length < 8} onClick={() => act(() => post(prefix + "/approve-plan", { reason, package_digest: planning.task_approval_subject.package_digest }))}>确认计划与工具范围</button>{!canReview && <p>需要本部门负责人或管理员确认。</p>}</>}
      <details><summary>核对计划版本与摘要</summary><code>{planning.task_approval_subject?.package_digest}</code></details></>}
    {node.status === "plan_approved" && <button className="wb-primary" disabled={busy || !ready} onClick={() => act(() => post(prefix + "/execute"))}>提交受控执行</button>}
    {["needs_input", "awaiting_approval"].includes(node.status) && <button disabled={busy} onClick={() => act(() => post(prefix + "/cancel"))}>停止本次规划</button>}
  </div>;
}

function Execution({ workflow, node, act, busy, canReview, ready }) {
  const prefix = `/v1/workflows/${workflow.workflow_id}/departments/${node.department_id}`;
  return <div className="wb-panel"><div className="wb-section-head"><h3>受控执行</h3>{badge(node.status)}</div><p>{node.next_action}</p>
    <div className="wb-note">执行经过原Router、固定Tool组合、签名Grant和SQL队列。专业工具在受限进程内实际运行；离线模式模型请求为0。进程限制不等于OS安全沙箱。</div>
    {node.status === "plan_approved" && <button className="wb-primary" disabled={busy || !ready} onClick={() => act(() => post(prefix + "/execute"))}>提交受控执行</button>}
    {node.runtime && <><dl className="wb-definition"><dt>运行</dt><dd>{node.runtime.run_id}</dd><dt>执行状态</dt><dd>{statuses[node.runtime.status] || node.runtime.status}</dd><dt>授权</dt><dd>{node.runtime.grant_id}</dd></dl>
      {node.runtime.failure_reason_code && <p className="wb-warning">{reasons[node.runtime.failure_reason_code] || node.runtime.failure_reason_code}</p>}</>}
    {["queued", "running", "cancel_requested"].includes(node.status) && <div className="wb-actions"><button disabled={busy} onClick={() => act(() => post(prefix + "/cancel"))}>取消执行并终止进程</button>{canReview && <button disabled={busy} onClick={() => act(() => post(prefix + "/revoke"))}>撤销授权并停止</button>}</div>}
    <h4>工具执行回执</h4>{node.candidate ? <table className="wb-table"><thead><tr><th>工具</th><th>实际执行</th><th>进程</th><th>输出摘要</th></tr></thead><tbody>{node.candidate.payload.tool_receipts.map(r => <tr key={r.operation}><td>{operations[r.operation]}</td><td>{r.actual_execution ? "已执行" : "未执行"}</td><td>{r.pid}</td><td><code>{r.output_digest.slice(0, 22)}…</code></td></tr>)}</tbody></table> : <p className="wb-muted">实际执行完成后显示回执，不用预置成功数据填充。</p>}
    {node.attempt?.composition && <details><summary>查看固定运行时组合</summary><pre>{JSON.stringify(node.attempt.composition, null, 2)}</pre></details>}
  </div>;
}

function RevisionComparison({ previous, candidate, revision }) {
  const diff = proseDiff(previous.candidate.payload.authored_prose || previous.candidate.payload.body,
    candidate.payload.authored_prose || candidate.payload.body);
  return <section className="wb-panel wb-diff" aria-label="返工版本差异"><h4>返工版本差异 · v{previous.revision} → v{revision}</h4><p>业务正文新增 {diff.added} 行，删除 {diff.removed} 行；依据清单与完整原文仍可在下方核查。</p>{diff.truncated && <p className="wb-warning">正文较长，当前只比较前500行；请展开完整版本核对其余内容。</p>}<div>{diff.lines.filter(line => line.kind !== "same").map((line, i) => <p className={`wb-diff-${line.kind}`} key={i}><strong>{line.kind === "added" ? "新增" : "删除"}</strong> {line.kind === "added" ? <ins>{line.text || "（空行）"}</ins> : <del>{line.text || "（空行）"}</del>}</p>)}</div>{!diff.added && !diff.removed && <p className="wb-warning">业务正文没有变化；请核对返工意见是否真正落实。</p>}</section>;
}

function Review({ workflow, node, act, busy, canReview }) {
  const [reason, setReason] = useState(""); const [ack, setAck] = useState(false);
  useEffect(() => { setReason(""); setAck(false); }, [node.attempt_id]);
  const candidate = node.candidate;
  const reasonRef = useRef(null);
  const prefix = `/v1/workflows/${workflow.workflow_id}/departments/${node.department_id}`;
  const index = Object.keys(departments).indexOf(node.department_id); const target = Object.keys(departments)[index + 1];
  const previous = node.history?.filter(h => h.candidate && h.attempt_id !== node.attempt_id).at(-1);
  const review = (decision) => act(() => post(prefix + "/review", { candidate_digest: candidate.candidate_digest, revision: node.revision,
    decision, reason, ...(decision === "approve" && target ? { handoff_to: target } : {}) }));
  return <><div className="wb-two-col"><section className="wb-panel"><div className="wb-section-head"><h3>{candidate ? `交付候选 · v${node.revision}` : node.revision ? `修订 v${node.revision} · 候选尚未生成` : "尚未生成交付候选"}</h3>{badge(node.status)}</div>
    {candidate ? <><div className="wb-actions"><button onClick={() => reasonRef.current?.focus()}>填写审核意见</button></div><Text text={candidate.payload.authored_prose || candidate.payload.body} /><details><summary>完整产物与宿主来源清单</summary><Text text={candidate.payload.body} /></details></> : <p className="wb-muted">执行完成后生成候选。通过检查也不等于已经批准。</p>}
    {candidate?.payload.rework_response?.items.length > 0 && <section aria-label="返工要求处理"><h4>返工要求逐项核对</h4><p>离线模板只处理明确支持的要求；未解决项不能批准。</p>{candidate.payload.rework_response.items.map(item => <div className={item.status === "unresolved" ? "wb-warning" : "wb-note"} key={item.id}><strong>{item.status === "unresolved" ? "未解决" : "已生成对应修改，待人工核对"}</strong><p>{item.request}</p>{item.reason && <p>{item.reason}</p>}</div>)}</section>}
    {previous && candidate && <RevisionComparison previous={previous} candidate={candidate} revision={node.revision} />}
    {previous && <details><summary>对照上一版本 v{previous.revision}</summary><Text text={previous.candidate.payload.body} /></details>}
    {node.history?.length > 1 && <details><summary>全部尝试与历史候选</summary>{node.history.map(h => <div key={h.attempt_id}><h4>v{h.revision} · {statuses[h.state] || h.state}</h4>{h.candidate && <Text text={h.candidate.payload.body} />}</div>)}</details>}
    </section><aside className="wb-panel"><h3>检查与证据</h3>{candidate ? <><ul className="wb-checklist">{uniqueChecks(candidate.payload.checks).map((c, i) => <li className={c.passed ? "wb-pass" : "wb-fail"} key={i}>{c.passed ? "✓" : "✕"} {c.name}</li>)}</ul>
      {node.current_sharing_passed === false && <div className="wb-error" role="alert"><strong>当前共享规则未通过</strong><p>旧检查与原文已保留，不能直接继续批准或交接。请创建修订后重新检查。</p><ul>{node.current_sharing_checks.filter(c => !c.passed).map(c => <li key={c.code}>{c.name}</li>)}</ul></div>}
      <p className="wb-muted">独立检查覆盖引用、结构、权限与固定用例，不能认证全部正文语义。请审阅结论和限制。</p>
      <h4>原文引用</h4>{candidate.payload.citations.map((c, i) => <details className="wb-citation" key={i}><summary>{c.filename} · v{c.version} · 第{c.line}行</summary><p>{c.text}</p><code>{c.digest}</code></details>)}
      {!candidate.payload.citations.length && <p className="wb-warning">没有可核验引用，不能批准。</p>}</> : <p>暂无检查结果。</p>}</aside></div>
    <section className="wb-panel"><h3>人工审核与返工</h3><p>决定由当前本机登录账号提交，绑定产物版本和摘要。不代表企业身份认证或对外发布。</p>
      {node.review && <div className="wb-note">审核意见：{node.review.reason}<br />决定：{node.review.decision === "approve" ? "批准" : "退回修改"} · {node.review.actor}</div>}
      <label>审核或修订说明（至少8字）<textarea ref={reasonRef} value={reason} maxLength={1000} onChange={e => setReason(e.target.value)} placeholder="指出依据、缺失项或需要修改的内容。" /></label>
      {candidate && ["awaiting_review", "blocked"].includes(node.status) && <div className="wb-actions"><button className="wb-primary" disabled={busy || !canReview || reason.trim().length < 8 || !candidate.checks_passed || node.current_sharing_passed === false} onClick={() => review("approve")}>{target ? `批准并授权交接${departments[target]}` : "批准本部门产物"}</button>
        <button disabled={busy || !canReview || reason.trim().length < 8} onClick={() => review("request_changes")}>退回修改</button></div>}
      {node.status === "approved" && target && !node.outgoing_handoff && <button disabled={busy || !canReview || node.current_sharing_passed === false} onClick={() => act(() => post(prefix + "/handoff", { target_department: target }))}>核对并补办交接{departments[target]}</button>}
      {node.outgoing_handoff && <section className="wb-note" aria-label="交接已完成"><strong>交接已完成 · v{node.revision} → {departments[node.outgoing_handoff.target_department]}</strong><p>仅授权使用这份已批准产物；接收部门的规划、执行和审核仍需分别完成。</p><button className="wb-primary" onClick={() => go(nextTaskRoute(workflow, node))}>进入{departments[node.outgoing_handoff.target_department]}继续</button><details><summary>核对交接版本与摘要</summary><code>{node.outgoing_handoff.candidate_digest}</code></details></section>}
      {["stale", "changes_requested", "failed", "cancelled", "blocked", "approved", "failed_closed", "stop_requested"].includes(node.status) && <><label className="wb-inline"><input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />我已核查旧尝试；新建修订不会盲目重放不确定步骤。</label><button className="wb-primary" disabled={busy || !canReview || !ack || reason.trim().length < 8} onClick={() => act(async () => { await post(prefix + "/revise", { reason, acknowledge_uncertain: ack }); go(`tasks/${workflow.workflow_id}/planning/${node.department_id}`); })}>创建新修订并重新规划</button></>}
      {!canReview && <p className="wb-warning">当前账号可查看产物，审核和修订需要本部门负责人或管理员。</p>}
    </section></>;
}

function TaskDetail({ workflow, tab, department, act, busy, user, catalog }) {
  const node = workflow.nodes.find(n => n.department_id === department) || workflow.nodes[0];
  const isAdmin = user.role_refs.includes("role_control_plane_admin");
  const canReview = isAdmin || (user.role_refs.includes("role_department_owner") && user.department_refs.includes(node.department_id));
  const [deliveryReason, setDeliveryReason] = useState("");
  const path = (nextTab, nextDept = node.department_id) => `tasks/${workflow.workflow_id}/${nextTab}/${nextDept}`;
  return <><button className="wb-link" onClick={() => go("tasks")}>← 返回任务工作台</button><div className="wb-page-head"><div><span className="wb-kicker">AI FEATURE DELIVERY / OFFLINE</span><h1>{workflow.title}</h1><p>{workflow.goal}</p></div>{badge(workflow.status)}</div>
    <div className="wb-dept-flow">{workflow.nodes.map((n, i) => <button key={n.department_id} className={n.department_id === node.department_id ? "selected" : ""} onClick={() => go(path(departmentTab(workflow, n), n.department_id))}><small>0{i + 1}</small><strong>{n.name}</strong>{badge(n.status)}<span>{n.next_action}</span></button>)}</div>
    <nav className="wb-tabs" aria-label="任务详情标签">{tabs.map(([id, name]) => <button className={tab === id ? "selected" : ""} key={id} onClick={() => go(path(id))}>{name}</button>)}</nav>
    {["overview", "documents", "review"].includes(tab) && <SharingBoundary compact />}
    {workflow.nodes.some(n => n.current_sharing_passed === false) && <div className="wb-note">存在未通过当前共享规则的旧产物。原文、批准和交付记录已保留；新的批准、交接或交付必须先创建修订并重新检查。</div>}
    {node.accessible && !setupState(catalog).ready && <Preparation catalog={catalog} isAdmin={isAdmin} busy={busy} returnTo={path(tab)} />}
    {!node.accessible ? <div className="wb-panel"><h3>此部门内容未向当前账号开放</h3><p>你可查看交付阶段，但不能读取其他部门的资料、规划或候选正文。需要负责人显式交接。</p></div> : <>
      {tab === "overview" && <><div className="wb-two-col"><section className="wb-panel"><h3>下一步</h3><p className="wb-next-action">{workflow.delivery ? "交付已完成，可查看证据或下载" : node.next_action}</p>
        <div className="wb-actions">{workflow.delivery ? <a className="wb-download" href={`/v1/workflows/${workflow.workflow_id}/download`}>下载交付包 ZIP</a> : <button className="wb-primary" onClick={() => go(nextTaskRoute(workflow, node))}>前往处理</button>}<button onClick={() => go(path("execution"))}>查看执行</button></div>
        <dl className="wb-definition"><dt>当前部门</dt><dd>{node.name}</dd><dt>版本</dt><dd>{node.revision || "尚未规划"}</dd><dt>模型模式</dt><dd>{workflow.live_model_enabled ? `真实模型活动${workflow.campaign_closed ? "（已关闭）" : "（已授权）"}＋实际工具执行` : "离线规划＋实际工具执行"}</dd><dt>活动用量</dt><dd>¥{((workflow.cost_cny_micros || 0) / 1000000).toFixed(4)} · 真实请求{workflow.model_requests || 0}次（含失败与预留）</dd></dl></section>
        <section className="wb-panel"><h3>交接记录</h3>{workflow.handoffs.length ? workflow.handoffs.map(h => <p key={h.handoff_id}>{departments[h.source_department]} → {departments[h.target_department]}<small>仅共享已批准的产物版本 · {h.recorded_at}</small></p>) : <p className="wb-muted">暂无交接。前一部门的产物获批准且显式共享后，下一部门才能开始。</p>}</section></div>
        {workflow.status === "awaiting_final_review" && isAdmin && <section className="wb-panel"><h3>最终交付审核</h3><button onClick={() => go(finalReviewRoute(workflow))}>打开最终审核</button><p>三个部门当前版本均已批准。请确认交付包及证据；此操作仅形成可下载的本地文件。</p><label>最终审核说明<textarea value={deliveryReason} onChange={e => setDeliveryReason(e.target.value)} /></label><button className="wb-primary" disabled={busy || deliveryReason.trim().length < 8} onClick={() => act(() => post(`/v1/workflows/${workflow.workflow_id}/deliver`, { reason: deliveryReason }))}>批准本地交付</button></section>}
        {workflow.delivery && <section className="wb-panel"><h3>本地交付包已就绪</h3><p>包含三个部门的文档、检查与引用清单，以及审核记录。没有对外发布。</p><p>可以在“产物与审核”中复核各部门结果和版本历史。</p></section>}</>}
      {tab === "final-review" && <section className="wb-panel"><h3>最终交付审核</h3>{workflow.status === "awaiting_final_review" && isAdmin ? <><p>三个部门当前版本均已批准。请核对产物、引用、返工处理和审核记录；此操作仅生成本地交付包。</p><label>最终审核说明<textarea value={deliveryReason} onChange={e => setDeliveryReason(e.target.value)} /></label><button className="wb-primary" disabled={busy || deliveryReason.trim().length < 8} onClick={() => act(() => post(`/v1/workflows/${workflow.workflow_id}/deliver`, { reason: deliveryReason }))}>批准本地交付</button></> : workflow.status === "delivered" ? <><p>本地交付已完成。</p><a className="wb-download" href={`/v1/workflows/${workflow.workflow_id}/download`}>下载交付包 ZIP</a></> : <p>{isAdmin ? "当前版本尚未满足最终审核条件，请先完成部门审核和交接。" : "最终交付审核需要本机管理员；部门负责人不能替代最终审核。"}</p>}<button onClick={() => go(path("overview"))}>返回任务概览</button></section>}
      {tab === "documents" && <Documents workflow={workflow} department={node.department_id} act={act} busy={busy} isAdmin={isAdmin} />}
      {tab === "planning" && <Planning workflow={workflow} node={node} act={act} busy={busy} canReview={canReview} ready={setupState(catalog).ready} />}
      {tab === "execution" && <Execution workflow={workflow} node={node} act={act} busy={busy} canReview={canReview} ready={setupState(catalog).ready} />}
      {tab === "review" && <Review workflow={workflow} node={node} act={act} busy={busy} canReview={canReview} />}
      {tab === "events" && <section className="wb-panel"><h3>按序事件</h3><div className="wb-events">{workflow.events.map(e => <div key={e.event_id}><span>{e.sequence + 1}</span><section><strong>{eventNames[e.kind] || e.kind}</strong><small>{e.recorded_at}</small><details><summary>核查事件依据</summary><pre>{JSON.stringify(e.payload, null, 2)}</pre></details></section></div>)}</div></section>}
    </>}
  </>;
}

function Assets({ catalog, act, busy, isAdmin, returnTo }) {
  if (!catalog) return <p>正在读取登记与生命周期记录…</p>;
  const candidates = (status) => ["agents", "tools"].flatMap(kind => catalog[kind].filter(a => a.status === status).map(a => ({ kind, id: a.id, release_digest: a.release_digest })));
  return <><div className="wb-page-head"><div><h1>Agent 与工具</h1><p>内置候选启动时仅登记，必须分别评估、人工批准激活。激活不是任务执行授权。</p></div>{isAdmin && <div className="wb-actions"><button disabled={busy || !candidates("draft").length} onClick={() => act(() => post("/v1/workbench/assets/batch/evaluate", { items: candidates("draft") }))}>评价全部已登记候选</button><button className="wb-primary" disabled={busy || !candidates("evaluation").length} onClick={() => act(() => post("/v1/workbench/assets/batch/activate", { items: candidates("evaluation") }))}>批准并激活全部已通过候选</button></div>}</div>
    {returnTo && <section className="wb-panel"><p>配置完成后可回到刚才的任务；原计划和资料保持原状。</p><button className="wb-primary" onClick={() => go(returnTo.startsWith("tasks") ? returnTo : "tasks")}>{returnTo === "tasks" ? "返回任务工作台" : "返回原任务"}</button></section>}
    {["agents", "tools"].map(kind => <section key={kind}><h2>{kind === "agents" ? "部门专业 Agent" : "固定工具契约"}</h2><div className="wb-asset-grid">{catalog[kind].map(a => <article className="wb-panel" key={a.id}><div className="wb-section-head"><h3>{operations[a.name] || a.name}</h3>{badge(a.status)}</div><p>版本 {a.version} · {a.department_id ? departments[a.department_id] : "固定输入输出契约 · 禁止网络外发"}</p>
      <small className="wb-mono">{a.release_digest}</small><p>{a.status === "active" ? "评价与批准记录已完成；激活不替代任务授权。" : a.evaluation ? "离线契约评价已记录，仍需明确批准激活。" : "已登记，尚未形成独立评价。"}</p>
      {isAdmin && <div className="wb-actions">{a.status === "draft" && <button disabled={busy} onClick={() => act(() => post(`/v1/workbench/assets/${kind}/${a.id}/evaluate`))}>执行离线评价</button>}{a.status === "evaluation" && <button className="wb-primary" disabled={busy} onClick={() => act(() => post(`/v1/workbench/assets/${kind}/${a.id}/activate`))}>批准并激活</button>}{a.status === "active" && <button disabled={busy} onClick={() => act(() => post(`/v1/workbench/assets/${kind}/${a.id}/suspend`))}>暂停</button>}</div>}
      {a.status === "suspended" && <p className="wb-warning">已暂停，关联任务不能继续使用。原状态机要求新发布版本重新登记评价，不提供绕过批准的一键恢复。</p>}
    </article>)}</div></section>)}<section className="wb-panel"><h3>能力边界</h3><p>本地专业执行器已接入。Hermes、Codex仍为未连接候选；没有将登记、评价或本机账号包装成生产资格。</p></section></>;
}

function Runtime({ data }) {
  if (!data) return <p>正在读取运行队列与租约…</p>;
  return <><div className="wb-page-head"><div><h1>运行与预算</h1><p>队列、签名授权、租约与执行结果来自原生持久服务。</p></div>{badge(data.worker_online ? "active" : "blocked")}</div>
    <div className="wb-stats"><div><strong>{data.worker_online ? "在线" : "离线"}</strong><span>本机单Worker</span></div><div><strong>{data.budget.model_requests}</strong><span>真实模型请求（含失败）</span></div><div><strong>¥{((data.budget.cost_cny_micros || 0) / 1000000).toFixed(4)}</strong><span>活动费用及未知预留</span></div><div><strong>{data.runs.length}</strong><span>执行记录</span></div></div>
    <section className="wb-panel"><h3>执行记录</h3>{data.reconciliation_error && <p className="wb-error">候选协调失败：{data.reconciliation_error}。保持阻断，请检查本机日志。</p>}
      <table className="wb-table"><thead><tr><th>运行</th><th>状态</th><th>租约</th><th>结果或原因</th></tr></thead><tbody>{data.runs.map(r => <tr key={r.run_id}><td><code>{r.run_id}</code></td><td>{badge(r.status)}</td><td>{r.lease ? `${r.lease.status === "closed" ? "已闭合" : "有效"} · ${r.lease.outcome || "执行中"}` : "尚未领取"}</td><td>{reasons[r.failure_reason_code] || r.failure_reason_code || "—"}</td></tr>)}</tbody></table></section>
    <section className="wb-panel"><h3>模型与预算门禁</h3><p>{data.budget.reason}。旧真实验证报告只读，不会恢复其剩余额度。新模型请求仍需另行授权。</p><p>SQLite单Worker；受限进程不是OS安全沙箱；不宣称已完成分布式并发或生产部署。</p></section></>;
}

function Reviews({ workflows, isAdmin }) {
  const items = reviewItems(workflows, isAdmin);
  return <><div className="wb-page-head"><div><h1>审核待办</h1><p>分别确认计划、审核产物和最终交付；自动检查通过不能代替人工决定。</p></div></div>{items.length ? items.map(item => <button className="wb-review-card" key={item.key} onClick={() => go(item.route)}><div><h3>{item.workflow.title}</h3><p>{item.description}</p></div>{badge(item.status)}<span>打开审核 →</span></button>) : <div className="wb-empty"><h2>暂无待办</h2><p>计划和候选生成后进入待办；三个部门当前版本均获批准后，管理员可办理最终交付审核。</p></div>}</>;
}

function Accounts({ act }) {
  const [accounts, setAccounts] = useState([]);
  useEffect(() => { request("/v1/auth/pending-accounts").then(r => setAccounts(r.accounts)).catch(() => {}); }, []);
  return <section className="wb-panel"><h3>本机账号审批</h3>{accounts.length ? accounts.map(a => <div className="wb-section-head" key={a.account_id}><span>{a.display_name || a.username} · {departments[a.department_id] || a.department_id}</span><div className="wb-actions"><button onClick={() => act(async () => { await authPost(`accounts/${a.account_id}/approve`, { role_ref: "role_department_user" }); setAccounts(items => items.filter(x => x.account_id !== a.account_id)); })}>批准为部门用户</button><button onClick={() => act(async () => { await authPost(`accounts/${a.account_id}/approve`, { role_ref: "role_department_owner" }); setAccounts(items => items.filter(x => x.account_id !== a.account_id)); })}>批准为部门负责人</button></div></div>) : <p>暂无待批准账号。你可从登录页申请其他部门账号。</p>}</section>;
}

export default function Workbench() {
  const [user, setUser] = useState(undefined); const [route, setRoute] = useState(window.location.hash.slice(2) || "tasks");
  const [workflows, setWorkflows] = useState([]); const [detail, setDetail] = useState(null); const [catalog, setCatalog] = useState(null); const [runtime, setRuntime] = useState(null);
  const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  const [routePath, routeQuery = ""] = route.split("?");
  const [page, workflowId, tab = "overview", department = "product_center"] = routePath.split("/");
  const setupReturn = new window.URLSearchParams(routeQuery).get("returnTo");
  const isAdmin = user?.role_refs.includes("role_control_plane_admin");
  const login = useCallback(async () => { try { const me = await request("/v1/auth/me"); setUser(me.user); } catch { setUser(null); } }, []);
  useEffect(() => { login(); const update = () => setRoute(window.location.hash.slice(2) || "tasks"); window.addEventListener("hashchange", update); return () => window.removeEventListener("hashchange", update); }, [login]);
  const load = useCallback(async () => {
    if (!user) return;
    const data = await request("/v1/workflows"); setWorkflows(data.items);
    if (workflowId && page === "tasks") setDetail(await request(`/v1/workflows/${workflowId}`));
    setCatalog(await request("/v1/workbench/assets"));
    if (page === "runtime" && isAdmin) setRuntime(await request("/v1/workbench/runtime"));
  }, [user, workflowId, page, isAdmin]);
  useEffect(() => { let alive = true; const poll = () => load().catch(e => { if (alive) { if (e.status === 401) setUser(null); else setError(e.message); } }); poll(); const timer = window.setInterval(poll, 1800); return () => { alive = false; window.clearInterval(timer); }; }, [load]);
  const act = async (operation) => { setBusy(true); setError(""); try { await operation(); await load(); } catch (e) { setError(e.message); } finally { setBusy(false); } };
  if (user === undefined) return <div className="wb-loading">正在恢复本机会话…</div>;
  if (!user) return <Login onLogin={login} />;
  if (page === "governance") return <><div className="wb-legacy-bar"><button onClick={() => go("tasks")}>← 返回任务工作台</button><span>治理管理 · {user.display_name} · 本机登录权限</span></div>{isAdmin ? <Governance /> : <div className="wb-panel">治理操作需要管理员权限；你可在任务详情中查看本部门证据。</div>}</>;
  return <div className="wb-shell"><aside className="wb-sidebar"><a className="wb-brand" href="#/tasks"><b>O</b><span>Orbit<small>DELIVERY WORKBENCH</small></span></a><div className="wb-workspace-tag">本机协作工作区<span>虚构AI功能交付</span></div>
    <nav aria-label="工作台导航">{nav.map(([id, name, number]) => <button className={page === id ? "selected" : ""} key={id} onClick={() => go(id)}><small>{number}</small>{name}{id === "reviews" && <i>{reviewItems(workflows, isAdmin).length}</i>}</button>)}</nav>
    <div className="wb-sidebar-bottom"><p>本机身份 · 非企业认证<br />受控模型 · 实际工具执行<br />生产发布始终关闭</p><strong>{user.display_name || user.username}</strong><small>{isAdmin ? "本机管理员" : user.role_refs.includes("role_department_owner") ? "部门负责人" : "部门用户"}</small><button onClick={() => act(async () => { await authPost("logout"); setUser(null); })}>退出登录</button></div></aside>
    <main className="wb-main"><header className="wb-topbar"><span>工作区 / {nav.find(([id]) => id === page)?.[1] || "任务详情"}</span><span><i /> {(runtime?.budget || catalog?.budget || detail || workflows[0])?.live_model_enabled ? "独立授权模型活动 · 用量见任务与预算" : "离线模式 · 模型请求0次"}</span></header><div className="wb-content">
      {error && <div className="wb-error" role="alert"><strong>操作未完成</strong><span>{error}</span><button onClick={() => setError("")}>关闭</button></div>}
      {page === "tasks" && (workflowId ? detail?.workflow_id === workflowId ? <TaskDetail workflow={detail} tab={tab} department={department} act={act} busy={busy} user={user} catalog={catalog} /> : <p>正在读取任务…</p> : <Tasks workflows={workflows} busy={busy} act={act} catalog={catalog} isAdmin={isAdmin} />)}
      {page === "reviews" && <Reviews workflows={workflows} isAdmin={isAdmin} />}
      {page === "assets" && <Assets catalog={catalog} act={act} busy={busy} isAdmin={isAdmin} returnTo={setupReturn} />}
      {page === "runtime" && (isAdmin ? <Runtime data={runtime} /> : <section className="wb-panel">全局队列与预算仅向管理员开放。你可在本部门任务中查看执行状态。</section>)}
      {page === "examples" && <><div className="wb-page-head"><div><h1>示例与验证</h1><p>历史验证证据与日常任务分开。历史真实模型授权已关闭。</p></div></div>{isAdmin && <WorkbenchLiveEvidence />}<OfflineDemo />{isAdmin && <Accounts act={act} />}</>}
    </div></main></div>;
}
