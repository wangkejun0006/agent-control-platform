import { useEffect, useMemo, useState } from "react";
import { api, newIdempotencyKey } from "./api.js";
import OfflineDemo from "./OfflineDemo.jsx";
import {
  approvalTone,
  compactDigest,
  healthTone,
  routeCanApprove,
  stateFracture,
} from "./state.js";

const NAV = [
  ["offline_demo", "离线执行演示", true],
  ["overview", "公司治理总览", true],
  ["model_routes", "Model Routes", true],
  ["task_scope_audit", "Task Scope 审计", true],
  ["evidence_audit", "Evidence & Audit", true],
];

const labels = {
  approved: "已批准",
  rejected: "已拒绝",
  revoked: "已撤销",
  not_reviewed: "待审阅",
  ready: "READY",
  blocked: "BLOCKED",
  not_created: "NO SNAPSHOT",
  historical: "HISTORICAL",
  allow: "SCOPE PASS",
  deny: "POLICY DENY",
  not_run: "NOT AUDITED",
};

const Status = ({ value, tone }) => (
  <span className={`status status--${tone || "slate"}`}>{labels[value] || value || "—"}</span>
);

const Mono = ({ children, title }) => <span className="mono" title={title}>{children}</span>;

function App() {
  const [page, setPage] = useState("offline_demo");
  const [bootstrap, setBootstrap] = useState(null);
  const [routes, setRoutes] = useState([]);
  const [audits, setAudits] = useState([]);
  const [selectedRoute, setSelectedRoute] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [dialog, setDialog] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [readback, setReadback] = useState(null);

  const load = async () => {
    const [boot, routeData, auditData] = await Promise.all([
      api.bootstrap(), api.routes(), api.audits(),
    ]);
    setBootstrap(boot);
    setRoutes(routeData.items);
    setAudits(auditData.items);
    if (!selectedRoute && routeData.items[0]) setSelectedRoute(routeData.items[0].route_id);
  };

  useEffect(() => {
    load().catch((cause) => setError(cause.message));
  }, []);

  useEffect(() => {
    if ((page === "evidence_audit" || dialog?.kind === "evidence") && selectedRoute) {
      api.routeEvidence(selectedRoute).then(setEvidence).catch((cause) => setError(cause.message));
    }
  }, [page, selectedRoute, dialog?.kind]);

  const selected = useMemo(
    () => routes.find((route) => route.route_id === selectedRoute) || routes[0],
    [routes, selectedRoute],
  );

  const mutate = async (operation) => {
    setBusy(true);
    setError("");
    try {
      const result = await operation();
      await load();
      setReadback(result);
      setDialog(null);
      if (selectedRoute) setEvidence(await api.routeEvidence(selectedRoute));
    } catch (cause) {
      setError(cause.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <span className="brand__mark">O</span>
          <div><strong>Orbit</strong><small>CONTROL PLANE</small></div>
        </div>
        <div className="rail__scope"><span>公司执行边界</span><b>D0 · LOOPBACK</b></div>
        <nav aria-label="公司控制台导航">
          {NAV.map(([id, text, enabled], index) => (
            <button
              key={id}
              className={page === id ? "nav-item active" : "nav-item"}
              disabled={!enabled}
              onClick={() => enabled && setPage(id)}
              title={enabled ? text : "服务 API 与 D0 数据就绪后启用"}
            >
              <span>{String(index + 1).padStart(2, "0")}</span>{text}
              {!enabled && <em>后续</em>}
            </button>
          ))}
        </nav>
        <div className="rail__boundary">
          <b>权威边界</b>
          <p>公司审计 Scope；不编辑、不批准部门 Task。</p>
        </div>
        <div className="principal">
          <span className="pulse" />
          <div><b>{bootstrap?.principal?.display_name || "正在连接"}</b><small>role_control_plane_admin</small></div>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div>
            <span className="eyebrow">RESOURCE GOVERNANCE / 2026.09</span>
            <h1>{NAV.find(([id]) => id === page)?.[1]}</h1>
          </div>
          <div className="topbar__status"><span className="pulse" /> LOOPBACK CONTROL PLANE</div>
        </header>

        {error && <div className="error" role="alert"><b>失败关闭</b><span>{error}</span><button onClick={() => setError("")}>关闭</button></div>}

        {page === "offline_demo" && <OfflineDemo />}
        {page === "overview" && (
          <Overview routes={routes} audits={audits} onSelect={(id) => { setSelectedRoute(id); setPage("model_routes"); }} />
        )}
        {page === "model_routes" && (
          <ModelRoutes
            routes={routes}
            selected={selected}
            onSelect={setSelectedRoute}
            onAction={setDialog}
            onReconcile={(route) => mutate(() => api.reconcileRoute(route.route_id, {
              expected_revision_digest: route.revision_digest,
              reason: "管理员请求刷新当前 Route 的合成健康证据",
              idempotency_key: newIdempotencyKey("route-reconcile"),
            }))}
            busy={busy}
          />
        )}
        {page === "task_scope_audit" && (
          <TaskAudits audits={audits} busy={busy} onReconcile={(task) => mutate(() => api.reconcileAudit(task.task_id, {
            expected_revision: task.revision,
            expected_task_digest: task.task_digest,
            reason: "管理员触发确定性 Task Scope 重新核对",
            idempotency_key: newIdempotencyKey("task-audit"),
          }))} />
        )}
        {page === "evidence_audit" && (
          <Evidence evidence={evidence} routes={routes} selected={selectedRoute} onSelect={setSelectedRoute} />
        )}

        {readback && <Readback value={readback} onClose={() => setReadback(null)} />}
      </main>

      {dialog && (
        <ActionDialog
          dialog={dialog}
          route={selected}
          busy={busy}
          onClose={() => setDialog(null)}
          onSubmit={(payload) => mutate(() => performAction(dialog.kind, selected, payload))}
        />
      )}
      <div className="mobile-readonly">移动视图 · 仅状态与证据 · D0 交互约束</div>
    </div>
  );
}

function Overview({ routes, audits, onSelect }) {
  const blocked = routes.filter((route) => !route.eligible).length;
  const denied = audits.filter((audit) => audit.audit_status === "deny").length;
  return (
    <section className="content">
      <div className="section-intro">
        <div><span className="eyebrow">INDEPENDENT STATE PROJECTION</span><h2>公司资源治理矩阵</h2></div>
        <p>候选、ApprovalDecision、目录可选性、当前健康与 Execution Grant 分列呈现，任何一列都不推导另一列。</p>
      </div>
      <div className="signal-strip">
        <div><span>MODEL ROUTES</span><b>{routes.length}</b><small>精确 Revision</small></div>
        <div className={blocked ? "risk" : ""}><span>NOT ELIGIBLE</span><b>{blocked}</b><small>批准与健康分别核对</small></div>
        <div className={denied ? "risk" : ""}><span>SCOPE DENY</span><b>{denied}</b><small>不改变部门 Task</small></div>
        <div><span>GRANTS ISSUED</span><b>0</b><small>控制台不签发</small></div>
      </div>
      <RouteMatrix routes={routes} onSelect={onSelect} />
      <div className="audit-lane">
        <div className="audit-lane__label">TASK SCOPE AUDIT</div>
        <div className="audit-flow"><b>task_x</b><i>→</i><span>scope compare</span><i>→</i><strong>Policy deny</strong><i>→</i><span>Grant not issued</span><i>→</i><span>AuditEvent</span></div>
        <small>证据轨道没有批准按钮</small>
      </div>
    </section>
  );
}

function RouteMatrix({ routes, onSelect }) {
  return (
    <div className="matrix-wrap">
      <table className="matrix">
        <thead><tr><th>公司执行边界</th><th>候选 / 登记</th><th>ApprovalDecision</th><th>公司可选性</th><th>当前健康</th><th>Task Grant</th></tr></thead>
        <tbody>
          {routes.length === 0 && <tr><td colSpan="6" className="empty">目录为空 · 未伪造默认资源</td></tr>}
          {routes.map((route) => (
            <tr key={route.route_id} className={stateFracture(route) ? "fracture" : ""} onClick={() => onSelect?.(route.route_id)}>
              <td data-label="资源"><b>{route.requested_model}</b><Mono title={route.route_id}>{route.route_id}</Mono></td>
              <td data-label="候选"><Status value={route.candidate_status} tone="cyan" /><Mono title={route.revision_digest}>{compactDigest(route.revision_digest)}</Mono></td>
              <td data-label="批准"><Status value={route.approval_status} tone={approvalTone(route.approval_status)} />{stateFracture(route) && <small className="fracture-note">已批准 ≠ 当前可用</small>}</td>
              <td data-label="可选性"><Status value={route.eligible ? "ELIGIBLE" : "INELIGIBLE"} tone={route.eligible ? "green" : "red"} /></td>
              <td data-label="健康"><Status value={route.health.status} tone={healthTone(route.health.status)} /><small>{route.health.reason_codes?.[0] || "证据当前有效"}</small></td>
              <td data-label="Grant"><Status value="NOT ISSUED" tone="slate" /><small>Task 级权威独立</small></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ModelRoutes({ routes, selected, onSelect, onAction, onReconcile, busy }) {
  return (
    <section className="content split">
      <div className="workspace">
        <div className="section-intro compact"><div><span className="eyebrow">FIRST WRITABLE LOOP</span><h2>Model Route 目录</h2></div><button className="button secondary desktop-action" onClick={() => onAction({ kind: "candidate" })}>导入 Revision</button></div>
        <RouteMatrix routes={routes} onSelect={onSelect} />
        <div className="boundary-note"><b>进入公司可选目录</b><span>仅允许精确 Revision 被 Binding、Policy 与 Runtime Composition 引用；不切换 Task、不调用模型、不生成 Grant。</span></div>
      </div>
      <aside className="inspector">
        <span className="eyebrow">SELECTED RESOURCE</span>
        {selected ? <>
          <h3>{selected.requested_model}</h3>
          <Mono title={selected.route_id}>{selected.route_id}</Mono>
          <dl>
            <dt>Revision</dt><dd><Mono title={selected.revision_digest}>{compactDigest(selected.revision_digest)}</Mono></dd>
            <dt>批准</dt><dd><Status value={selected.approval_status} tone={approvalTone(selected.approval_status)} /></dd>
            <dt>Snapshot</dt><dd><Status value={selected.health.status} tone={healthTone(selected.health.status)} /></dd>
            <dt>Secret Ref</dt><dd><Mono>{selected.secret_ref}</Mono></dd>
            <dt>Binding</dt><dd><Mono>{selected.secret_binding_version || "unavailable"}</Mono></dd>
          </dl>
          <div className="action-stack desktop-action">
            <button className="button" disabled={busy} onClick={() => onReconcile(selected)}>Reconcile / Preflight</button>
            <button className="button secondary" onClick={() => onAction({ kind: "observation" })}>记录 Observation</button>
            {routeCanApprove(selected) && <button className="button approve" onClick={() => onAction({ kind: "approve" })}>批准精确 Revision</button>}
            {selected.approval_status === "not_reviewed" && <button className="button danger-ghost" onClick={() => onAction({ kind: "reject" })}>拒绝候选</button>}
            {selected.approval_status === "approved" && <button className="button danger" onClick={() => onAction({ kind: "revoke" })}>撤销批准</button>}
            <button className="text-button" onClick={() => onAction({ kind: "evidence" })}>查看证据链 →</button>
          </div>
        </> : <p>尚无 Model Route。</p>}
      </aside>
    </section>
  );
}

function TaskAudits({ audits, onReconcile, busy }) {
  return (
    <section className="content">
      <div className="section-intro"><div><span className="eyebrow">EVIDENCE-ONLY POLICY LANE</span><h2>Task Scope 审计</h2></div><p>公司只比较边界。越界由确定性 Policy/Gateway 阻断或撤销 Grant；Task 内容、责任人和部门审批保持不变。</p></div>
      <div className="task-list">
        {audits.map((task) => <article className="task-row" key={task.task_id}>
          <div><span className="department">{task.department_id}</span><h3>{task.title}</h3><Mono>{task.task_id} · rev.{task.revision}</Mono></div>
          <div><small>部门状态</small><Status value={task.authority_state} tone="cyan" /></div>
          <div><small>Scope 结果</small><Status value={task.audit_status} tone={task.audit_status === "allow" ? "green" : task.audit_status === "deny" ? "red" : "amber"} />{task.reason_codes?.[0] && <span className="reason">{task.reason_codes[0]}</span>}</div>
          <div><small>Grant 动作</small><Status value={task.grant_action} tone={task.grant_action === "revoked" ? "red" : "slate"} /></div>
          <button className="button secondary desktop-action" disabled={busy} onClick={() => onReconcile(task)}>重新核对</button>
        </article>)}
      </div>
      <div className="no-approval"><b>NO TASK APPROVAL</b><span>此页面不会创建或修改 `task_execution_approval`。</span></div>
    </section>
  );
}

function Evidence({ evidence, routes, selected, onSelect }) {
  return (
    <section className="content evidence-page">
      <div className="section-intro"><div><span className="eyebrow">IMMUTABLE READBACK</span><h2>Evidence & Audit</h2></div><select aria-label="选择 Model Route" value={selected || ""} onChange={(event) => onSelect(event.target.value)}>{routes.map((route) => <option key={route.route_id}>{route.route_id}</option>)}</select></div>
      {!evidence ? <div className="empty-block">正在读取服务端证据…</div> : <>
        <div className="evidence-index">
          <div><span>REVISION</span><b>{evidence.revisions.length}</b></div>
          <div><span>DECISION</span><b>{evidence.decisions.length}</b></div>
          <div><span>RECEIPT</span><b>{evidence.receipts.length}</b></div>
          <div><span>SNAPSHOT</span><b>{evidence.snapshots.length}</b></div>
          <div><span>AUDIT EVENT</span><b>{evidence.audit_events.length}</b></div>
        </div>
        <pre className="evidence-json">{JSON.stringify(evidence, null, 2)}</pre>
      </>}
    </section>
  );
}

function Readback({ value, onClose }) {
  return <aside className="readback" aria-live="polite"><div><span className="eyebrow">SERVER READBACK</span><b>写入后已从 Control Plane 重读</b></div><button onClick={onClose}>关闭</button><pre>{JSON.stringify(value, null, 2)}</pre></aside>;
}

function ActionDialog({ dialog, route, busy, onClose, onSubmit }) {
  const [reason, setReason] = useState("");
  const [document, setDocument] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const isJson = ["candidate", "observation"].includes(dialog.kind);
  const title = { candidate: "导入 Route Revision", observation: "记录 Provider Observation", approve: "批准 Model Route", reject: "拒绝 Model Route", revoke: "撤销 Model Route 批准", evidence: "证据链" }[dialog.kind];
  if (dialog.kind === "evidence") return <div className="modal" role="dialog" aria-modal="true"><div className="dialog"><button className="dialog__close" onClick={onClose}>关闭</button><h2>{title}</h2><p>请在 Evidence & Audit 页面查看服务端完整读回。</p><button className="button" onClick={onClose}>返回</button></div></div>;
  const submit = () => {
    let parsed = null;
    if (isJson) {
      try { parsed = JSON.parse(document); } catch { return; }
    }
    onSubmit({ reason, document: parsed });
  };
  return <div className="modal" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><div className="dialog">
    <button className="dialog__close" onClick={onClose}>关闭</button>
    <span className="eyebrow">DIGEST-BOUND MUTATION</span><h2 id="dialog-title">{title}</h2>
    {route && dialog.kind !== "candidate" && <div className="binding"><span>{route.route_id}</span><Mono>{compactDigest(route.revision_digest)}</Mono></div>}
    {isJson && <label>合成 JSON 文档<textarea rows="11" value={document} onChange={(event) => setDocument(event.target.value)} spellCheck="false" /></label>}
    <label>精确原因<textarea rows="3" value={reason} onChange={(event) => setReason(event.target.value)} placeholder="至少 8 个字符；将进入审计证据" /></label>
    <label className="confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>我确认本次动作绑定当前 Revision；它不批准 Task、不签发 Grant、不调用模型。</span></label>
    <button className={dialog.kind === "revoke" || dialog.kind === "reject" ? "button danger" : "button approve"} disabled={busy || reason.trim().length < 8 || !confirmed || (isJson && !document)} onClick={submit}>{busy ? "正在写入…" : "提交并读回证据"}</button>
  </div></div>;
}

const performAction = (kind, route, payload) => {
  if (kind === "candidate") {
    const current = route && payload.document?.route_id === route.route_id ? route.revision_digest : "none";
    return api.submitCandidate({ document: payload.document, expected_latest_revision_digest: current, reason: payload.reason, idempotency_key: newIdempotencyKey("route-candidate") });
  }
  if (kind === "observation") return api.submitObservation({ route_id: route.route_id, expected_revision_digest: route.revision_digest, document: payload.document, reason: payload.reason, idempotency_key: newIdempotencyKey("provider-observation") });
  if (kind === "approve" || kind === "reject") return api.decideRoute({ decision_scope: "model_route_approval", route_id: route.route_id, expected_revision_digest: route.revision_digest, expected_snapshot_digest: route.health.snapshot_digest, decision: kind === "approve" ? "approved" : "rejected", reason: payload.reason, idempotency_key: newIdempotencyKey("route-decision") });
  if (kind === "revoke") return api.revokeRoute(route.route_id, { expected_revision_digest: route.revision_digest, expected_approval_decision_digest: route.approval_decision_digest, reason: payload.reason, idempotency_key: newIdempotencyKey("route-revoke") });
  throw new Error("unsupported_action");
};

export default App;

