import { useEffect, useState } from "react";
import { api } from "./api.js";

const names = {
  success: "虚构资料处理成功", bad_quality: "质量门禁拒绝", wrong_task: "任务引用错配",
  duplicate_json: "重复 JSON 键", timeout: "进程超时", cancel: "执行中撤销",
  output_limit: "输出超限", missing_grant: "缺少有效授权", unknown_capability: "未注册能力",
  private_input: "拒绝非演示资料", idempotent_replay: "幂等重放", approval_gate: "生命周期审批门禁",
  runtime_composition: "冻结三个 Tool 的运行时组合", tool_operation_gate: "拒绝未批准的 Tool 操作",
};

export default function OfflineDemo() {
  const [report, setReport] = useState(null);
  const [live, setLive] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.offlineReport().then(setReport).catch(e => setError(e.message)); }, []);
  useEffect(() => { api.liveReport().then(setLive).catch(() => {}); }, []);
  const run = async () => {
    setBusy(true); setError("");
    try { setReport(await api.runOfflineDemo()); } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };
  return <section className="offline-demo">
    <h2>Paper Orbit · 虚构任务执行闭环</h2>
    {live && <details open style={{ marginBottom: "20px" }}>
      <summary>真实模型验证证据（只读）</summary>
      <p>请求 {live.requests}/{live.request_limit}；保守计费与未知请求预留合计 ¥{live.accounted_cost_cny} / ¥{live.cost_limit_cny}。
        授权{live.closed ? "已关闭" : "正在使用"}。资料为虚构，审核为脚本夹具。本页操作不会调用真实模型。</p>
      <p>状态：{live.close_reason || "验证中"}；失败请求 {live.failed_requests.length} 条，均保留。</p>
      <details><summary>查看真实规划、工具执行、返工与审核记录</summary>
        <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: "480px", overflow: "auto" }}>{JSON.stringify(live.events, null, 2)}</pre>
      </details>
    </details>}
    <p>保留原 Router → 受限子进程 → 独立 Evaluator → 追加式台账与租约。资料、规划输出与审核操作均为演示夹具。</p>
    <p>本页仅运行固定的本地流程；模型请求 {report?.model_calls ?? 0} 次，费用 ¥{report?.cost_cny ?? "0"}。脚本审核不代表真实人工审批或生产授权。</p>
    <button onClick={run} disabled={busy}>{busy ? "正在执行离线闭环…" : "运行离线演示"}</button>
    {error && <p role="alert">{error}</p>}
    {report && <>
      <h3>{report.passed ? "验收通过" : "验收未通过"}</h3>
      <table style={{ width: "100%", textAlign: "left", lineHeight: 2.2 }}>
        <thead><tr><th>场景</th><th>验收</th><th>任务结果</th><th>阻断原因</th></tr></thead>
        <tbody>{Object.entries(report.checks).map(([name, passed]) => {
          const item = report.cases.find(c => c.scenario === name);
          return <tr key={name}><td>{names[name] || name}</td><td>{passed ? "PASS" : "FAIL"}</td>
            <td>{item?.status || "控制验证"}</td><td>{item?.reason_codes?.join(", ") || "—"}</td></tr>;
        })}</tbody>
      </table>
      {report.cases.map(item => <details key={item.scenario} style={{ marginTop: "12px" }}>
        <summary>{names[item.scenario]}：查看真实执行回执与台账</summary>
        <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify(item, null, 2)}</pre>
      </details>)}
      <details><summary>查看 Tool 生命周期与不可变组合（不执行发布）</summary>
        <pre>{JSON.stringify(report.composition, null, 2)}</pre></details>
    </>}
  </section>;
}
