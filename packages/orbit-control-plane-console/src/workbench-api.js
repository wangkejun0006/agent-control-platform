export async function request(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  const value = await response.json().catch(() => ({ detail: "响应格式无效" }));
  if (!response.ok) {
    const error = new Error(typeof value.detail === "string" ? value.detail : "请求失败，请检查填写内容");
    error.status = response.status;
    throw error;
  }
  return value;
}

export function post(path, data = {}) {
  return request(path, { method: "POST", headers: { "Content-Type": "application/json", "X-Orbit-Request": "department-cockpit" },
    body: JSON.stringify({ ...data, idempotency_key: `web:${crypto.randomUUID()}` }) });
}

export function authPost(action, data = {}) {
  return request(`/v1/auth/${action}`, { method: "POST", headers: { "Content-Type": "application/json", "X-Orbit-Request": "department-cockpit" }, body: JSON.stringify(data) });
}

export const departments = { product_center: "产品部门", technology_center: "技术部门", market_center: "市场部门" };
export const statuses = { not_started: "待开始", needs_input: "待澄清", awaiting_approval: "待确认计划", plan_approved: "计划已确认",
  queued: "排队中", running: "执行中", cancel_requested: "正在取消", completed: "执行已完成", awaiting_review: "待审核",
  blocked: "检查未通过", approved: "已批准", changes_requested: "需返工", stale: "上游变更·已失效", failed: "执行失败",
  cancelled: "已取消", delivered: "已交付", awaiting_final_review: "待最终审核", draft: "已登记", evaluation: "待批准激活",
  active: "已激活", suspended: "已暂停", failed_closed: "已阻断", stop_requested: "规划已停止" };
export const operations = { query_documents: "查询受控资料", retrieve_evidence: "检索与定位引用", validate_requirements: "校验需求与版本",
  run_acceptance: "执行权限与引用验收", submit_candidate: "提交本地候选" };
