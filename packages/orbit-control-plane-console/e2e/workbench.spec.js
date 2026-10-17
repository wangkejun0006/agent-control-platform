import { expect, test } from "@playwright/test";
import { command, ensureAssets, login } from "./workbench-helpers.js";

test("从浏览器完成三部门规划、实际执行、人工审核与本地交付", async ({ page }) => {
  const external = [];
  await page.route("**/*", route => {
    if (!["127.0.0.1", "localhost"].includes(new URL(route.request().url()).hostname)) { external.push(route.request().url()); return route.abort(); }
    return route.continue();
  });
  await login(page); await ensureAssets(page); await page.goto("/#/tasks");
  await page.getByRole("button", { name: "＋ 创建交付任务" }).click();
  await page.getByLabel("任务标题").fill("浏览器全流程 · 团队知识助手");
  await page.getByRole("button", { name: "创建任务", exact: true }).click();
  await expect(page.getByRole("heading", { name: "浏览器全流程 · 团队知识助手" })).toBeVisible();
  const workflow = page.url().split("/tasks/")[1].split("/")[0];
  await page.getByRole("button", { name: "资料", exact: true }).click();
  await page.getByRole("button", { name: "导入13份虚构资料并授权三部门使用" }).click();
  await expect(page.getByRole("button", { name: /requirements-v2.md/ })).toBeVisible();
  for (const [index, department] of ["product_center", "technology_center", "market_center"].entries()) {
    await page.goto(`/#/tasks/${workflow}/planning/${department}`);
    await page.getByRole("button", { name: "开始部门规划", exact: true }).click();
    await page.getByLabel("补充约束").fill("不越部门检索；不承诺生产能力；所有引用应可定位，交付须人工审核。");
    await page.getByRole("button", { name: "提交回答并生成计划" }).click();
    await page.getByLabel("计划审核说明（至少8字）").fill("浏览器验收确认计划范围和固定工具，禁止自动发布。");
    await page.getByRole("button", { name: "确认计划与工具范围" }).click();
    await page.getByRole("button", { name: "提交受控执行", exact: true }).click();
    await page.getByRole("button", { name: "执行", exact: true }).click();
    await expect(page.getByRole("cell", { name: "已执行", exact: true })).toHaveCount(5, { timeout: 20000 });
    await page.getByRole("button", { name: "产物与审核", exact: true }).click();
    await expect(page.getByText("引用对应批准的资料版本与原文")).toBeVisible();
    await page.getByLabel("审核或修订说明（至少8字）").fill("已人工核对引用、部门权限、检查结果和限制说明，批准当前候选。");
    const target = ["技术部门", "市场部门", null][index];
    await page.getByRole("button", { name: target ? `批准并授权交接${target}` : "批准本部门产物", exact: true }).click();
    await expect(page.getByText("审核意见：已人工核对", { exact: false })).toBeVisible();
  }
  await page.getByRole("button", { name: "概览", exact: true }).click();
  await page.getByLabel("最终审核说明").fill("三个部门的当前版本和引用均已核对，批准本地交付，不对外发布。");
  await page.getByRole("button", { name: "批准本地交付", exact: true }).click();
  await expect(page.getByRole("link", { name: "下载交付包 ZIP" })).toBeVisible();
  const downloaded = await page.request.get(`/v1/workflows/${workflow}/download`);
  expect(downloaded.status()).toBe(200);
  expect(downloaded.headers()["content-type"]).toContain("application/zip");
  await page.reload();
  await expect(page.getByRole("link", { name: "下载交付包 ZIP" })).toBeVisible();
  expect(external).toEqual([]);
  const data = await (await page.request.get(`/v1/workflows/${workflow}`)).json();
  expect(data.model_requests).toBe(0); expect(data.status).toBe("delivered");
  await page.screenshot({ path: "test-results/screenshots/workbench-delivery.png", fullPage: true });
  await page.getByRole("button", { name: "任务工作台", exact: false }).first().click();
  await page.screenshot({ path: "test-results/screenshots/workbench-tasks.png", fullPage: true });
});

test("界面退回创建新版本，旧候选保留且旧批准被拒绝", async ({ page }) => {
  await login(page); await ensureAssets(page);
  const workflow = await command(page, "/v1/workflows", { title: "浏览器返工与权限拒绝", goal: "为团队知识助手验证权限、引用、撤权和验收，并在人工意见后形成新版本。" });
  const id = workflow.workflow_id;
  await command(page, `/v1/workflows/${id}/import-fixtures`);
  await page.goto(`/#/tasks/${id}/planning/product_center`);
  await page.getByRole("button", { name: "开始部门规划", exact: true }).click();
  await page.getByRole("button", { name: "提交回答并生成计划" }).click();
  await page.getByLabel("计划审核说明（至少8字）").fill("本机负责人确认计划和工具范围，准备离线执行。");
  await page.getByRole("button", { name: "确认计划与工具范围" }).click();
  await page.getByRole("button", { name: "提交受控执行", exact: true }).click();
  await page.getByRole("button", { name: "产物与审核", exact: true }).click();
  await expect(page.getByLabel("审核或修订说明（至少8字）")).toBeVisible();
  await expect(page.getByRole("button", { name: "退回修改", exact: true })).toBeVisible({ timeout: 20000 });
  const old = await (await page.request.get(`/v1/workflows/${id}`)).json();
  const node = old.nodes[0];
  await page.getByLabel("审核或修订说明（至少8字）").fill("请补充引用不足时的处理和负责人的具体验收清单。");
  await page.getByRole("button", { name: "退回修改", exact: true }).click();
  await page.getByLabel("我已核查旧尝试；新建修订不会盲目重放不确定步骤。").check();
  await page.getByRole("button", { name: "创建新修订并重新规划" }).click();
  await expect(page.getByRole("button", { name: "提交回答并生成计划" })).toBeVisible();
  const rejection = await page.request.post(`/v1/workflows/${id}/departments/product_center/review`, { headers: { Origin: "http://127.0.0.1:8432", "X-Orbit-Request": "department-cockpit" }, data: {
    candidate_digest: node.candidate.candidate_digest, revision: 1, decision: "approve", reason: "旧版审批必须失败，不得覆盖当前版本。", idempotency_key: `old:${crypto.randomUUID()}` } });
  expect(rejection.status()).toBe(409);
  await page.getByRole("button", { name: "提交回答并生成计划" }).click();
  await page.getByLabel("计划审核说明（至少8字）").fill("修订计划已纳入审核意见，重新执行引用和权限验收。");
  await page.getByRole("button", { name: "确认计划与工具范围" }).click();
  await page.getByRole("button", { name: "提交受控执行", exact: true }).click();
  await page.goto(`/#/tasks/${id}/review/product_center`);
  await expect(page.getByRole("button", { name: "批准并授权交接技术部门", exact: true })).toBeVisible({ timeout: 20000 });
  await page.getByLabel("审核或修订说明（至少8字）").fill("新版本已补充引用不足处理和验收清单，检查通过后明确批准。");
  await page.getByRole("button", { name: "批准并授权交接技术部门", exact: true }).click();
  await expect(page.getByText("全部尝试与历史候选")).toBeVisible();
  await page.reload(); await expect(page.getByRole("heading", { name: "交付候选 · v2" })).toBeVisible();
});
