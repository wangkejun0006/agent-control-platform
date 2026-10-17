import { expect, test } from "@playwright/test";
import { login } from "./workbench-helpers.js";

test("Model Route、Task Scope 与移动只读形成真实 D0 闭环", async ({ page }) => {
  await login(page);
  await page.goto("/#/governance");
  await page.getByRole("button", { name: /公司治理总览/ }).click();

  await expect(page.getByRole("heading", { name: "公司治理总览" })).toBeVisible();
  await expect(page.getByText("公司资源治理矩阵", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /Runtime Adapters/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Agent Registry/ })).toHaveCount(0);
  await expect(page.getByRole("columnheader", { name: "ApprovalDecision" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Task Grant" })).toBeVisible();

  await page.getByRole("button", { name: /Model Routes/ }).click();
  await page.getByRole("button", { name: "批准精确 Revision" }).click();
  await page.getByLabel("精确原因").fill("Playwright 批准该精确 D0 合成 Revision");
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "提交并读回证据" }).click();
  const approvalReadback = page.getByRole("complementary").filter({
    hasText: "SERVER READBACK",
  });
  await expect(approvalReadback).toContainText("写入后已从 Control Plane 重读");
  await expect(approvalReadback).toContainText('"eligible": true');
  await expect(approvalReadback).toContainText('"execution_grant_issued": false');
  await approvalReadback.getByRole("button", { name: "关闭" }).click();

  await page.getByRole("button", { name: /Task Scope 审计/ }).click();
  const eligibleTask = page.locator(".task-row").filter({
    hasText: "task_technology_syn_001",
  });
  await eligibleTask.getByRole("button", { name: "重新核对" }).click();
  const auditReadback = page.getByRole("complementary").filter({
    hasText: "SERVER READBACK",
  });
  await expect(auditReadback).toContainText('"decision": "allow"');
  await expect(auditReadback).toContainText('"task_content_changed": false');
  await expect(auditReadback).toContainText(
    '"department_approval_state_changed": false',
  );
  await auditReadback.getByRole("button", { name: "关闭" }).click();

  await page.getByRole("button", { name: /Evidence & Audit/ }).click();
  await expect(page.getByText("RECEIPT", { exact: true })).toBeVisible();
  await expect(page.locator(".evidence-json")).toContainText("ApprovalDecision");

  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await expect(
    page.getByText("移动视图 · 仅状态与证据 · D0 交互约束"),
  ).toBeVisible();
  await page.getByRole("button", { name: /Model Routes/ }).click();
  await expect(page.getByRole("button", { name: "撤销批准" })).toBeHidden();
  await expect(page.locator(".boundary-note")).toContainText(
    "不切换 Task、不调用模型、不生成 Grant",
  );
});

