import { expect, test } from "@playwright/test";
import { login, command } from "./workbench-helpers.js";

test("共享例外与默认隔离在桌面及移动任务页可理解且不溢出", async ({ page }) => {
  await login(page);
  await page.goto("/#/tasks");
  await expect(page.getByRole("heading", { name: "未经共享的资料，不能访问", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "已批准并显式共享的产物，可以使用", exact: true })).toBeVisible();
  const task = await command(page, "/v1/workflows", { title: "共享规则离线页面验证", goal: "检查未经共享不能读取，批准并显式共享的产物仅能按绑定版本交接。" });
  await page.goto(`/#/tasks/${task.workflow_id}/overview/product_center`);
  await page.locator("summary").filter({ hasText: "资料访问与交接规则" }).click();
  await expect(page.getByRole("heading", { name: "已批准并显式共享的产物，可以使用", exact: true })).toBeVisible();
  await page.screenshot({ path: "test-results/screenshots/sharing-workbench-desktop.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("heading", { name: "未经共享的资料，不能访问", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: "test-results/screenshots/sharing-workbench-mobile.png", fullPage: true });
});
