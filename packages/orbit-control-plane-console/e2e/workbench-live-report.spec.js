import { test, expect } from "@playwright/test";
import { login } from "./workbench-helpers.js";

test("工作台真实验证证据只读展示关闭预算、正文问题与返工原文", async ({ page }) => {
  const external = [];
  await page.route("**/*", route => {
    if (!["127.0.0.1", "localhost"].includes(new URL(route.request().url()).hostname)) {
      external.push(route.request().url());
      return route.abort();
    }
    return route.continue();
  });
  await login(page);
  await page.goto("/#/examples");
  await expect(page.getByRole("heading", { name: "跨部门工作台 · 真实模型验证" })).toBeVisible();
  await expect(page.getByText("22/24 次", { exact: true })).toBeVisible();
  await expect(page.getByText(/正文待改进/)).toBeVisible();
  await page.getByRole("button", { name: "查看返工前后原文" }).click();
  await expect(page.getByRole("heading", { name: "市场 v1 · 已退回", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "市场 v2 · 测试审核通过，正文仍待人工复核", exact: true })).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("link", { name: "下载历史验证交付包", exact: true }).click();
  expect((await download).suggestedFilename()).toBe("workbench-live-delivery.zip");
  await page.screenshot({ path: "test-results/screenshots/workbench-live-evidence.png", fullPage: false });
  expect(external).toEqual([]);
});
