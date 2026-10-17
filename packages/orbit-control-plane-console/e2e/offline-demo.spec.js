import { test, expect } from "@playwright/test";
import { login } from "./workbench-helpers.js";

test("fictional offline workflow closes in the retained console", async ({ page }) => {
  const external = [];
  await page.route("**/*", route => {
    const url = new URL(route.request().url());
    if (!["127.0.0.1", "localhost"].includes(url.hostname)) {
      external.push(url.origin);
      return route.abort();
    }
    return route.continue();
  });
  await login(page);
  await page.goto("/#/examples");
  await expect(page.getByRole("heading", { name: "Paper Orbit · 虚构任务执行闭环" })).toBeVisible();
  const finished = page.waitForResponse(response => response.url().endsWith("/v1/showcase/run") && response.request().method() === "POST");
  await page.getByRole("button", { name: "运行离线演示", exact: true }).click();
  expect((await finished).status()).toBe(200);
  await expect(page.getByRole("heading", { name: "验收通过", exact: true })).toBeVisible({ timeout: 15000 });
  await expect(page.getByRole("cell", { name: "PASS", exact: true })).toHaveCount(14);
  const response = await page.request.get("/v1/showcase/report");
  const report = await response.json();
  expect(report.model_calls).toBe(0);
  expect(report.cases.find(c => c.scenario === "cancel").ledger.tasks[0].worker_lease.status).toBe("cancelled");
  expect(report.checks.idempotent_replay).toBe(true);
  expect(external).toEqual([]);
  await page.screenshot({ path: "test-results/screenshots/offline-console.png", fullPage: true });
});
