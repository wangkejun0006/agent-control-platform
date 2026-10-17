import { expect } from "@playwright/test";

export const headers = { Origin: "http://127.0.0.1:8432", "X-Orbit-Request": "department-cockpit" };
export async function login(page) {
  const status = await (await page.request.get("/v1/auth/status")).json();
  const credentials = { username: "workbench_test_admin", password: "offline-browser-test-only" };
  if (status.bootstrap_required) {
    const registered = await page.request.post("/v1/auth/register", { headers, data: { ...credentials, display_name: "浏览器验收管理员" } });
    expect(registered.status()).toBe(201);
  }
  const logged = await page.request.post("/v1/auth/login", { headers, data: credentials });
  expect(logged.status()).toBe(200);
}

export async function command(page, path, data = {}) {
  const response = await page.request.post(path, { headers, data: { ...data, idempotency_key: `browser:${crypto.randomUUID()}` } });
  expect(response.ok(), await response.text()).toBe(true);
  return response.json();
}

export async function ensureAssets(page) {
  const assets = await (await page.request.get("/v1/workbench/assets")).json();
  for (const kind of ["agents", "tools"]) {
    for (const asset of assets[kind]) {
      if (asset.status === "draft") await command(page, `/v1/workbench/assets/${kind}/${asset.id}/evaluate`);
      if (["draft", "evaluation"].includes(asset.status)) await command(page, `/v1/workbench/assets/${kind}/${asset.id}/activate`);
    }
  }
}
