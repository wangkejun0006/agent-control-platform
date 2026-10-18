import { expect, test } from "@playwright/test";

// All mutations in this acceptance are through visible UI controls, including
// first-account bootstrap and catalog approval. No request/API setup shortcuts.
test("新账号从任务到市场实质返工、最终待办审核和ZIP交付", async ({ page }, testInfo) => {
  const external = [];
  await page.route("**/*", route => {
    if (!["127.0.0.1", "localhost"].includes(new URL(route.request().url()).hostname)) {
      external.push(route.request().url()); return route.abort();
    }
    return route.continue();
  });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "初始化本机工作台" })).toBeVisible();
  await page.getByLabel("用户名", { exact: true }).fill("p0_browser_admin");
  await page.getByLabel("显示名称", { exact: true }).fill("零模型页面验收");
  await page.getByLabel("口令（至少12位）", { exact: true }).fill("synthetic-offline-p0-only");
  await page.getByRole("button", { name: "创建管理员并进入", exact: true }).click();
  await page.getByRole("button", { name: "03 Agent 与工具", exact: true }).click();
  await page.getByRole("button", { name: "评价全部已登记候选", exact: true }).click();
  await page.getByRole("button", { name: "批准并激活全部已通过候选", exact: true }).click();
  await expect(page.getByRole("button", { name: "暂停", exact: true })).toHaveCount(8);
  await page.getByRole("button", { name: "01 任务工作台", exact: true }).click();
  await page.getByRole("button", { name: "＋ 创建交付任务", exact: true }).click();
  await page.getByLabel("任务标题").fill("P0验收 · 三部门实质返工与本地交付");
  await page.getByRole("button", { name: "创建任务", exact: true }).click();
  await page.getByRole("button", { name: "前往处理", exact: true }).click();
  await page.getByRole("button", { name: "导入13份虚构资料并授权三部门使用", exact: true }).click();
  await expect(page.getByRole("button", { name: /requirements-v2.md/ })).toBeVisible();

  async function planAndExecute(start) {
    await page.getByRole("button", { name: "规划", exact: true }).click();
    if (start) await page.getByRole("button", { name: "开始部门规划", exact: true }).click();
    await page.getByRole("button", { name: "提交回答并生成计划", exact: true }).click();
    await page.getByLabel("计划审核说明（至少8字）").fill("已核对固定工具、引用及权限范围，同意本机离线执行。");
    await page.getByRole("button", { name: "确认计划与工具范围", exact: true }).click();
    await page.getByRole("button", { name: "提交受控执行", exact: true }).click();
    await page.getByRole("button", { name: "执行", exact: true }).click();
    await expect(page.getByRole("cell", { name: "已执行", exact: true })).toHaveCount(5, { timeout: 25000 });
    await page.getByRole("button", { name: "产物与审核", exact: true }).click();
    await expect(page.getByText("引用对应批准的资料版本与原文", { exact: false })).toBeVisible();
  }

  for (const [index, department] of ["产品部门", "技术部门", "市场部门"].entries()) {
    if (index) await page.getByRole("button", { name: new RegExp(`0${index + 1} ${department} `) }).click();
    await planAndExecute(true);
    if (department === "市场部门") {
      await page.getByLabel("审核或修订说明（至少8字）").fill("请补充资料不足时的处理步骤，并给出负责人可逐项核对的验收清单。");
      await page.getByRole("button", { name: "退回修改", exact: true }).click();
      await page.getByLabel("我已核查旧尝试；新建修订不会盲目重放不确定步骤。").check();
      await page.getByRole("button", { name: "创建新修订并重新规划", exact: true }).click();
      await planAndExecute(false);
      await expect(page.getByRole("heading", { name: "交付候选 · v2", exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "缺少依据时的处理步骤", exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "负责人逐项验收清单", exact: true })).toBeVisible();
      await expect(page.locator(".wb-prose").first().getByText("2. 暂停无依据结论和后续交付，向负责人提出补充资料请求。", { exact: true })).toBeVisible();
      await expect(page.getByRole("region", { name: "返工要求处理" })).toContainText("已生成对应修改");
      await expect(page.locator("summary").filter({ hasText: "全部尝试与历史候选" })).toBeVisible();
      await page.screenshot({ path: testInfo.outputPath("market-v2.png"), fullPage: true });
    }
    await page.getByLabel("审核或修订说明（至少8字）").fill("已核对当前产物、证据和实际修改，批准本机虚构演示当前版本。");
    const target = ["技术部门", "市场部门", null][index];
    await page.getByRole("button", { name: target ? `批准并授权交接${target}` : "批准本部门产物", exact: true }).click();
    await expect(page.getByText("审核意见：已核对当前产物", { exact: false })).toBeVisible();
  }
  // The task's next-action button now opens the actual final review form.
  await page.getByRole("button", { name: "概览", exact: true }).click();
  await page.getByRole("button", { name: "前往处理", exact: true }).click();
  await expect(page).toHaveURL(/final-review\/market_center/);
  await expect(page.getByLabel("最终审核说明")).toBeVisible();
  // Badge and card use the same pending-review projection.
  await page.getByRole("button", { name: "02 审核待办 1", exact: true }).click();
  await expect(page.getByRole("button", { name: /最终交付审核 · 三部门当前版本已批准/ })).toHaveCount(1);
  await page.getByRole("button", { name: /最终交付审核 · 三部门当前版本已批准/ }).click();
  await expect(page.getByLabel("最终审核说明")).toBeVisible();
  await page.reload();
  await page.getByLabel("最终审核说明").fill("三部门当前版本、实质返工和证据均已核对，仅批准虚构演示的本地ZIP交付。");
  await page.getByRole("button", { name: "批准本地交付", exact: true }).click();
  await expect(page.getByRole("link", { name: "下载交付包 ZIP", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "02 审核待办 0", exact: true })).toBeVisible();
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("link", { name: "下载交付包 ZIP", exact: true }).click();
  const download = await downloadEvent;
  await download.saveAs(testInfo.outputPath("local-delivery.zip"));
  await page.reload();
  await expect(page.getByRole("link", { name: "下载交付包 ZIP", exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("delivery-complete.png"), fullPage: true });
  expect(external).toEqual([]);
});
