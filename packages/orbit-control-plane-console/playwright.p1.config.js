import { defineConfig } from "@playwright/test";
import os from "node:os";
import path from "node:path";

export default defineConfig({
  testDir: "./acceptance",
  testMatch: "p1-usability.spec.js",
  workers: 1,
  timeout: 180000,
  retries: 0,
  use: { baseURL: "http://127.0.0.1:8432", headless: true,
    viewport: { width: 1440, height: 1000 }, trace: "retain-on-failure",
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {},
  },
  webServer: {
    command: "cd ../.. && bash scripts/run_demo.sh",
    url: "http://127.0.0.1:8432/health/live",
    reuseExistingServer: false,
    timeout: 30000,
    env: { ORBIT_WORKBENCH_STATE_ROOT: process.env.ORBIT_P1_ACCEPTANCE_STATE_ROOT || path.join(os.tmpdir(), `orbit-p1-workbench-${process.pid}`) },
  },
});
