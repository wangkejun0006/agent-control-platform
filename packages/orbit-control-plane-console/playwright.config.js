import { defineConfig } from "@playwright/test";
import os from "node:os";
import path from "node:path";

const databasePath = path.join(os.tmpdir(), `orbit-control-console-playwright-${process.pid}.sqlite3`);
process.env.ORBIT_CONTROL_CONSOLE_PLAYWRIGHT_DATABASE_PATH = databasePath;
const workbenchRoot = path.join(os.tmpdir(), `orbit-workbench-playwright-${process.pid}`);

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  retries: 0,
  outputDir: "test-results",
  globalTeardown: "./e2e/global-teardown.js",
  use: {
    baseURL: "http://127.0.0.1:8432",
    launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {},
    headless: true,
    viewport: { width: 1440, height: 1000 },
    reducedMotion: "reduce",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "cd ../.. && PYTHONPATH=src:. uv run --locked python -m showcase.server",
    url: "http://127.0.0.1:8432/health/live",
    reuseExistingServer: false,
    timeout: 30_000,
    env: {
      ORBIT_CONTROL_CONSOLE_D0_DATABASE_PATH: databasePath,
      ORBIT_WORKBENCH_STATE_ROOT: workbenchRoot,
    },
  },
});

