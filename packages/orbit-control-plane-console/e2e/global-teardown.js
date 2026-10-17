import { unlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export default async function globalTeardown() {
  // Per-run workbench state is private and intentionally retained in /tmp for
  // failure diagnosis. No original DB or previous model ledger is removed.
  const databasePath = process.env.ORBIT_CONTROL_CONSOLE_PLAYWRIGHT_DATABASE_PATH;
  if (!databasePath?.startsWith(path.join(os.tmpdir(), "orbit-control-console-playwright-"))) {
    throw new Error("playwright_database_cleanup_path_invalid");
  }
  try {
    await unlink(databasePath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

