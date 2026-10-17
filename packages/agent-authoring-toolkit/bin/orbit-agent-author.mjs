#!/usr/bin/env node
import { runCli } from "../src/toolkit.mjs";

process.exitCode = await runCli(process.argv.slice(2));

