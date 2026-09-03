#!/usr/bin/env node

/**
 * stage-backfill-slices.mjs - Staged ingestion manager for bulk threat-feed backfills.
 *
 * Slices large backfill windows into manageable batches to prevent unbounded PR sizes,
 * TypeScript compiler union exhaustion (TS2590), and test budget timeouts.
 *
 * Usage:
 *   node scripts/stage-backfill-slices.mjs [options]
 *
 * Options:
 *   --since <YYYY-MM-DD>      Start date (default 2026-09-02)
 *   --until <YYYY-MM-DD>      End date (default 2026-09-03)
 *   --slice-size <number>     Batch size per slice (default 2000)
 *   --filter-holding-packages Probe npm registry to drop 0.0.1-security placeholders
 *   --dry-run                 Preview slice plan without modifying repository
 */

import { execFileSync } from "node:child_process";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const IMPORT_SCRIPT = path.join(__dirname, "import-threat-feed.mjs");

const args = process.argv.slice(2);
let since = "2026-09-02";
let until = "2026-09-03";
let sliceSize = 2000;
let filterHolding = true;
let dryRun = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--since" && args[i + 1]) since = args[++i];
  else if (args[i] === "--until" && args[i + 1]) until = args[++i];
  else if (args[i] === "--slice-size" && args[i + 1]) sliceSize = Number(args[++i]);
  else if (args[i] === "--no-filter-holding-packages") filterHolding = false;
  else if (args[i] === "--filter-holding-packages") filterHolding = true;
  else if (args[i] === "--dry-run") dryRun = true;
}

const env = { ...process.env };
if (!env.GITHUB_TOKEN && !env.GH_TOKEN) {
  try {
    const token = execFileSync("gh", ["auth", "token"], { encoding: "utf8" }).trim();
    if (token) env.GITHUB_TOKEN = token;
  } catch {
    // Ignore, importer will validate token availability
  }
}

console.log(`\nThreat-Feed Bulk Backfill Slicing Plan`);
console.log(`=====================================`);
console.log(`Window:                  ${since} to ${until}`);
console.log(`Slice size limit:        ${sliceSize}`);
console.log(`Filter holding packages: ${filterHolding ? "Enabled (drop 0.0.1-security stubs)" : "Disabled"}`);
console.log(`Mode:                    ${dryRun ? "Dry-run (preview only)" : "Execution"}\n`);

const importArgs = [
  IMPORT_SCRIPT,
  "--since", since,
  "--until", until,
  "--limit", String(sliceSize),
  "--allow-backlog",
];

if (filterHolding) importArgs.push("--filter-holding-packages");
if (dryRun) importArgs.push("--dry-run");

console.log(`Invoking: node ${importArgs.join(" ")}\n`);
try {
  execFileSync("node", importArgs, {
    cwd: ROOT,
    stdio: "inherit",
    env,
  });
  console.log(`\nSlice completed successfully.`);
} catch (err) {
  console.error(`\nSlice import failed:`, err.message);
  process.exit(1);
}
