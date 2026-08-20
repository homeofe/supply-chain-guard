#!/usr/bin/env node
/**
 * Preflight for `check:aahp`: the governance CLI that runs must be the one this
 * repository pinned.
 *
 * WHY THIS EXISTS
 * ---------------
 * `npx --no-install aahp check .` was believed to guarantee "the pinned copy in
 * node_modules, never a fetched one". It guarantees only the second half. `--no-install`
 * suppresses the download; it does NOT stop npx from resolving a globally installed
 * `aahp` on PATH.
 *
 * So in a checkout whose node_modules is missing or partial, the gate silently ran a
 * DIFFERENT, older governance CLI and printed "Governance OK: 7 gate(s) ran, no
 * failures". Measured on 2026-08-20: this repository pins 3.9.2 exactly, a global
 * 3.8.0 was on PATH, and in a checkout without node_modules the gates reported green
 * from 3.8.0. Nothing anywhere said which version had actually spoken.
 *
 * That is the exact failure class this project exists to detect in other people's
 * builds: a pinned dependency quietly served from somewhere else. A gate that fails
 * open is worse than no gate, because it manufactures the evidence of its own success.
 *
 * The check is deliberately narrow. It answers one question, before the gates run:
 * is the aahp that is about to speak the version package.json pinned?
 */
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as path from "node:path";

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);

const pkg = JSON.parse(readFileSync(path.join(repo, "package.json"), "utf-8"));
const PIN = (pkg.devDependencies || {})["@elvatis_com/aahp"];

if (!PIN) {
  console.error("check:aahp-pin FAILED: @elvatis_com/aahp is not in devDependencies.");
  process.exit(1);
}

// The pin is deliberately exact, with no range operator: a governance CLI that can
// float is a governance CLI whose verdict can change without a commit.
if (!/^\d+\.\d+\.\d+$/.test(PIN)) {
  console.error(
    `check:aahp-pin FAILED: @elvatis_com/aahp must be pinned to an exact version, found "${PIN}".`,
  );
  process.exit(1);
}

let resolvedVersion;
let resolvedFrom;
try {
  resolvedFrom = require.resolve("@elvatis_com/aahp/package.json", { paths: [repo] });
  resolvedVersion = JSON.parse(readFileSync(resolvedFrom, "utf-8")).version;
} catch {
  console.error(
    "check:aahp-pin FAILED: @elvatis_com/aahp does not resolve from this checkout.\n" +
      "  Run `npm ci`. Do NOT rely on a globally installed aahp: `npx --no-install`\n" +
      "  will happily use one, and the gates would then report on a version this\n" +
      "  repository never pinned.",
  );
  process.exit(1);
}

if (resolvedVersion !== PIN) {
  console.error(
    `check:aahp-pin FAILED: package.json pins @elvatis_com/aahp ${PIN}, but ${resolvedVersion} resolved.\n` +
      `  Resolved from: ${resolvedFrom}\n` +
      "  Run `npm ci` so the gates run under the pinned version.",
  );
  process.exit(1);
}

console.log(`check:aahp-pin OK - @elvatis_com/aahp ${resolvedVersion} resolves from node_modules, matching the exact pin.`);
