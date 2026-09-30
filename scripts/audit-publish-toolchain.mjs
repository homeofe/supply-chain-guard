#!/usr/bin/env node
// Audits the pinned publish npm (.github/publish-toolchain) at a severity
// threshold, with a short list of reviewed, dated exceptions.
//
// Why not plain `npm audit --audit-level=high`: npm ships its dependencies
// bundled inside its own tarball, so an advisory against one of them can only be
// fixed by a new npm release. `overrides` do not reach bundled packages. For an
// advisory published before npm has shipped the fix (2026-09-30: npm 11.19.1,
// 11.20.0 and 12.1.0 all bundle the same affected versions), a reviewed exception
// keeps the audit meaningful for everything else, and it is deliberately narrow:
//
//   - it names one advisory (GHSA id) for one package, with a reason
//   - it carries an expiry date; an expired exception fails the audit
//   - an exception whose advisory no longer appears in the report fails the
//     audit, so the list is emptied in the same change that bumps the pin
//   - any advisory at or above the threshold that is NOT listed fails the audit
//
// The verdict is taken from the JSON report, never from npm's exit status, which
// is non-zero for any finding at all. A report that cannot be read fails closed.
//
// Usage:
//   node scripts/audit-publish-toolchain.mjs --audit-level=high
//   node scripts/audit-publish-toolchain.mjs --audit-level=high --report <file> --today YYYY-MM-DD
//     (--report and --today exist for the tests)

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TOOLCHAIN = join(ROOT, ".github", "publish-toolchain");
const EXCEPTIONS_FILE = join(TOOLCHAIN, "audit-exceptions.json");
const LEVELS = ["info", "low", "moderate", "high", "critical"];
const GHSA_RE = /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function arg(name) {
  const hit = process.argv.slice(2).find((a) => a === name || a.startsWith(`${name}=`));
  if (!hit) return undefined;
  if (hit.includes("=")) return hit.slice(name.length + 1);
  const i = process.argv.indexOf(hit);
  return process.argv[i + 1];
}

export function evaluate(report, exceptions, { level, today }) {
  const errors = [];
  const threshold = LEVELS.indexOf(level);
  if (threshold < 0) return { errors: [`unknown --audit-level "${level}"`], excepted: [] };
  if (!report || typeof report !== "object" || report.error || typeof report.vulnerabilities !== "object" || report.vulnerabilities === null) {
    return { errors: ["the npm audit report could not be read, so nothing is known to be clean"], excepted: [] };
  }

  if (!Array.isArray(exceptions)) {
    return { errors: ["audit-exceptions.json must hold an array"], excepted: [] };
  }
  const seenIds = new Set();
  for (const e of exceptions) {
    const where = `exception ${JSON.stringify(e?.ghsa ?? e)}`;
    if (!e || typeof e !== "object") { errors.push(`${where}: not an object`); continue; }
    if (typeof e.ghsa !== "string" || !GHSA_RE.test(e.ghsa)) errors.push(`${where}: "ghsa" must be a GHSA id`);
    if (typeof e.package !== "string" || e.package.length === 0) errors.push(`${where}: "package" is required`);
    if (typeof e.reason !== "string" || e.reason.trim().length < 20) errors.push(`${where}: "reason" must explain the exception`);
    if (typeof e.expires !== "string" || !DATE_RE.test(e.expires) || Number.isNaN(Date.parse(e.expires))) {
      errors.push(`${where}: "expires" must be a YYYY-MM-DD date`);
    } else if (e.expires < today) {
      errors.push(`${where}: expired on ${e.expires}; bump the pinned npm or re-review the exception`);
    }
    if (seenIds.has(e.ghsa)) errors.push(`${where}: listed twice`);
    seenIds.add(e.ghsa);
  }

  const reported = new Set();
  const excepted = [];
  for (const [pkg, vuln] of Object.entries(report.vulnerabilities)) {
    for (const via of Array.isArray(vuln?.via) ? vuln.via : []) {
      if (typeof via !== "object" || via === null) continue; // names another vulnerable package, which is listed itself
      const id = String(via.url ?? "").split("/").pop();
      const name = via.dependency ?? via.name ?? pkg;
      reported.add(`${id} ${name}`);
      const severity = LEVELS.indexOf(via.severity);
      if (severity < 0) {
        errors.push(`${name}: advisory ${id || via.source} has unknown severity "${via.severity}"`);
        continue;
      }
      if (severity < threshold) continue;
      const exception = exceptions.find((e) => e && e.ghsa === id && e.package === name);
      if (exception) excepted.push(`${id} (${via.severity}) in ${name}`);
      else errors.push(`${name}: ${via.severity} advisory ${id || via.source} is not excepted: ${via.title ?? ""}`.trim());
    }
  }

  for (const e of exceptions) {
    if (e && typeof e === "object" && !reported.has(`${e.ghsa} ${e.package}`)) {
      errors.push(`exception ${e.ghsa} for ${e.package} matches nothing in the report; remove it`);
    }
  }
  return { errors, excepted };
}

function main() {
  const level = arg("--audit-level") ?? "high";
  const today = arg("--today") ?? new Date().toISOString().slice(0, 10);
  const reportFile = arg("--report");

  let raw;
  if (reportFile) {
    raw = readFileSync(reportFile, "utf8");
  } else {
    try {
      raw = execFileSync("npm", ["audit", "--json", "--prefix", TOOLCHAIN], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "inherit"],
        shell: process.platform === "win32",
      });
    } catch (err) {
      // npm audit exits non-zero whenever it finds anything; the report is on stdout.
      raw = err.stdout ?? "";
    }
  }

  let report;
  try { report = JSON.parse(raw); } catch { report = null; }
  let exceptions;
  try { exceptions = JSON.parse(readFileSync(EXCEPTIONS_FILE, "utf8")); } catch (err) {
    console.error(`audit: cannot read ${EXCEPTIONS_FILE}: ${err.message}`);
    process.exit(1);
  }

  const { errors, excepted } = evaluate(report, exceptions, { level, today });
  for (const line of excepted) console.log(`audit: excepted ${line}`);
  if (errors.length > 0) {
    for (const line of errors) console.error(`audit: FAIL ${line}`);
    process.exit(1);
  }
  console.log(`audit: OK, no unexcepted advisory at or above ${level}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
