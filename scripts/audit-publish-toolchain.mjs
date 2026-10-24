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
//   - a CRITICAL advisory that is NOT listed fails the audit
//   - a HIGH advisory that is NOT listed fails the audit only when it is
//     actionable: the newest npm release of the pinned major no longer reports
//     it, so moving the pin fixes it, and the failure names that release
//   - a HIGH advisory that the newest release still reports is a warning (a
//     GitHub annotation in CI): no npm release can fix it yet, and an exception
//     would only restate that. The Dependabot alert stays open meanwhile.
//
// Before 2026-10-24 every unlisted advisory failed. That turned every pull
// request red four times in four weeks for advisories no npm release had fixed
// (GHSA-xjj6-f33q-929c in undici was the fourth), and each time the only
// possible answer was a hand-written exception with the same reasoning.
//
// The verdict is taken from the JSON report, never from npm's exit status, which
// is non-zero for any finding at all. A report that cannot be read fails closed,
// and so does the newest release's report, or a failed lookup of that release.
//
// Usage:
//   node scripts/audit-publish-toolchain.mjs --audit-level=high
//   node scripts/audit-publish-toolchain.mjs --audit-level=high --report <file> --today YYYY-MM-DD
//     [--newest none | --newest X.Y.Z --newest-report <file>]
//     (--report, --today, --newest and --newest-report exist for the tests)

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
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

const readable = (report) =>
  Boolean(report) && typeof report === "object" && !report.error && typeof report.vulnerabilities === "object" && report.vulnerabilities !== null;

/** `${id} ${package}` for every advisory object in an npm audit report. */
function reportedIds(report) {
  const ids = new Set();
  for (const [pkg, vuln] of Object.entries(report.vulnerabilities)) {
    for (const via of Array.isArray(vuln?.via) ? vuln.via : []) {
      if (typeof via !== "object" || via === null) continue;
      ids.add(`${String(via.url ?? "").split("/").pop()} ${via.dependency ?? via.name ?? pkg}`);
    }
  }
  return ids;
}

/**
 * `newer` describes the newest npm release of the pinned major:
 *   undefined                 not looked up: every unlisted advisory fails (the old rule)
 *   { version: null }         the pinned npm IS the newest release
 *   { version, report }       a newer release, with its own `npm audit --json` report
 */
export function evaluate(report, exceptions, { level, today, newer }) {
  const errors = [];
  const warnings = [];
  const threshold = LEVELS.indexOf(level);
  if (threshold < 0) return { errors: [`unknown --audit-level "${level}"`], excepted: [], warnings };
  if (!readable(report)) {
    return { errors: ["the npm audit report could not be read, so nothing is known to be clean"], excepted: [], warnings };
  }
  if (newer !== undefined && newer.version !== null && !readable(newer.report)) {
    return {
      errors: [`the npm audit report for npm ${newer.version} could not be read (the newest release of the pinned major), so nothing is known to be unfixable`],
      excepted: [],
      warnings,
    };
  }
  const newerIds = newer?.version ? reportedIds(newer.report) : null;

  if (!Array.isArray(exceptions)) {
    return { errors: ["audit-exceptions.json must hold an array"], excepted: [], warnings };
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
      const label = `${name}: ${via.severity} advisory ${id || via.source}`;
      const title = via.title ?? "";
      if (exception) excepted.push(`${id} (${via.severity}) in ${name}`);
      else if (newer === undefined || via.severity === "critical") errors.push(`${label} is not excepted: ${title}`.trim());
      else if (newerIds === null) warnings.push(`${label} has no fix in any npm release yet (the pinned npm is the newest of its major): ${title}`.trim());
      else if (newerIds.has(`${id} ${name}`)) warnings.push(`${label} is still reported by npm ${newer.version}, the newest release of the pinned major, so no npm release fixes it yet: ${title}`.trim());
      else errors.push(`${label} is fixed in npm ${newer.version}; move the pin there: ${title}`.trim());
    }
  }

  for (const e of exceptions) {
    if (e && typeof e === "object" && !reported.has(`${e.ghsa} ${e.package}`)) {
      errors.push(`exception ${e.ghsa} for ${e.package} matches nothing in the report; remove it`);
    }
  }
  return { errors, excepted, warnings };
}

const semverParts = (v) => v.split(".").map(Number);
const semverCompare = (a, b) => {
  const [x, y] = [semverParts(a), semverParts(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
};

function npm(args, options = {}) {
  return execFileSync("npm", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
    shell: process.platform === "win32",
    ...options,
  });
}

function auditJson(prefix) {
  try {
    return npm(["audit", "--json", "--prefix", prefix]);
  } catch (err) {
    // npm audit exits non-zero whenever it finds anything; the report is on stdout.
    return err.stdout ?? "";
  }
}

const parse = (raw) => {
  try { return JSON.parse(raw); } catch { return null; }
};

/**
 * Look up the newest stable npm release of the pinned major and audit it from a
 * lockfile-only install (no package code runs). Throws when the lookup fails, so
 * the caller fails closed.
 */
function lookUpNewer(pinned) {
  const major = pinned.split(".")[0];
  const versions = parse(npm(["view", "npm", "versions", "--json"]));
  if (!Array.isArray(versions)) throw new Error("npm view npm versions did not return a list");
  const line = versions.filter((v) => typeof v === "string" && /^\d+\.\d+\.\d+$/.test(v) && v.split(".")[0] === major);
  if (!line.includes(pinned)) throw new Error(`npm ${pinned} is not among the published ${major}.x releases`);
  const newest = line.sort(semverCompare).pop();
  if (newest === pinned) return { version: null };
  const dir = mkdtempSync(join(tmpdir(), "scg-newest-npm-"));
  try {
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "scg-newest-npm", private: true, dependencies: { npm: newest } }));
    npm(["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--prefix", dir]);
    return { version: newest, report: parse(auditJson(dir)) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** GitHub workflow commands treat %, CR and LF in a message as syntax. */
const annotation = (text) => text.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");

function main() {
  const level = arg("--audit-level") ?? "high";
  const today = arg("--today") ?? new Date().toISOString().slice(0, 10);
  const reportFile = arg("--report");
  const newestArg = arg("--newest");
  const newestReportFile = arg("--newest-report");

  const report = parse(reportFile ? readFileSync(reportFile, "utf8") : auditJson(TOOLCHAIN));
  let exceptions;
  try { exceptions = JSON.parse(readFileSync(EXCEPTIONS_FILE, "utf8")); } catch (err) {
    console.error(`audit: cannot read ${EXCEPTIONS_FILE}: ${err.message}`);
    process.exit(1);
  }

  let newer;
  if (newestArg === "none") {
    newer = { version: null };
  } else if (newestArg) {
    newer = { version: newestArg, report: newestReportFile ? parse(readFileSync(newestReportFile, "utf8")) : null };
  } else {
    try {
      const pinned = JSON.parse(readFileSync(join(TOOLCHAIN, "package-lock.json"), "utf8")).packages["node_modules/npm"].version;
      newer = lookUpNewer(pinned);
      console.log(newer.version ? `audit: newest npm of the pinned major is ${newer.version}` : `audit: the pinned npm ${pinned} is the newest of its major`);
    } catch (err) {
      console.error(`audit: FAIL could not look up the newest npm release, so nothing is known to be unfixable: ${err.message}`);
      process.exit(1);
    }
  }

  const { errors, excepted, warnings } = evaluate(report, exceptions, { level, today, newer });
  for (const line of excepted) console.log(`audit: excepted ${line}`);
  for (const line of warnings) {
    if (process.env.GITHUB_ACTIONS === "true") console.log(`::warning title=Publish toolchain advisory::${annotation(line)}`);
    console.log(`audit: WARN ${line}`);
  }
  if (errors.length > 0) {
    for (const line of errors) console.error(`audit: FAIL ${line}`);
    process.exit(1);
  }
  console.log(`audit: OK, no actionable advisory at or above ${level}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
