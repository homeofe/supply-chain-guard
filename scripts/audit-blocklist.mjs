#!/usr/bin/env node
/**
 * audit-blocklist - re-validate every BARE-NAME npm package IOC against the
 * live registry.
 *
 * WHY THIS EXISTS
 * ---------------
 * A bare-name package IOC blocks EVERY version of that name. That is the right
 * call for an attacker-created name with no legitimate history, and the wrong
 * call for a hijacked package, where only specific releases are poisoned.
 *
 * The distinction is a claim about the registry AT THE MOMENT OF INGESTION, and
 * nothing re-checks it afterwards. It decays in both directions:
 *
 *   - npm removes an attacker's package, and later the name is taken (or
 *     restored) by someone legitimate. The block now hits an innocent package.
 *   - A vendor write-up calls a package "attacker-uploaded" when it was really
 *     hijacked. The block is wrong from the start, and no offline gate can see
 *     it, because the evidence lives in the registry rather than in the repo.
 *
 * Both happened here. On 2026-08-29 an audit of the shipped feed found
 * html-to-gutenberg and fetch-page-assets name-blocked despite being live,
 * legitimate packages with ~30 clean releases between them and exactly one
 * poisoned version each; and frint - a ten-year-old npm framework plugin -
 * blocked because a PyPI IOC had lost its `pypi:` prefix. Both had been
 * shipping for about two months.
 *
 * This script is the standing check for that class of defect. It is NOT wired
 * into `prebuild`: it needs the network, and a build must not fail because
 * registry.npmjs.org is slow. Run it on a schedule, and before a release.
 *
 * USAGE
 *   node scripts/audit-blocklist.mjs [--json] [--max-age-days N] [--limit N]
 *
 * EXIT CODES
 *   0  no bare-name block points at a package with a legitimate history
 *   1  at least one suspected false positive (or a usage error)
 *
 * WHAT COUNTS AS A SUSPECTED FALSE POSITIVE
 * A name that currently resolves on the registry with a real release history:
 * at least two published versions AND a first-to-last publish span of at least
 * --max-age-days (default 30). Campaign packages are published in a burst and
 * are days old; a package that has been shipping releases for a month or more
 * is behaving like somebody's real project. npm "security holding" placeholders
 * and unpublished stubs are NOT flagged - those are takedowns, which is exactly
 * what a name-block should sit on.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");

const argv = process.argv.slice(2);
const asJson = argv.includes("--json");
const numArg = (flag, fallback) => {
  const i = argv.indexOf(flag);
  if (i === -1) return fallback;
  const v = Number(argv[i + 1]);
  if (!Number.isFinite(v) || v <= 0) {
    console.error(`audit-blocklist: ${flag} needs a positive number`);
    process.exit(1);
  }
  return v;
};
const MAX_AGE_DAYS = numArg("--max-age-days", 30);
const LIMIT = numArg("--limit", Infinity);
const CONCURRENCY = 16;

// An allowlist for names that ARE legitimately blocked despite looking live.
// Each entry needs a reason; the file is optional.
const ALLOW_PATH = path.join(ROOT, "blocklist-audit-allow.json");
let allow = {};
if (fs.existsSync(ALLOW_PATH)) {
  try {
    const raw = JSON.parse(fs.readFileSync(ALLOW_PATH, "utf8"));
    for (const [name, reason] of Object.entries(raw.names ?? {})) {
      if (typeof reason !== "string" || reason.trim().length < 10) {
        console.error(`audit-blocklist: allowlist entry "${name}" needs a written reason`);
        process.exit(1);
      }
      allow[name] = reason;
    }
  } catch (err) {
    console.error(`audit-blocklist: cannot read ${ALLOW_PATH}: ${err.message}`);
    process.exit(1);
  }
}

const feedPath = path.join(ROOT, "feed.json");
if (!fs.existsSync(feedPath)) {
  console.error("audit-blocklist: feed.json not found - run `npm run feed:generate` first");
  process.exit(1);
}
const feed = JSON.parse(fs.readFileSync(feedPath, "utf8"));

const strip = (v) => String(v).replace(/^(pypi|ruby|composer|nuget|go):/, "");
const ecoOf = (v) => (String(v).match(/^(pypi|ruby|composer|nuget|go):/) || [null, "npm"])[1];
const isPin = (v) => strip(v).lastIndexOf("@") > 0;

const bare = [
  ...new Set(
    (feed.entries ?? [])
      .filter((e) => e.type === "package" && ecoOf(e.value) === "npm" && !isPin(e.value))
      .map((e) => strip(e.value)),
  ),
]
  .filter((n) => !(n in allow))
  .slice(0, LIMIT === Infinity ? undefined : LIMIT);

if (!asJson) {
  console.log(`\n  audit-blocklist: re-validating ${bare.length} bare-name npm block(s)`);
  console.log(`  a name is suspect at >= 2 versions and a >= ${MAX_AGE_DAYS}-day publish span`);
  if (Object.keys(allow).length) console.log(`  ${Object.keys(allow).length} name(s) allowlisted`);
  console.log("");
}

async function probe(name) {
  const url =
    "https://registry.npmjs.org/" +
    (name.startsWith("@") ? name.replace("/", "%2f") : encodeURIComponent(name));
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(url);
      if (res.status === 404) return { name, state: "gone" };
      if (res.status === 429 || res.status >= 500) {
        await new Promise((r) => setTimeout(r, 600 * (attempt + 1)));
        continue;
      }
      if (!res.ok) return { name, state: "error", detail: `HTTP ${res.status}` };
      const doc = await res.json();
      const time = doc.time ?? {};
      const versions = Object.keys(doc.versions ?? {});
      if (time.unpublished || versions.length === 0) return { name, state: "unpublished" };
      if (versions.length === 1 && /-security$/.test(versions[0])) {
        return { name, state: "npm-holding" };
      }
      if (/security holding package/i.test(doc.description ?? "")) {
        return { name, state: "npm-holding" };
      }
      const stamps = versions.map((v) => time[v]).filter(Boolean).sort();
      const first = stamps[0];
      const last = stamps[stamps.length - 1];
      const spanDays =
        first && last ? Math.round((Date.parse(last) - Date.parse(first)) / 86400000) : 0;
      return {
        name,
        state: "live",
        versions: versions.length,
        spanDays,
        first,
        last,
        maintainers: (doc.maintainers ?? []).map((m) => m.name),
        repo: String(doc.repository?.url ?? doc.repository ?? ""),
      };
    } catch (err) {
      if (attempt === 2) return { name, state: "error", detail: err.message };
      await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
    }
  }
  return { name, state: "error", detail: "retries exhausted" };
}

const results = [];
let cursor = 0;
let completed = 0;
async function worker() {
  while (cursor < bare.length) {
    const name = bare[cursor++];
    results.push(await probe(name));
    completed++;
    if (!asJson && completed % 250 === 0) {
      process.stderr.write(`  ...${completed}/${bare.length}\n`);
    }
  }
}
await Promise.all(Array.from({ length: CONCURRENCY }, worker));

const suspect = results.filter(
  (r) => r.state === "live" && r.versions >= 2 && r.spanDays >= MAX_AGE_DAYS,
);
const counts = results.reduce((acc, r) => ((acc[r.state] = (acc[r.state] ?? 0) + 1), acc), {});
const errors = results.filter((r) => r.state === "error");

if (asJson) {
  console.log(JSON.stringify({ checked: results.length, counts, suspect, errors }, null, 2));
} else {
  console.log("  registry state of every bare-name block:");
  for (const [state, n] of Object.entries(counts).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${state.padEnd(14)} ${String(n).padStart(5)}`);
  }
  if (errors.length) {
    console.log(`\n  ${errors.length} name(s) could not be resolved; they are not judged.`);
  }
  if (suspect.length === 0) {
    console.log(`\n  OK - no bare-name block points at a package with a legitimate history.\n`);
  } else {
    console.log(`\n  SUSPECTED FALSE POSITIVES: ${suspect.length}`);
    console.log(`  Each blocks EVERY version of a package that is still publishing.\n`);
    for (const r of suspect.sort((a, b) => b.spanDays - a.spanDays)) {
      console.log(`    ${r.name}`);
      console.log(
        `      ${r.versions} versions over ${r.spanDays} days ` +
          `(${String(r.first).slice(0, 10)} .. ${String(r.last).slice(0, 10)})`,
      );
      console.log(`      maintainers: ${r.maintainers.join(", ") || "(none)"}`);
      if (r.repo) console.log(`      repo: ${r.repo}`);
    }
    console.log(
      `\n  Fix each one by version-pinning the releases that are actually malicious,\n` +
        `  or add it to blocklist-audit-allow.json with a written reason if the whole\n` +
        `  name really is attacker-controlled.\n`,
    );
  }
}

process.exit(suspect.length === 0 ? 0 : 1);
