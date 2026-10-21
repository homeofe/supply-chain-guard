#!/usr/bin/env node
// build-daily-feed.mjs - the feed the daily channel publishes without a release.
//
//   node scripts/build-daily-feed.mjs --report <importer dry-run JSON> \
//     --main-root <checkout of main> --release-root <checkout of the latest tag> \
//     --out <dir> [--cap 2000]
//   node scripts/build-daily-feed.mjs --verify <feed.json> \
//     --main-root <checkout of main> --release-root <checkout of the latest tag> [--cap 2000]
//
// --verify re-runs only the invariant against an already built feed. The
// signing job uses it: that job installs no dependencies, so whatever ran in
// the build job cannot hand it a different document to sign.
//
// Design: docs/daily-feed-channel-design.md. The daily feed reaches users WITHOUT
// review, so what it may add is the owner's decision of 2026-10-21: main's
// reviewed feed unchanged, plus exact-version pins whose version a source names
// (the importer's `listed` derivation), plus hashes, plus the catalog entries
// main gained since the latest release. Everything else waits for the weekly
// review on main.
//
// assertDailyInvariant is the control, and it is deliberately NOT built on
// selectDailyPins: it compares the finished document against main's on its own
// terms, so a bug in the selection cannot also blind the check.
//
// Any failure writes nothing and exits 1. The channel then keeps yesterday's
// feed, whose age stays visible to clients; a fresh timestamp on main's feed
// would claim a freshness this run did not deliver.

import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readCatalogLines } from "./catalog-store.mjs";
import { ECOSYSTEM_PREFIX, splitPackageValue } from "./import-threat-feed.mjs";

/** More added pins than this in one day is a bulk wave, and a bulk wave needs a human. */
export const DEFAULT_DAILY_CAP = 2000;

/**
 * The largest daily feed the job publishes: half of the 32 MiB a client
 * accepts (FEED_REMOTE_LIMITS). Above that, clients would refuse it and fall
 * back to the release feed every day without anyone noticing.
 */
export const DEFAULT_DAILY_MAX_BYTES = 16 * 1024 * 1024;

const LISTED = "listed";
const HASH = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i;
const FULL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const key = (entry) => `${entry.type}\u0000${entry.value}`;

/** JSON with sorted keys, so two equal entries compare equal whatever their key order. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

const isVersionedPackage = (entry) =>
  entry?.type === "package" && typeof entry.value === "string" && splitPackageValue(entry.value).version !== undefined;

/**
 * The prefixes the importer emits (`openvsx:` comes from its OSV aliases). A
 * Firefox add-on id is an email address, so `firefox:name@domain` is a
 * WHOLE-package claim although it splits like a pin; prefixes outside this
 * list never pass as a pin.
 */
const PIN_PREFIXES = new Set([...Object.values(ECOSYSTEM_PREFIX), "openvsx:"]);
/** A literal version: no empty version, no wildcard, no range operator. */
const LITERAL_VERSION = /^[0-9A-Za-z][0-9A-Za-z.+_-]*$/;

/**
 * The invariant's own notion of an exact pin, deliberately stricter than
 * selectDailyPins: an importer ecosystem prefix and a literal version.
 */
function isExactPin(entry) {
  if (entry?.type !== "package" || typeof entry.value !== "string") return false;
  const prefix = /^([a-z]+:)/.exec(entry.value)?.[1] ?? "";
  if (!PIN_PREFIXES.has(prefix)) return false;
  const rest = entry.value.slice(prefix.length);
  const at = rest.lastIndexOf("@");
  // An npm name never holds a colon: `PYPI:x@1` is not an npm package. Maven's
  // group:artifact names do, behind their own prefix.
  if (prefix === "" && rest.slice(0, Math.max(at, 0)).includes(":")) return false;
  return at > 0 && LITERAL_VERSION.test(rest.slice(at + 1));
}

/**
 * The importer's proposed entries that may reach the daily channel: package pins
 * with a version whose derivation is `listed`. Everything else is counted by its
 * derivation (or `no-version`, `unlabelled`, `type:<type>`).
 */
export function selectDailyPins(report) {
  const entries = Array.isArray(report?.entries) ? report.entries : null;
  const derivations = Array.isArray(report?.derivations) ? report.derivations : null;
  if (!entries || !derivations || derivations.length !== entries.length) {
    throw new Error(
      "the importer report carries no derivations aligned with its entries; an importer without derivation labels cannot feed the daily channel",
    );
  }
  const pins = [];
  const dropped = {};
  entries.forEach((entry, i) => {
    let reason;
    if (entry?.type !== "package") reason = `type:${entry?.type}`;
    else if (!isVersionedPackage(entry)) reason = "no-version";
    else if (derivations[i] === LISTED) {
      pins.push(entry);
      return;
    } else reason = derivations[i] ?? "unlabelled";
    dropped[reason] = (dropped[reason] ?? 0) + 1;
  });
  return { pins, dropped };
}

/** Catalog entries present on main and absent from the latest release, parsed. */
export function catalogAdditionsSinceRelease(mainLines, releaseLines) {
  const released = new Set(releaseLines.map((line) => key(JSON.parse(line))));
  return mainLines.map((line) => JSON.parse(line)).filter((entry) => !released.has(key(entry)));
}

/** main's feed followed by the additions it does not already hold, stamped `now`. */
export function buildDailyFeed(mainFeed, additions, now) {
  const seen = new Set(mainFeed.entries.map(key));
  const entries = [...mainFeed.entries];
  for (const entry of additions) {
    if (seen.has(key(entry))) continue;
    seen.add(key(entry));
    entries.push(entry);
  }
  return { ...mainFeed, entryCount: entries.length, generatedAt: now.toISOString(), entries };
}

/**
 * Throw on the first way `daily` differs from `main` beyond what the channel may
 * add: every main entry present unchanged; every other entry a catalog addition
 * (unchanged), an exact-version package pin or a hash; at most `cap` added pins;
 * a full `generatedAt` later than main's.
 */
export function assertDailyInvariant(mainFeed, dailyFeed, catalogAdditions, { cap = DEFAULT_DAILY_CAP } = {}) {
  const fail = (why) => {
    throw new Error(`daily feed invariant: ${why}`);
  };
  for (const field of ["schema", "package", "version"]) {
    if (dailyFeed[field] !== mainFeed[field]) fail(`${field} differs from main`);
  }
  if (!Array.isArray(dailyFeed.entries)) fail("entries is not an array");
  if (dailyFeed.entryCount !== dailyFeed.entries.length) fail("entryCount does not match entries");

  const daily = new Map();
  for (const entry of dailyFeed.entries) {
    if (daily.has(key(entry))) fail(`duplicate entry ${entry.type} ${entry.value}`);
    daily.set(key(entry), entry);
  }
  for (const entry of mainFeed.entries) {
    const found = daily.get(key(entry));
    if (!found) fail(`main entry removed: ${entry.type} ${entry.value}`);
    if (canonical(found) !== canonical(entry)) fail(`main entry changed: ${entry.type} ${entry.value}`);
    daily.delete(key(entry));
  }
  const catalog = new Map(catalogAdditions.map((entry) => [key(entry), canonical(entry)]));
  let pins = 0;
  for (const entry of daily.values()) {
    if (catalog.get(key(entry)) === canonical(entry)) continue;
    if (entry.type === "hash" && typeof entry.value === "string" && HASH.test(entry.value)) continue;
    if (isExactPin(entry)) {
      pins++;
      continue;
    }
    fail(`not allowed without review: ${entry.type} ${entry.value}`);
  }
  if (pins > cap) fail(`${pins} added pins exceed the daily cap of ${cap}; a bulk wave needs a human`);

  const generated = dailyFeed.generatedAt;
  if (typeof generated !== "string" || !FULL_TIMESTAMP.test(generated) || generated.endsWith("T00:00:00.000Z")) {
    fail(`generatedAt ${JSON.stringify(generated)} is not a full build timestamp`);
  }
  if (!(Date.parse(generated) > Date.parse(mainFeed.generatedAt))) fail(`generatedAt ${generated} is not later than main's`);
}

function parseArgs(argv) {
  const opts = { cap: DEFAULT_DAILY_CAP, maxBytes: DEFAULT_DAILY_MAX_BYTES };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => {
      const value = argv[++i];
      if (value === undefined) throw new Error(`${arg} needs a value`);
      return value;
    };
    if (arg === "--report") opts.report = next();
    else if (arg === "--main-root") opts.mainRoot = next();
    else if (arg === "--release-root") opts.releaseRoot = next();
    else if (arg === "--out") opts.out = next();
    else if (arg === "--verify") opts.verify = next();
    else if (arg === "--cap") opts.cap = Number(next());
    else if (arg === "--max-bytes") opts.maxBytes = Number(next());
    else throw new Error(`unknown argument ${arg}`);
  }
  for (const required of opts.verify ? ["mainRoot", "releaseRoot"] : ["report", "mainRoot", "releaseRoot", "out"]) {
    if (!opts[required]) throw new Error(`--${required.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)} is required`);
  }
  if (!Number.isInteger(opts.cap) || opts.cap < 0) throw new Error("--cap must be a non-negative integer");
  if (!Number.isInteger(opts.maxBytes) || opts.maxBytes <= 0) throw new Error("--max-bytes must be a positive integer");
  return opts;
}

/** Build, check and write `<out>/feed.json`. Returns the exit code; writes nothing on failure. */
export async function main(argv, { now = new Date() } = {}) {
  try {
    const opts = parseArgs(argv);
    if (opts.verify) {
      const mainFeed = JSON.parse(readFileSync(join(opts.mainRoot, "feed.json"), "utf8"));
      const daily = JSON.parse(readFileSync(opts.verify, "utf8"));
      const catalogAdditions = catalogAdditionsSinceRelease(readCatalogLines(opts.mainRoot), readCatalogLines(opts.releaseRoot));
      assertDailyInvariant(mainFeed, daily, catalogAdditions, { cap: opts.cap });
      console.log(`verified: ${daily.entryCount} entries, generatedAt ${daily.generatedAt}`);
      return 0;
    }
    const report = JSON.parse(readFileSync(opts.report, "utf8"));
    if (report.dryRun !== true) throw new Error("the importer report is not from a dry run");
    if (report.truncated !== false) throw new Error("the importer report is truncated");
    // An unmapped record is not among the report's entries, so the feed stays
    // correct without it; feed-reconcile.yml reports the gap. Publishing stops
    // for real failures only, not for a backlog.
    if (!Number.isInteger(report.unmapped) || report.unmapped < 0) throw new Error("the importer report has no unmapped count");
    const { pins, dropped } = selectDailyPins(report);

    const mainFeed = JSON.parse(readFileSync(join(opts.mainRoot, "feed.json"), "utf8"));
    const catalogAdditions = catalogAdditionsSinceRelease(readCatalogLines(opts.mainRoot), readCatalogLines(opts.releaseRoot));
    const daily = buildDailyFeed(mainFeed, [...pins, ...catalogAdditions], now);
    assertDailyInvariant(mainFeed, daily, catalogAdditions, { cap: opts.cap });

    const body = `${JSON.stringify(daily, null, 2)}\n`;
    const bytes = Buffer.byteLength(body);
    if (bytes > opts.maxBytes) throw new Error(`the daily feed is ${bytes} bytes, above the ${opts.maxBytes}-byte cap`);
    mkdirSync(opts.out, { recursive: true });
    const target = join(opts.out, "feed.json");
    writeFileSync(`${target}.tmp`, body);
    renameSync(`${target}.tmp`, target);
    console.log(
      `daily feed: ${daily.entryCount} entries (${mainFeed.entryCount} from main, ${pins.length} listed pin(s) proposed, ` +
        `${catalogAdditions.length} catalog addition(s) since the release), generatedAt ${daily.generatedAt}; ` +
        `not published without review: ${JSON.stringify(dropped)}` +
        (report.unmapped > 0 ? `; ${report.unmapped} unmapped upstream record(s) not in this feed (see feed-reconcile)` : ""),
    );
    return 0;
  } catch (err) {
    console.error(`build-daily-feed: ${err instanceof Error ? err.message : String(err)}. Nothing was written.`);
    return 1;
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.exit(await main(process.argv.slice(2)));
