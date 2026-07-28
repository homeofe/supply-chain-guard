// generate-feed.mjs - Generate (and gate) the publishable IOC feed feed.json
// at the repo root from the bundled feed in src/threat-intel.ts.
//
// Two modes:
//   node scripts/generate-feed.mjs          -> WRITE feed.json (npm run feed:generate)
//   node scripts/generate-feed.mjs --check  -> FAIL if the committed feed.json is
//                                              stale (wired into `prebuild`, like
//                                              check:changelog / check:handoff)
//
// Single source of truth: the BUNDLED_FEED array literal in src/threat-intel.ts.
// Scripts are .mjs and cannot import TypeScript, so the array body is extracted
// textually and evaluated in an empty node:vm sandbox (it is plain object /
// string / number literals plus // comments - valid JavaScript on its own).
//
// The output is a PURE FUNCTION of committed files (src/threat-intel.ts +
// package.json version) - no timestamps, no randomness - so running it twice
// yields byte-identical output and the --check gate is deterministic + offline.
// Consumers: `supply-chain-guard feed refresh` downloads this file from
// raw.githubusercontent.com/homeofe/supply-chain-guard/main/feed.json into the
// local .scg-cache that loadThreatIntel() merges at scan time.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { runInNewContext } from "node:vm";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Every `FeedIOC[]` array declaration, at line start, in source order. The feed
 * is stored as capacity-bounded `FEED_CHUNK_n` consts spread back together into
 * BUNDLED_FEED (a single array literal that large trips TS2590 in tsc), so this
 * has to collect all of them, not just one array.
 */
const DECL_RE = /^(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*:\s*FeedIOC\[\]\s*=\s*\[/gm;

/** Extract the BUNDLED_FEED entries from src/threat-intel.ts. */
export function extractBundledEntries(root = repoRoot) {
  const source = readFileSync(join(root, "src", "threat-intel.ts"), "utf8");
  const decls = [];
  for (const m of source.matchAll(DECL_RE)) {
    const bodyStart = m.index + m[0].length;
    const end = source.indexOf("\n];", bodyStart);
    if (end === -1) {
      throw new Error(`${m[1]} array terminator not found in src/threat-intel.ts`);
    }
    decls.push({ name: m[1], body: source.slice(bodyStart, end) });
  }
  if (!decls.some((d) => d.name === "BUNDLED_FEED")) {
    throw new Error("BUNDLED_FEED marker not found in src/threat-intel.ts");
  }

  // Declare every array in source order in ONE empty sandbox (no require, no
  // process, no fs - just literal evaluation), then read BUNDLED_FEED out of it.
  // The chunk consts are declared before BUNDLED_FEED, so its spread resolves.
  const chunkNames = decls.map((d) => d.name).filter((n) => n !== "BUNDLED_FEED");
  const script =
    decls.map((d) => `const ${d.name} = [${d.body}\n];`).join("\n") +
    `\n({ entries: BUNDLED_FEED, chunkTotal: ${
      chunkNames.length ? chunkNames.map((n) => `${n}.length`).join(" + ") : "null"
    } });`;
  const { entries, chunkTotal } = runInNewContext(script, {});

  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error("BUNDLED_FEED evaluation produced no entries");
  }
  // A chunk that exists but was never added to the BUNDLED_FEED spread would
  // silently ship a short feed. Fail the gate instead of publishing the gap.
  if (chunkTotal !== null && chunkTotal !== entries.length) {
    throw new Error(
      `BUNDLED_FEED spreads ${entries.length} entries but the ${chunkNames.length} ` +
        `FEED_CHUNK_* consts hold ${chunkTotal}. A chunk is missing from the spread ` +
        `in src/threat-intel.ts.`,
    );
  }
  return entries;
}

/** Build the publishable feed document (deterministic, offline). */
export function buildFeed(root = repoRoot) {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const entries = extractBundledEntries(root);
  return {
    schema: 1,
    package: "supply-chain-guard",
    version: pkg.version,
    entryCount: entries.length,
    entries,
  };
}

/** Serialize the feed document to its canonical byte representation. */
export function serializeFeed(feed) {
  return JSON.stringify(feed, null, 2) + "\n";
}

const norm = (s) => s.replace(/\r/g, ""); // CRLF-agnostic (Windows working tree)

/** True if the file at filePath matches the expected serialized feed. */
export function feedFileIsFresh(filePath, expected) {
  const current = existsSync(filePath) ? readFileSync(filePath, "utf8") : "";
  return norm(current) === norm(expected);
}

// --- write or check ----------------------------------------------------------

const isMain =
  process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  const target = join(repoRoot, "feed.json");
  const feed = buildFeed();
  const content = serializeFeed(feed);

  if (process.argv.includes("--check")) {
    if (!feedFileIsFresh(target, content)) {
      console.error(
        `\n  feed.json is stale (or missing).\n` +
          `  It is generated from the BUNDLED_FEED array in src/threat-intel.ts\n` +
          `  plus the package.json version.\n` +
          `  Fix: run \`npm run feed:generate\`, then re-commit.\n`,
      );
      process.exit(1);
    }
    console.log(`feed.json up to date (${feed.entryCount} entries, v${feed.version}).`);
  } else {
    writeFileSync(target, content);
    console.log(
      `feed:generate OK - feed.json written (${feed.entryCount} entries, v${feed.version}).`,
    );
  }
}
