#!/usr/bin/env node
// Verify that package.json's version is present in every source file
// that hardcodes a version string. Exits 1 if any mismatch is found.
//
// Wired into `npm run build` as part of `prebuild` so a release cannot
// ship with a stale CLI banner, SARIF version, SBOM version, or HTML
// footer. This caught us on v5.2.14 (reporter at v5.2.14, test at
// v5.2.8) and v5.2.17 (reporter at v5.2.17, test at v5.2.16). After
// the test was refactored to read from package.json the only remaining
// hardcoded strings are in src/cli.ts and src/reporter.ts.
//
// If you legitimately need a different version somewhere (you don't),
// add an explicit allow-comment and update this script.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
const version = pkg.version;

// Files that must contain the current version, with a description of why.
const required = [
  { file: "src/cli.ts", minOccurrences: 1, note: "CLI --version output" },
  {
    file: "src/reporter.ts",
    minOccurrences: 5,
    note: "text-header VERSION const + SARIF + SBOM + HTML footer + GitLab scanner version",
  },
  // scanner.ts's TOOL_VERSION feeds ScanReport.tool (emitted verbatim by the JSON
  // reporter) and the persisted .scg-history/ entries. It drifted to 5.2.0 undetected
  // for many releases precisely because it was NOT gated here (fixed in v5.17.4).
  { file: "src/scanner.ts", minOccurrences: 1, note: "TOOL_VERSION const (ScanReport.tool + risk-history)" },
  // The pre-commit docs pin a release tag (rev: vX.Y.Z). v5.5.0 verification
  // gate finding MF-3: the snippet shipped pinning a tag that did not contain
  // the hook file. Keeping these in the sync gate forces the rev bump on
  // every release.
  { file: "README.md", minOccurrences: 1, note: "pre-commit snippet rev: tag" },
  { file: ".pre-commit-hooks.yaml", minOccurrences: 1, note: "example rev: tag in header comment" },
  // The MCP registry server.json pins the version twice (top-level + the npm
  // package entry). It must track releases or the published registry listing
  // points at a stale package version.
  { file: "server.json", minOccurrences: 2, note: "MCP registry version + npm package version" },
];

const failures = [];

for (const { file, minOccurrences, note } of required) {
  const contents = readFileSync(join(repoRoot, file), "utf8");
  // Count exact occurrences of the version string. Use a non-regex match
  // so dots are literal.
  let count = 0;
  let idx = 0;
  while ((idx = contents.indexOf(version, idx)) !== -1) {
    count++;
    idx += version.length;
  }
  if (count < minOccurrences) {
    // Find what stale versions ARE there, to make the fix obvious.
    const stale = [
      ...new Set(
        Array.from(contents.matchAll(/\b\d+\.\d+\.\d+\b/g), (m) => m[0]),
      ),
    ].filter((v) => v !== version);
    failures.push({ file, found: count, expected: minOccurrences, note, stale });
  }
}

if (failures.length > 0) {
  console.error(
    `\n  Version sync check failed for v${version}.\n` +
      `  Every release must bump the version in package.json AND in the\n` +
      `  source files listed below. Forgetting one causes the published\n` +
      `  CLI/SARIF/SBOM/HTML output to display a stale version.\n`,
  );
  for (const { file, found, expected, note, stale } of failures) {
    console.error(`  - ${file}`);
    console.error(`      expected: at least ${expected} occurrence(s) of "${version}" (${note})`);
    console.error(`      found:    ${found}`);
    if (stale.length > 0) {
      console.error(`      stale versions still in file: ${stale.join(", ")}`);
    }
  }
  console.error("\n  Fix: bump the version everywhere, then re-run `npm run build`.\n");
  process.exit(1);
}

console.log(`Version sync OK: package.json v${version} matches all source files.`);
