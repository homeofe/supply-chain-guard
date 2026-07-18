#!/usr/bin/env node
// Verify that the repo's hand-authored CAPABILITY numbers agree with a single
// canonical value AND stay honest against ground truth computed from src/.
//
// This is the capability-number analogue of scripts/check-version-sync.mjs:
// that script pins the package.json VERSION string across every file that
// hardcodes it; this one pins each capability FACT ("350+" rules, "15+"
// correlation rules, "12 categories") across every live marketing surface.
//
// Wired into `npm run build` as part of `prebuild` so a release cannot ship
// with one surface saying "350+" and another (e.g. the MCP tool description)
// still saying "200+". History has already burned us on this: the "350+"
// rollout updated README + package.json but missed src/mcp-server.ts.
//
// Design (mirrors check-version-sync.mjs exactly):
//   - ONE canonical token per fact.
//   - A ground-truth count is computed from src/ so the advertised floor can
//     NEVER overstate reality (350 <= real rule-IDs, 15 <= real correlations).
//   - Only LIVE surfaces are scanned (explicit whitelist). Version-stamped
//     history (CHANGELOG.md, .ai/handoff/) is deliberately excluded - rewriting
//     it would falsify the historical record, and it also keeps the README
//     competitor table ("11+ ecosystems", etc.) from false-tripping.
//   - Exit 1 on any disagreement, with the same message shape as version-sync.
//
// If you legitimately change a number, bump the canonical value here and every
// listed surface in the same commit, then re-run `npm run build`.

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (rel) => readFileSync(join(repoRoot, rel), "utf8");

// --- Ground truth computed from source (advertised floor must not exceed it) ---
function countRuleIds() {
  const ids = new Set();
  for (const f of readdirSync(join(repoRoot, "src")).filter((n) => n.endsWith(".ts"))) {
    for (const m of read(join("src", f)).matchAll(/rule:\s*"([^"]+)"/g)) ids.add(m[1]);
  }
  return ids.size;
}
function countCorrelationRules() {
  return [...read("src/correlation-engine.ts").matchAll(/incident:\s*"[^"]+"/g)].length;
}

const truth = { rules: countRuleIds(), correlation: countCorrelationRules() };

// --- Canonical facts -------------------------------------------------------
// phrase:   matches "<number>+ <keyword>" (or "<number> <keyword>" for count-only);
//           the captured number on every listed surface must equal `advertised`.
// floor:    ground-truth number the advertised value must be <= (null = editorial,
//           no source of truth, skip the honesty check).
// surfaces: LIVE files that must each carry the canonical token >= once.
const CLAIMS = [
  {
    id: "rule/indicator count",
    canonical: "350+",
    advertised: 350,
    floor: truth.rules,
    // threat indicators | static heuristics | detection rules | rules
    // (longest alternatives first so "detection rules" wins over "rules")
    phrase: /(\d+)\+\s*(?:threat indicators|static heuristics|detection rules|detection|rules)\b/gi,
    surfaces: [
      { file: "package.json", note: "npm description" },
      { file: "README.md", note: "intro + heuristics cell + architecture block" },
      { file: "docs/mcp.md", note: "scan_directory description" },
      { file: "src/mcp-server.ts", note: "scan_directory MCP tool description" },
    ],
  },
  {
    id: "correlation-rule count",
    canonical: "15+",
    advertised: 15,
    floor: truth.correlation,
    phrase: /(\d+)\+\s*correlation rules\b/gi,
    surfaces: [{ file: "README.md", note: "correlation rules bullet" }],
  },
  {
    id: "category count",
    canonical: "12",
    advertised: 12,
    floor: null, // editorial: no category constant exists in src
    phrase: /(\d+)\s*categories\b/gi,
    surfaces: [{ file: "README.md", note: "architecture: rules across N categories" }],
  },
];

const failures = [];

for (const claim of CLAIMS) {
  const { id, canonical, advertised, floor, phrase, surfaces } = claim;

  // Honesty check: the advertised floor must not exceed ground truth.
  if (floor !== null && advertised > floor) {
    failures.push({
      kind: "overstate",
      id,
      msg: `advertised "${canonical}" exceeds ground truth (${floor} found in src/). ` +
        `Either the count regressed or the marketing number is a lie - lower the canonical value.`,
    });
  }

  for (const { file, note } of surfaces) {
    let contents = read(file);
    // Join adjacent JS string-literal concatenations ("...a " + "b...") so a
    // phrase split across two literals (as in src/mcp-server.ts) is still seen.
    if (file.endsWith(".ts")) contents = contents.replace(/"\s*\+\s*\n?\s*"/g, "");

    const nums = [...contents.matchAll(phrase)].map((m) => Number(m[1]));
    if (nums.length === 0) {
      failures.push({
        kind: "missing",
        id,
        file,
        msg: `expected the ${id} claim "${canonical}" (${note}) - found no matching phrase at all`,
      });
      continue;
    }
    const wrong = [...new Set(nums.filter((n) => n !== advertised))];
    if (wrong.length > 0) {
      failures.push({
        kind: "mismatch",
        id,
        file,
        msg: `${id} on this surface says ${wrong.map((n) => `"${n}"`).join(", ")} (${note}); ` +
          `canonical is "${canonical}"`,
      });
    }
  }
}

if (failures.length > 0) {
  console.error(
    `\n  Capability-claim check failed.\n` +
      `  Every capability number must match ONE canonical value across all live\n` +
      `  surfaces (the way check:version-sync pins the version string). A copy left\n` +
      `  behind ships a scanner that boasts a different number in different places.\n`,
  );
  for (const f of failures) {
    if (f.file) console.error(`  - ${f.file}: ${f.msg}`);
    else console.error(`  - [${f.id}]: ${f.msg}`);
  }
  console.error(
    `\n  Fix: set the same canonical value everywhere (and, if the count really\n` +
      `  grew, bump the canonical in scripts/check-claims.mjs), then re-run\n` +
      `  \`npm run build\`. Historical files (CHANGELOG.md, .ai/handoff/) are NOT\n` +
      `  scanned on purpose - do not rewrite version-stamped history.\n`,
  );
  process.exit(1);
}

console.log(
  `Capability claims OK: rules="350+" (<=${truth.rules} in src), ` +
    `correlation="15+" (<=${truth.correlation} in src), categories="12" - all surfaces agree.`,
);
