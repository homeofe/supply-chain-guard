#!/usr/bin/env node
/**
 * Preflight for `check:aahp`: every tracked file is inside the `em-dash` rule's
 * scope, or has a written reason for not being.
 *
 * WHAT THIS IS NOT
 * ----------------
 * This is NOT a second em-dash checker. It never reads the content of a tracked
 * file and never searches for U+2014. Searching is the job of the AAHP
 * `forbidden-patterns` gate, which runs immediately after this script inside
 * `check:aahp`, and `aahp.config.json` stays the single source of truth for the
 * rule. This script answers the one question that gate cannot answer about
 * itself: does the set of files it looks at still cover the repository?
 *
 * WHY THIS EXISTS
 * ---------------
 * https://github.com/homeofe/supply-chain-guard/issues/178. On 2026-08-22 the
 * repository held 77 em dashes across 17 files while `forbidden-patterns`
 * reported "no matches" and exited 0, on every pull request, inside a required
 * status check. Nothing was broken and nothing was lying. The rule's `include`
 * list named six pathspecs, and those six happened to match none of the 17
 * files, so "no matches" was the truthful answer to the question the rule
 * actually asked. A rule whose scope can shrink to nothing while its gate stays
 * green is not enforced, it is only observed.
 *
 * Two properties of that failure are worth naming, because both are invisible
 * from inside the gate:
 *
 *   1. An OPT-IN scope fails open. Every file added after the rule was written
 *      was outside it by default, silently, forever. The scope is now the single
 *      pathspec "*", so a new file is covered the moment it is tracked and the
 *      only way out is an entry below, in a diff a reviewer reads.
 *   2. A config line can read like a mechanism without being one. `exclude` held
 *      "CHANGELOG.md", which every reader took for the reason the changelog went
 *      unchecked. It was inert: the gate replaces its default file set with
 *      `include` when `include` is non-empty, so CHANGELOG.md was never in scope
 *      for `exclude` to remove. Deleting that line alone changed nothing. This
 *      script refuses to answer at all if an `exclude` entry subtracts nothing.
 *
 * EXIT CODES
 * ----------
 *   0  every tracked file is in scope, or is listed below with a reason.
 *   1  policy gap: a tracked file is outside the rule's scope and no reason is
 *      recorded for it. This is the state issue 178 found, expressed as a
 *      number instead of as prose.
 *   2  the question cannot be answered: no git work tree, config missing or
 *      unparseable, the `em-dash` rule absent, a pathspec that matches nothing,
 *      an `exclude` entry that subtracts nothing, or an exception with no
 *      reason. Kept separate from 1 because "I found a violation" and "I could
 *      not determine whether there is one" are different facts, and collapsing
 *      the second into 0 is the failure mode that made this class invisible in
 *      the first place. Both are non-zero, so CI fails either way.
 *
 * Why 1 and 2 and not other numbers: the AAHP gates and `check-aahp-pin.mjs`
 * already use 1 for a policy failure, so 1 keeps that meaning here; 2 is the
 * next value, and nothing in the Node or npm exit-code conventions claims it.
 * No other code is ever returned.
 *
 * Files are enumerated with `git ls-files` through execFileSync with an argument
 * array and NO shell, which is both how the AAHP gate enumerates them (so the
 * two agree on pathspec semantics by construction) and the reason a pathspec
 * string from the config cannot become a shell metacharacter.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as path from "node:path";

const EXIT_OK = 0;
const EXIT_GAP = 1;
const EXIT_INDETERMINATE = 2;

const RULE_ID = "em-dash";

/**
 * Tracked files that are deliberately outside the `em-dash` rule's scope.
 *
 * One entry per exclusion, each a git pathspec and a reason a stranger auditing
 * this repository can evaluate. An entry with no reason, an entry matching no
 * tracked file, and an entry matching only files that ARE in scope are all
 * refused with exit 2, so this table cannot drift away from what the config
 * does. `aahp.config.json` cannot hold these reasons itself: the AAHP config
 * schema sets additionalProperties:false on a forbiddenPatterns rule, so the
 * rule object has no field to put them in.
 *
 * No minimum length is imposed on a reason. Any threshold would be arbitrary and
 * is satisfied by padding; what makes a reason real is that a human reads it in
 * the pull request that adds it. The check is only that one exists.
 */
const SCOPE_EXCEPTIONS = [
  {
    pathspec: "assets/demo.gif",
    reason:
      "Binary. The gate decodes each in-scope file as UTF-8 and matches line by line, so the byte sequence E2 80 94 occurring by chance inside compressed image data would be reported as an em dash in prose. Measured at the time of writing: this file contains that sequence zero times, so the exclusion is precautionary and suppresses no known occurrence. It is the only tracked file that is not text.",
  },
  {
    pathspec: ".ai/handoff/LOG-ARCHIVE.md",
    reason:
      "Inherited exclusion, retained rather than newly decided. The file's own header declares it append-only and states that entries predating the 2026-07-18 rotation are 'preserved below verbatim', so a gate that requires editing archived text would contradict the contract the file states about itself. Assumption being relied on, recorded here because it is an inference from that header and not from a written policy: verbatim preservation is the reason for the carve-out. It holds zero occurrences today, so this preserves history rather than hiding a violation, and anyone who disagrees can delete this entry and the matching `exclude` line together and the gate will simply cover the file.",
  },
];

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Report that the question cannot be answered, and stop. Never returns. */
function indeterminate(lines) {
  console.error(`check:em-dash-scope INDETERMINATE (exit ${EXIT_INDETERMINATE}):`);
  for (const line of [].concat(lines)) console.error(`  ${line}`);
  process.exit(EXIT_INDETERMINATE);
}

/** Tracked paths matching `specs`; all tracked paths when `specs` is empty. */
function lsFiles(specs) {
  const out = execFileSync("git", ["-C", repo, "ls-files", "-z", "--", ...specs], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return out.split("\0").filter(Boolean);
}

try {
  const inside = execFileSync("git", ["-C", repo, "rev-parse", "--is-inside-work-tree"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
  if (inside !== "true") throw new Error(`git reported is-inside-work-tree=${inside}`);
} catch (err) {
  indeterminate([
    `not inside a git work tree at ${repo}: ${err.message}`,
    "`git ls-files` would enumerate zero files and every check below would pass vacuously.",
    "In CI, run actions/checkout before this script.",
  ]);
}

let config;
const configPath = path.join(repo, "aahp.config.json");
try {
  config = JSON.parse(readFileSync(configPath, "utf8"));
} catch (err) {
  indeterminate([`cannot read or parse ${configPath}: ${err.message}`]);
}

const rules = Array.isArray(config.forbiddenPatterns) ? config.forbiddenPatterns : [];
const rule = rules.find((r) => r && r.id === RULE_ID);
if (!rule) {
  indeterminate([
    `no forbiddenPatterns rule with id "${RULE_ID}" in ${configPath}.`,
    "The rule this script exists to keep honest is gone; deleting it must not look like success.",
  ]);
}

// An absent or empty `include` is NOT equivalent to "everything". The AAHP gate
// falls back to its own DEFAULT_INCLUDE, a list of common text extensions that
// does not contain *.ts, so the scope would silently become something this
// repository never chose and the fallback would move whenever the pinned CLI
// moves. Demand an explicit list.
const includeSpecs = rule.include;
if (!Array.isArray(includeSpecs) || includeSpecs.length === 0 || includeSpecs.some((s) => typeof s !== "string")) {
  indeterminate([
    `the "${RULE_ID}" rule has no explicit non-empty include list of strings.`,
    "Without one the gate falls back to the pinned CLI's own default file set, which excludes *.ts",
    "and can change with a dependency bump. State the scope here instead.",
  ]);
}

const excludeSpecs = Array.isArray(rule.exclude) ? rule.exclude : [];
if (excludeSpecs.some((s) => typeof s !== "string")) {
  indeterminate([`the "${RULE_ID}" rule has a non-string entry in its exclude list.`]);
}

const tracked = lsFiles([]);
if (tracked.length === 0) {
  indeterminate([
    `git ls-files returned no tracked files at ${repo}.`,
    "Every set below would be empty and the comparison would pass without proving anything.",
  ]);
}

const included = new Set();
for (const spec of includeSpecs) {
  const matched = lsFiles([spec]);
  if (matched.length === 0) {
    indeterminate([
      `include pathspec ${JSON.stringify(spec)} matches no tracked file.`,
      "A pathspec that has stopped matching narrows the scope without changing the rule's text,",
      "which is how a gate goes quietly green. Fix or remove it.",
    ]);
  }
  for (const f of matched) included.add(f);
}

const excluded = new Set();
for (const spec of excludeSpecs) {
  const matched = lsFiles([spec]);
  if (matched.length === 0) {
    indeterminate([
      `exclude pathspec ${JSON.stringify(spec)} matches no tracked file.`,
      "It documents an exception to nothing and misleads the next reader about what is covered.",
    ]);
  }
  if (!matched.some((f) => included.has(f))) {
    indeterminate([
      `exclude pathspec ${JSON.stringify(spec)} subtracts nothing: no file it matches is in the include set.`,
      "This is exactly the state issue 178 found, where an inert \"CHANGELOG.md\" entry read like",
      "the reason the changelog was unchecked. Delete it, or widen include so it means something.",
    ]);
  }
  for (const f of matched) excluded.add(f);
}

const inScope = new Set([...included].filter((f) => !excluded.has(f)));

const explained = new Set();
for (const [i, exception] of SCOPE_EXCEPTIONS.entries()) {
  const where = `SCOPE_EXCEPTIONS[${i}] (${JSON.stringify(exception.pathspec)})`;
  if (typeof exception.reason !== "string" || exception.reason.trim() === "") {
    indeterminate([`${where} has no written reason.`, "An undocumented carve-out is the defect, not the fix."]);
  }
  const matched = lsFiles([exception.pathspec]);
  if (matched.length === 0) {
    indeterminate([`${where} matches no tracked file.`, "A stale exception hides which files are really uncovered."]);
  }
  const outOfScope = matched.filter((f) => !inScope.has(f));
  if (outOfScope.length === 0) {
    indeterminate([
      `${where} explains nothing: every file it matches is already in scope.`,
      "Delete it, so the table lists only real carve-outs.",
    ]);
  }
  for (const f of outOfScope) explained.add(f);
}

const gaps = tracked.filter((f) => !inScope.has(f) && !explained.has(f));
if (gaps.length > 0) {
  console.error(`check:em-dash-scope FAILED (exit ${EXIT_GAP}): ${gaps.length} tracked file(s) outside the "${RULE_ID}" rule with no recorded reason.`);
  for (const f of gaps) console.error(`  - ${f}`);
  console.error("");
  console.error("  Either widen the rule's include list in aahp.config.json so these are covered,");
  console.error("  or add each one to SCOPE_EXCEPTIONS in scripts/check-em-dash-scope.mjs with a");
  console.error("  reason a stranger auditing this repository can evaluate.");
  process.exit(EXIT_GAP);
}

console.log(
  `check:em-dash-scope OK - ${inScope.size} of ${tracked.length} tracked file(s) in the "${RULE_ID}" rule's scope, ` +
    `${explained.size} excluded with a written reason, 0 uncovered.`,
);
process.exit(EXIT_OK);
