/**
 * Central file/path applicability for PatternEntry rules.
 *
 * Pattern metadata is a contract. A scanner must not selectively honour only
 * `requiresInFile` while ignoring extension, path, or test-fixture guards,
 * because that gives the same bytes different verdicts through different
 * entry points.
 */

import * as path from "node:path";
import type { PatternEntry } from "./types.js";
import { isSelfScanInertFile, isVerifiedSelfScanFile } from "./self-scan-trust.js";

/**
 * Test directory names every test-path matcher agrees on. Test-path exemptions
 * are chosen by the scanned tree (it names its own files), so each entry is a
 * place malware could hide; widen this only with a reason.
 */
const SHARED_TEST_DIRS = [
  "tests?",
  "__tests__",
  "__fixtures__",
  "__mocks__",
  "__snapshots__",
  "e2e",
  "integration-tests?",
  "fixtures?",
  "testdata",
  "test-data",
];

/**
 * File-name forms of a test, shared by every test-path matcher: a `.test.` /
 * `_spec.` style suffix, pytest's `conftest.py`, and a Bats suite (`*.bats`).
 *
 * `.bats` is here because the format is test-only: bats is the only thing that
 * runs such a file, the same way a `.test.ts` name marks a suite. Measured when
 * `.bats` files started being read: the Bats suites of a project that tests
 * its own secret detection, copied out of their `tests/` directory, raised 3
 * criticals (fixture AWS, GitHub and private-key strings) that the same files
 * under `tests/` did not.
 * Before that change `.bats` content was never read at all, so classifying it
 * as a test costs no coverage the scan ever had.
 */
const TEST_FILE_NAME_SOURCE =
  "[._-](?:test|spec|mock|fixture|stub|fake)\\.|(?:^|\\/)conftest\\.py$|\\.bats$";

/**
 * pytest's default prefix collection form `test_*.py` (basename only, so
 * `testing.py`, `latest_net.py` and `contest.py` stay production source).
 * OPT-IN, never part of the shared TEST_FILE_PATTERN: a test-path exemption
 * is chosen by the scanned package (it names its own files), and the shared
 * pattern gates every `notTestFile` malware rule. Adding this form there let
 * an eval of a base64-decoded payload in `test_backdoor.py` scan clean. Only
 * the internal disclosure rules, where a test's private literals are expected,
 * opt in.
 */
const PYTEST_PREFIX_SOURCE = "(?:^|\\/)test_[^/]*\\.py$";

/**
 * Build a test-path matcher from the shared directory core, the shared file
 * name forms, and any directory names one consumer adds on top.
 */
export function buildTestFilePattern(
  extraDirs: readonly string[] = [],
  options: { pytestPrefix?: boolean } = {},
): RegExp {
  const dirs = [...SHARED_TEST_DIRS, ...extraDirs].join("|");
  const names = options.pytestPrefix ? `${TEST_FILE_NAME_SOURCE}|${PYTEST_PREFIX_SOURCE}` : TEST_FILE_NAME_SOURCE;
  return new RegExp(`(?:^|\\/)(?:${dirs})\\/|${names}`, "i");
}

/** Detect test / spec / fixture / mock files using normalized "/" paths. */
export const TEST_FILE_PATTERN = buildTestFilePattern([
  "specs?",
  "snapshots?",
  "test-fixtures?",
  "mocks?",
  "stubs?",
  "fakes?",
]);

/**
 * Test-path matcher for the `notTestFile` gate of the malware rules.
 *
 * Narrower than TEST_FILE_PATTERN on purpose. The scanned package names its
 * own files, so every file-name form here is a name an attacker can pick: the
 * separator-prefixed forms (`x-test.js`, `a_spec.js`, `a.stub.js`, `a-fake.js`)
 * are conventions no test runner requires, and each one made a payload scan
 * clean. Only the forms a runner itself discovers by name stay: `.test.` and
 * `.spec.` (jest, vitest, mocha), `_test.go` and `_test.py` (go test, pytest),
 * pytest's `conftest.py` and a Bats suite. The directory forms are shared.
 */
export const MALWARE_RULE_TEST_FILE_PATTERN = new RegExp(
  `(?:^|\\/)(?:${[
    ...SHARED_TEST_DIRS,
    "specs?",
    "snapshots?",
    "test-fixtures?",
    "mocks?",
    "stubs?",
    "fakes?",
  ].join("|")})\\/|\\.(?:test|spec)\\.|_test\\.(?:go|py)$|(?:^|\\/)conftest\\.py$|\\.bats$`,
  "i",
);

/**
 * Credential-hygiene rules: a secret-shaped literal in a test fixture is an
 * ordinary, expected thing (a security tool's own tests are full of them), so
 * these keep the test-path exemption at every severity, and so do the README
 * lure heuristics (prose aimed at someone reading the top-level README, never
 * code that runs). Every other critical
 * `notTestFile` rule is a malware verdict and is NOT exempted by path: the
 * path is chosen by the scanned package, so exempting it let an encoded-eval payload
 * in `x-test.js` or `tests/a.js` scan clean.
 */
const TEST_PATH_EXEMPT_CRITICAL_RULE = /^(?:SECRETS_|IAC_HARDCODED_SECRET$)|LURE/;

export type ApplicablePattern = Pick<
  PatternEntry,
  | "onlyExtensions"
  | "onlyFilePattern"
  | "notFilePattern"
  | "notTestFile"
  | "requiresInFile"
  | "requiresInFileMatcher"
> &
  Partial<Pick<PatternEntry, "severity" | "rule">>;

/**
 * RegExp.prototype.test mutates lastIndex for global/sticky expressions.
 * Pattern guards are currently non-global, but resetting here keeps metadata
 * safe if a future rule accidentally supplies one.
 */
function stableTest(regex: RegExp, value: string): boolean {
  regex.lastIndex = 0;
  const matched = regex.test(value);
  regex.lastIndex = 0;
  return matched;
}
/** Apply only the whole-content part of the centralized metadata contract. */
export function satisfiesPatternContentRequirement(
  pattern: Pick<PatternEntry, "requiresInFile" | "requiresInFileMatcher">,
  content: string,
): boolean {
  if (pattern.requiresInFile && !stableTest(pattern.requiresInFile, content)) {
    return false;
  }
  if (
    pattern.requiresInFileMatcher &&
    !pattern.requiresInFileMatcher(content)
  ) {
    return false;
  }
  return true;
}

let lastOwnFileCheck: { path: string; content: string; verified: boolean } | undefined;

/**
 * Whether this file is one of the scanner's own reviewed files, byte-identical
 * to the copy the running scanner ships a digest for. Those files spell out the
 * signatures and fixtures the rules detect, and used to be skipped by NAME
 * (a scanner-module basename, a test-shaped path). Name-based skipping is
 * chosen by the scanned package, so the exemption is now earned by exact path
 * plus content digest instead: a same-named third-party file, or any edit to
 * the file, fails the check and is scanned in full.
 *
 * Single-entry memo: every pattern asks about the same file in a row, and the
 * digest is only computed for the few paths on the allowlist.
 */
function isVerifiedOwnFile(normalizedPath: string, content: string): boolean {
  if (!isSelfScanInertFile(normalizedPath)) return false;
  const last = lastOwnFileCheck;
  if (last && last.path === normalizedPath && last.content === content) return last.verified;
  const verified = isVerifiedSelfScanFile(normalizedPath, Buffer.from(content, "utf8"));
  lastOwnFileCheck = { path: normalizedPath, content, verified };
  return verified;
}

/**
 * Return true when a pattern may be evaluated against this file.
 *
 * `relativePath` is optional only for low-level/unit callers that have no file
 * context. Production scanners must pass it so every metadata guard is
 * enforceable.
 *
 * `fileExtension` is the language the file is READ as, when that is not its
 * own extension: an extensionless `#!/usr/bin/env node` hook is `.js` and a
 * `.bats` suite is `.bash` (see script-language.ts). It feeds `onlyExtensions`
 * only. Every path guard, including the test-file one, still reads the real
 * path, so a script is never reclassified by the extension it was given.
 */
export function isPatternApplicableToFile(
  pattern: ApplicablePattern,
  content: string,
  relativePath = "",
  fileExtension?: string,
): boolean {
  const normalizedPath = relativePath.replace(/\\/g, "/");
  const extension = (fileExtension ?? path.extname(normalizedPath)).toLowerCase();

  if (
    pattern.onlyExtensions &&
    !pattern.onlyExtensions.some((candidate) => candidate.toLowerCase() === extension)
  ) {
    return false;
  }
  if (
    pattern.onlyFilePattern &&
    !stableTest(pattern.onlyFilePattern, normalizedPath)
  ) {
    return false;
  }
  if (
    pattern.notFilePattern &&
    stableTest(pattern.notFilePattern, normalizedPath) &&
    // `.txt` is not a prose-only format: Node executes `require("./a.txt")`.
    // A critical rule is therefore not skipped on the strength of a `.txt`
    // name; `.md`, `.markdown` and `.rst` (threat write-ups) stay exempt.
    !(
      pattern.severity === "critical" &&
      /\.txt$/i.test(normalizedPath) &&
      !stableTest(pattern.notFilePattern, normalizedPath.replace(/\.txt$/i, ".js"))
    )
  ) {
    return false;
  }
  // A rule that carries a path exemption (notFilePattern or notTestFile) is
  // also skipped for the scanner's own digest-verified files; see
  // isVerifiedOwnFile.
  if (
    (pattern.notFilePattern || pattern.notTestFile) &&
    isVerifiedOwnFile(normalizedPath, content)
  ) {
    return false;
  }
  if (
    pattern.notTestFile &&
    stableTest(MALWARE_RULE_TEST_FILE_PATTERN, normalizedPath) &&
    (pattern.severity !== "critical" ||
      TEST_PATH_EXEMPT_CRITICAL_RULE.test(pattern.rule ?? ""))
  ) {
    return false;
  }
  if (!satisfiesPatternContentRequirement(pattern, content)) return false;

  return true;
}
