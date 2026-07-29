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

/** Detect test / spec / fixture / mock files using normalized "/" paths. */
export const TEST_FILE_PATTERN =
  /(?:^|\/)(?:tests?|specs?|__tests__|__fixtures__|__mocks__|__snapshots__|snapshots?|e2e|integration-tests?|test-fixtures?|fixtures?|testdata|test-data|mocks?|stubs?|fakes?)\/|[._-](?:test|spec|mock|fixture|stub|fake)\.|(?:^|\/)conftest\.py$/i;

export type ApplicablePattern = Pick<
  PatternEntry,
  | "onlyExtensions"
  | "onlyFilePattern"
  | "notFilePattern"
  | "notTestFile"
  | "requiresInFile"
  | "requiresInFileMatcher"
>;

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

/**
 * Return true when a pattern may be evaluated against this file.
 *
 * `relativePath` is optional only for low-level/unit callers that have no file
 * context. Production scanners must pass it so every metadata guard is
 * enforceable.
 */
export function isPatternApplicableToFile(
  pattern: ApplicablePattern,
  content: string,
  relativePath = "",
): boolean {
  const normalizedPath = relativePath.replace(/\\/g, "/");
  const extension = path.extname(normalizedPath).toLowerCase();

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
    stableTest(pattern.notFilePattern, normalizedPath)
  ) {
    return false;
  }
  if (
    pattern.notTestFile &&
    stableTest(TEST_FILE_PATTERN, normalizedPath)
  ) {
    return false;
  }
  if (!satisfiesPatternContentRequirement(pattern, content)) return false;

  return true;
}
