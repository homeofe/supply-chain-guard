/**
 * Diff-based scanning (v4.5).
 *
 * Identifies files changed since a given commit and returns only
 * those paths for scanning, enabling incremental CI integration.
 */

import { execToolSync } from "./safe-exec.js";
import * as fs from "node:fs";
import * as path from "node:path";

/**
 * A git revision: a ref name or sha, optionally followed by ancestry suffixes
 * (`HEAD~1`, `HEAD^`, `HEAD^2`, `main~3`, `HEAD~1^2`). Everything else (`@`,
 * `{`, `:`, whitespace, shell metacharacters) stays rejected, and a leading `-`
 * is rejected separately so a ref can never be read as a git option.
 */
export const SAFE_REF_RE = /^[A-Za-z0-9._/-]+(?:[~^][0-9]*)*$/;

/** Split NUL-terminated git output (`-z`) into paths. */
function splitNul(output: string): string[] {
  return output.split("\0").filter(Boolean);
}

/**
 * Get list of files changed since a given commit.
 */
export function getChangedFiles(
  dir: string,
  sinceCommit: string,
): string[] {
  return getChangedFilesResult(dir, sinceCommit).files;
}

/** Keep an empty successful diff distinct from an invalid or unavailable ref. */
export function getChangedFilesResult(
  dir: string,
  sinceCommit: string,
): { status: "ok" | "error"; files: string[] } {
  // Reject a ref that could be read as a git option or inject arguments;
  // execFileSync (no shell) handles the rest.
  if (!SAFE_REF_RE.test(sinceCommit) || sinceCommit.startsWith("-")) {
    return { status: "error", files: [] };
  }
  try {
    // -z with core.quotePath=false: without them git C-quotes a non-ASCII name
    // (a quoted octal string) that never matches a walked file, and the changed
    // file silently drops out of the incremental scan. Deleted paths are
    // excluded because they legitimately no longer exist.
    const output = execToolSync(
      "git",
      [
        "-c", "core.quotePath=false", "-C", dir, "diff", "--name-only", "-z",
        "--diff-filter=d", sinceCommit, "HEAD",
      ],
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    const files = splitNul(output).map((f) => path.join(dir, f));
    // A changed path that does not resolve to anything on disk cannot be
    // scanned: report the diff as unavailable (high finding, partial scan)
    // instead of dropping the file and answering as if it had been covered.
    if (files.some((f) => !fs.existsSync(f))) {
      return { status: "error", files: [] };
    }
    return { status: "ok", files };
  } catch {
    return { status: "error", files: [] };
  }
}

/**
 * Get list of files changed in the working tree (uncommitted).
 */
export function getUncommittedFiles(dir: string): string[] {
  try {
    const tracked = splitNul(execToolSync(
      "git",
      ["-c", "core.quotePath=false", "-C", dir, "diff", "--name-only", "-z", "HEAD"],
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    ));

    const untracked = splitNul(execToolSync(
      "git",
      ["-c", "core.quotePath=false", "-C", dir, "ls-files", "-z", "--others", "--exclude-standard"],
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    ));

    return [...tracked, ...untracked].map((f) => path.join(dir, f));
  } catch {
    return [];
  }
}
