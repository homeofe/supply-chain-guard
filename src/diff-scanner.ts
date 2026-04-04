/**
 * Diff-based scanning (v4.5).
 *
 * Identifies files changed since a given commit and returns only
 * those paths for scanning, enabling incremental CI integration.
 */

import { execSync } from "node:child_process";
import * as path from "node:path";

/**
 * Get list of files changed since a given commit.
 */
export function getChangedFiles(
  dir: string,
  sinceCommit: string,
): string[] {
  try {
    const output = execSync(
      `git -C "${dir}" diff --name-only ${sinceCommit} HEAD`,
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    return output
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((f) => path.join(dir, f));
  } catch {
    return [];
  }
}

/**
 * Get list of files changed in the working tree (uncommitted).
 */
export function getUncommittedFiles(dir: string): string[] {
  try {
    const output = execSync(
      `git -C "${dir}" diff --name-only HEAD`,
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    );
    const tracked = output.trim().split("\n").filter(Boolean);

    const untracked = execSync(
      `git -C "${dir}" ls-files --others --exclude-standard`,
      { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] },
    ).trim().split("\n").filter(Boolean);

    return [...tracked, ...untracked].map((f) => path.join(dir, f));
  } catch {
    return [];
  }
}
