/**
 * The scanner's own state directory inside a scanned repository.
 *
 * Both the risk-history and the triage store write here. The directory is
 * scanner state, not project content, so it must never end up in the
 * consumer's commits. Relying on the consumer to add it to .gitignore does not
 * work: it is created by whichever scan runs first, usually before anyone has
 * thought about it, and a later `git add -A` sweeps it in. That is exactly how
 * a stale history file from one April afternoon ended up committed to a public
 * repository months later, inside an unrelated commit.
 *
 * So the directory ignores itself. Creating it also writes a .gitignore
 * containing `*`, which git honours for everything beneath it including the
 * .gitignore itself. Nothing is required of the consumer and it cannot be
 * forgotten.
 */

import * as fs from "node:fs";
import * as path from "node:path";

/** Directory name used for all scanner state inside a scanned repository. */
export const STATE_DIR = ".scg-history";

const SELF_IGNORE = `# Created automatically by supply-chain-guard.
# This directory holds scanner state (risk history, triage decisions), not
# project content, so it is excluded from the repository that is being scanned.
# Deleting this file would let a later 'git add -A' commit scanner state.
*
`;

/**
 * Create the state directory if needed and make sure it excludes itself.
 *
 * Safe to call on every write. The .gitignore is rewritten only when it is
 * missing or has been altered, so this does not churn the file, and a failure
 * to write it is never fatal: state persistence is a convenience and must not
 * break a scan on a read-only or otherwise restricted filesystem.
 */
export function ensureStateDir(repoDir: string): string {
  const stateDir = path.join(repoDir, STATE_DIR);
  fs.mkdirSync(stateDir, { recursive: true });

  const ignorePath = path.join(stateDir, ".gitignore");
  try {
    if (!fs.existsSync(ignorePath) || fs.readFileSync(ignorePath, "utf-8") !== SELF_IGNORE) {
      fs.writeFileSync(ignorePath, SELF_IGNORE);
    }
  } catch {
    // A missing self-ignore is a hygiene problem, not a scan failure.
  }

  return stateDir;
}
