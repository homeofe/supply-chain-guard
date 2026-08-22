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

// ---------------------------------------------------------------------------
// Reading a state store
// ---------------------------------------------------------------------------

/**
 * How a state store answered.
 *
 * `absent` and `unreadable` mean opposite things and must never collapse to the
 * same value. An absent store is a first scan and a correct empty baseline. An
 * unreadable store is lost evidence: everything computed from it silently
 * produces nothing while the scan still reports success.
 *
 * Both stores in this directory previously ended their read in
 * `catch { return []; }`, which returned the absent answer for the unreadable
 * case. Measured consequence, identical in both: the default gate flipped from
 * exit 1 to exit 0 with the scanned code unchanged, because the findings that
 * disappear are `high` and the default gate is `summary.high > 0`. The triage
 * store additionally reported `slaComplianceRate: 100` where the intact store
 * gave 0, so a corrupt file did not merely hide a verdict, it manufactured a
 * clean one.
 *
 * Reading through {@link readJsonArrayStore} is what keeps the two cases apart.
 * A new store under this directory should use it rather than write a third
 * `catch` that returns `[]`.
 */
export type StateStoreStatus = "absent" | "ok" | "unreadable";

/**
 * Why a store file that exists could not be used.
 *
 * These are fixed identifiers, never an exception message. The reason is
 * published inside a scan report, and an exception message from `fs` or
 * `JSON.parse` carries the absolute path of the file, which on a developer
 * machine carries the account name. `normalizePublicCoveragePath` in
 * `src/pattern-scanner.ts` exists for the same hazard; here the vocabulary is
 * enumerated instead, so there is nothing to normalise.
 */
export type StateStoreUnreadableReason =
  /** The file exists but could not be read from disk (permissions, I/O). */
  | "read-failed"
  /** The bytes are not valid JSON: truncated mid-write, zero length, garbage. */
  | "not-json"
  /** Valid JSON, but not a JSON array: `null`, `{}`, a string, a number. */
  | "not-an-array"
  /** A JSON array, but at least one element fails the store's shape check. */
  | "invalid-entry";

/** The result of reading a state store. */
export interface StateStoreRead<T> {
  /** Usable entries. Empty unless `status` is `ok`. */
  entries: T[];
  status: StateStoreStatus;
  /** Set if and only if `status` is `unreadable`. */
  reason?: StateStoreUnreadableReason;
}

/**
 * Read one JSON-array state store and report which of the three things happened.
 *
 * Contract, so that a later reader does not "simplify" the failure branch back
 * into an empty array:
 *
 * - no file at all: `absent`, `entries: []`. A genuine first scan, and it must
 *   stay silent, which is why `fs.existsSync` answers it first.
 * - readable and well shaped: `ok`, with the entries. An empty JSON array is
 *   `ok` with zero entries, because an empty array is a store that says, in a
 *   well formed way, that it holds nothing.
 * - anything else: `unreadable`, `entries: []`, and a `reason`. The caller is
 *   responsible for turning that into a reported failure.
 *
 * `isEntry` is required rather than optional. The readers this replaces both
 * ended in an `as` cast, which is an assertion and not a check, so two shapes
 * that are valid JSON never reached their `catch` at all and instead crashed
 * the scan downstream with an unhandled `TypeError` and no report: `null` and
 * `{}` on each of the two stores, four cases in total. An optional predicate
 * would let a third store re-introduce exactly that.
 *
 * Deliberately unbounded: the number of entries and the size of the file. Each
 * writer already trims its own store, and a read-side cap invented here would
 * reject stores this tool itself produced under an older limit, converting a
 * working setup into a failing gate for no evidentiary gain. The file is inside
 * the tree being scanned, so anyone able to grow it can already edit the code
 * under scan, which is a strictly stronger position.
 */
export function readJsonArrayStore<T>(
  repoDir: string,
  fileName: string,
  isEntry: (value: unknown) => value is T,
): StateStoreRead<T> {
  const storePath = path.join(repoDir, STATE_DIR, fileName);
  if (!fs.existsSync(storePath)) return { entries: [], status: "absent" };

  let raw: string;
  try {
    raw = fs.readFileSync(storePath, "utf-8");
  } catch {
    return { entries: [], status: "unreadable", reason: "read-failed" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { entries: [], status: "unreadable", reason: "not-json" };
  }

  if (!Array.isArray(parsed)) {
    return { entries: [], status: "unreadable", reason: "not-an-array" };
  }
  if (!parsed.every(isEntry)) {
    return { entries: [], status: "unreadable", reason: "invalid-entry" };
  }

  return { entries: parsed, status: "ok" };
}
