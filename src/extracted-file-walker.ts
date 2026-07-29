import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { recordUnreadablePath } from "./pattern-scanner.js";

/** Generous defaults that bound hostile alias expansion without penalizing normal packages. */
export const DEFAULT_EXTRACTED_WALK_MAX_DEPTH = 64;
export const DEFAULT_EXTRACTED_WALK_MAX_ENTRIES = 100_000;

export interface ExtractedWalkOptions {
  shouldEnterDirectory?: (name: string, relativePath: string) => boolean;
  maxDepth?: number;
  /** Maximum public directory entries expanded, including symlink aliases. */
  maxEntries?: number;
}

export interface ContainedFileReadOptions {
  maxBytes?: number;
  onOversized?: (sizeBytes: number) => void;
}

function isWithinRoot(rootRealPath: string, candidateRealPath: string): boolean {
  const relative = path.relative(rootRealPath, candidateRealPath);
  return relative === "" ||
    (!path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`));
}

function boundedOption(value: number | undefined, hardLimit: number): number {
  return value !== undefined && Number.isSafeInteger(value) && value >= 0
    ? Math.min(value, hardLimit)
    : hardLimit;
}

/** Read one previously collected public path through its contained canonical target. */
export function readContainedExtractedUtf8File(
  rootDir: string,
  publicPath: string,
  findings: Finding[],
  options: ContainedFileReadOptions = {},
): string | null {
  const relativePath = path.relative(rootDir, publicPath) || ".";
  const lexicalRoot = path.resolve(rootDir);
  const lexicalTarget = path.resolve(publicPath);
  if (!isWithinRoot(lexicalRoot, lexicalTarget)) {
    recordUnreadablePath(findings, relativePath);
    return null;
  }

  let rootRealPath: string;
  let targetRealPath: string;
  try {
    rootRealPath = fs.realpathSync(rootDir);
    targetRealPath = fs.realpathSync(publicPath);
  } catch {
    recordUnreadablePath(findings, relativePath);
    return null;
  }
  if (!isWithinRoot(rootRealPath, targetRealPath)) {
    recordUnreadablePath(findings, relativePath);
    return null;
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(targetRealPath);
  } catch {
    recordUnreadablePath(findings, relativePath);
    return null;
  }
  if (!stat.isFile()) {
    recordUnreadablePath(findings, relativePath);
    return null;
  }
  if (options.maxBytes !== undefined && stat.size > options.maxBytes) {
    options.onOversized?.(stat.size);
    return null;
  }

  try {
    return fs.readFileSync(targetRealPath, "utf-8");
  } catch {
    recordUnreadablePath(findings, relativePath);
    return null;
  }
}

/**
 * Walk an extracted artifact while retaining each public archive path. Internal
 * symlinks are followed, but their canonical targets are used for containment
 * and ancestor-cycle checks only, so path-scoped rules still see the symlink's
 * shipped name and extension. Both recursion depth and expanded public entries
 * are bounded because a tiny symlink DAG can otherwise create exponential work.
 */
export function collectExtractedFiles(
  rootDir: string,
  findings: Finding[],
  options: ExtractedWalkOptions = {},
): string[] {
  let rootRealPath: string;
  try {
    rootRealPath = fs.realpathSync(rootDir);
  } catch {
    recordUnreadablePath(findings, ".");
    return [];
  }

  const maxDepth = boundedOption(
    options.maxDepth,
    DEFAULT_EXTRACTED_WALK_MAX_DEPTH,
  );
  const maxEntries = boundedOption(
    options.maxEntries,
    DEFAULT_EXTRACTED_WALK_MAX_ENTRIES,
  );
  const files: string[] = [];
  let expandedEntries = 0;
  let entryBudgetExhausted = false;

  const exhaustEntryBudget = (): void => {
    if (entryBudgetExhausted) return;
    entryBudgetExhausted = true;
    // The budget ends the entire walk, not just this path. Use a global scope
    // so a policy ignore for the next entry cannot erase incomplete coverage
    // for later, unenumerated paths.
    recordUnreadablePath(findings, ".");
  };

  const walk = (
    publicDir: string,
    ancestors: ReadonlySet<string>,
    depth: number,
  ): void => {
    if (entryBudgetExhausted) return;
    const relativeDir = path.relative(rootDir, publicDir) || ".";
    if (depth > maxDepth) {
      recordUnreadablePath(findings, relativeDir);
      return;
    }
    let realDir: string;
    try {
      realDir = fs.realpathSync(publicDir);
    } catch {
      recordUnreadablePath(findings, relativeDir);
      return;
    }
    if (!isWithinRoot(rootRealPath, realDir) || ancestors.has(realDir)) {
      recordUnreadablePath(findings, relativeDir);
      return;
    }

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(realDir, { withFileTypes: true });
    } catch {
      recordUnreadablePath(findings, relativeDir);
      return;
    }
    entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);

    const nextAncestors = new Set(ancestors);
    nextAncestors.add(realDir);
    for (const entry of entries) {
      const publicPath = path.join(publicDir, entry.name);
      const relativePath = path.relative(rootDir, publicPath);
      if (expandedEntries >= maxEntries) {
        exhaustEntryBudget();
        break;
      }
      expandedEntries++;

      let isFile = entry.isFile();
      let isDirectory = entry.isDirectory();

      if (entry.isSymbolicLink()) {
        if (options.shouldEnterDirectory?.(entry.name, relativePath) === false) {
          continue;
        }
        let targetRealPath: string;
        let targetStat: fs.Stats;
        try {
          targetRealPath = fs.realpathSync(publicPath);
          targetStat = fs.statSync(targetRealPath);
        } catch {
          recordUnreadablePath(findings, relativePath);
          continue;
        }
        if (!isWithinRoot(rootRealPath, targetRealPath)) {
          recordUnreadablePath(findings, relativePath);
          continue;
        }
        isFile = targetStat.isFile();
        isDirectory = targetStat.isDirectory();
        if (!isFile && !isDirectory) {
          recordUnreadablePath(findings, relativePath);
          continue;
        }
      }

      if (isDirectory) {
        if (options.shouldEnterDirectory?.(entry.name, relativePath) === false) continue;
        walk(publicPath, nextAncestors, depth + 1);
      } else if (isFile) {
        files.push(publicPath);
      } else {
        // FIFOs, sockets, and device nodes cannot be evaluated as static
        // package content. Surface that limitation instead of silently skipping.
        recordUnreadablePath(findings, relativePath);
      }
      if (entryBudgetExhausted) break;
    }
  };

  walk(rootDir, new Set(), 0);
  return files;
}