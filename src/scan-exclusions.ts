/**
 * Which directories a scan does not walk, and what it says about them.
 *
 * A directory the walker declines is a place the scanned project can put code
 * that no rule ever reads. Before this module the directory scan dropped eight
 * names without a word and the PyPI walker dropped six others, so
 * `node_modules/x/index.js` carrying a critical payload, a bundled dependency
 * with an install hook, or a `venv/a.py` all scanned clean with
 * `partialScan: false`.
 *
 * The policy, per directory:
 * - `node_modules` stays out of a directory scan (almost every JavaScript
 *   checkout has one on disk, and the scanner is not a dependency auditor)
 *   UNLESS the root manifest bundles the package or an auto-run lifecycle hook
 *   points into it. Those are exactly the packages a tarball ships and an
 *   install executes, so they are walked, together with the packages they
 *   depend on.
 * - `__pycache__`, `.scg-cache` and `.scg-history` hold no source in an
 *   ordinary tree (bytecode, and the scanner's own JSON). Source-like files
 *   there are an anomaly, so the directory produces a coverage finding that
 *   sets `partialScan`.
 * - `venv` and `.venv` are full of third-party Python by design. They produce
 *   an informational finding naming the directory, without `partialScan`:
 *   flagging every working copy that has a virtualenv would be noise that gets
 *   the tool switched off. A lifecycle hook that points into one walks it.
 * - `.git` (git hooks have their own scanner) and `.claude` (read by the agent
 *   skill scanner) stay silently excluded.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { AUTO_RUN_LIFECYCLE_HOOKS, MAX_FILE_SIZE, SCANNABLE_EXTENSIONS } from "./patterns.js";
import { isJsonObject, parseJsonObject, stripBom } from "./json-utils.js";
import { isMarkupOrScriptHostExtension } from "./script-language.js";

/** Directory names the project scan does not walk by default. */
export const EXCLUDED_DIRECTORY_NAMES: ReadonlySet<string> = new Set([
  "node_modules",
  ".git",
  "__pycache__",
  ".venv",
  "venv",
  ".claude",
  ".scg-history",
  ".scg-cache",
]);

/**
 * Directory names an extracted package ARCHIVE walk skips. An archive is the
 * package, so a `venv/`, `node_modules/` or `__pycache__/` inside it is shipped
 * content, not a local development artefact: only the version-control metadata
 * is left out.
 */
export const ARCHIVE_EXCLUDED_DIRECTORY_NAMES: ReadonlySet<string> = new Set([".git"]);

/** Names that never produce a coverage finding: another scanner owns them. */
const SILENT_EXCLUSIONS: ReadonlySet<string> = new Set(["node_modules", ".git", ".claude"]);

/** Excluded directories whose source-like content is anomalous enough to make the scan partial. */
const PARTIAL_WHEN_POPULATED: ReadonlySet<string> = new Set([
  "__pycache__",
  ".scg-cache",
  ".scg-history",
]);

/** Scannable extensions that are data or prose, not code a tree could hide a payload in. */
const DATA_EXTENSIONS: ReadonlySet<string> = new Set([
  ".json",
  ".md",
  ".yml",
  ".yaml",
  ".toml",
  ".svg",
]);

/** Bound on directory entries inspected while deciding whether an excluded directory holds source. */
const PROBE_ENTRY_BUDGET = 5000;

function toPosix(value: string): string {
  return value.replace(/\\/g, "/");
}

function isCodeLikeExtension(ext: string): boolean {
  if (ext === ".pth" || isMarkupOrScriptHostExtension(ext)) return true;
  return SCANNABLE_EXTENSIONS.has(ext) && !DATA_EXTENSIONS.has(ext);
}

/** Parsed root manifest of a scan directory, or undefined when absent or unparseable. */
export function readRootManifest(rootDir: string): Record<string, unknown> | undefined {
  const manifestPath = path.join(rootDir, "package.json");
  try {
    if (fs.statSync(manifestPath).size > MAX_FILE_SIZE) return undefined;
    return parseJsonObject(stripBom(fs.readFileSync(manifestPath, "utf-8")));
  } catch {
    return undefined;
  }
}

function bundledPackageNames(manifest: Record<string, unknown>): Set<string> {
  const names = new Set<string>();
  const bundled = manifest.bundleDependencies ?? manifest.bundledDependencies;
  if (Array.isArray(bundled)) {
    for (const entry of bundled) if (typeof entry === "string" && entry) names.add(entry);
  } else if (bundled === true && isJsonObject(manifest.dependencies)) {
    for (const name of Object.keys(manifest.dependencies)) names.add(name);
  }
  return names;
}

function lifecycleScriptTexts(manifest: Record<string, unknown>): string[] {
  if (!isJsonObject(manifest.scripts)) return [];
  const texts: string[] = [];
  for (const hook of AUTO_RUN_LIFECYCLE_HOOKS) {
    const value = manifest.scripts[hook];
    if (typeof value === "string") texts.push(value);
  }
  return texts;
}

const NODE_MODULES_REFERENCE = /node_modules[\\/]((?:@[^\\/\s"'`;|&)]+[\\/])?[^\\/\s"'`;|&)]+)/g;

function referencedNodeModulePackages(scripts: readonly string[]): Set<string> {
  const names = new Set<string>();
  for (const script of scripts) {
    for (const match of script.matchAll(NODE_MODULES_REFERENCE)) {
      names.add(match[1]!.replace(/\\/g, "/"));
    }
  }
  return names;
}

function referencedExcludedDirectories(scripts: readonly string[]): Set<string> {
  const names = new Set<string>();
  for (const name of ["venv", ".venv", "__pycache__", ".scg-cache", ".scg-history"]) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const reference = new RegExp(`(?:^|[^\\w.-])(?:\\.[\\\\/])?${escaped}[\\\\/]`);
    if (scripts.some((script) => reference.test(script))) names.add(name);
  }
  return names;
}

/** Packages `pkg` needs at run time, read from the copy installed under node_modules. */
function installedDependencies(rootDir: string, pkg: string): string[] {
  try {
    const manifestPath = path.join(rootDir, "node_modules", ...pkg.split("/"), "package.json");
    if (fs.statSync(manifestPath).size > MAX_FILE_SIZE) return [];
    const manifest = parseJsonObject(fs.readFileSync(manifestPath, "utf-8"));
    if (!manifest) return [];
    const out: string[] = [];
    for (const key of ["dependencies", "optionalDependencies"] as const) {
      const block = manifest[key];
      if (isJsonObject(block)) out.push(...Object.keys(block));
    }
    return out;
  } catch {
    return [];
  }
}

/** Upper bound on the packages one scan walks under node_modules. */
const MAX_BUNDLED_PACKAGES = 2000;

/**
 * Packages under the ROOT node_modules this scan must walk: the manifest's
 * bundled dependencies, whatever an auto-run lifecycle hook references, and
 * the run-time dependencies of those (npm ships a bundled package's own
 * dependencies beside it).
 */
function packagesToWalk(rootDir: string, manifest: Record<string, unknown> | undefined): Set<string> {
  const result = new Set<string>();
  if (!manifest) return result;
  const queue = [
    ...bundledPackageNames(manifest),
    ...referencedNodeModulePackages(lifecycleScriptTexts(manifest)),
  ];
  while (queue.length > 0 && result.size < MAX_BUNDLED_PACKAGES) {
    const name = queue.pop()!;
    if (result.has(name)) continue;
    result.add(name);
    for (const dependency of installedDependencies(rootDir, name)) {
      if (!result.has(dependency)) queue.push(dependency);
    }
  }
  return result;
}

/** True when `dir` (a real directory) holds a source-like file, or could not be ruled out. */
function holdsSourceLikeFiles(dir: string): boolean {
  const stack = [dir];
  let budget = PROBE_ENTRY_BUDGET;
  while (stack.length > 0) {
    const current = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return true;
    }
    for (const entry of entries) {
      if (--budget < 0) return true;
      if (entry.isDirectory()) stack.push(path.join(current, entry.name));
      else if (entry.isFile() && isCodeLikeExtension(path.extname(entry.name).toLowerCase())) return true;
    }
  }
  return false;
}

export interface DirectoryWalkPolicy {
  shouldEnterDirectory: (name: string, relativePath: string) => boolean;
  onSkippedDirectory: (name: string, publicPath: string, relativePath: string) => void;
}

/**
 * Walk policy for a directory scan rooted at `rootDir`. Coverage findings for
 * excluded directories that hold source are appended to `findings`.
 */
export function createDirectoryWalkPolicy(rootDir: string, findings: Finding[]): DirectoryWalkPolicy {
  const manifest = readRootManifest(rootDir);
  const walkedPackages = packagesToWalk(rootDir, manifest);
  const walkedScopes = new Set<string>();
  for (const name of walkedPackages) if (name.startsWith("@")) walkedScopes.add(name.split("/")[0]!);
  const hookDirectories = manifest
    ? referencedExcludedDirectories(lifecycleScriptTexts(manifest))
    : new Set<string>();

  const shouldEnterDirectory = (name: string, relativePath: string): boolean => {
    const segments = toPosix(relativePath).split("/").filter(Boolean);
    if (segments[0] === "node_modules") {
      if (segments.length === 1) return walkedPackages.size > 0;
      const first = segments[1]!;
      const scoped = first.startsWith("@");
      if (scoped && segments.length === 2) return walkedScopes.has(first);
      const pkg = scoped ? `${first}/${segments[2]}` : first;
      if (!walkedPackages.has(pkg)) return false;
      // Inside a walked package its own nested node_modules is walked too; the
      // other excluded names (.git, venv, ...) stay out.
      return name === "node_modules" || !EXCLUDED_DIRECTORY_NAMES.has(name);
    }
    if (!EXCLUDED_DIRECTORY_NAMES.has(name)) return true;
    return segments.length === 1 && hookDirectories.has(name);
  };

  const onSkippedDirectory = (name: string, publicPath: string, relativePath: string): void => {
    if (SILENT_EXCLUSIONS.has(name)) return;
    // Only a real directory is probed: a symlink is not followed out of the tree.
    try {
      if (!fs.lstatSync(publicPath).isDirectory()) return;
    } catch {
      return;
    }
    if (!holdsSourceLikeFiles(publicPath)) return;
    const publicName = toPosix(relativePath);
    if (PARTIAL_WHEN_POPULATED.has(name)) {
      findings.push({
        rule: "PATH_SCAN_INCOMPLETE",
        description: `${publicName} is excluded from the scan but holds source-like files, which this directory does not ordinarily contain. Their contents were not scanned.`,
        severity: "info",
        confidence: 1,
        category: "info",
        file: publicName,
        match: "excluded directory holds source",
        recommendation: "Treat this result as partial, not clean. Inspect the directory by hand, or remove it and scan again.",
      });
      return;
    }
    findings.push({
      rule: "EXCLUDED_DIRECTORY_SKIPPED",
      description: `${publicName} is not walked by the scan, and it holds source-like files that were not scanned (virtual environments are third-party code by design).`,
      severity: "info",
      confidence: 1,
      category: "info",
      file: publicName,
      match: "excluded directory with source",
      recommendation: "Scan the packages that matter in their own right, or reference a file in this directory from an install hook so it is walked.",
    });
  };

  return { shouldEnterDirectory, onSkippedDirectory };
}

/**
 * Directories (relative to the scan root, "/" separated) whose package.json is
 * pulled into the install by the ROOT manifest: `workspaces` members, and
 * `file:` / `link:` dependencies. npm links and installs those, so their
 * lifecycle scripts run like the root's, wherever the directory is named.
 * Workspace globs are returned as-is in `workspaceGlobs`.
 */
export function referencedManifestTargets(
  manifest: Record<string, unknown> | undefined,
  rootDir?: string,
): { directories: Set<string>; workspaceGlobs: string[] } {
  const directories = new Set<string>();
  const workspaceGlobs: string[] = [];
  if (!manifest) return { directories, workspaceGlobs };

  const workspaces = manifest.workspaces;
  const entries = Array.isArray(workspaces)
    ? workspaces
    : isJsonObject(workspaces) && Array.isArray(workspaces.packages)
      ? workspaces.packages
      : [];
  for (const entry of entries) {
    if (typeof entry === "string") workspaceGlobs.push(normalizeRelativeDir(entry));
  }

  if (rootDir) {
    // pnpm keeps its workspace list outside package.json.
    try {
      const yaml = fs.readFileSync(path.join(rootDir, "pnpm-workspace.yaml"), "utf-8");
      for (const line of yaml.split(/\r?\n/)) {
        const item = /^\s*-\s*["']?([^"'#\s]+)["']?\s*(?:#.*)?$/.exec(line);
        if (item) workspaceGlobs.push(normalizeRelativeDir(item[1]!));
      }
    } catch {
      // No pnpm workspace file.
    }
  }

  for (const key of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const) {
    const block = manifest[key];
    if (!isJsonObject(block)) continue;
    for (const spec of Object.values(block)) {
      if (typeof spec !== "string") continue;
      const local = /^(?:file|link):(.*)$/.exec(spec.trim());
      if (local) directories.add(normalizeRelativeDir(local[1]!));
    }
  }
  return { directories, workspaceGlobs };
}

function normalizeRelativeDir(value: string): string {
  return path.posix.normalize(toPosix(value).replace(/^\.\//, "")).replace(/\/+$/, "");
}
