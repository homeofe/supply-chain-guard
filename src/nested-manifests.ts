/**
 * Package manifests and lockfiles BELOW the scan root.
 *
 * The Ruby, Composer, NuGet, Cargo and Go scanners read only the scan root
 * (scanRubyGemsFiles(dir) and friends). A monorepo service, a .NET project in
 * src/App/, or any project that is not at the top of the repository was
 * therefore never matched: measured 2026-09-23, one directory down all five
 * ecosystems detected nothing, in every format.
 *
 * The root stays with those scanners; this dispatcher takes every NESTED file,
 * so each file has exactly one dispatch point. `vendor/` and `target/` are
 * skipped, as for nested Python lockfiles: they hold copies of already-installed
 * dependencies (Composer and Go vendoring, Cargo build output), whose own
 * manifests would re-report what the project lockfile already lists.
 */

import type { Finding } from "./types.js";
import type { FeedIOC } from "./threat-intel.js";
import { scanGemfileContent, scanGemfileLockContent } from "./rubygems-scanner.js";
import { scanComposerJsonContent, scanComposerLockContent } from "./composer-scanner.js";
import {
  scanCsprojContent,
  scanNuGetConfigContent,
  scanPackagesConfigContent,
  scanPackagesLockContent,
} from "./nuget-scanner.js";
import { scanCargoContent, scanCargoLockContent, scanCargoTomlDependencies } from "./cargo-scanner.js";
import { scanGoContent, scanGoModDependencies, scanGoSumContent } from "./go-scanner.js";

type Scanner = (content: string, relativePath: string, feed: FeedIOC[]) => Finding[];

/** Exact file names (case as the ecosystem writes them; NuGet is case-insensitive). */
const BY_NAME: Record<string, Scanner> = {
  "Gemfile": (c, p, f) => scanGemfileContent(c, p, f),
  "Gemfile.lock": (c, p, f) => scanGemfileLockContent(c, p, f),
  "composer.json": (c, p, f) => scanComposerJsonContent(c, p, f),
  "composer.lock": (c, p, f) => scanComposerLockContent(c, p, f),
  "packages.lock.json": (c, p, f) => scanPackagesLockContent(c, p, f),
  "packages.config": (c, p, f) => scanPackagesConfigContent(c, p, f),
  "nuget.config": (c, p) => scanNuGetConfigContent(c, p),
  "Cargo.toml": (c, p, f) => [...scanCargoContent(c, p, "toml"), ...scanCargoTomlDependencies(c, p, f)],
  "Cargo.lock": (c, p, f) => scanCargoLockContent(c, p, f),
  "go.mod": (c, p, f) => [...scanGoContent(c, p, "mod"), ...scanGoModDependencies(c, p, f)],
  "go.sum": (c, p, f) => scanGoSumContent(c, p, f),
};

const NUGET_NAMES = new Set(["packages.lock.json", "packages.config", "nuget.config"]);

function scannerFor(basename: string): Scanner | undefined {
  const lower = basename.toLowerCase();
  if (NUGET_NAMES.has(lower)) return BY_NAME[lower];
  if (lower.endsWith(".csproj")) return (c, p, f) => scanCsprojContent(c, p, f);
  return BY_NAME[basename];
}

/**
 * True for a Ruby, Composer, NuGet, Cargo or Go manifest below the scan root,
 * outside vendor/ and target/.
 */
export function isNestedManifest(relativePath: string): boolean {
  const parts = relativePath.replace(/\\/g, "/").split("/");
  if (parts.length < 2) return false;
  if (parts.some((segment) => segment === "vendor" || segment === "target")) return false;
  return scannerFor(parts[parts.length - 1] ?? "") !== undefined;
}

/**
 * Scan one nested manifest with the same function its ecosystem scanner uses
 * at the root, so root and nested findings are identical in shape.
 */
export function scanNestedManifest(content: string, relativePath: string, feed: FeedIOC[]): Finding[] {
  const posix = relativePath.replace(/\\/g, "/");
  const scanner = scannerFor(posix.split("/").pop() ?? "");
  return scanner ? scanner(content, posix, feed) : [];
}
