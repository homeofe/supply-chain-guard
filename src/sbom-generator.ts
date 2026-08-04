/**
 * SBOM Generator — CycloneDX 1.6
 *
 * Generates a proper Software Bill of Materials from a project's
 * package.json + package-lock.json (npm v2+), including VEX statements
 * for suppressed findings. Falls back to an empty component list if no
 * manifest is found.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import type { Finding, SbomComponent, SbomDocument, VexStatement } from "./types.js";

const TOOL_VERSION = "5.25.2";

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface LockfileV2Package {
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  peer?: boolean;
  dependencies?: Record<string, string>;
}

interface LockfileV2 {
  lockfileVersion?: number;
  packages?: Record<string, LockfileV2Package>;
}

/**
 * Build a Package URL (purl) for an npm package.
 */
function npmPurl(name: string, version: string): string {
  // Scoped packages: @scope/name → pkg:npm/%40scope%2Fname@version
  const encodedName = name.startsWith("@")
    ? name.replace("@", "%40").replace("/", "%2F")
    : name;
  return `pkg:npm/${encodedName}@${version}`;
}

/**
 * Parse integrity hash (sha512-<base64> or sha1-<base64>) into CycloneDX format.
 */
function parseIntegrity(
  integrity: string,
): Array<{ alg: "SHA-256" | "SHA-512" | "SHA-1"; content: string }> {
  const results: Array<{ alg: "SHA-256" | "SHA-512" | "SHA-1"; content: string }> = [];
  for (const part of integrity.split(" ")) {
    if (part.startsWith("sha512-")) {
      results.push({ alg: "SHA-512", content: part.slice(7) });
    } else if (part.startsWith("sha256-")) {
      results.push({ alg: "SHA-256", content: part.slice(7) });
    } else if (part.startsWith("sha1-")) {
      results.push({ alg: "SHA-1", content: part.slice(5) });
    }
  }
  return results;
}

/**
 * Read components from package-lock.json v2+ (packages field).
 */
function readLockfileComponents(lockfilePath: string): SbomComponent[] {
  let raw: string;
  try {
    raw = fs.readFileSync(lockfilePath, "utf-8");
  } catch {
    return [];
  }

  let lockfile: LockfileV2;
  try {
    lockfile = JSON.parse(raw) as LockfileV2;
  } catch {
    return [];
  }

  if (!lockfile.packages || lockfile.lockfileVersion === 1) {
    return [];
  }

  const components: SbomComponent[] = [];

  for (const [pkgPath, pkg] of Object.entries(lockfile.packages)) {
    // Skip the root package entry (empty string key)
    if (pkgPath === "" || !pkg.version) continue;

    // Extract name from path like "node_modules/foo" or "node_modules/@scope/bar"
    const name = pkgPath.replace(/^node_modules\//, "");

    const component: SbomComponent = {
      type: "library",
      name,
      version: pkg.version,
      purl: npmPurl(name, pkg.version),
      scope: pkg.dev ? "excluded" : pkg.optional ? "optional" : "required",
    };

    if (pkg.integrity) {
      const hashes = parseIntegrity(pkg.integrity);
      if (hashes.length > 0) component.hashes = hashes;
    }

    components.push(component);
  }

  return components;
}

/**
 * Read direct dependencies from package.json when no lockfile is available.
 * Returns minimal components without hashes.
 */
function readPackageJsonComponents(packageJsonPath: string): SbomComponent[] {
  let raw: string;
  try {
    raw = fs.readFileSync(packageJsonPath, "utf-8");
  } catch {
    return [];
  }

  let pkg: PackageJson;
  try {
    pkg = JSON.parse(raw) as PackageJson;
  } catch {
    return [];
  }

  const components: SbomComponent[] = [];
  const seen = new Set<string>();

  const addDeps = (
    deps: Record<string, string> | undefined,
    scope: SbomComponent["scope"],
  ) => {
    if (!deps) return;
    for (const [name, versionRange] of Object.entries(deps)) {
      if (seen.has(name)) continue;
      seen.add(name);
      // Strip semver range operators to get a clean version string
      const version = versionRange.replace(/^[^0-9]/, "") || versionRange;
      components.push({
        type: "library",
        name,
        version,
        purl: npmPurl(name, version),
        scope,
      });
    }
  };

  addDeps(pkg.dependencies, "required");
  addDeps(pkg.devDependencies, "excluded");
  addDeps(pkg.peerDependencies, "optional");
  addDeps(pkg.optionalDependencies, "optional");

  return components;
}

/**
 * Build VEX statements from suppressed findings.
 */
function buildVexStatements(findings: Finding[]): VexStatement[] {
  return findings
    .filter((f) => f.suppressed)
    .map((f) => ({
      id: `scg-${f.rule}`,
      source: { name: "supply-chain-guard" },
      analysis: {
        state: "not_affected" as const,
        justification: "protected_by_compiler",
        detail: f.recommendation,
      },
      affects: f.file ? [{ ref: f.file }] : undefined,
    }));
}

/**
 * Generate a CycloneDX 1.6 SBOM document for the given project directory.
 *
 * Strategy:
 * 1. Try package-lock.json v2+ for full transitive component inventory
 * 2. Fall back to package.json direct deps if no lockfile
 * 3. Attach VEX statements for any suppressed findings
 */
export function generateSbomDocument(
  projectDir: string,
  findings: Finding[],
): SbomDocument {
  // Determine project name from package.json
  let projectName = path.basename(projectDir);
  let projectVersion = "0.0.0";
  const packageJsonPath = path.join(projectDir, "package.json");
  if (fs.existsSync(packageJsonPath)) {
    try {
      const pkgJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8")) as PackageJson;
      if (pkgJson.name) projectName = pkgJson.name;
      if (pkgJson.version) projectVersion = pkgJson.version;
    } catch {
      // ignore
    }
  }

  // Collect components
  let components: SbomComponent[] = [];
  const lockfilePath = path.join(projectDir, "package-lock.json");
  if (fs.existsSync(lockfilePath)) {
    components = readLockfileComponents(lockfilePath);
  }
  if (components.length === 0 && fs.existsSync(packageJsonPath)) {
    components = readPackageJsonComponents(packageJsonPath);
  }

  // Build VEX
  const vulnerabilities = buildVexStatements(findings);

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [
          { type: "application", name: "supply-chain-guard", version: TOOL_VERSION },
        ],
      },
      component: {
        type: "application",
        name: `${projectName}@${projectVersion}`,
        "bom-ref": "target",
      },
    },
    components,
    vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : undefined,
  };
}
