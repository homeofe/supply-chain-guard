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

const TOOL_VERSION = "5.28.1";

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
 * Property recorded on a component for which no canonical purl could be built.
 *
 * The name is namespaced as CycloneDX asks custom properties to be. Its value is
 * a stable machine-readable reason code followed by a human sentence, so a
 * consumer can branch on the code and a reader can understand the document
 * without one.
 */
const PURL_UNAVAILABLE_PROPERTY = "supply-chain-guard:sbom:purl-unavailable";

/**
 * Reason code used when a component's name is not an npm package name and no
 * npm purl therefore exists for it.
 */
const PURL_UNAVAILABLE_NOT_A_PACKAGE_NAME =
  "not-an-npm-package-name: the component name is not a valid npm package name, " +
  "so no npm Package URL can be derived from it; identify this component by its " +
  "name and version instead";

/**
 * Characters that a purl component must NOT percent-encode.
 *
 * Source: the purl specification, "Character encoding" section
 * (https://github.com/package-url/purl-spec,
 * `docs/specification/standard/specification.md`). The characters that shall not
 * be percent-encoded are the Alphanumeric Characters (A-Z, a-z, 0-9), the
 * Punctuation Characters (`.`, `-`, `_`, `~`), the Separator Characters when
 * they are being used as purl separators, and the colon `:` whether used as a
 * separator or otherwise. Everything else in a namespace segment, a name or a
 * version is percent-encoded.
 *
 * Two consequences that this generator depends on, recorded because they are not
 * obvious from the regex:
 *
 * - `:` is deliberately in this set. The specification exempts it
 *   unconditionally, so a version such as `workspace:^` encodes to
 *   `workspace:%5E`, not `workspace%3A%5E`.
 * - `/` and `@` are NOT in this set. They are Separator Characters, and the
 *   exemption applies only while they ARE the separator. Inside a segment they
 *   are data and are encoded, which is why an npm scope encodes to `%40scope`.
 *   The separators this generator writes (the `/` between namespace and name,
 *   the `@` before the version) are emitted as literals by npmPurl() and never
 *   passed through encodePurlSegment(). That split is the whole fix: encoding
 *   the joined string instead turned the namespace separator into `%2F`.
 */
const PURL_UNENCODED_CHARACTER = /[A-Za-z0-9.\-_~:]/;

/**
 * Percent-encode a single purl segment (one namespace segment, a name, or a
 * version).
 *
 * `encodeURIComponent` is deliberately NOT used: it leaves `!`, `'`, `(`, `)`
 * and `*` unencoded, and none of those five is in the specification's
 * unencoded set, so it would under-encode a name or version containing one.
 * Bytes are emitted with uppercase hex digits, which RFC 3986 section 2.1 states
 * as the preferred form and which the reference purl implementations produce.
 *
 * Iteration is `for...of`, which walks code points rather than UTF-16 code
 * units, so a character outside the Basic Multilingual Plane is encoded as one
 * character's worth of UTF-8 bytes instead of two broken surrogate halves.
 */
function encodePurlSegment(value: string): string {
  let encoded = "";
  for (const character of value) {
    if (PURL_UNENCODED_CHARACTER.test(character)) {
      encoded += character;
      continue;
    }
    for (const byte of Buffer.from(character, "utf-8")) {
      encoded += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }
  return encoded;
}

/**
 * Split an npm package name into the purl namespace (the npm scope) and the
 * purl name, or return undefined when the string is not an npm package name.
 *
 * The purl specification's npm type definition
 * (https://github.com/package-url/purl-spec, `types/npm-definition.json`) states
 * that the namespace is the scope of a scoped npm package, that the scope's `@`
 * prefix is always percent-encoded, and that both namespace and name are
 * CASE SENSITIVE. The case-sensitivity point is the one assumption here worth
 * writing down, because the most-used JavaScript reference implementation
 * disagrees with it: packageurl-js 2.0.1 lowercases both, turning the real
 * legacy package `Base64` into `pkg:npm/base64`. This generator follows the type
 * definition and preserves case, because lowercasing renames a package that npm
 * still serves under its mixed-case name, and a renamed component in a
 * compliance artefact is a false statement about what is installed. npm has
 * refused new uppercase names since 2015, so the two behaviours differ only for
 * grandfathered packages.
 *
 * Returning undefined is a real path, not a defensive branch.
 * readLockfileComponents() derives the name from a lockfile KEY, and npm
 * lockfile keys are filesystem paths: a nested duplicate arrives as
 * `middle/node_modules/@acme/dep` and a workspace member as `packages/app`
 * (tracked in https://github.com/homeofe/supply-chain-guard/issues/192). An npm
 * purl carries at most one namespace segment, so neither can be expressed as
 * one. Emitting `pkg:npm/packages/app@1.0.0` anyway would assert that a scope
 * named `packages` publishes a package named `app`, which is not true of any
 * package on the registry, so the caller omits the purl and records why instead.
 */
function splitNpmPackageName(
  packageName: string,
): { namespace?: string; name: string } | undefined {
  if (packageName === "") return undefined;

  if (packageName.startsWith("@")) {
    const separator = packageName.indexOf("/");
    // Needs at least one character of scope between "@" and "/".
    if (separator < 2) return undefined;
    const namespace = packageName.slice(0, separator);
    const name = packageName.slice(separator + 1);
    if (name === "" || name.includes("/") || name.includes("@")) return undefined;
    if (namespace.slice(1).includes("@")) return undefined;
    return { namespace, name };
  }

  if (packageName.includes("/") || packageName.includes("@")) return undefined;
  return { name: packageName };
}

/**
 * Build a canonical Package URL (purl) for an npm package, or return undefined
 * when the name cannot be expressed as one.
 *
 * Built per the purl specification's build procedure
 * (https://github.com/package-url/purl-spec,
 * `docs/specification/standard/how-to-build.md`): the namespace is split on `/`
 * into segments and EACH SEGMENT is percent-encoded individually, the separator
 * itself being preserved; the name is percent-encoded; the version is
 * percent-encoded. An npm namespace is a single segment, the scope.
 *
 * The version is omitted entirely when it is empty, because the specification
 * makes the version optional and `pkg:npm/foo@` is not a valid purl.
 */
function npmPurl(name: string, version: string): string | undefined {
  const parts = splitNpmPackageName(name);
  if (!parts) return undefined;

  const namespace = parts.namespace ? `${encodePurlSegment(parts.namespace)}/` : "";
  const versionSuffix = version === "" ? "" : `@${encodePurlSegment(version)}`;
  return `pkg:npm/${namespace}${encodePurlSegment(parts.name)}${versionSuffix}`;
}

/**
 * Either the canonical purl for a component, or the property that records why
 * there is none. Exactly one of the two is present on every component, so a
 * consumer never has to read an absent purl as either an answer or an oversight.
 */
function purlOrReason(
  name: string,
  version: string,
): { purl: string } | { properties: Array<{ name: string; value: string }> } {
  const purl = npmPurl(name, version);
  if (purl !== undefined) return { purl };
  return {
    properties: [
      { name: PURL_UNAVAILABLE_PROPERTY, value: PURL_UNAVAILABLE_NOT_A_PACKAGE_NAME },
    ],
  };
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
      ...purlOrReason(name, pkg.version),
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
        ...purlOrReason(name, version),
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
