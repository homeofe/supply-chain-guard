/**
 * SBOM Generator - CycloneDX 1.6
 *
 * Generates a Software Bill of Materials from a project's
 * package.json + package-lock.json (npm v2+), including VEX statements
 * for suppressed findings. Falls back to the direct dependencies declared in
 * package.json if no lockfile is found, and to an empty component list if
 * there is no manifest at all.
 *
 * WHAT THIS FILE WILL NOT DO (v5.29): it will not present an absent field as
 * an assessed one. Everything the generator could not answer is stated in the
 * document instead of being left to look like a negative result:
 *
 * - a component whose manifest declares no licence carries a
 *   `supply-chain-guard:license` property saying so, rather than no `licenses`
 *   key and no explanation;
 * - `metadata.properties` records which manifest the inventory came from, how
 *   many components carry a declared licence, whether the dependency graph was
 *   resolved, partial or not assessed, and how many declared edges could not be
 *   resolved to a component;
 * - the subject's `version` and `purl` are omitted, with a property saying why,
 *   when no package.json declared a version.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import type {
  Finding,
  SbomComponent,
  SbomDependency,
  SbomDocument,
  SbomLicenseEntry,
  SbomProperty,
  VexStatement,
} from "./types.js";

const TOOL_VERSION = "5.28.1";

/** bom-ref of the component the document is about. */
const SUBJECT_BOM_REF = "target";

/** Property namespace, matching the `supply-chain-guard:scan-status` property reporter.ts adds. */
const PROP = "supply-chain-guard:sbom";

interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface LockfileV2Package {
  name?: string;
  version?: string;
  resolved?: string;
  integrity?: string;
  license?: unknown;
  link?: boolean;
  dev?: boolean;
  optional?: boolean;
  peer?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface LockfileV2 {
  lockfileVersion?: number;
  packages?: Record<string, LockfileV2Package>;
}

/**
 * SPDX identifiers this generator is willing to emit as `licenses[].license.id`.
 *
 * ASSUMPTION, and the reason this is a list rather than a "looks like an id"
 * test: the CycloneDX 1.6 JSON schema constrains `license.id` to the SPDX
 * identifier enum, so an unrecognised value there makes the entire document
 * fail schema validation. The list is deliberately a conservative subset of the
 * SPDX list, covering the identifiers that occur in package manifests. A string
 * that is not in it is emitted as `license.name`, which is free text and always
 * schema-valid: that under-states precision, but it never asserts an identifier
 * the schema rejects, and it never drops the licence.
 *
 * Only add a current, non-deprecated SPDX identifier here. Deprecated forms
 * (for example the bare "GPL-3.0") are intentionally absent: they are not
 * guaranteed to be in the schema's enum, so they take the `license.name` path.
 */
const SPDX_LICENSE_IDS = new Set([
  "0BSD", "AFL-2.1", "AFL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
  "Apache-1.1", "Apache-2.0", "Artistic-1.0", "Artistic-2.0", "Beerware",
  "BlueOak-1.0.0", "BSD-2-Clause", "BSD-2-Clause-Patent", "BSD-3-Clause",
  "BSD-3-Clause-Clear", "BSD-4-Clause", "BSL-1.0", "CC-BY-2.0", "CC-BY-3.0",
  "CC-BY-4.0", "CC-BY-SA-4.0", "CC0-1.0", "CDDL-1.0", "CDDL-1.1", "CPAL-1.0",
  "EPL-1.0", "EPL-2.0", "EUPL-1.1", "EUPL-1.2", "GPL-2.0-only",
  "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "ISC", "JSON",
  "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later",
  "LGPL-3.0-only", "LGPL-3.0-or-later", "MIT", "MIT-0", "MPL-1.1", "MPL-2.0",
  "MS-PL", "NCSA", "ODC-By-1.0", "OFL-1.1", "OSL-3.0", "PostgreSQL",
  "Python-2.0", "Ruby", "Sendmail", "Unlicense", "UPL-1.0", "Vim", "W3C",
  "WTFPL", "X11", "Zlib", "ZPL-2.1",
]);

/** Property attached to a component whose manifest declares no licence. */
const LICENSE_NOT_ASSESSED: SbomProperty = {
  name: "supply-chain-guard:license",
  value: "not-assessed: the source manifest declares no license for this component",
};

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
 * Encode one manifest `license` value as a CycloneDX 1.6 licence entry.
 *
 * Returns undefined when the value carries no licence information, so the
 * caller marks the component "not assessed" instead of inventing a licence.
 */
export function encodeLicense(value: unknown): SbomLicenseEntry | undefined {
  if (typeof value !== "string") return undefined;
  const text = value.trim();
  if (text === "") return undefined;
  // SPDX expression: compound licences, and the trailing "+" (or-later)
  // operator. The schema leaves `expression` an unconstrained string, so this
  // branch is safe even for expressions built from identifiers this file does
  // not know about.
  if (/[()]/.test(text) || /(^|\s)(AND|OR|WITH)(\s|$)/.test(text) || text.endsWith("+")) {
    return { expression: text };
  }
  if (SPDX_LICENSE_IDS.has(text)) return { license: { id: text } };
  // Not an SPDX identifier we can vouch for ("UNLICENSED", "SEE LICENSE IN
  // COPYING", a project-specific name). Keep the text, do not claim it is SPDX.
  return { license: { name: text } };
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
 * Resolve a dependency name declared by the lockfile entry at `fromPath` to the
 * lockfile key of the entry that satisfies it.
 *
 * ASSUMPTION: npm resolves a dependency by looking in the dependent's own
 * node_modules first and then walking up towards the project root, so the
 * deepest matching key wins. Mirroring that here is what makes an edge point at
 * the version actually installed for that dependent rather than at whichever
 * copy happens to be hoisted to the top.
 *
 * Returns undefined when nothing satisfies the name. That is a normal outcome,
 * not a parse failure: peer dependencies the project never installed and
 * optional dependencies npm skipped are declared in the lockfile with no entry
 * of their own. Callers count those rather than emitting a reference to a
 * component that is not in the document.
 */
function resolveDependencyKey(
  packages: Record<string, LockfileV2Package>,
  fromPath: string,
  depName: string,
): string | undefined {
  let base = fromPath;
  for (;;) {
    const candidate = base === "" ? `node_modules/${depName}` : `${base}/node_modules/${depName}`;
    if (Object.hasOwn(packages, candidate)) {
      const entry = packages[candidate];
      // Workspace stubs: node_modules/<name> carries link: true and points at
      // the real entry (for example "packages/<name>"), which is the one that
      // became a component.
      if (entry.link && typeof entry.resolved === "string" && Object.hasOwn(packages, entry.resolved)) {
        return entry.resolved;
      }
      return candidate;
    }
    if (base === "") return undefined;
    const cut = base.lastIndexOf("/node_modules/");
    base = cut === -1 ? "" : base.slice(0, cut);
  }
}

interface Inventory {
  components: SbomComponent[];
  /** Undefined means the graph was not assessed at all. */
  dependencies?: SbomDependency[];
  /** Declared edges that resolve to no component in the document. */
  unresolvedEdges?: number;
  componentsWithLicense: number;
  graphStatus: string;
}

/**
 * Read components and the dependency graph from package-lock.json v2+.
 *
 * ASSUMPTION: a lockfile key ("node_modules/express",
 * "node_modules/a/node_modules/b", "packages/app") is unique by construction,
 * because it is a JSON object key, and it is stable across runs of npm for the
 * same tree. That is what makes it usable directly as the component's bom-ref,
 * and it keeps the bom-ref independent of how the purl is encoded.
 */
function readLockfileInventory(lockfilePath: string): Inventory | undefined {
  let raw: string;
  try {
    raw = fs.readFileSync(lockfilePath, "utf-8");
  } catch {
    return undefined;
  }

  let lockfile: LockfileV2;
  try {
    lockfile = JSON.parse(raw) as LockfileV2;
  } catch {
    return undefined;
  }

  const packages = lockfile.packages;
  if (!packages || lockfile.lockfileVersion === 1) {
    return undefined;
  }

  const components: SbomComponent[] = [];
  const emitted = new Set<string>();
  let componentsWithLicense = 0;

  for (const [pkgPath, pkg] of Object.entries(packages)) {
    // Skip the root package entry (empty string key)
    if (pkgPath === "" || !pkg.version) continue;

    // Extract name from path like "node_modules/foo" or "node_modules/@scope/bar"
    const name = pkgPath.replace(/^node_modules\//, "");

    const component: SbomComponent = {
      type: "library",
      "bom-ref": pkgPath,
      name,
      version: pkg.version,
      purl: npmPurl(name, pkg.version),
      scope: pkg.dev ? "excluded" : pkg.optional ? "optional" : "required",
    };

    if (pkg.integrity) {
      const hashes = parseIntegrity(pkg.integrity);
      if (hashes.length > 0) component.hashes = hashes;
    }

    const license = encodeLicense(pkg.license);
    if (license) {
      component.licenses = [license];
      componentsWithLicense++;
    } else {
      component.properties = [LICENSE_NOT_ASSESSED];
    }

    components.push(component);
    emitted.add(pkgPath);
  }

  // Dependency graph. Only edges whose target is a component in this document
  // are emitted; the rest are counted, because a dependsOn pointing at a
  // bom-ref that does not exist is a claim the document cannot support.
  let unresolvedEdges = 0;
  const edgesFor = (key: string, entry: LockfileV2Package): string[] => {
    const fields: Array<keyof LockfileV2Package> =
      key === ""
        ? // The subject's devDependencies are edges too: dev packages are in
          // the inventory (with scope "excluded"), so leaving their edges out
          // would orphan 118 of the 119 components of a typical tool project.
          ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
        : ["dependencies", "peerDependencies", "optionalDependencies"];
    const targets: string[] = [];
    for (const field of fields) {
      const map = entry[field] as Record<string, string> | undefined;
      if (!map) continue;
      for (const depName of Object.keys(map)) {
        const resolved = resolveDependencyKey(packages, key, depName);
        if (resolved === undefined || !emitted.has(resolved)) {
          unresolvedEdges++;
          continue;
        }
        targets.push(resolved);
      }
    }
    return [...new Set(targets)];
  };

  const dependencies: SbomDependency[] = [];
  const root = Object.hasOwn(packages, "") ? packages[""] : undefined;
  dependencies.push({
    ref: SUBJECT_BOM_REF,
    dependsOn: root ? edgesFor("", root) : [],
  });
  for (const key of emitted) {
    dependencies.push({ ref: key, dependsOn: edgesFor(key, packages[key]) });
  }

  return {
    components,
    dependencies,
    unresolvedEdges,
    componentsWithLicense,
    graphStatus: "resolved-from-package-lock.json",
  };
}

/**
 * Read direct dependencies from package.json when no lockfile is available.
 * Returns minimal components without hashes.
 *
 * ASSUMPTION: package.json declares neither licences for its dependencies nor
 * their transitive edges, so both are recorded as not assessed rather than
 * omitted silently. The subject's own direct edges ARE known here, so the
 * graph is emitted as partial: one entry for the subject, and no entry for any
 * dependency, which states that nothing was concluded about their edges.
 */
function readPackageJsonInventory(packageJsonPath: string): Inventory | undefined {
  let raw: string;
  try {
    raw = fs.readFileSync(packageJsonPath, "utf-8");
  } catch {
    return undefined;
  }

  let pkg: PackageJson;
  try {
    pkg = JSON.parse(raw) as PackageJson;
  } catch {
    return undefined;
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
        // Dependency names are unique across the four maps because of `seen`,
        // so the name is a safe bom-ref on this path.
        "bom-ref": name,
        name,
        version,
        purl: npmPurl(name, version),
        scope,
        properties: [LICENSE_NOT_ASSESSED],
      });
    }
  };

  addDeps(pkg.dependencies, "required");
  addDeps(pkg.devDependencies, "excluded");
  addDeps(pkg.peerDependencies, "optional");
  addDeps(pkg.optionalDependencies, "optional");

  return {
    components,
    dependencies: [
      { ref: SUBJECT_BOM_REF, dependsOn: components.map((c) => c["bom-ref"]) },
    ],
    componentsWithLicense: 0,
    graphStatus:
      "partial: direct dependencies of the subject only; without package-lock.json the transitive edges were not assessed",
  };
}

/**
 * Build VEX statements from findings the project's policy suppressed.
 *
 * The suppressed findings are passed in separately because applyPolicy() drops
 * them from the findings it returns, so filtering the report's findings for
 * `suppressed` finds nothing on the scanner path. Direct API callers that hand
 * this function findings already marked `suppressed` still work.
 *
 * No `analysis.justification` is emitted. CycloneDX constrains that field to a
 * fixed enum ("protected_by_compiler" and friends) which a free-text policy
 * reason cannot be mapped to, so the project's own words are carried verbatim
 * in `analysis.detail` and nothing is asserted that the policy did not say. A
 * suppression with no recorded reason says exactly that.
 */
function buildVexStatements(suppressed: Finding[]): VexStatement[] {
  const seen = new Set<string>();
  const statements: VexStatement[] = [];
  for (const f of suppressed) {
    const key = `${f.rule}|${f.file ?? ""}|${f.line ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const reason = f.suppressionReason?.trim();
    const where = f.file ? ` Finding location: ${f.file}${f.line ? `:${f.line}` : ""}.` : "";
    statements.push({
      id: `scg-${f.rule}`,
      source: { name: "supply-chain-guard" },
      analysis: {
        state: "not_affected",
        detail: reason
          ? `Suppressed by project policy. Declared reason: ${reason}.${where}`
          : `Suppressed by project policy; no reason was recorded for this suppression.${where}`,
      },
      // The subject is the only component a finding about the project's own
      // files can be attributed to. Referencing the file path here instead
      // would produce a bom-ref that resolves to nothing in this document.
      affects: [{ ref: SUBJECT_BOM_REF }],
    });
  }
  return statements;
}

/**
 * Generate a CycloneDX 1.6 SBOM document for the given project directory.
 *
 * Strategy:
 * 1. Try package-lock.json v2+ for full transitive component inventory
 * 2. Fall back to package.json direct deps if no lockfile
 * 3. Attach VEX statements for any suppressed findings
 *
 * @param suppressedFindings findings applyPolicy() removed from the report, so
 *   the VEX statements can describe them. Optional: a caller with no policy
 *   pipeline passes nothing and gets no VEX statements, which is accurate.
 */
export function generateSbomDocument(
  projectDir: string,
  findings: Finding[],
  suppressedFindings: Finding[] = [],
): SbomDocument {
  // Determine project name and version from package.json. The version is left
  // undefined when nothing declares it: this is the one component that
  // identifies the product, and a stand-in version here is a false statement
  // about what was shipped.
  let projectName = path.basename(projectDir);
  let projectVersion: string | undefined;
  let manifestParsed = false;
  const packageJsonPath = path.join(projectDir, "package.json");
  if (fs.existsSync(packageJsonPath)) {
    try {
      const pkgJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8")) as PackageJson;
      manifestParsed = true;
      if (pkgJson.name) projectName = pkgJson.name;
      if (typeof pkgJson.version === "string" && pkgJson.version.trim() !== "") {
        projectVersion = pkgJson.version.trim();
      }
    } catch {
      // ignore
    }
  }

  // Collect components. The lockfile wins when it yields any component, which
  // is the selection this generator has always made; the extra branches below
  // only decide which source a genuinely dependency-free project is credited
  // to, so that "this project declares no dependencies" is not reported as
  // "nothing was read".
  const lockfilePath = path.join(projectDir, "package-lock.json");
  const lockInventory = fs.existsSync(lockfilePath)
    ? readLockfileInventory(lockfilePath)
    : undefined;
  const manifestInventory = fs.existsSync(packageJsonPath)
    ? readPackageJsonInventory(packageJsonPath)
    : undefined;

  let inventory: Inventory | undefined;
  let componentSource = "none";
  if (lockInventory && lockInventory.components.length > 0) {
    inventory = lockInventory;
    componentSource = "package-lock.json";
  } else if (manifestInventory && manifestInventory.components.length > 0) {
    inventory = manifestInventory;
    componentSource = "package.json";
  } else if (lockInventory) {
    inventory = lockInventory;
    componentSource = "package-lock.json";
  } else if (manifestInventory) {
    inventory = manifestInventory;
    componentSource = "package.json";
  }

  const components = inventory?.components ?? [];
  const properties: SbomProperty[] = [
    { name: `${PROP}:component-source`, value: componentSource },
    {
      name: `${PROP}:components-with-declared-license`,
      value: `${inventory?.componentsWithLicense ?? 0}/${components.length}`,
    },
    {
      name: `${PROP}:dependency-graph`,
      value:
        inventory?.graphStatus ??
        "not-assessed: no readable npm manifest (package-lock.json v2+ or package.json) in the scanned directory",
    },
  ];
  if (inventory?.unresolvedEdges !== undefined) {
    properties.push({
      name: `${PROP}:dependency-edges-unresolved`,
      value: String(inventory.unresolvedEdges),
    });
  }
  if (!projectVersion) {
    properties.push({
      name: `${PROP}:subject-version`,
      value: manifestParsed
        ? "not-assessed: package.json declares no version"
        : "not-assessed: no readable package.json in the scanned directory",
    });
  }

  const subject: SbomDocument["metadata"]["component"] = {
    type: "application",
    name: projectName,
    "bom-ref": SUBJECT_BOM_REF,
  };
  if (projectVersion) {
    subject.version = projectVersion;
    subject.purl = npmPurl(projectName, projectVersion);
  }

  // Build VEX. Findings already marked suppressed by a direct API caller are
  // honoured alongside the ones the policy engine removed from the report.
  const vulnerabilities = buildVexStatements([
    ...findings.filter((f) => f.suppressed),
    ...suppressedFindings,
  ]);

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
      component: subject,
      properties,
    },
    components,
    dependencies: inventory?.dependencies,
    vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : undefined,
  };
}
