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
 *
 * WHAT THIS FILE WILL NOT DO (v5.30): it will not emit a value the CycloneDX
 * 1.6 schema rejects, and it will not let an unread ecosystem look like an
 * empty one:
 *
 * - `hashes[].content` is the hex digest the schema's `hash-content` pattern
 *   requires, decoded from npm's base64 `integrity`; a digest whose decoded
 *   length does not match its algorithm is dropped and counted, never emitted;
 * - purls are canonical: the npm scope is the purl namespace and the `/` after
 *   it is a literal separator, not `%2F`;
 * - a component's name comes from the lockfile entry's `name` field or the
 *   segment after the LAST `node_modules/`, so a nested duplicate is findable
 *   under its own name and a workspace member under its declared one;
 * - without a lockfile, a dependency SPECIFIER is never printed as a resolved
 *   version: `version` and `purl` are omitted and the declared specifier is
 *   recorded in a property;
 * - `metadata.properties` carries `inventory-coverage` and, when any are
 *   present, `not-inventoried`, so "this ecosystem was not read" is a distinct
 *   statement from "this project has no components".
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { isJsonObject, parseJsonObject } from "./json-utils.js";
import type {
  Finding,
  SbomComponent,
  SbomDependency,
  SbomDocument,
  SbomLicenseEntry,
  SbomProperty,
  VexStatement,
} from "./types.js";

const TOOL_VERSION = "6.0.5";

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
 * Build a canonical Package URL (purl) for an npm package.
 *
 * The npm scope is the purl NAMESPACE, and the `/` between namespace and name
 * is a literal separator that purl does not percent encode. Encoding it as
 * `%2F` (what this function did before v5.30) produces a string that parses
 * without throwing but decomposes into namespace `undefined` and a name
 * containing a slash, so it never equals the canonical purl and never matches
 * advisory data keyed on the namespace/name pair.
 *
 * Encoding rules mirror the purl specification's reference implementation
 * (`packageurl-js`), which the test suite compares every emitted purl against:
 *
 * - namespace: `encodeURIComponent`, then `%3A` back to `:` and `%2F` back to `/`
 * - name: `encodeURIComponent`
 * - version: `encodeURIComponent`, then `%3A` back to `:` and `%2B` back to `+`
 * - the npm purl type lowercases namespace and name (the component's own `name`
 *   field keeps the declared casing; only the purl is normalised)
 */
function npmPurl(name: string, version: string): string {
  let namespace: string | undefined;
  let bare = name;
  if (name.startsWith("@")) {
    const slash = name.indexOf("/");
    if (slash > 0) {
      namespace = name.slice(0, slash);
      bare = name.slice(slash + 1);
    }
  }

  const encNamespace = namespace
    ? encodeURIComponent(namespace.toLowerCase()).replace(/%3A/g, ":").replace(/%2F/g, "/")
    : undefined;
  const encName = encodeURIComponent(bare.toLowerCase());
  const encVersion = encodeURIComponent(version).replace(/%3A/g, ":").replace(/%2B/g, "+");

  return encNamespace
    ? `pkg:npm/${encNamespace}/${encName}@${encVersion}`
    : `pkg:npm/${encName}@${encVersion}`;
}

/**
 * The version string a `package.json` dependency value states outright.
 *
 * Returns undefined for everything that is not one exact version, which is most
 * of what npm accepts: ranges (`^1.2.3`, `>=1.0.0 <2.0.0`, `1.x`, `*`),
 * dist-tags (`latest`), git/URL specifiers, `workspace:` and `file:` protocols.
 * Before v5.30 those were turned into a "version" by deleting one leading
 * non-digit character, which produced `atest` from `latest` and, worse,
 * presented `^1.2.3` as the resolved version 1.2.3.
 *
 * The pattern is deliberately strict semver: an exact `1.2.3`, `1.2.3-beta.2`
 * or `1.2.3+build.4` is a factual statement about one release, and anything
 * else is a constraint that only a lockfile can resolve.
 */
export function exactVersionOf(specifier: string): string | undefined {
  const text = specifier.trim();
  return /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(text) ? text : undefined;
}

/**
 * Resolve an `npm:` alias specifier to the package it actually names.
 *
 * `"alias-dep": "npm:real-package@4.5.6"` installs `real-package`, so the
 * component identifies `real-package`; the alias key is only how this project
 * refers to it. Returns undefined for anything that is not an alias.
 */
export function resolveNpmAlias(
  specifier: string,
): { name: string; specifier: string } | undefined {
  const text = specifier.trim();
  if (!text.startsWith("npm:")) return undefined;
  const rest = text.slice(4);
  if (rest === "") return undefined;
  // The separator is the last "@" that is not the scope marker at index 0.
  const at = rest.lastIndexOf("@");
  if (at <= 0) return { name: rest, specifier: "*" };
  return { name: rest.slice(0, at), specifier: rest.slice(at + 1) };
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

type SbomHash = NonNullable<SbomComponent["hashes"]>[number];

/**
 * How many hex characters a digest of each algorithm must have. CycloneDX 1.6
 * constrains `hashes[].content` with
 * `^([a-fA-F0-9]{32}|{40}|{64}|{96}|{128})$`, so a value of any other length
 * fails schema validation for the whole document.
 */
const DIGEST_HEX_LENGTH: Record<SbomHash["alg"], number> = {
  "SHA-1": 40,
  "SHA-256": 64,
  "SHA-384": 96,
  "SHA-512": 128,
};

/**
 * The Subresource Integrity prefixes npm writes, mapped to the CycloneDX
 * `hash-alg` enum value for each. A prefix that is not here is reported, never
 * guessed: emitting the payload under a neighbouring algorithm would assert a
 * digest the lockfile never made.
 */
const INTEGRITY_PREFIXES: Array<[string, SbomHash["alg"]]> = [
  ["sha512-", "SHA-512"],
  ["sha384-", "SHA-384"],
  ["sha256-", "SHA-256"],
  ["sha1-", "SHA-1"],
];

export interface ParsedIntegrity {
  hashes: SbomHash[];
  /**
   * Integrity parts that produced no hash: an algorithm prefix this generator
   * does not map (`sha384-`, a future one), or a payload that did not decode to
   * a digest of the length the algorithm requires. Counted so the document can
   * say the field was not assessed instead of silently carrying fewer hashes.
   */
  rejected: string[];
}

/**
 * Parse an npm `integrity` value (`sha512-<base64> sha1-<base64>`) into
 * CycloneDX 1.6 hashes.
 *
 * The npm value is base64. CycloneDX requires HEX: the `hash-content` pattern
 * in bom-1.6.schema.json admits only `[a-fA-F0-9]` runs of 32/40/64/96/128
 * characters. Passing the base64 through unchanged (what this did before
 * v5.30) makes every component with a hash fail schema validation, which is
 * every component npm resolved from a registry.
 *
 * A part whose payload does not base64-decode to exactly the digest length its
 * algorithm requires is REJECTED rather than emitted: a hash of the wrong
 * length is not a weaker claim, it is a false one, and it would take the whole
 * document out of conformance again.
 */
export function parseIntegrity(integrity: string): ParsedIntegrity {
  const hashes: SbomHash[] = [];
  const rejected: string[] = [];

  for (const part of integrity.split(/\s+/)) {
    if (part === "") continue;

    const dash = part.indexOf("-");
    const prefix = dash === -1 ? "" : part.slice(0, dash + 1);
    const known = INTEGRITY_PREFIXES.find(([p]) => p === prefix);
    if (!known) {
      rejected.push(prefix === "" ? part : prefix.slice(0, -1));
      continue;
    }

    const alg = known[1];
    const payload = part.slice(prefix.length);
    // Buffer.from(..., "base64") never throws; it stops at the first character
    // outside the alphabet, so the decoded LENGTH is the check that matters.
    const hex = Buffer.from(payload, "base64").toString("hex");
    if (hex.length !== DIGEST_HEX_LENGTH[alg]) {
      rejected.push(prefix.slice(0, -1));
      continue;
    }
    hashes.push({ alg, content: hex });
  }

  return { hashes, rejected };
}

/**
 * The package name a lockfile entry is really about.
 *
 * npm lockfile keys are filesystem paths, not package names. Stripping ONE
 * leading `node_modules/` (what this did before v5.30) leaves
 * `middle/node_modules/@acme/dep` for a nested duplicate - a name no consumer
 * can find the package under - and leaves a workspace member named after its
 * directory, `packages/app`, while the entry's own `name` field carries
 * `@acme/app`.
 *
 * Order matters: the entry's declared `name` wins, because it is the only
 * authoritative source and it is what workspace entries carry. Otherwise the
 * segment after the LAST `node_modules/` is the package, which is exactly how
 * npm nests duplicates. A key that is neither (a workspace member with no
 * declared name) falls back to its last path segment, and the caller records
 * that the name was derived from a path rather than declared.
 */
export function lockfileEntryName(
  pkgPath: string,
  declaredName: unknown,
): { name: string; derivedFromPath: boolean } {
  if (typeof declaredName === "string" && declaredName.trim() !== "") {
    return { name: declaredName.trim(), derivedFromPath: false };
  }
  const marker = "node_modules/";
  const last = pkgPath.lastIndexOf(marker);
  if (last !== -1) {
    return { name: pkgPath.slice(last + marker.length), derivedFromPath: false };
  }
  const slash = pkgPath.lastIndexOf("/");
  return {
    name: slash === -1 ? pkgPath : pkgPath.slice(slash + 1),
    derivedFromPath: slash !== -1,
  };
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
  /** How complete this inventory is, in one machine-readable token. */
  coverage: "full-transitive" | "direct-only";
  /** Components whose version the source could not resolve (package.json path). */
  componentsWithoutVersion: number;
  /** Integrity parts that produced no hash, keyed by what was rejected. */
  rejectedHashes: Map<string, number>;
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

  const parsedLockfile = parseJsonObject(raw);
  if (!parsedLockfile) return undefined;
  const lockfile = parsedLockfile as LockfileV2;

  const packages = lockfile.packages;
  if (!packages || lockfile.lockfileVersion === 1) {
    return undefined;
  }

  const components: SbomComponent[] = [];
  const emitted = new Set<string>();
  let componentsWithLicense = 0;
  const rejectedHashes = new Map<string, number>();

  for (const [pkgPath, pkg] of Object.entries(packages)) {
    // Skip the root package entry (empty string key)
    if (pkgPath === "" || !pkg.version) continue;

    // The lockfile key is a filesystem path. The package NAME comes from the
    // entry's own `name` field, or from the segment after the last
    // "node_modules/" - see lockfileEntryName().
    const { name, derivedFromPath } = lockfileEntryName(pkgPath, pkg.name);
    const properties: SbomProperty[] = [];
    if (derivedFromPath) {
      properties.push({
        name: "supply-chain-guard:component-name",
        value: `derived-from-lockfile-path: the entry "${pkgPath}" declares no name field, so the last path segment was used`,
      });
    }

    const component: SbomComponent = {
      type: "library",
      "bom-ref": pkgPath,
      name,
      version: pkg.version,
      purl: npmPurl(name, pkg.version),
      scope: pkg.dev ? "excluded" : pkg.optional ? "optional" : "required",
    };

    if (pkg.integrity) {
      const { hashes, rejected } = parseIntegrity(pkg.integrity);
      if (hashes.length > 0) component.hashes = hashes;
      for (const r of rejected) {
        rejectedHashes.set(r, (rejectedHashes.get(r) ?? 0) + 1);
        properties.push({
          name: "supply-chain-guard:integrity",
          value: `not-assessed: the lockfile integrity value carries a "${r}" digest this generator does not encode as a CycloneDX hash`,
        });
      }
    }

    const license = encodeLicense(pkg.license);
    if (license) {
      component.licenses = [license];
      componentsWithLicense++;
    } else {
      properties.push(LICENSE_NOT_ASSESSED);
    }

    if (properties.length > 0) component.properties = properties;

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
    coverage: "full-transitive",
    componentsWithoutVersion: 0,
    rejectedHashes,
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
 *
 * WHAT THIS PATH WILL NOT DO (v5.30): it will not present a SPECIFIER as a
 * resolved version. A package.json dependency value is a constraint, and only a
 * lockfile says which release satisfied it. `version` and `purl` are therefore
 * emitted only for a value that is one exact semver; every other value leaves
 * both fields absent and records the declared specifier in a property. That is
 * a visibly incomplete component, which is the point: `^1.2.3` rendered as
 * version 1.2.3 reads as a fact and is wrong in either direction against an
 * advisory range.
 */
function readPackageJsonInventory(packageJsonPath: string): Inventory | undefined {
  let raw: string;
  try {
    raw = fs.readFileSync(packageJsonPath, "utf-8");
  } catch {
    return undefined;
  }

  const parsedPackage = parseJsonObject(raw);
  if (!parsedPackage) return undefined;
  const pkg = parsedPackage as PackageJson;

  const components: SbomComponent[] = [];
  const seen = new Set<string>();
  let componentsWithoutVersion = 0;

  const addDeps = (
    deps: Record<string, string> | undefined,
    scope: SbomComponent["scope"],
  ) => {
    if (!deps) return;
    for (const [declaredKey, rawSpecifier] of Object.entries(deps)) {
      if (seen.has(declaredKey)) continue;
      seen.add(declaredKey);

      // "npm:real-package@4.5.6" installs real-package under the alias key.
      const alias = resolveNpmAlias(rawSpecifier);
      const name = alias ? alias.name : declaredKey;
      const specifier = alias ? alias.specifier : rawSpecifier;
      const version = exactVersionOf(specifier);

      const properties: SbomProperty[] = [LICENSE_NOT_ASSESSED];
      if (alias) {
        properties.push({
          name: "supply-chain-guard:alias",
          value: `declared in package.json as "${declaredKey}": "${rawSpecifier}"`,
        });
      }
      if (!version) {
        componentsWithoutVersion++;
        properties.push({
          name: "supply-chain-guard:version",
          value: `not-assessed: package.json declares "${rawSpecifier}", which is a specifier and not a resolved version; no package-lock.json was available to resolve it`,
        });
      }
      properties.push({
        name: "supply-chain-guard:declared-specifier",
        value: rawSpecifier,
      });

      components.push({
        type: "library",
        // Dependency KEYS are unique across the four maps because of `seen`, so
        // the key is a safe bom-ref even when an alias makes `name` differ.
        "bom-ref": declaredKey,
        name,
        ...(version ? { version, purl: npmPurl(name, version) } : {}),
        scope,
        properties,
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
    coverage: "direct-only",
    componentsWithoutVersion,
    rejectedHashes: new Map(),
  };
}

/**
 * Manifests and lockfiles that declare components this generator does NOT
 * read, mapped to the ecosystem a reader would name them by.
 *
 * The list exists so that "this ecosystem was not inventoried" can be stated as
 * a fact about a file that is present, rather than left to look like "this
 * project has no components". A Python service scanned before v5.30 got a
 * well-formed CycloneDX 1.6 document with `components: []` and exit 0, and
 * nothing in it distinguished the two.
 *
 * npm lockfiles other than package-lock.json are in this list too: a pnpm tree
 * falls back to package.json and yields the direct dependencies only, so the
 * lockfile that WOULD have given the full tree has to be named as unread.
 */
const NOT_INVENTORIED_MANIFESTS: Array<[file: string, ecosystem: string]> = [
  ["pnpm-lock.yaml", "npm (pnpm lockfile)"],
  ["yarn.lock", "npm (yarn lockfile)"],
  ["bun.lockb", "npm (bun lockfile)"],
  ["bun.lock", "npm (bun lockfile)"],
  ["requirements.txt", "PyPI"],
  ["Pipfile.lock", "PyPI"],
  ["poetry.lock", "PyPI"],
  ["pyproject.toml", "PyPI"],
  ["Cargo.toml", "Cargo"],
  ["Cargo.lock", "Cargo"],
  ["go.mod", "Go"],
  ["go.sum", "Go"],
  ["Gemfile.lock", "RubyGems"],
  ["composer.json", "Composer"],
  ["composer.lock", "Composer"],
  ["packages.config", "NuGet"],
  ["pom.xml", "Maven"],
  ["build.gradle", "Gradle"],
  ["build.gradle.kts", "Gradle"],
];

/**
 * Which dependency manifests exist in `projectDir` that the SBOM generator does
 * not read. Returns `"<file> (<ecosystem>)"` entries, deduplicated by file, in
 * the order of the table above so the string is stable across runs.
 */
/** Directories that never hold a manifest worth reporting, and that every
 *  real project has. Skipping them is what keeps the walk cheap. */
const MANIFEST_WALK_SKIP = new Set([
  "node_modules", ".git", ".hg", ".svn", "dist", "build", "out", "coverage",
  "vendor", "target", ".venv", "venv", "__pycache__", ".tox", ".next",
  ".cache", ".gradle", ".idea", ".vscode",
]);

/** Depth ceiling and report ceiling. The sentence this feeds is a signal to a
 *  human, not an inventory, so it stops well before exhaustiveness. */
const MANIFEST_WALK_MAX_DEPTH = 4;
const MANIFEST_WALK_MAX_REPORTED = 25;

export function detectUninventoriedManifests(projectDir: string): string[] {
  // Walks rather than checking only the root. In a monorepo - the layout most
  // likely to hold more than one ecosystem - pyproject.toml and Cargo.toml sit
  // under packages/* or services/*, never at the top, so a root-only check
  // reported nothing there and the document went on asserting an empty
  // inventory. That is issue 195 surviving in the case it matters most.
  const wanted = new Map(NOT_INVENTORIED_MANIFESTS);
  const found: string[] = [];
  const seen = new Set<string>();

  const walk = (dir: string, rel: string, depth: number): void => {
    if (depth > MANIFEST_WALK_MAX_DEPTH || found.length >= MANIFEST_WALK_MAX_REPORTED) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      // Unreadable directory: reported nowhere here on purpose. Coverage gaps
      // are the scanner's to report, and it already does; inventing a second
      // channel for them would put the same fact in two places.
      return;
    }
    for (const entry of entries) {
      if (found.length >= MANIFEST_WALK_MAX_REPORTED) return;
      const childRel = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (MANIFEST_WALK_SKIP.has(entry.name) || entry.name.startsWith(".")) continue;
        walk(path.join(dir, entry.name), childRel, depth + 1);
      } else if (wanted.has(entry.name) && !seen.has(childRel)) {
        seen.add(childRel);
        found.push(`${childRel} (${wanted.get(entry.name)})`);
      }
    }
  };

  try {
    walk(projectDir, "", 0);
  } catch {
    return found;
  }
  // Deterministic order: shallowest first, then alphabetical, so the sentence
  // does not change between runs on the same tree.
  return found.sort((a, b) => {
    const da = a.split("/").length;
    const db = b.split("/").length;
    return da === db ? a.localeCompare(b) : da - db;
  });
}

/**
 * One sentence describing how complete a generated document's inventory is,
 * derived from the document itself rather than from a second copy of the
 * decision. The CLI prints it next to the component count, because a bare count
 * cannot distinguish an empty inventory from an unread one.
 */
export function describeInventoryCoverage(doc: SbomDocument): string {
  const prop = (suffix: string): string | undefined =>
    doc.metadata.properties?.find((p) => p.name === `${PROP}:${suffix}`)?.value;

  const coverage = prop("inventory-coverage") ?? "unknown";
  const notInventoried = prop("not-inventoried");
  const unresolved = prop("components-without-resolved-version");

  const parts: string[] = [];
  if (coverage.startsWith("full-transitive")) {
    parts.push("full transitive inventory from package-lock.json");
  } else if (coverage.startsWith("direct-only")) {
    parts.push("DIRECT DEPENDENCIES ONLY, read from package.json; transitive components not inventoried");
    if (unresolved && unresolved !== "0") {
      parts.push(`${unresolved} of them carry no resolved version (package.json declares a range or a tag)`);
    }
  } else {
    parts.push("NOTHING WAS INVENTORIED: no npm manifest this generator reads was found");
  }
  if (notInventoried) parts.push(`not inventoried: ${notInventoried}`);
  return parts.join("; ");
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
      const parsed: unknown = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
      if (!isJsonObject(parsed)) throw new TypeError("package.json is not an object");
      const pkgJson = parsed as PackageJson;
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

  // How complete this inventory is, as one token a consumer can branch on. The
  // "none" value is the one that matters: without it an empty `components`
  // array is indistinguishable from a product that ships no third-party code.
  properties.push({
    name: `${PROP}:inventory-coverage`,
    value:
      inventory?.coverage === "full-transitive"
        ? "full-transitive: every entry of package-lock.json (v2+)"
        : inventory?.coverage === "direct-only"
          ? "direct-only: the dependencies package.json declares; transitive components were NOT inventoried"
          : "none: no npm manifest this generator reads (package-lock.json v2+ or package.json) was found, so NOTHING was inventoried - an empty component list here is not a statement that this project has no components",
  });

  // Manifests that are present and declare components this generator does not
  // read. Stated as a fact about files on disk, so a Python, Cargo or Go
  // project is never handed an empty inventory with no explanation.
  const uninventoried = detectUninventoriedManifests(projectDir);
  if (uninventoried.length > 0) {
    properties.push({
      name: `${PROP}:not-inventoried`,
      value: uninventoried.join(", "),
    });
  }

  if (inventory && inventory.componentsWithoutVersion > 0) {
    properties.push({
      name: `${PROP}:components-without-resolved-version`,
      value: String(inventory.componentsWithoutVersion),
    });
  }
  if (inventory && inventory.rejectedHashes.size > 0) {
    properties.push({
      name: `${PROP}:integrity-digests-not-encoded`,
      value: [...inventory.rejectedHashes.entries()]
        .map(([alg, n]) => `${alg}:${n}`)
        .join(", "),
    });
  }
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
