/**
 * SBOM correctness cluster (issues 191, 192, 193, 195, 197, 198, 200).
 *
 * Seven defects with one shape: the emitted document was WELL FORMED AND WRONG.
 * It parsed, it carried `bomFormat: CycloneDX` and `specVersion: 1.6`, the
 * process exited 0, and every consumer-facing value in it was either
 * unmatchable, truncated, unresolvable, or absent without saying so.
 *
 * The point of this file is the FIRST describe block. Six of the seven defects
 * were invisible to a suite that asserts individual literal fields, and one of
 * them (base64 hashes) failed on every single component of every document this
 * tool has ever produced while a test named "should return a valid CycloneDX
 * 1.6 document" stayed green - it asserted four literals and never opened a
 * schema. Validating against the REAL schema closes the class, not seven
 * instances of it.
 *
 * The schemas are the unmodified official ones, vendored under
 * fixtures/cyclonedx/ with their upstream URLs and checksums; see the README
 * there. purls are compared against `packageurl-js`, the purl specification's
 * own reference implementation, rather than against strings this file believes
 * to be canonical.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import Ajv, { type ValidateFunction } from "ajv";
import addFormats from "ajv-formats";
import { PackageURL } from "packageurl-js";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { generateSbomDocument, describeInventoryCoverage } from "../sbom-generator.js";
import { formatReport } from "../reporter.js";
import { correlateFindings } from "../correlation-engine.js";
import type { Finding, ScanReport, SbomDocument } from "../types.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "../..");
const CLI = path.join(ROOT, "dist", "cli.js");
const SCHEMA_DIR = path.join(__dirname, "fixtures", "cyclonedx");

/**
 * A real sha512 Subresource Integrity value, its hex digest, and a sha1 pair.
 * Generated with node:crypto over the literal "supply-chain-guard fixture".
 * Stand-in values like "sha512-abc123==" decode to a few bytes and would be
 * rejected, which is correct behaviour but exercises nothing.
 */
const SHA512_INTEGRITY =
  "sha512-jcAFFknyfkZaZb2DHeScupgoE6x139/wsyvAhtMQbbmuRSXkWqVch+IgHRLNSv5AfwUMYKSu+V5fNgUtzBrkDA==";
const SHA512_HEX =
  "8dc0051649f27e465a65bd831de49cba982813ac75dfdff0b32bc086d3106db9ae4525e45aa55c87e2201d12cd4afe407f050c60a4aef95e5f36052dcc1ae40c";
const SHA1_INTEGRITY = "sha1-sq6HuizMJLlE84GrlXD0oPE6LC8=";
const SHA1_HEX = "b2ae87ba2ccc24b944f381ab9570f4a0f13a2c2f";

// ---------------------------------------------------------------------------
// Schema harness
// ---------------------------------------------------------------------------

let validateBom: ValidateFunction;

beforeAll(() => {
  const load = (file: string) =>
    JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, file), "utf-8")) as object;

  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  // The CycloneDX schemas use a handful of formats ajv-formats does not define.
  // Registering them as always-true keeps them from being silently dropped as
  // "unknown format", which would be a check that cannot fire.
  for (const format of ["string", "iri-reference", "idn-email"]) {
    if (!ajv.formats[format]) ajv.addFormat(format, () => true);
  }
  ajv.addSchema(load("spdx.schema.json"), "http://cyclonedx.org/schema/spdx.schema.json");
  ajv.addSchema(load("jsf-0.82.schema.json"), "http://cyclonedx.org/schema/jsf-0.82.schema.json");
  validateBom = ajv.compile(load("bom-1.6.schema.json"));
});

/** Schema errors as `instancePath keyword message`, one line each. */
function schemaErrors(doc: unknown): string[] {
  const ok = validateBom(doc);
  if (ok) return [];
  return (validateBom.errors ?? []).map(
    (e) => `${e.instancePath} ${e.keyword} ${e.message}`,
  );
}

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-sbom-cluster-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeLock(lockfile: unknown): void {
  fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
}

function writeManifest(manifest: unknown): void {
  fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify(manifest));
}

function propertyValue(doc: SbomDocument, name: string): string | undefined {
  return doc.metadata.properties?.find((p) => p.name === name)?.value;
}

/** A finding with only the fields the renderers read. */
function finding(over: Partial<Finding> & Pick<Finding, "rule">): Finding {
  return {
    severity: "critical",
    description: `description of ${over.rule}`,
    recommendation: "recommendation",
    ...over,
  } as Finding;
}

/** A minimal ScanReport carrying a real generated sbomDocument. */
function reportFor(doc: SbomDocument, findings: Finding[], incidents?: ScanReport["incidents"]): ScanReport {
  return {
    target: tmpDir,
    timestamp: new Date().toISOString(),
    scanType: "directory",
    filesScanned: 1,
    findings,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length },
    score: 0,
    riskLevel: "low",
    recommendations: [],
    sbomDocument: doc,
    incidents,
  } as unknown as ScanReport;
}

// ---------------------------------------------------------------------------
// The class: conformance against the official CycloneDX 1.6 schema
// ---------------------------------------------------------------------------

describe("CycloneDX 1.6 schema conformance (issue 191, and the whole class)", () => {
  it("the validator itself rejects a document it must reject (control)", () => {
    writeLock({
      lockfileVersion: 3,
      packages: { "": {}, "node_modules/a": { version: "1.0.0", integrity: SHA512_INTEGRITY } },
    });
    const doc = generateSbomDocument(tmpDir, []) as unknown as Record<string, unknown>;
    expect(schemaErrors(doc)).toEqual([]);

    // If any of these mutations passed, the harness would be certifying
    // nothing, and every "valid: true" below would be meaningless.
    const broken = JSON.parse(JSON.stringify(doc));
    delete broken.bomFormat;
    expect(schemaErrors(broken).length).toBeGreaterThan(0);

    const badType = JSON.parse(JSON.stringify(doc));
    badType.components[0].type = "not-a-real-type";
    expect(schemaErrors(badType).some((e) => e.includes("/components/0/type"))).toBe(true);

    const base64Hash = JSON.parse(JSON.stringify(doc));
    base64Hash.components[0].hashes[0].content = SHA512_INTEGRITY.slice("sha512-".length);
    expect(
      schemaErrors(base64Hash).some((e) => e.includes("/components/0/hashes/0/content")),
    ).toBe(true);
  });

  it("emits hash content as hex, not the lockfile's base64 (issue 191)", () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/sha512-pkg": { version: "1.0.0", integrity: SHA512_INTEGRITY },
        "node_modules/sha1-pkg": { version: "2.0.0", integrity: SHA1_INTEGRITY },
      },
    });
    const doc = generateSbomDocument(tmpDir, []);

    const sha512 = doc.components.find((c) => c.name === "sha512-pkg");
    expect(sha512?.hashes).toEqual([{ alg: "SHA-512", content: SHA512_HEX }]);
    const sha1 = doc.components.find((c) => c.name === "sha1-pkg");
    expect(sha1?.hashes).toEqual([{ alg: "SHA-1", content: SHA1_HEX }]);

    for (const component of doc.components) {
      for (const hash of component.hashes ?? []) {
        expect(hash.content).toMatch(/^[0-9a-f]+$/);
      }
    }
    expect(schemaErrors(doc)).toEqual([]);
  });

  it("refuses an integrity value it cannot encode, and says so (issue 191)", () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        "": {},
        // A prefix this generator does not map, and a sha512 payload that is
        // not 64 bytes. Neither may be passed through: a hash of the wrong
        // length is a false claim, not a weaker one.
        "node_modules/future-alg": { version: "1.0.0", integrity: "sha3512-QUJD" },
        "node_modules/truncated": { version: "1.0.0", integrity: "sha512-QUJD" },
      },
    });
    const doc = generateSbomDocument(tmpDir, []);

    for (const name of ["future-alg", "truncated"]) {
      const component = doc.components.find((c) => c.name === name);
      expect(component?.hashes).toBeUndefined();
      expect(
        component?.properties?.some(
          (p) => p.name === "supply-chain-guard:integrity" && p.value.startsWith("not-assessed:"),
        ),
      ).toBe(true);
    }
    expect(propertyValue(doc, "supply-chain-guard:sbom:integrity-digests-not-encoded")).toBeDefined();
    expect(schemaErrors(doc)).toEqual([]);
  });

  it("validates every document shape this generator can produce", () => {
    const shapes: Array<[label: string, build: () => SbomDocument]> = [
      [
        "lockfile with scopes, nesting, a workspace and a dev dependency",
        () => {
          writeLock({
            lockfileVersion: 3,
            packages: {
              "": { name: "root", version: "1.0.0", dependencies: { middle: "^1.0.0" } },
              "node_modules/@acme/dep": { version: "2.0.0", license: "BSD-3-Clause", integrity: SHA512_INTEGRITY },
              "node_modules/middle": { version: "1.0.0", license: "ISC", dependencies: { "@acme/dep": "^1.0.0" } },
              "node_modules/middle/node_modules/@acme/dep": { version: "1.0.0", license: "MIT" },
              "node_modules/@acme/app": { link: true, resolved: "packages/app" },
              "packages/app": { name: "@acme/app", version: "1.0.0", license: "Apache-2.0" },
              "node_modules/tsc": { version: "5.0.0", dev: true, license: "UNLICENSED" },
            },
          });
          return generateSbomDocument(tmpDir, []);
        },
      ],
      [
        "package.json fallback across every specifier form",
        () => {
          writeManifest(RANGE_MANIFEST);
          return generateSbomDocument(tmpDir, []);
        },
      ],
      [
        "no npm manifest at all",
        () => {
          fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "requests==2.31.0\n");
          return generateSbomDocument(tmpDir, []);
        },
      ],
      [
        "suppressed findings, emitted as VEX",
        () => {
          writeManifest({ name: "app", version: "1.0.0" });
          return generateSbomDocument(tmpDir, [], [
            finding({ rule: "EVAL_ATOB", file: "src/a.js", line: 3, suppressionReason: "test fixture" }),
          ]);
        },
      ],
    ];

    for (const [label, build] of shapes) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      fs.mkdirSync(tmpDir, { recursive: true });
      const errors = schemaErrors(build());
      expect(errors, `${label} produced schema errors`).toEqual([]);
    }
  });

  it("validates the rendered document, findings and incidents included", () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/@acme/dep": { version: "1.0.0", license: "MIT", integrity: SHA512_INTEGRITY },
      },
    });
    const doc = generateSbomDocument(tmpDir, []);
    const findings = [
      finding({ rule: "DEAD_DROP_STEAM", file: "src/config.js", line: 1 }),
      finding({ rule: "VIDAR_BROWSER_THEFT", file: "src/config.js", line: 3 }),
      finding({ rule: "IN_A_PACKAGE", file: "node_modules/@acme/dep/index.js", line: 9 }),
    ];
    const { incidents } = correlateFindings(findings);
    const rendered = JSON.parse(formatReport(reportFor(doc, findings, incidents), "sbom"));

    expect(schemaErrors(rendered)).toEqual([]);
    expect(rendered.vulnerabilities.length).toBe(3);
  });

  it("validates the SBOM this repository generates for itself", () => {
    // The 119-component case the issue was measured on. Reads the repository's
    // own package-lock.json, so it exercises real scoped names, real integrity
    // values and a real dependency graph rather than a fixture.
    const doc = generateSbomDocument(ROOT, []);
    expect(doc.components.length).toBeGreaterThan(50);
    expect(schemaErrors(doc)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// purls (issue 193)
// ---------------------------------------------------------------------------

describe("canonical purls (issue 193)", () => {
  it("encodes the scope separator as a literal slash, not %2F", () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/@babel/parser": { version: "7.29.7" },
        "node_modules/typescript": { version: "7.0.2" },
      },
    });
    const doc = generateSbomDocument(tmpDir, []);

    expect(doc.components.find((c) => c.name === "@babel/parser")?.purl).toBe(
      "pkg:npm/%40babel/parser@7.29.7",
    );
    expect(doc.components.find((c) => c.name === "typescript")?.purl).toBe(
      "pkg:npm/typescript@7.0.2",
    );
    for (const component of doc.components) {
      expect(component.purl).not.toContain("%2F");
    }
  });

  it("every emitted purl equals the reference implementation's canonical form", () => {
    // Acceptance criterion of issue 193, measured the way the issue measured
    // it: against packageurl-js, not against a string this file asserts is
    // canonical. Run over this repository's real inventory.
    const doc = generateSbomDocument(ROOT, []);
    const mismatches: string[] = [];
    let scoped = 0;

    for (const component of doc.components) {
      if (!component.purl || !component.version) continue;
      let namespace: string | undefined;
      let name = component.name;
      if (name.startsWith("@")) {
        scoped++;
        const slash = name.indexOf("/");
        namespace = name.slice(0, slash);
        name = name.slice(slash + 1);
      }
      const canonical = new PackageURL("npm", namespace, name, component.version).toString();
      if (canonical !== component.purl) {
        mismatches.push(`${component.name}: emitted ${component.purl}, canonical ${canonical}`);
      }
    }

    // Positive control: the inventory really does contain scoped packages, so
    // an empty mismatch list is not an empty comparison.
    expect(scoped).toBeGreaterThan(10);
    expect(mismatches).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Lockfile identity (issue 192)
// ---------------------------------------------------------------------------

describe("nested and workspace lockfile entries (issue 192)", () => {
  it("names a nested duplicate after the package, not its path", () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        "": { name: "nested-app", version: "1.0.0", dependencies: { middle: "^1.0.0", "@acme/dep": "^2.0.0" } },
        "node_modules/@acme/dep": { version: "2.0.0", license: "BSD-3-Clause" },
        "node_modules/middle": { version: "1.0.0", license: "ISC", dependencies: { "@acme/dep": "^1.0.0" } },
        "node_modules/middle/node_modules/@acme/dep": { version: "1.0.0", license: "MIT" },
      },
    });
    const doc = generateSbomDocument(tmpDir, []);

    const bothVersions = doc.components
      .filter((c) => c.name === "@acme/dep")
      .map((c) => c.version)
      .sort();
    // The whole point of an inventory: the older nested copy is findable under
    // its own name, distinguished by version rather than by path.
    expect(bothVersions).toEqual(["1.0.0", "2.0.0"]);
    expect(doc.components.find((c) => c.version === "1.0.0" && c.name === "@acme/dep")?.purl).toBe(
      "pkg:npm/%40acme/dep@1.0.0",
    );
    // bom-refs stay path-shaped, which is what keeps them unique and what the
    // dependency graph resolves against.
    expect(doc.dependencies?.find((d) => d.ref === "node_modules/middle")?.dependsOn).toEqual([
      "node_modules/middle/node_modules/@acme/dep",
    ]);
  });

  it("names a workspace member from its declared name, not its directory", () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        "": { name: "mono-root", version: "1.0.0" },
        "node_modules/@acme/app": { link: true, resolved: "packages/app" },
        "node_modules/@acme/lib": { link: true, resolved: "packages/lib" },
        "packages/app": { name: "@acme/app", version: "1.0.0", license: "Apache-2.0", dependencies: { "@acme/lib": "2.3.4" } },
        "packages/lib": { name: "@acme/lib", version: "2.3.4", license: "MIT" },
      },
    });
    const doc = generateSbomDocument(tmpDir, []);

    expect(doc.components.map((c) => c.name).sort()).toEqual(["@acme/app", "@acme/lib"]);
    expect(doc.components.find((c) => c.name === "@acme/app")?.purl).toBe(
      "pkg:npm/%40acme/app@1.0.0",
    );
  });

  it("no component name emitted from a lockfile contains a path", () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/a/node_modules/b/node_modules/c": { version: "1.0.0" },
        // A workspace entry with no declared name: the last path segment is
        // used and the component says the name was derived, not declared.
        "packages/unnamed": { version: "1.0.0" },
      },
    });
    const doc = generateSbomDocument(tmpDir, []);

    expect(doc.components.map((c) => c.name).sort()).toEqual(["c", "unnamed"]);
    for (const component of doc.components) {
      expect(component.name).not.toContain("node_modules");
      expect(component.name.replace(/^@[^/]+\//, "")).not.toContain("/");
    }
    const unnamed = doc.components.find((c) => c.name === "unnamed");
    expect(
      unnamed?.properties?.some(
        (p) => p.name === "supply-chain-guard:component-name" && p.value.startsWith("derived-from-lockfile-path:"),
      ),
    ).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Specifiers without a lockfile (issue 197)
// ---------------------------------------------------------------------------

const RANGE_MANIFEST = {
  name: "range-app",
  version: "1.0.0",
  dependencies: {
    "caret-dep": "^1.2.3",
    "tilde-dep": "~2.0.0",
    "gte-dep": ">=3.1.0",
    "range-dep": ">=1.0.0 <2.0.0",
    "star-dep": "*",
    "latest-dep": "latest",
    "url-dep": "github:owner/repo#v1.2.3",
    "ws-dep": "workspace:^",
    "alias-dep": "npm:real-package@4.5.6",
    "x-dep": "1.x",
    "pre-dep": "^1.0.0-beta.2",
    "exact-dep": "3.4.5",
    "exact-pre-dep": "1.0.0-beta.2",
  },
};

describe("dependency specifiers without a lockfile (issue 197)", () => {
  it("never presents a specifier as a resolved version", () => {
    writeManifest(RANGE_MANIFEST);
    const doc = generateSbomDocument(tmpDir, []);

    const byRef = new Map(doc.components.map((c) => [c["bom-ref"], c]));
    // Only two of the thirteen declare one exact version, and only those two
    // carry a version and a purl.
    const withVersion = doc.components.filter((c) => c.version !== undefined).map((c) => c["bom-ref"]).sort();
    expect(withVersion).toEqual(["alias-dep", "exact-dep", "exact-pre-dep"]);

    expect(byRef.get("exact-dep")?.purl).toBe("pkg:npm/exact-dep@3.4.5");
    expect(byRef.get("exact-pre-dep")?.purl).toBe("pkg:npm/exact-pre-dep@1.0.0-beta.2");

    // The specific strings the issue measured. `^1.2.3` used to become the
    // FACT "1.2.3"; `latest` used to become "atest".
    for (const ref of ["caret-dep", "tilde-dep", "latest-dep", "ws-dep", "url-dep", "star-dep", "x-dep", "gte-dep", "range-dep", "pre-dep"]) {
      const component = byRef.get(ref);
      expect(component?.version, `${ref} must carry no version`).toBeUndefined();
      expect(component?.purl, `${ref} must carry no purl`).toBeUndefined();
      expect(
        component?.properties?.some(
          (p) => p.name === "supply-chain-guard:version" && p.value.startsWith("not-assessed:"),
        ),
        `${ref} must say why it has no version`,
      ).toBe(true);
    }
  });

  it("records the declared specifier verbatim, so nothing is lost", () => {
    writeManifest(RANGE_MANIFEST);
    const doc = generateSbomDocument(tmpDir, []);
    for (const [key, specifier] of Object.entries(RANGE_MANIFEST.dependencies)) {
      const component = doc.components.find((c) => c["bom-ref"] === key);
      expect(
        component?.properties?.find((p) => p.name === "supply-chain-guard:declared-specifier")?.value,
      ).toBe(specifier);
    }
  });

  it("identifies an npm: alias by the package it installs", () => {
    writeManifest(RANGE_MANIFEST);
    const doc = generateSbomDocument(tmpDir, []);
    const alias = doc.components.find((c) => c["bom-ref"] === "alias-dep");

    expect(alias?.name).toBe("real-package");
    expect(alias?.version).toBe("4.5.6");
    expect(alias?.purl).toBe("pkg:npm/real-package@4.5.6");
    expect(
      alias?.properties?.some((p) => p.name === "supply-chain-guard:alias"),
    ).toBe(true);
  });

  it("emits no purl containing a space, and counts the unresolved ones", () => {
    writeManifest(RANGE_MANIFEST);
    const doc = generateSbomDocument(tmpDir, []);

    for (const component of doc.components) {
      expect(component.purl ?? "").not.toContain(" ");
    }
    expect(propertyValue(doc, "supply-chain-guard:sbom:components-without-resolved-version")).toBe(
      "10",
    );
    expect(schemaErrors(doc)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Unread ecosystems (issue 195)
// ---------------------------------------------------------------------------

describe("an unread ecosystem is not an empty one (issue 195)", () => {
  it("names the manifests it did not inventory, and says nothing was read", () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "requests==2.31.0\n");
    fs.writeFileSync(path.join(tmpDir, "Cargo.toml"), '[package]\nname = "demo"\n');
    fs.writeFileSync(path.join(tmpDir, "go.mod"), "module example.com/demo\n");
    const doc = generateSbomDocument(tmpDir, []);

    expect(doc.components).toHaveLength(0);
    const coverage = propertyValue(doc, "supply-chain-guard:sbom:inventory-coverage");
    expect(coverage).toMatch(/^none:/);
    // The distinction the whole issue is about, in one assertion.
    expect(coverage).toContain("not a statement that this project has no components");

    const notInventoried = propertyValue(doc, "supply-chain-guard:sbom:not-inventoried");
    expect(notInventoried).toContain("requirements.txt (PyPI)");
    expect(notInventoried).toContain("Cargo.toml (Cargo)");
    expect(notInventoried).toContain("go.mod (Go)");
    expect(schemaErrors(doc)).toEqual([]);
  });

  it("marks a pnpm project as a direct-dependency inventory and names the unread lockfile", () => {
    writeManifest({ name: "pnpm-app", version: "1.0.0", dependencies: { commander: "^14.0.3" } });
    fs.writeFileSync(path.join(tmpDir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    const doc = generateSbomDocument(tmpDir, []);

    expect(propertyValue(doc, "supply-chain-guard:sbom:inventory-coverage")).toMatch(/^direct-only:/);
    expect(propertyValue(doc, "supply-chain-guard:sbom:not-inventoried")).toContain(
      "pnpm-lock.yaml (npm (pnpm lockfile))",
    );
  });

  it("says full-transitive only when a package-lock.json was actually read", () => {
    writeLock({
      lockfileVersion: 3,
      packages: { "": {}, "node_modules/a": { version: "1.0.0" } },
    });
    const doc = generateSbomDocument(tmpDir, []);
    expect(propertyValue(doc, "supply-chain-guard:sbom:inventory-coverage")).toMatch(
      /^full-transitive:/,
    );
    expect(propertyValue(doc, "supply-chain-guard:sbom:not-inventoried")).toBeUndefined();
  });

  it("the CLI message distinguishes an empty inventory from an unread one", () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "requests==2.31.0\n");
    const out = path.join(tmpDir, "sbom.json");
    const result = spawnSync(
      process.execPath,
      [CLI, "scan", tmpDir, "--sbom-output", out, "--format", "json", "--no-history"],
      { encoding: "utf-8" },
    );
    // stderr carries the SBOM line; a bare "0 components" reads as a clean
    // result and is what this assertion exists to prevent.
    expect(result.stderr).toContain("NOTHING WAS INVENTORIED");
    expect(result.stderr).toContain("requirements.txt (PyPI)");
  });

  it("describeInventoryCoverage names all three coverage states", () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "requests==2.31.0\n");
    expect(describeInventoryCoverage(generateSbomDocument(tmpDir, []))).toContain(
      "NOTHING WAS INVENTORIED",
    );

    writeManifest({ name: "app", version: "1.0.0", dependencies: { commander: "^14.0.3" } });
    expect(describeInventoryCoverage(generateSbomDocument(tmpDir, []))).toContain(
      "DIRECT DEPENDENCIES ONLY",
    );

    writeLock({
      lockfileVersion: 3,
      packages: { "": {}, "node_modules/a": { version: "1.0.0" } },
    });
    expect(describeInventoryCoverage(generateSbomDocument(tmpDir, []))).toContain(
      "full transitive inventory",
    );
  });

  it("the default text report prints the coverage sentence, not only a component count", () => {
    fs.writeFileSync(path.join(tmpDir, "requirements.txt"), "requests==2.31.0\n");
    const output = formatReport(reportFor(generateSbomDocument(tmpDir, []), []), "text");
    expect(output).toContain("0 components");
    expect(output).toContain("NOTHING WAS INVENTORIED");
  });
});

// ---------------------------------------------------------------------------
// One artefact from two commands (issue 198)
// ---------------------------------------------------------------------------

describe("the two documented SBOM commands (issue 198)", () => {
  it("--format sbom and --sbom-output emit the same document", () => {
    fs.cpSync(path.join(__dirname, "fixtures", "malicious-npm-pkg"), tmpDir, { recursive: true });
    const out = path.join(os.tmpdir(), `scg-sbom-cmp-${process.pid}.json`);

    const stdout = spawnSync(
      process.execPath,
      [CLI, "scan", tmpDir, "--format", "sbom", "--no-history"],
      { encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 },
    ).stdout;
    spawnSync(
      process.execPath,
      [CLI, "scan", tmpDir, "--sbom-output", out, "--format", "json", "--no-history"],
      { encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 },
    );
    const fromFile = fs.readFileSync(out, "utf-8");
    fs.rmSync(out, { force: true });

    const a = JSON.parse(stdout);
    const b = JSON.parse(fromFile);

    // serialNumber and the document timestamp are per-run by construction (a
    // fresh uuid and a fresh clock reading on each invocation), so they are
    // normalised away; everything a consumer reads as CONTENT must be
    // identical, and the vulnerabilities key is the one that used to be absent
    // from the file entirely.
    const normalise = (doc: Record<string, unknown>) => {
      const copy = JSON.parse(JSON.stringify(doc));
      for (const annotation of copy.annotations ?? []) delete annotation.timestamp;
      return copy;
    };
    expect((b.vulnerabilities ?? []).length).toBe((a.vulnerabilities ?? []).length);
    expect((a.vulnerabilities ?? []).length).toBeGreaterThan(0);
    for (const key of ["bomFormat", "specVersion", "version", "components", "dependencies", "vulnerabilities"]) {
      expect(b[key], `${key} differs between the two commands`).toEqual(a[key]);
    }
    expect(normalise(b).annotations, "annotations differ between the two commands").toEqual(
      normalise(a).annotations,
    );
    expect(schemaErrors(a)).toEqual([]);
  });

  it("no affects reference points at a bom-ref that is not in the document", () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/@acme/dep": { version: "1.0.0", license: "MIT" },
        "node_modules/middle": { version: "1.0.0", license: "MIT" },
        "node_modules/middle/node_modules/@acme/dep": { version: "0.9.0", license: "MIT" },
      },
    });
    const doc = generateSbomDocument(tmpDir, []);
    const findings = [
      finding({ rule: "IN_TOP_LEVEL", file: "node_modules/@acme/dep/index.js", line: 1 }),
      finding({ rule: "IN_NESTED", file: "node_modules/middle/node_modules/@acme/dep/index.js", line: 2 }),
      finding({ rule: "IN_PROJECT", file: "src/app.js", line: 3 }),
      finding({ rule: "NO_FILE" }),
    ];
    const rendered = JSON.parse(formatReport(reportFor(doc, findings), "sbom"));

    const refs = new Set<string>([
      rendered.metadata.component["bom-ref"],
      ...rendered.components.map((c: { "bom-ref": string }) => c["bom-ref"]),
    ]);
    const dangling: string[] = [];
    for (const vulnerability of rendered.vulnerabilities) {
      for (const affected of vulnerability.affects) {
        if (!refs.has(affected.ref)) dangling.push(`${vulnerability.id} -> ${affected.ref}`);
      }
    }
    expect(dangling).toEqual([]);

    const byId = new Map<string, { affects: Array<{ ref: string }>; properties?: Array<{ name: string; value: string }> }>(
      rendered.vulnerabilities.map((v: { id: string }) => [v.id, v]),
    );
    // Attribution, not just resolvability: the deepest matching component wins.
    expect(byId.get("IN_TOP_LEVEL")?.affects[0]?.ref).toBe("node_modules/@acme/dep");
    expect(byId.get("IN_NESTED")?.affects[0]?.ref).toBe(
      "node_modules/middle/node_modules/@acme/dep",
    );
    // A file that belongs to no component goes to the subject, and the path is
    // kept in a property rather than thrown away.
    expect(byId.get("IN_PROJECT")?.affects[0]?.ref).toBe("target");
    expect(
      byId.get("IN_PROJECT")?.properties?.find((p) => p.name === "supply-chain-guard:file")?.value,
    ).toBe("src/app.js");
    expect(byId.get("NO_FILE")?.affects[0]?.ref).toBe("target");
    expect(schemaErrors(rendered)).toEqual([]);
  });

  it("does not attribute a finding to a package.json key that happens to prefix the file path", () => {
    // package.json fallback uses the declared key as the bom-ref. Prefix
    // matching against those keys would pin a finding in src/app.js on a
    // dependency named "src". The !refsArePaths guard is the only thing that
    // stops that; deleting it turns this red while the lockfile attribution
    // tests above stay green.
    writeManifest({
      name: "app",
      version: "1.0.0",
      dependencies: { src: "1.0.0", lib: "1.0.0" },
    });
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.components.map((c) => c["bom-ref"])).toEqual(expect.arrayContaining(["src", "lib"]));
    const rendered = JSON.parse(
      formatReport(reportFor(doc, [finding({ rule: "IN_SRC", file: "src/app.js" })]), "sbom"),
    );
    const vuln = rendered.vulnerabilities.find((v: { id: string }) => v.id === "IN_SRC");
    expect(vuln?.affects[0]?.ref).toBe("target");
  });

  it("keeps source.name on every entry so these are not mistaken for advisories", () => {
    writeManifest({ name: "app", version: "1.0.0" });
    const doc = generateSbomDocument(tmpDir, []);
    const rendered = JSON.parse(
      formatReport(reportFor(doc, [finding({ rule: "SOME_RULE", file: "a.js" })]), "sbom"),
    );
    for (const vulnerability of rendered.vulnerabilities) {
      expect(vulnerability.source.name).toBe("supply-chain-guard");
    }
  });
});

// ---------------------------------------------------------------------------
// Incident survival (issue 200)
// ---------------------------------------------------------------------------

describe("NIS2 incident evidence survives export (issue 200)", () => {
  /** The fixture from the issue: two correlation rules fire on three findings. */
  function correlatedFindings(): { findings: Finding[]; incidents: ScanReport["incidents"] } {
    const findings = [
      finding({ rule: "DEAD_DROP_STEAM", file: "src/config.js", line: 1 }),
      finding({ rule: "DEAD_DROP_TELEGRAM", file: "src/config.js", line: 2 }),
      finding({ rule: "VIDAR_BROWSER_THEFT", file: "src/config.js", line: 3 }),
    ];
    const { incidents } = correlateFindings(findings);
    return { findings, incidents };
  }

  it("the fixture really correlates into more than one incident (control)", () => {
    const { incidents, findings } = correlatedFindings();
    expect((incidents ?? []).length).toBeGreaterThanOrEqual(2);
    const multi = findings.find((f) => (f.correlationIds ?? []).length > 1);
    expect(multi, "at least one finding must belong to two incidents").toBeDefined();
  });

  it("a finding in two incidents reports both (issue 200)", () => {
    const { findings, incidents } = correlatedFindings();
    const steam = findings.find((f) => f.rule === "DEAD_DROP_STEAM");

    const ids = (incidents ?? [])
      .filter((i) => i.findings.some((f) => f.rule === "DEAD_DROP_STEAM"))
      .map((i) => i.id)
      .sort();
    expect((steam?.correlationIds ?? []).slice().sort()).toEqual(ids);
    const idsOnFinding = steam?.correlationIds ?? [];
    expect(idsOnFinding.length).toBeGreaterThan(1);
    // The legacy field is the FIRST incident, not "any of them". The pre-change
    // overwrite wrote the LAST incident into correlationId, which is still one
    // of `ids`, so toContain(correlationId) could not fail under that behaviour.
    expect(steam?.correlationId).toBe(idsOnFinding[0]);
    expect(steam?.correlationId).not.toBe(idsOnFinding[idsOnFinding.length - 1]);
  });

  it("SARIF carries the incident name, confidence and indicators", () => {
    const { findings, incidents } = correlatedFindings();
    const sarif = JSON.parse(formatReport(reportFor(generateSbomDocument(tmpDir, []), findings, incidents), "sarif"));

    const carried = sarif.runs[0].properties.incidents;
    expect(carried.length).toBe((incidents ?? []).length);
    for (const incident of incidents ?? []) {
      const found = carried.find((i: { id: string }) => i.id === incident.id);
      expect(found.name).toBe(incident.name);
      expect(found.confidence).toBe(incident.confidence);
      expect(found.indicators).toEqual(incident.indicators);
    }
    // And membership is reachable from each result, not only from the run.
    const steamResult = sarif.runs[0].results.find(
      (r: { ruleId: string }) => r.ruleId === "DEAD_DROP_STEAM",
    );
    expect(steamResult.properties.incidentIds.length).toBeGreaterThanOrEqual(2);
  });

  it("CycloneDX links the entries of one incident to a named incident", () => {
    const { findings, incidents } = correlatedFindings();
    writeManifest({ name: "incident-demo", version: "1.0.0" });
    const rendered = JSON.parse(
      formatReport(reportFor(generateSbomDocument(tmpDir, []), findings, incidents), "sbom"),
    );

    expect(rendered.annotations.length).toBe((incidents ?? []).length);
    const refs = new Set<string>(
      rendered.vulnerabilities.map((v: { "bom-ref": string }) => v["bom-ref"]),
    );
    for (const incident of incidents ?? []) {
      const annotation = rendered.annotations.find(
        (a: { "bom-ref": string }) => a["bom-ref"] === `scg-${incident.id}`,
      );
      expect(annotation, `${incident.id} must have an annotation`).toBeDefined();
      expect(annotation.text).toContain(incident.name);
      expect(annotation.text).toContain(`${(incident.confidence * 100).toFixed(0)}%`);
      for (const indicator of incident.indicators) {
        expect(annotation.text).toContain(indicator);
      }
      // Subjects must resolve, both ways.
      expect(annotation.subjects.length).toBeGreaterThan(0);
      for (const subject of annotation.subjects) {
        expect(refs.has(subject)).toBe(true);
        const entry = rendered.vulnerabilities.find(
          (v: { "bom-ref": string }) => v["bom-ref"] === subject,
        );
        expect(
          entry.properties.some(
            (p: { name: string; value: string }) =>
              p.name === "supply-chain-guard:incident" && p.value === incident.id,
          ),
        ).toBe(true);
      }
    }
    expect(schemaErrors(rendered)).toEqual([]);
  });

  it("carries the incident in every format the README's NIS2 bullet names", () => {
    const { findings, incidents } = correlatedFindings();
    writeManifest({ name: "incident-demo", version: "1.0.0" });
    const report = reportFor(generateSbomDocument(tmpDir, []), findings, incidents);
    const name = (incidents ?? [])[0]!.name;

    for (const format of ["json", "sarif", "sbom"] as const) {
      const rendered = formatReport(report, format);
      expect(rendered, `${format} lost the incident name`).toContain(name);
      for (const incident of incidents ?? []) {
        expect(rendered, `${format} lost ${incident.id}`).toContain(incident.id);
      }
    }
  });
});
