import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { generateSbomDocument } from "../sbom-generator.js";
import { scan } from "../scanner.js";
import pkg from "../../package.json";

/** Every ref a dependsOn entry in the document is allowed to point at. */
function resolvableRefs(doc: ReturnType<typeof generateSbomDocument>): Set<string> {
  return new Set([
    doc.metadata.component["bom-ref"],
    ...doc.components.map((c) => c["bom-ref"]),
  ]);
}

function propertyValue(
  doc: ReturnType<typeof generateSbomDocument>,
  name: string,
): string | undefined {
  return doc.metadata.properties?.find((p) => p.name === name)?.value;
}

/**
 * A REAL sha512 Subresource Integrity value and its hex form.
 *
 * The fixtures used to carry stand-ins such as "sha512-abc123==". Those decode
 * to a handful of bytes, which is not a SHA-512 digest, so nothing in the test
 * suite ever exercised the encoding the CycloneDX schema constrains. Generated
 * with `crypto.createHash("sha512").update("supply-chain-guard fixture")`.
 */
const SHA512_INTEGRITY =
  "sha512-jcAFFknyfkZaZb2DHeScupgoE6x139/wsyvAhtMQbbmuRSXkWqVch+IgHRLNSv5AfwUMYKSu+V5fNgUtzBrkDA==";
const SHA512_HEX =
  "8dc0051649f27e465a65bd831de49cba982813ac75dfdff0b32bc086d3106db9ae4525e45aa55c87e2201d12cd4afe407f050c60a4aef95e5f36052dcc1ae40c";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-sbom-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("generateSbomDocument", () => {
  it("should return a valid CycloneDX 1.6 document", () => {
    fs.writeFileSync(
      path.join(tmpDir, "package.json"),
      JSON.stringify({ name: "my-app", version: "1.0.0", dependencies: { express: "^4.18.0" } }),
    );
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.specVersion).toBe("1.6");
    expect(doc.serialNumber).toMatch(/^urn:uuid:/);
    expect(doc.version).toBe(1);
  });

  it("should read project name and version from package.json", () => {
    fs.writeFileSync(
      path.join(tmpDir, "package.json"),
      JSON.stringify({ name: "my-cool-app", version: "2.3.4" }),
    );
    const doc = generateSbomDocument(tmpDir, []);
    // Name and version are separate fields (issue 196): a consumer reading
    // metadata.component.version to identify the product used to get undefined
    // because both were concatenated into the name.
    expect(doc.metadata.component.name).toBe("my-cool-app");
    expect(doc.metadata.component.version).toBe("2.3.4");
    expect(doc.metadata.component.purl).toBe("pkg:npm/my-cool-app@2.3.4");
  });

  it("should return empty components array when no manifest found", () => {
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.components).toHaveLength(0);
  });

  it("should parse components from package-lock.json v2", () => {
    const lockfile = {
      lockfileVersion: 2,
      packages: {
        "": { name: "my-app", version: "1.0.0" },
        "node_modules/express": { version: "4.18.3", integrity: SHA512_INTEGRITY },
        "node_modules/commander": { version: "13.1.0", integrity: SHA512_INTEGRITY },
      },
    };
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.components.length).toBe(2);
    const express = doc.components.find((c) => c.name === "express");
    expect(express).toBeDefined();
    expect(express?.version).toBe("4.18.3");
    expect(express?.purl).toBe("pkg:npm/express@4.18.3");
  });

  it("should generate correct purl for scoped packages", () => {
    const lockfile = {
      lockfileVersion: 2,
      packages: {
        "": { name: "my-app" },
        "node_modules/@types/node": { version: "22.0.0", integrity: SHA512_INTEGRITY },
      },
    };
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
    const doc = generateSbomDocument(tmpDir, []);
    const typesNode = doc.components.find((c) => c.name === "@types/node");
    // issue 193: the npm scope is the purl NAMESPACE and the separator after it
    // is a literal "/". The old assertion pinned "%40types%2Fnode", which
    // decomposes to no namespace and a name containing a slash.
    expect(typesNode?.purl).toBe("pkg:npm/%40types/node@22.0.0");
  });

  it("should parse integrity hashes into CycloneDX format", () => {
    const lockfile = {
      lockfileVersion: 2,
      packages: {
        "": {},
        "node_modules/lodash": { version: "4.17.21", integrity: SHA512_INTEGRITY },
      },
    };
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
    const doc = generateSbomDocument(tmpDir, []);
    const lodash = doc.components.find((c) => c.name === "lodash");
    expect(lodash?.hashes).toBeDefined();
    expect(lodash?.hashes?.[0]?.alg).toBe("SHA-512");
    // issue 191: CycloneDX requires hex, npm's integrity field is base64.
    expect(lodash?.hashes?.[0]?.content).toBe(SHA512_HEX);
  });

  it("should fall back to package.json direct deps when no lockfile", () => {
    fs.writeFileSync(
      path.join(tmpDir, "package.json"),
      JSON.stringify({
        name: "fallback-app",
        dependencies: { chalk: "^5.0.0" },
        devDependencies: { vitest: "^3.0.0" },
      }),
    );
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.components.length).toBe(2);
    const chalk = doc.components.find((c) => c.name === "chalk");
    expect(chalk).toBeDefined();
    expect(chalk?.scope).toBe("required");
    const vitest = doc.components.find((c) => c.name === "vitest");
    expect(vitest?.scope).toBe("excluded");
  });

  it("should add VEX statements for suppressed findings", () => {
    fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({ name: "app" }));
    const findings = [
      {
        rule: "HIGH_ENTROPY_FILE",
        description: "High entropy",
        severity: "medium" as const,
        file: "dist/bundle.js",
        recommendation: "Review",
        suppressed: true,
      },
      {
        rule: "EVAL_USAGE",
        description: "Eval",
        severity: "high" as const,
        recommendation: "Remove eval",
        suppressed: false,
      },
    ];
    const doc = generateSbomDocument(tmpDir, findings);
    expect(doc.vulnerabilities).toBeDefined();
    expect(doc.vulnerabilities?.length).toBe(1);
    expect(doc.vulnerabilities?.[0]?.id).toBe("scg-HIGH_ENTROPY_FILE");
    expect(doc.vulnerabilities?.[0]?.analysis.state).toBe("not_affected");
  });

  it("should include tool metadata", () => {
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.metadata.tools.components[0]?.name).toBe("supply-chain-guard");
    // Version must track package.json - hardcoding broke releases before
    // (v5.2.14, v5.2.17) and left this suite a release behind at v5.23.2.
    expect(doc.metadata.tools.components[0]?.version).toBe(pkg.version);
  });

  it("should mark dev deps as excluded scope", () => {
    const lockfile = {
      lockfileVersion: 2,
      packages: {
        "": {},
        "node_modules/typescript": { version: "5.7.0", dev: true },
      },
    };
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
    const doc = generateSbomDocument(tmpDir, []);
    const ts = doc.components.find((c) => c.name === "typescript");
    expect(ts?.scope).toBe("excluded");
  });

  it("should not include root package entry (empty key) in components", () => {
    const lockfile = {
      lockfileVersion: 2,
      packages: {
        "": { name: "root-pkg", version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.21" },
      },
    };
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.components.some((c) => c.name === "root-pkg")).toBe(false);
    expect(doc.components.some((c) => c.name === "lodash")).toBe(true);
  });

  it("should handle malformed package-lock.json gracefully", () => {
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), "{ invalid json }");
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.components).toHaveLength(0);
  });

  it("should handle lockfile v1 gracefully (no packages key)", () => {
    const lockfile = { lockfileVersion: 1, dependencies: { lodash: { version: "4.17.21" } } };
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
    const doc = generateSbomDocument(tmpDir, []);
    // v1 lockfiles fall back to package.json or empty
    expect(Array.isArray(doc.components)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Regression tests for https://github.com/homeofe/supply-chain-guard/issues/196
//
// The SBOM emitted every component without a licence, without a bom-ref and
// without any dependency relationship, while the package-lock.json the
// generator had already parsed carried all three. These tests fail if any of
// the three is dropped again, and they also pin the honesty properties: a field
// that could not be assessed has to SAY it was not assessed rather than simply
// be missing.
// ---------------------------------------------------------------------------

/**
 * Lockfile covering the four cases the fix has to distinguish: a plain SPDX
 * identifier, an SPDX expression, an entry with no licence at all, and a
 * declared edge that resolves to nothing (an uninstalled peer).
 */
const ISSUE_196_LOCKFILE = {
  lockfileVersion: 3,
  packages: {
    "": {
      name: "host-app",
      version: "1.0.0",
      dependencies: { express: "^4.18.3" },
      devDependencies: { typescript: "^5.7.0" },
    },
    "node_modules/express": {
      version: "4.18.3",
      license: "MIT",
      integrity: SHA512_INTEGRITY,
      dependencies: { "body-parser": "^1.20.2" },
      peerDependencies: { "never-installed-peer": "^1.0.0" },
    },
    "node_modules/body-parser": { version: "1.20.2", license: "(MIT OR Apache-2.0)" },
    "node_modules/typescript": { version: "5.7.0", dev: true },
  },
};

describe("issue 196: licences, bom-refs and dependency relationships", () => {
  const writeLock = (lockfile: unknown) =>
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));

  it("gives every lockfile component a unique bom-ref", () => {
    writeLock(ISSUE_196_LOCKFILE);
    const doc = generateSbomDocument(tmpDir, []);

    expect(doc.components).toHaveLength(3);
    const refs = doc.components.map((c) => c["bom-ref"]);
    expect(refs.filter((r) => typeof r === "string" && r.length > 0)).toHaveLength(3);
    expect(new Set(refs).size).toBe(3);
  });

  it("populates licences from the lockfile: SPDX id, expression, and not-assessed", () => {
    writeLock(ISSUE_196_LOCKFILE);
    const doc = generateSbomDocument(tmpDir, []);

    const express = doc.components.find((c) => c.name === "express");
    expect(express?.licenses).toEqual([{ license: { id: "MIT" } }]);

    const bodyParser = doc.components.find((c) => c.name === "body-parser");
    expect(bodyParser?.licenses).toEqual([{ expression: "(MIT OR Apache-2.0)" }]);

    // The lockfile entry for typescript declares no licence. The component must
    // say the field was not assessed instead of just lacking a licences key.
    const ts = doc.components.find((c) => c.name === "typescript");
    expect(ts?.licenses).toBeUndefined();
    expect(ts?.properties?.map((p) => p.name)).toContain("supply-chain-guard:license");
    expect(ts?.properties?.[0]?.value).toMatch(/^not-assessed:/);

    expect(propertyValue(doc, "supply-chain-guard:sbom:components-with-declared-license")).toBe(
      "2/3",
    );
  });

  it("emits a dependencies array rooted at the subject component", () => {
    writeLock(ISSUE_196_LOCKFILE);
    const doc = generateSbomDocument(tmpDir, []);

    expect(doc.dependencies).toBeDefined();
    expect(doc.dependencies!.length).toBeGreaterThan(0);

    const root = doc.dependencies!.find((d) => d.ref === doc.metadata.component["bom-ref"]);
    expect(root?.dependsOn).toEqual(["node_modules/express", "node_modules/typescript"]);

    const express = doc.dependencies!.find((d) => d.ref === "node_modules/express");
    expect(express?.dependsOn).toEqual(["node_modules/body-parser"]);

    // Every component makes a statement: an empty dependsOn means "declares
    // none", which is different from having no entry at all.
    const covered = doc.components.filter((c) =>
      doc.dependencies!.some((d) => d.ref === c["bom-ref"]),
    );
    expect(covered).toHaveLength(doc.components.length);
    expect(
      doc.dependencies!.find((d) => d.ref === "node_modules/typescript")?.dependsOn,
    ).toEqual([]);
  });

  it("counts an unresolvable edge instead of emitting a reference to nothing", () => {
    writeLock(ISSUE_196_LOCKFILE);
    const doc = generateSbomDocument(tmpDir, []);

    // never-installed-peer is declared by express but has no lockfile entry.
    expect(propertyValue(doc, "supply-chain-guard:sbom:dependency-edges-unresolved")).toBe("1");

    const refs = resolvableRefs(doc);
    const dangling = doc.dependencies!.flatMap((d) =>
      [d.ref, ...d.dependsOn].filter((r) => !refs.has(r)),
    );
    expect(dangling).toEqual([]);
  });

  it("resolves a nested duplicate to the nested entry, not the hoisted one", () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        "": { name: "host", version: "1.0.0", dependencies: { middle: "^1.0.0", dep: "^2.0.0" } },
        "node_modules/dep": { version: "2.0.0", license: "MIT" },
        "node_modules/middle": { version: "1.0.0", license: "MIT", dependencies: { dep: "^1.0.0" } },
        "node_modules/middle/node_modules/dep": { version: "1.0.0", license: "MIT" },
      },
    });
    const doc = generateSbomDocument(tmpDir, []);

    const middle = doc.dependencies!.find((d) => d.ref === "node_modules/middle");
    expect(middle?.dependsOn).toEqual(["node_modules/middle/node_modules/dep"]);
    expect(propertyValue(doc, "supply-chain-guard:sbom:dependency-edges-unresolved")).toBe("0");
  });

  it("follows a workspace link stub to the entry that became a component", () => {
    writeLock({
      lockfileVersion: 3,
      packages: {
        "": { name: "root", version: "1.0.0", dependencies: { "@acme/app": "*" } },
        "node_modules/@acme/app": { link: true, resolved: "packages/app" },
        "packages/app": { name: "@acme/app", version: "0.1.0", license: "Apache-2.0" },
      },
    });
    const doc = generateSbomDocument(tmpDir, []);

    const root = doc.dependencies!.find((d) => d.ref === "target");
    expect(root?.dependsOn).toEqual(["packages/app"]);
    expect(propertyValue(doc, "supply-chain-guard:sbom:dependency-edges-unresolved")).toBe("0");
  });

  it("records the component source and a resolved graph for a lockfile scan", () => {
    writeLock(ISSUE_196_LOCKFILE);
    const doc = generateSbomDocument(tmpDir, []);

    expect(propertyValue(doc, "supply-chain-guard:sbom:component-source")).toBe(
      "package-lock.json",
    );
    expect(propertyValue(doc, "supply-chain-guard:sbom:dependency-graph")).toBe(
      "resolved-from-package-lock.json",
    );
  });

  it("marks the package.json fallback graph partial and its licences not assessed", () => {
    fs.writeFileSync(
      path.join(tmpDir, "package.json"),
      JSON.stringify({ name: "fallback-app", version: "1.0.0", dependencies: { chalk: "^5.0.0" } }),
    );
    const doc = generateSbomDocument(tmpDir, []);

    expect(propertyValue(doc, "supply-chain-guard:sbom:component-source")).toBe("package.json");
    expect(propertyValue(doc, "supply-chain-guard:sbom:dependency-graph")).toMatch(/^partial:/);
    expect(propertyValue(doc, "supply-chain-guard:sbom:components-with-declared-license")).toBe(
      "0/1",
    );
    // The subject's own direct edges are known; the dependency's are not, so it
    // gets no entry rather than a fabricated empty one.
    expect(doc.dependencies).toEqual([{ ref: "target", dependsOn: ["chalk"] }]);
  });

  it("says the graph was not assessed when there is no manifest at all", () => {
    const doc = generateSbomDocument(tmpDir, []);

    expect(doc.dependencies).toBeUndefined();
    expect(propertyValue(doc, "supply-chain-guard:sbom:component-source")).toBe("none");
    expect(propertyValue(doc, "supply-chain-guard:sbom:dependency-graph")).toMatch(
      /^not-assessed:/,
    );
  });

  it("omits the subject version and purl, and says why, when none is declared", () => {
    fs.writeFileSync(path.join(tmpDir, "package.json"), JSON.stringify({ name: "no-version-app" }));
    const doc = generateSbomDocument(tmpDir, []);

    expect(doc.metadata.component.name).toBe("no-version-app");
    expect(doc.metadata.component.version).toBeUndefined();
    expect(doc.metadata.component.purl).toBeUndefined();
    expect(propertyValue(doc, "supply-chain-guard:sbom:subject-version")).toBe(
      "not-assessed: package.json declares no version",
    );
  });
});

describe("issue 196: VEX statements reach the document and quote the real reason", () => {
  it("builds a statement from the policy's own reason and asserts no justification", async () => {
    fs.writeFileSync(path.join(tmpDir, "bad.js"), 'eval(atob("Y29uc29sZS5sb2coMSk="));\n');
    fs.writeFileSync(
      path.join(tmpDir, ".supply-chain-guard.yml"),
      ["suppress:", "  - rule: EVAL_ATOB", "    reason: reviewed and accepted for this build", ""].join(
        "\n",
      ),
    );

    const report = await scan({ target: tmpDir, format: "json" });

    // Control: the suppression really fired, so an empty result below would be
    // the VEX path failing, not an unmatched rule.
    expect(report.suppressedCount).toBeGreaterThan(0);
    expect(report.findings.some((f) => f.rule === "EVAL_ATOB")).toBe(false);

    const vex = (report.sbomDocument?.vulnerabilities ?? []).filter(
      (v) => v.id === "scg-EVAL_ATOB",
    );
    expect(vex).toHaveLength(1);
    expect(vex[0].analysis.state).toBe("not_affected");
    expect(vex[0].analysis.detail).toContain("reviewed and accepted for this build");
    // The old code hardcoded "protected_by_compiler" for every suppression. A
    // free-text reason cannot be mapped to the CycloneDX justification enum, so
    // none is asserted.
    expect(vex[0].analysis.justification).toBeUndefined();
    // affects must name a bom-ref that exists in this document.
    const refs = new Set([
      report.sbomDocument!.metadata.component["bom-ref"],
      ...report.sbomDocument!.components.map((c) => c["bom-ref"]),
    ]);
    for (const a of vex[0].affects ?? []) expect(refs.has(a.ref)).toBe(true);
  });

  it("says no reason was recorded when the suppression declares none", async () => {
    fs.writeFileSync(path.join(tmpDir, "bad.js"), 'eval(atob("Y29uc29sZS5sb2coMSk="));\n');
    fs.writeFileSync(
      path.join(tmpDir, ".supply-chain-guard.yml"),
      ["suppress:", "  - rule: EVAL_ATOB", ""].join("\n"),
    );

    const report = await scan({ target: tmpDir, format: "json" });

    const vex = (report.sbomDocument?.vulnerabilities ?? []).filter(
      (v) => v.id === "scg-EVAL_ATOB",
    );
    expect(vex).toHaveLength(1);
    // The parser fills in a placeholder reason. Publishing that placeholder as
    // if the project had written it would be a fabricated justification.
    expect(vex[0].analysis.detail).toContain("no reason was recorded");
    expect(vex[0].analysis.detail).not.toContain("Declared reason:");
  });
});
