import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { generateSbomDocument } from "../sbom-generator.js";
import pkg from "../../package.json";

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
    expect(doc.metadata.component.name).toBe("my-cool-app@2.3.4");
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
        "node_modules/express": { version: "4.18.3", integrity: "sha512-abc123==" },
        "node_modules/commander": { version: "13.1.0", integrity: "sha512-def456==" },
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
        "node_modules/@types/node": { version: "22.0.0", integrity: "sha512-xyz==" },
      },
    };
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
    const doc = generateSbomDocument(tmpDir, []);
    const typesNode = doc.components.find((c) => c.name === "@types/node");
    // The "/" between the npm scope and the package name is the purl NAMESPACE
    // separator and stays literal. This assertion previously pinned
    // "pkg:npm/%40types%2Fnode@22.0.0", which parses as a package with no
    // namespace whose name contains a slash.
    expect(typesNode?.purl).toBe("pkg:npm/%40types/node@22.0.0");
  });

  it("should parse integrity hashes into CycloneDX format", () => {
    const lockfile = {
      lockfileVersion: 2,
      packages: {
        "": {},
        "node_modules/lodash": { version: "4.17.21", integrity: "sha512-v2kDE8oK3X==" },
      },
    };
    fs.writeFileSync(path.join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
    const doc = generateSbomDocument(tmpDir, []);
    const lodash = doc.components.find((c) => c.name === "lodash");
    expect(lodash?.hashes).toBeDefined();
    expect(lodash?.hashes?.[0]?.alg).toBe("SHA-512");
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
// purl encoding, pinned against the purl specification
//
// These cases exist because a scoped package used to be emitted as
// "pkg:npm/%40types%2Fnode@22.0.0". That string round trips through a parser
// without throwing, which is why it survived, but it decomposes into a package
// with NO namespace whose name contains a slash, so it matches neither a
// canonical purl by string equality nor a namespace-and-name lookup. Scoped
// packages are the majority of a typical npm inventory, so the majority of the
// document did not correlate with anything.
//
// The expectations below are taken from the specification itself
// (https://github.com/package-url/purl-spec), not from any one implementation:
//   - tests/types/npm-test.json           the npm type's own build test cases
//   - types/npm-definition.json           namespace = scope, "@" always encoded,
//                                         namespace and name CASE SENSITIVE
//   - docs/specification/standard/how-to-build.md
//                                         encode each namespace segment, the
//                                         name and the version individually
//   - docs/specification/standard/specification.md
//                                         which characters are never encoded
// ---------------------------------------------------------------------------

/** Write a package-lock.json v3 mapping each lockfile key to a version. */
function writeLockfile(dir: string, entries: Record<string, string>): void {
  const packages: Record<string, { version: string }> = {};
  for (const [key, version] of Object.entries(entries)) packages[key] = { version };
  fs.writeFileSync(
    path.join(dir, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: { "": { name: "host", version: "1.0.0" }, ...packages },
    }),
  );
}

/**
 * Decompose a purl the way the specification says to parse one: split the part
 * before the version on the UNENCODED "/" separators, then percent-decode each
 * segment. The last segment is the name and everything before it is the
 * namespace. This is the operation that advisory and inventory lookups perform,
 * and it is the one the old encoding broke.
 */
function decomposePurl(purl: string): { segments: string[]; version: string } {
  const body = purl.slice("pkg:npm/".length);
  const versionAt = body.lastIndexOf("@");
  const named = versionAt === -1 ? body : body.slice(0, versionAt);
  return {
    segments: named.split("/").map(decodeURIComponent),
    version: versionAt === -1 ? "" : decodeURIComponent(body.slice(versionAt + 1)),
  };
}

describe("npm purl encoding", () => {
  it("matches the purl specification's own npm build test cases", () => {
    writeLockfile(tmpDir, {
      "node_modules/@angular/animation": "12.3.1",
      "node_modules/foobar": "12.3.1",
    });
    const doc = generateSbomDocument(tmpDir, []);
    const purlFor = (name: string) => doc.components.find((c) => c.name === name)?.purl;

    // purl-spec tests/types/npm-test.json, test_type "build":
    //   {namespace: "@angular", name: "animation", version: "12.3.1"}
    //     -> pkg:npm/%40angular/animation@12.3.1
    //   {namespace: null,       name: "foobar",    version: "12.3.1"}
    //     -> pkg:npm/foobar@12.3.1
    expect(purlFor("@angular/animation")).toBe("pkg:npm/%40angular/animation@12.3.1");
    expect(purlFor("foobar")).toBe("pkg:npm/foobar@12.3.1");
  });

  it("never percent-encodes the namespace separator", () => {
    writeLockfile(tmpDir, {
      "node_modules/@types/node": "22.0.0",
      "node_modules/@babel/parser": "7.29.7",
      "node_modules/@babel/helper-validator-identifier": "7.29.7",
      "node_modules/typescript": "7.0.2",
      "node_modules/commander": "14.0.3",
    });
    const doc = generateSbomDocument(tmpDir, []);

    // Positive controls: the fixture really loaded, and it really contains both
    // scoped and unscoped names, so a green run is not a green run over nothing.
    expect(doc.components).toHaveLength(5);
    expect(doc.components.filter((c) => c.name.startsWith("@"))).toHaveLength(3);
    expect(doc.components.filter((c) => !c.name.startsWith("@"))).toHaveLength(2);

    for (const component of doc.components) {
      expect(component.purl).toBeDefined();
      expect(component.purl).not.toContain("%2F");
      expect(component.purl).not.toContain("%2f");
    }
  });

  it("decomposes into the namespace and name that advisory data is keyed on", () => {
    writeLockfile(tmpDir, { "node_modules/@types/node": "22.0.0" });
    const doc = generateSbomDocument(tmpDir, []);
    const emitted = doc.components.find((c) => c.name === "@types/node")?.purl ?? "";

    expect(decomposePurl(emitted)).toEqual({
      segments: ["@types", "node"],
      version: "22.0.0",
    });

    // The half of the finding that is easy to miss: the old form parses without
    // throwing, so it looks fine, but it carries no namespace at all. Asserting
    // it here keeps the reason the two are not interchangeable in the suite.
    expect(decomposePurl("pkg:npm/%40types%2Fnode@22.0.0")).toEqual({
      segments: ["@types/node"],
      version: "22.0.0",
    });
  });

  it("percent-encodes each segment individually, separators excepted", () => {
    writeLockfile(tmpDir, {
      // A version carrying characters the specification requires to be encoded,
      // next to a colon, which it requires to be left alone.
      "node_modules/@scope/pkg": "workspace:^",
      "node_modules/other": ">=1.0.0 <2.0.0",
    });
    const doc = generateSbomDocument(tmpDir, []);

    expect(doc.components.find((c) => c.name === "@scope/pkg")?.purl).toBe(
      "pkg:npm/%40scope/pkg@workspace:%5E",
    );
    expect(doc.components.find((c) => c.name === "other")?.purl).toBe(
      "pkg:npm/other@%3E%3D1.0.0%20%3C2.0.0",
    );
  });

  it("preserves the case of a grandfathered mixed-case package name", () => {
    // types/npm-definition.json marks namespace and name case_sensitive, and
    // notes that packages predating the 2015 lowercase rule were grandfathered
    // in. Lowercasing here would rename a package npm still serves.
    writeLockfile(tmpDir, { "node_modules/Base64": "1.0.0" });
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.components.find((c) => c.name === "Base64")?.purl).toBe(
      "pkg:npm/Base64@1.0.0",
    );
  });

  it("omits the purl and records why when the name is not an npm package name", () => {
    // npm lockfile keys are filesystem paths, so a nested duplicate and a
    // workspace member both arrive here as something that is not a package
    // name. An npm purl holds at most one namespace segment, so no canonical
    // purl exists for either, and inventing one would assert a scope named
    // "packages" publishing a package named "app".
    writeLockfile(tmpDir, {
      "node_modules/middle/node_modules/@acme/dep": "1.0.0",
      "packages/app": "1.0.0",
      "node_modules/@acme/dep": "2.0.0",
    });
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.components).toHaveLength(3);

    for (const name of ["middle/node_modules/@acme/dep", "packages/app"]) {
      const component = doc.components.find((c) => c.name === name);
      expect(component?.purl).toBeUndefined();
      expect(component?.properties).toEqual([
        {
          name: "supply-chain-guard:sbom:purl-unavailable",
          value:
            "not-an-npm-package-name: the component name is not a valid npm " +
            "package name, so no npm Package URL can be derived from it; " +
            "identify this component by its name and version instead",
        },
      ]);
    }

    // Control: the well-formed sibling in the same document still gets a purl,
    // so "no purl" is a statement about that component and not about the run.
    const resolvable = doc.components.find((c) => c.name === "@acme/dep");
    expect(resolvable?.purl).toBe("pkg:npm/%40acme/dep@2.0.0");
    expect(resolvable?.properties).toBeUndefined();
  });

  it("gives every component exactly one of a purl and a purl-unavailable property", () => {
    writeLockfile(tmpDir, {
      "node_modules/@types/node": "22.0.0",
      "node_modules/typescript": "7.0.2",
      "packages/app": "1.0.0",
    });
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.components).toHaveLength(3);

    for (const component of doc.components) {
      const hasPurl = component.purl !== undefined;
      const hasReason = (component.properties ?? []).some(
        (p) => p.name === "supply-chain-guard:sbom:purl-unavailable",
      );
      expect(hasPurl).not.toBe(hasReason);
    }
  });

  it("applies the same encoding on the package.json fallback path", () => {
    // The lockfile path and the no-lockfile path build their components
    // separately, so a fix applied to one of them only would leave every
    // pnpm, yarn and bun project on the old form.
    fs.writeFileSync(
      path.join(tmpDir, "package.json"),
      JSON.stringify({
        name: "fallback-app",
        dependencies: { "@types/node": "22.0.0" },
      }),
    );
    const doc = generateSbomDocument(tmpDir, []);
    expect(doc.components.find((c) => c.name === "@types/node")?.purl).toBe(
      "pkg:npm/%40types/node@22.0.0",
    );
  });
});
