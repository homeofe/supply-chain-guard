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
    expect(typesNode?.purl).toBe("pkg:npm/%40types%2Fnode@22.0.0");
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
