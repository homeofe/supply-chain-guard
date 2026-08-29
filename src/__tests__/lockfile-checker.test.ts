import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { checkLockfile } from "../lockfile-checker.js";

describe("Lockfile Checker (T-006)", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-lockfile-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("should return empty findings when no lockfile exists", () => {
    const findings = checkLockfile(tempDir);
    expect(findings).toHaveLength(0);
  });

  it("should report parse errors for invalid JSON lockfiles", () => {
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      "this is not json",
    );

    const findings = checkLockfile(tempDir);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.rule).toBe("LOCKFILE_PARSE_ERROR");
  });

  it("does not cross-reference a null package.json", () => {
    fs.writeFileSync(path.join(tempDir, "package.json"), "null");
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify({ name: "test", lockfileVersion: 3, packages: {} }),
    );

    expect(() => checkLockfile(tempDir)).not.toThrow();
  });

  it("should detect lockfile version 1 as a downgrade", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 1,
      dependencies: {},
    };
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );

    const findings = checkLockfile(tempDir);
    const downgrade = findings.find(
      (f) => f.rule === "LOCKFILE_VERSION_DOWNGRADE",
    );
    expect(downgrade).toBeDefined();
    expect(downgrade!.severity).toBe("medium");
  });

  it("should not flag lockfile version 3", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 3,
      packages: {},
    };
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );

    const findings = checkLockfile(tempDir);
    const downgrade = findings.find(
      (f) => f.rule === "LOCKFILE_VERSION_DOWNGRADE",
    );
    expect(downgrade).toBeUndefined();
  });

  it("should detect missing lockfileVersion", () => {
    const lockfile = {
      name: "test",
      dependencies: {},
    };
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );

    const findings = checkLockfile(tempDir);
    const noVersion = findings.find((f) => f.rule === "LOCKFILE_NO_VERSION");
    expect(noVersion).toBeDefined();
  });

  it("should detect invalid integrity hash format", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/evil-pkg": {
          version: "1.0.0",
          resolved: "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz",
          integrity: "md5-invalidhashformat1234567890abcdef",
        },
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );

    const findings = checkLockfile(tempDir);
    const invalid = findings.find(
      (f) => f.rule === "LOCKFILE_INVALID_INTEGRITY",
    );
    expect(invalid).toBeDefined();
    expect(invalid!.severity).toBe("high");
  });

  it("should accept valid sha512 integrity hashes", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/good-pkg": {
          version: "1.0.0",
          resolved:
            "https://registry.npmjs.org/good-pkg/-/good-pkg-1.0.0.tgz",
          integrity:
            "sha512-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP==",
        },
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );

    const findings = checkLockfile(tempDir);
    const invalid = findings.find(
      (f) => f.rule === "LOCKFILE_INVALID_INTEGRITY",
    );
    expect(invalid).toBeUndefined();
  });

  it("should detect missing integrity on packages with resolved URLs", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/no-integrity": {
          version: "1.0.0",
          resolved:
            "https://registry.npmjs.org/no-integrity/-/no-integrity-1.0.0.tgz",
        },
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );

    const findings = checkLockfile(tempDir);
    const missing = findings.find(
      (f) => f.rule === "LOCKFILE_MISSING_INTEGRITY",
    );
    expect(missing).toBeDefined();
    expect(missing!.severity).toBe("high");
  });

  it("should detect packages resolved from non-registry URLs", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/github-pkg": {
          version: "1.0.0",
          resolved: "https://github.com/user/repo/archive/refs/tags/v1.0.0.tar.gz",
          integrity: "sha512-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP==",
        },
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );

    const findings = checkLockfile(tempDir);
    const github = findings.find(
      (f) => f.rule === "LOCKFILE_GITHUB_RESOLVED",
    );
    expect(github).toBeDefined();
    expect(github!.severity).toBe("medium");
  });

  it("should detect packages resolved over plain HTTP", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/http-pkg": {
          version: "1.0.0",
          resolved: "http://evil-registry.com/http-pkg/-/http-pkg-1.0.0.tgz",
          integrity: "sha512-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP==",
        },
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );

    const findings = checkLockfile(tempDir);
    const http = findings.find((f) => f.rule === "LOCKFILE_HTTP_RESOLVED");
    expect(http).toBeDefined();
    expect(http!.severity).toBe("high");
  });

  it("should detect orphaned dependencies not in package.json", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/declared-pkg": {
          version: "1.0.0",
          resolved:
            "https://registry.npmjs.org/declared-pkg/-/declared-pkg-1.0.0.tgz",
          integrity: "sha512-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP==",
        },
        "node_modules/orphan-pkg": {
          version: "2.0.0",
          resolved:
            "https://registry.npmjs.org/orphan-pkg/-/orphan-pkg-2.0.0.tgz",
          integrity: "sha512-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP==",
        },
      },
    };
    const packageJson = {
      name: "test",
      version: "1.0.0",
      dependencies: {
        "declared-pkg": "^1.0.0",
      },
    };

    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify(packageJson),
    );

    const findings = checkLockfile(tempDir);
    const orphan = findings.find(
      (f) => f.rule === "LOCKFILE_ORPHANED_DEPENDENCY",
    );
    expect(orphan).toBeDefined();
    expect(orphan!.description).toContain("orphan-pkg");
  });

  it("should not flag declared dependencies as orphaned", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/lodash": {
          version: "4.17.21",
          resolved:
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
          integrity: "sha512-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP==",
        },
      },
    };
    const packageJson = {
      name: "test",
      version: "1.0.0",
      dependencies: {
        lodash: "^4.17.21",
      },
    };

    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify(packageJson),
    );

    const findings = checkLockfile(tempDir);
    const orphan = findings.find(
      (f) =>
        f.rule === "LOCKFILE_ORPHANED_DEPENDENCY" &&
        f.description.includes("lodash"),
    );
    expect(orphan).toBeUndefined();
  });

  it("should detect suspiciously short integrity hashes", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" },
        "node_modules/short-hash": {
          version: "1.0.0",
          resolved:
            "https://registry.npmjs.org/short-hash/-/short-hash-1.0.0.tgz",
          integrity: "sha512-abc",
        },
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );

    const findings = checkLockfile(tempDir);
    const short = findings.find(
      (f) => f.rule === "LOCKFILE_SHORT_INTEGRITY",
    );
    expect(short).toBeDefined();
    expect(short!.severity).toBe("high");
  });

  it("should handle v1 lockfile dependencies format", () => {
    const lockfile = {
      name: "test",
      lockfileVersion: 1,
      dependencies: {
        "some-pkg": {
          version: "1.0.0",
          resolved: "http://insecure.registry.com/some-pkg-1.0.0.tgz",
          integrity: "sha512-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP==",
        },
      },
    };
    fs.writeFileSync(
      path.join(tempDir, "package-lock.json"),
      JSON.stringify(lockfile),
    );

    const findings = checkLockfile(tempDir);
    const http = findings.find((f) => f.rule === "LOCKFILE_HTTP_RESOLVED");
    expect(http).toBeDefined();
  });
});
