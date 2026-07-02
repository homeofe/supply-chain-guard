import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  checkLockfile,
  checkPnpmLockfile,
  checkYarnLockfile,
  checkBunLockfile,
} from "../lockfile-checker.js";

/** A well-formed sha512 SRI hash (long enough to pass the truncation check) */
const SHA512 =
  "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==";

describe("Multi-format lockfile support (pnpm / yarn / bun)", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-multilock-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  const write = (name: string, content: string | Buffer): void => {
    fs.writeFileSync(path.join(tempDir, name), content);
  };

  // -------------------------------------------------------------------------
  // pnpm-lock.yaml v6
  // -------------------------------------------------------------------------

  describe("pnpm-lock.yaml v6", () => {
    it("reports no findings for a clean v6 lockfile", () => {
      write(
        "pnpm-lock.yaml",
        [
          "lockfileVersion: '6.0'",
          "",
          "dependencies:",
          "  lodash:",
          "    specifier: ^4.17.21",
          "    version: 4.17.21",
          "",
          "packages:",
          "",
          "  /lodash@4.17.21:",
          `    resolution: {integrity: ${SHA512}}`,
          "    dev: false",
          "",
        ].join("\n"),
      );

      expect(checkPnpmLockfile(tempDir)).toHaveLength(0);
    });

    it("detects a known-bad version (event-stream@3.3.6)", () => {
      write(
        "pnpm-lock.yaml",
        [
          "lockfileVersion: '6.0'",
          "",
          "packages:",
          "",
          "  /event-stream@3.3.6:",
          `    resolution: {integrity: ${SHA512}}`,
          "",
        ].join("\n"),
      );

      const findings = checkPnpmLockfile(tempDir);
      const bad = findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(bad).toBeDefined();
      expect(bad!.severity).toBe("critical");
      expect(bad!.file).toBe("pnpm-lock.yaml");
      expect(bad!.description).toContain("event-stream@3.3.6");
    });

    it("detects tarballs fetched over plain HTTP", () => {
      write(
        "pnpm-lock.yaml",
        [
          "lockfileVersion: '6.0'",
          "",
          "packages:",
          "",
          "  /internal-pkg@1.0.0:",
          `    resolution: {integrity: ${SHA512}, tarball: http://registry.internal.example/internal-pkg-1.0.0.tgz}`,
          "",
        ].join("\n"),
      );

      const findings = checkPnpmLockfile(tempDir);
      const http = findings.find((f) => f.rule === "LOCKFILE_HTTP_RESOLVED");
      expect(http).toBeDefined();
      expect(http!.severity).toBe("high");
      expect(http!.file).toBe("pnpm-lock.yaml");
    });

    it("detects registry packages without integrity", () => {
      write(
        "pnpm-lock.yaml",
        [
          "lockfileVersion: '6.0'",
          "",
          "packages:",
          "",
          "  /no-integrity@2.0.0:",
          "    resolution: {tarball: https://registry.npmjs.org/no-integrity/-/no-integrity-2.0.0.tgz}",
          "",
        ].join("\n"),
      );

      const findings = checkPnpmLockfile(tempDir);
      const missing = findings.find(
        (f) => f.rule === "LOCKFILE_MISSING_INTEGRITY",
      );
      expect(missing).toBeDefined();
      expect(missing!.file).toBe("pnpm-lock.yaml");
    });

    it("handles peer-dependency suffixes without false positives", () => {
      write(
        "pnpm-lock.yaml",
        [
          "lockfileVersion: '6.0'",
          "",
          "packages:",
          "",
          "  /react-dom@18.2.0(react@18.2.0):",
          `    resolution: {integrity: ${SHA512}}`,
          "",
        ].join("\n"),
      );

      expect(checkPnpmLockfile(tempDir)).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // pnpm-lock.yaml v9
  // -------------------------------------------------------------------------

  describe("pnpm-lock.yaml v9", () => {
    it("reports no findings for a clean v9 lockfile", () => {
      write(
        "pnpm-lock.yaml",
        [
          "lockfileVersion: '9.0'",
          "",
          "importers:",
          "",
          "  .:",
          "    dependencies:",
          "      lodash:",
          "        specifier: ^4.17.21",
          "        version: 4.17.21",
          "",
          "packages:",
          "",
          "  lodash@4.17.21:",
          `    resolution: {integrity: ${SHA512}}`,
          "",
          "  '@scope/pkg@1.0.0':",
          `    resolution: {integrity: ${SHA512}}`,
          "",
          "snapshots:",
          "",
          "  lodash@4.17.21: {}",
          "",
          "  '@scope/pkg@1.0.0': {}",
          "",
        ].join("\n"),
      );

      expect(checkPnpmLockfile(tempDir)).toHaveLength(0);
    });

    it("detects a known-bad version in v9 key style", () => {
      write(
        "pnpm-lock.yaml",
        [
          "lockfileVersion: '9.0'",
          "",
          "packages:",
          "",
          "  event-stream@3.3.6:",
          `    resolution: {integrity: ${SHA512}}`,
          "",
        ].join("\n"),
      );

      const findings = checkPnpmLockfile(tempDir);
      const bad = findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(bad).toBeDefined();
      expect(bad!.file).toBe("pnpm-lock.yaml");
    });

    it("flags git dependencies as unusual sources without demanding integrity", () => {
      write(
        "pnpm-lock.yaml",
        [
          "lockfileVersion: '9.0'",
          "",
          "packages:",
          "",
          "  some-fork@git+https://git.example/user/some-fork.git#abc123:",
          "    resolution: {commit: abc123, repo: git+https://git.example/user/some-fork.git, type: git}",
          "",
        ].join("\n"),
      );

      const findings = checkPnpmLockfile(tempDir);
      const unusual = findings.find(
        (f) => f.rule === "LOCKFILE_UNUSUAL_RESOLVED",
      );
      expect(unusual).toBeDefined();
      const missing = findings.find(
        (f) => f.rule === "LOCKFILE_MISSING_INTEGRITY",
      );
      expect(missing).toBeUndefined();
    });
  });

  describe("pnpm-lock.yaml edge cases", () => {
    it("returns no findings when no pnpm lockfile exists", () => {
      expect(checkPnpmLockfile(tempDir)).toHaveLength(0);
    });

    it("reports a parse error for an empty file", () => {
      write("pnpm-lock.yaml", "");
      const findings = checkPnpmLockfile(tempDir);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.rule).toBe("LOCKFILE_PARSE_ERROR");
      expect(findings[0]!.file).toBe("pnpm-lock.yaml");
    });

    it("reports a parse error for corrupt YAML", () => {
      write("pnpm-lock.yaml", "{{{ definitely: [not, a, pnpm, lockfile");
      const findings = checkPnpmLockfile(tempDir);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.rule).toBe("LOCKFILE_PARSE_ERROR");
    });
  });

  // -------------------------------------------------------------------------
  // yarn.lock classic v1
  // -------------------------------------------------------------------------

  describe("yarn.lock v1 (classic)", () => {
    it("reports no findings for a clean v1 lockfile", () => {
      write(
        "yarn.lock",
        [
          "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.",
          "# yarn lockfile v1",
          "",
          "",
          "lodash@^4.17.20, lodash@^4.17.21:",
          '  version "4.17.21"',
          '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae8454cf0b3df370c3d6911c"',
          `  integrity ${SHA512}`,
          "",
          '"@scope/pkg@^1.0.0":',
          '  version "1.0.0"',
          '  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.0.0.tgz#abc"',
          `  integrity ${SHA512}`,
          "",
        ].join("\n"),
      );

      expect(checkYarnLockfile(tempDir)).toHaveLength(0);
    });

    it("detects a known-bad version (event-stream@3.3.6)", () => {
      write(
        "yarn.lock",
        [
          "# yarn lockfile v1",
          "",
          "event-stream@^3.3.4:",
          '  version "3.3.6"',
          '  resolved "https://registry.yarnpkg.com/event-stream/-/event-stream-3.3.6.tgz#abc"',
          `  integrity ${SHA512}`,
          "",
        ].join("\n"),
      );

      const findings = checkYarnLockfile(tempDir);
      const bad = findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(bad).toBeDefined();
      expect(bad!.severity).toBe("critical");
      expect(bad!.file).toBe("yarn.lock");
    });

    it("detects packages resolved over plain HTTP", () => {
      write(
        "yarn.lock",
        [
          "# yarn lockfile v1",
          "",
          "sketchy-pkg@^1.0.0:",
          '  version "1.0.0"',
          '  resolved "http://registry.internal.example/sketchy-pkg-1.0.0.tgz"',
          `  integrity ${SHA512}`,
          "",
        ].join("\n"),
      );

      const findings = checkYarnLockfile(tempDir);
      const http = findings.find((f) => f.rule === "LOCKFILE_HTTP_RESOLVED");
      expect(http).toBeDefined();
      expect(http!.file).toBe("yarn.lock");
    });

    it("detects resolved entries without an integrity line", () => {
      write(
        "yarn.lock",
        [
          "# yarn lockfile v1",
          "",
          "no-integrity@^1.0.0:",
          '  version "1.0.0"',
          '  resolved "https://registry.yarnpkg.com/no-integrity/-/no-integrity-1.0.0.tgz#abc"',
          "",
        ].join("\n"),
      );

      const findings = checkYarnLockfile(tempDir);
      const missing = findings.find(
        (f) => f.rule === "LOCKFILE_MISSING_INTEGRITY",
      );
      expect(missing).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // yarn.lock Berry v2+
  // -------------------------------------------------------------------------

  describe("yarn.lock Berry (v2+)", () => {
    it("reports no findings for a clean Berry lockfile with a workspace", () => {
      write(
        "yarn.lock",
        [
          '# This file is generated by running "yarn install" inside your project.',
          "# Manual changes might be destroyed by the next install.",
          "",
          "__metadata:",
          "  version: 8",
          "  cacheKey: 10c0",
          "",
          '"lodash@npm:^4.17.21":',
          "  version: 4.17.21",
          '  resolution: "lodash@npm:4.17.21"',
          "  checksum: 10c0/d8cbea072bb08655bb4c989da418994b073a608dffa608b09ac04b43a791b12aeae7cd7ad919aa4c925f33b48490b5cfe6c1f71d827956071dae2e7bb3a6b74c",
          "  languageName: node",
          "  linkType: hard",
          "",
          '"my-app@workspace:.":',
          "  version: 0.0.0-use.local",
          '  resolution: "my-app@workspace:."',
          "  languageName: unknown",
          "  linkType: soft",
          "",
        ].join("\n"),
      );

      expect(checkYarnLockfile(tempDir)).toHaveLength(0);
    });

    it("detects a known-bad version in Berry key style", () => {
      write(
        "yarn.lock",
        [
          "__metadata:",
          "  version: 8",
          "  cacheKey: 10c0",
          "",
          '"event-stream@npm:3.3.6":',
          "  version: 3.3.6",
          '  resolution: "event-stream@npm:3.3.6"',
          "  checksum: 10c0/d8cbea072bb08655bb4c989da418994b073a608dffa608b09ac04b43a791b12a",
          "  linkType: hard",
          "",
        ].join("\n"),
      );

      const findings = checkYarnLockfile(tempDir);
      const bad = findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(bad).toBeDefined();
      expect(bad!.file).toBe("yarn.lock");
    });

    it("detects npm-protocol entries without a checksum", () => {
      write(
        "yarn.lock",
        [
          "__metadata:",
          "  version: 8",
          "  cacheKey: 10c0",
          "",
          '"no-checksum@npm:^1.0.0":',
          "  version: 1.0.0",
          '  resolution: "no-checksum@npm:1.0.0"',
          "  linkType: hard",
          "",
        ].join("\n"),
      );

      const findings = checkYarnLockfile(tempDir);
      const missing = findings.find(
        (f) => f.rule === "LOCKFILE_MISSING_INTEGRITY",
      );
      expect(missing).toBeDefined();
      expect(missing!.file).toBe("yarn.lock");
    });
  });

  describe("yarn.lock edge cases", () => {
    it("returns no findings when no yarn lockfile exists", () => {
      expect(checkYarnLockfile(tempDir)).toHaveLength(0);
    });

    it("reports a parse error for an empty file", () => {
      write("yarn.lock", "");
      const findings = checkYarnLockfile(tempDir);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.rule).toBe("LOCKFILE_PARSE_ERROR");
      expect(findings[0]!.file).toBe("yarn.lock");
    });

    it("reports a parse error for garbage content", () => {
      write("yarn.lock", "this is definitely\nnot a yarn lockfile");
      const findings = checkYarnLockfile(tempDir);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.rule).toBe("LOCKFILE_PARSE_ERROR");
    });
  });

  // -------------------------------------------------------------------------
  // bun.lock (JSONC text lockfile)
  // -------------------------------------------------------------------------

  describe("bun.lock (JSONC)", () => {
    it("reports no findings for a clean lockfile with comments and trailing commas", () => {
      write(
        "bun.lock",
        [
          "// bun text lockfile",
          "{",
          '  "lockfileVersion": 1,',
          '  "workspaces": {',
          '    "": {',
          '      "name": "test-app",',
          '      "dependencies": {',
          '        "lodash": "^4.17.21",',
          "      },",
          "    },",
          "  },",
          "  /* package resolutions */",
          '  "packages": {',
          `    "lodash": ["lodash@4.17.21", "", {}, "${SHA512}"],`,
          "  },",
          "}",
        ].join("\n"),
      );

      expect(checkBunLockfile(tempDir)).toHaveLength(0);
    });

    it("detects a known-bad version (event-stream@3.3.6)", () => {
      write(
        "bun.lock",
        [
          "{",
          '  "lockfileVersion": 1,',
          '  "packages": {',
          `    "event-stream": ["event-stream@3.3.6", "", {}, "${SHA512}"],`,
          "  },",
          "}",
        ].join("\n"),
      );

      const findings = checkBunLockfile(tempDir);
      const bad = findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(bad).toBeDefined();
      expect(bad!.severity).toBe("critical");
      expect(bad!.file).toBe("bun.lock");
    });

    it("detects packages fetched over plain HTTP", () => {
      write(
        "bun.lock",
        [
          "{",
          '  "lockfileVersion": 1,',
          '  "packages": {',
          `    "internal-pkg": ["internal-pkg@1.0.0", "http://registry.internal.example/internal-pkg-1.0.0.tgz", {}, "${SHA512}"],`,
          "  },",
          "}",
        ].join("\n"),
      );

      const findings = checkBunLockfile(tempDir);
      const http = findings.find((f) => f.rule === "LOCKFILE_HTTP_RESOLVED");
      expect(http).toBeDefined();
      expect(http!.file).toBe("bun.lock");
    });

    it("detects registry packages without integrity", () => {
      write(
        "bun.lock",
        [
          "{",
          '  "lockfileVersion": 1,',
          '  "packages": {',
          '    "no-integrity": ["no-integrity@1.0.0", "", {}],',
          "  },",
          "}",
        ].join("\n"),
      );

      const findings = checkBunLockfile(tempDir);
      const missing = findings.find(
        (f) => f.rule === "LOCKFILE_MISSING_INTEGRITY",
      );
      expect(missing).toBeDefined();
    });

    it("reports a parse error for corrupt JSONC", () => {
      write("bun.lock", '{ "packages": [not valid jsonc');
      const findings = checkBunLockfile(tempDir);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.rule).toBe("LOCKFILE_PARSE_ERROR");
      expect(findings[0]!.file).toBe("bun.lock");
    });

    it("reports a parse error for an empty file", () => {
      write("bun.lock", "");
      const findings = checkBunLockfile(tempDir);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.rule).toBe("LOCKFILE_PARSE_ERROR");
    });
  });

  // -------------------------------------------------------------------------
  // bun.lockb (binary lockfile)
  // -------------------------------------------------------------------------

  describe("bun.lockb (binary)", () => {
    it("flags a binary-only bun lockfile as unauditable", () => {
      // Realistic-looking binary header bytes; content is never parsed
      write(
        "bun.lockb",
        Buffer.from([0x62, 0x75, 0x6e, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00]),
      );

      const findings = checkBunLockfile(tempDir);
      expect(findings).toHaveLength(1);
      const binary = findings[0]!;
      expect(binary.rule).toBe("LOCKFILE_BUN_BINARY_UNAUDITABLE");
      expect(binary.severity).toBe("low");
      expect(binary.file).toBe("bun.lockb");
      expect(binary.confidence).toBe(1.0);
      expect(binary.category).toBe("supply-chain");
      expect(binary.recommendation).toContain("--save-text-lockfile");
    });

    it("does not flag bun.lockb when a text bun.lock is also present", () => {
      write(
        "bun.lockb",
        Buffer.from([0x62, 0x75, 0x6e, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00]),
      );
      write(
        "bun.lock",
        [
          "{",
          '  "lockfileVersion": 1,',
          '  "packages": {',
          `    "lodash": ["lodash@4.17.21", "", {}, "${SHA512}"],`,
          "  },",
          "}",
        ].join("\n"),
      );

      const findings = checkBunLockfile(tempDir);
      const binary = findings.find(
        (f) => f.rule === "LOCKFILE_BUN_BINARY_UNAUDITABLE",
      );
      expect(binary).toBeUndefined();
      expect(findings).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // Aggregation: checkLockfile checks all lockfiles present in a directory
  // -------------------------------------------------------------------------

  describe("checkLockfile aggregation", () => {
    it("returns no findings when no lockfile of any format exists", () => {
      expect(checkLockfile(tempDir)).toHaveLength(0);
    });

    it("checks all lockfile formats present in the same directory", () => {
      write(
        "package-lock.json",
        JSON.stringify({ name: "t", lockfileVersion: 3, packages: {} }),
      );
      write(
        "pnpm-lock.yaml",
        [
          "lockfileVersion: '9.0'",
          "",
          "packages:",
          "",
          "  event-stream@3.3.6:",
          `    resolution: {integrity: ${SHA512}}`,
          "",
        ].join("\n"),
      );
      write(
        "yarn.lock",
        [
          "# yarn lockfile v1",
          "",
          "sketchy-pkg@^1.0.0:",
          '  version "1.0.0"',
          '  resolved "http://registry.internal.example/sketchy-pkg-1.0.0.tgz"',
          `  integrity ${SHA512}`,
          "",
        ].join("\n"),
      );

      const findings = checkLockfile(tempDir);
      const pnpmBad = findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION" && f.file === "pnpm-lock.yaml",
      );
      const yarnHttp = findings.find(
        (f) => f.rule === "LOCKFILE_HTTP_RESOLVED" && f.file === "yarn.lock",
      );
      expect(pnpmBad).toBeDefined();
      expect(yarnHttp).toBeDefined();
      // The clean package-lock.json contributes no findings
      const npmFindings = findings.filter((f) => f.file === "package-lock.json");
      expect(npmFindings).toHaveLength(0);
    });
  });
});
