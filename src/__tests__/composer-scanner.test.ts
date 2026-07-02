import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  scanComposerFiles,
  scanComposerJsonContent,
  scanComposerLockContent,
  isComposerFile,
} from "../composer-scanner.js";
import { matchPackageIOC } from "../threat-intel.js";

// Real bundled IOC (Laravel-Lang DebugElevator campaign, bare-name entry)
const MALICIOUS_PACKAGE = "laravel-lang/lang";

describe("Composer Scanner", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-composer-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should identify Composer-related files", () => {
    expect(isComposerFile("composer.json")).toBe(true);
    expect(isComposerFile("composer.lock")).toBe(true);
    expect(isComposerFile("package.json")).toBe(false);
  });

  describe("composer.json scanning", () => {
    it("should flag a require entry matching a bundled composer: IOC", () => {
      const content = JSON.stringify({
        require: { php: "^8.2", [MALICIOUS_PACKAGE]: "^15.0" },
      });
      const findings = scanComposerJsonContent(content, "composer.json");
      const hit = findings.find((f) => f.rule === "COMPOSER_MALICIOUS_PACKAGE");
      expect(hit).toBeDefined();
      expect(hit?.severity).toBe("critical");
      expect(hit?.category).toBe("malware");
      expect(hit?.confidence).toBeGreaterThan(0);
    });

    it("should flag a require-dev entry matching an IOC", () => {
      const content = JSON.stringify({
        "require-dev": { [MALICIOUS_PACKAGE]: "*" },
      });
      const findings = scanComposerJsonContent(content, "composer.json");
      expect(findings.some((f) => f.rule === "COMPOSER_MALICIOUS_PACKAGE")).toBe(true);
    });

    it("should not flag a clean composer.json", () => {
      const content = JSON.stringify({
        require: { php: "^8.2", "monolog/monolog": "^3.0", "guzzlehttp/guzzle": "^7.8" },
        "require-dev": { "phpunit/phpunit": "^11.0" },
      });
      const findings = scanComposerJsonContent(content, "composer.json");
      expect(findings).toHaveLength(0);
    });

    it("should not crash on malformed composer.json", () => {
      expect(() => scanComposerJsonContent("{ not json", "composer.json")).not.toThrow();
      expect(scanComposerJsonContent("{ not json", "composer.json")).toHaveLength(0);
      expect(scanComposerJsonContent("null", "composer.json")).toHaveLength(0);
    });

    it("should flag repositories entries using plain http", () => {
      const content = JSON.stringify({
        repositories: [
          { type: "composer", url: "http://packages.internal.example" },
          { type: "vcs", url: "http://git.internal.example/repo.git" },
        ],
      });
      const findings = scanComposerJsonContent(content, "composer.json");
      const hits = findings.filter((f) => f.rule === "COMPOSER_HTTP_REPOSITORY");
      expect(hits).toHaveLength(2);
      expect(hits[0]?.severity).toBe("medium");
      expect(hits[0]?.category).toBe("supply-chain");
    });

    it("should not flag https repositories (array or object form)", () => {
      const arrayForm = JSON.stringify({
        repositories: [{ type: "composer", url: "https://packages.internal.example" }],
      });
      const objectForm = JSON.stringify({
        repositories: { internal: { type: "composer", url: "https://packages.internal.example" } },
      });
      expect(scanComposerJsonContent(arrayForm, "composer.json")).toHaveLength(0);
      expect(scanComposerJsonContent(objectForm, "composer.json")).toHaveLength(0);
    });
  });

  describe("composer.lock scanning", () => {
    it("should flag a locked package matching an IOC (v-prefixed version)", () => {
      const content = JSON.stringify({
        packages: [
          { name: MALICIOUS_PACKAGE, version: "v15.0.0" },
          { name: "monolog/monolog", version: "3.5.0" },
        ],
      });
      const findings = scanComposerLockContent(content, "composer.lock");
      const hit = findings.find((f) => f.rule === "COMPOSER_MALICIOUS_PACKAGE");
      expect(hit).toBeDefined();
      expect(hit?.description).toContain(`${MALICIOUS_PACKAGE}@15.0.0`);
    });

    it("should flag IOC packages in packages-dev too", () => {
      const content = JSON.stringify({
        "packages-dev": [{ name: MALICIOUS_PACKAGE, version: "15.1.0" }],
      });
      const findings = scanComposerLockContent(content, "composer.lock");
      expect(findings.some((f) => f.rule === "COMPOSER_MALICIOUS_PACKAGE")).toBe(true);
    });

    it("should flag plain-http dist and source URLs", () => {
      const content = JSON.stringify({
        packages: [
          {
            name: "acme/widget",
            version: "1.0.0",
            dist: { type: "zip", url: "http://dist.internal.example/widget.zip" },
            source: { type: "git", url: "http://git.internal.example/widget.git" },
          },
        ],
      });
      const findings = scanComposerLockContent(content, "composer.lock");
      expect(findings.some((f) => f.rule === "COMPOSER_HTTP_DIST_URL")).toBe(true);
      expect(findings.some((f) => f.rule === "COMPOSER_HTTP_SOURCE_URL")).toBe(true);
    });

    it("should not flag a clean composer.lock", () => {
      const content = JSON.stringify({
        packages: [
          {
            name: "monolog/monolog",
            version: "3.5.0",
            dist: { type: "zip", url: "https://api.github.com/repos/Seldaek/monolog/zipball/abc" },
            source: { type: "git", url: "https://github.com/Seldaek/monolog.git" },
          },
        ],
        "packages-dev": [],
      });
      const findings = scanComposerLockContent(content, "composer.lock");
      expect(findings).toHaveLength(0);
    });

    it("should not crash on malformed composer.lock", () => {
      expect(() => scanComposerLockContent("[1,2,", "composer.lock")).not.toThrow();
      expect(scanComposerLockContent('{"packages": "oops"}', "composer.lock")).toHaveLength(0);
      expect(scanComposerLockContent('{"packages": [null, 42]}', "composer.lock")).toHaveLength(0);
    });
  });

  describe("directory scanning", () => {
    it("should scan composer.json and composer.lock from a directory", () => {
      fs.writeFileSync(
        path.join(tmpDir, "composer.json"),
        JSON.stringify({ require: { [MALICIOUS_PACKAGE]: "^15.0" } }),
      );
      fs.writeFileSync(
        path.join(tmpDir, "composer.lock"),
        JSON.stringify({ packages: [{ name: MALICIOUS_PACKAGE, version: "v15.0.0" }] }),
      );
      const findings = scanComposerFiles(tmpDir);
      expect(findings.filter((f) => f.rule === "COMPOSER_MALICIOUS_PACKAGE")).toHaveLength(2);
    });

    it("should return no findings for an empty directory", () => {
      expect(scanComposerFiles(tmpDir)).toHaveLength(0);
    });
  });

  describe("matchPackageIOC (composer)", () => {
    it("should match bare-name IOCs regardless of version", () => {
      expect(matchPackageIOC("composer", MALICIOUS_PACKAGE)).not.toBeNull();
      expect(matchPackageIOC("composer", MALICIOUS_PACKAGE, "1.2.3")).not.toBeNull();
    });

    it("should not match unknown packages", () => {
      expect(matchPackageIOC("composer", "monolog/monolog")).toBeNull();
      expect(matchPackageIOC("composer", "laravel-lang/other")).toBeNull();
    });
  });
});
